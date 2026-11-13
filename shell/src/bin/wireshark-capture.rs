//! Minimal privileged capture helper.
//!
//! The GUI starts it through pkexec, so it runs as root. It opens one
//! AF_PACKET socket bound to one interface, switches to the user who ran
//! pkexec, drops every capability, and then writes the first `SNAPLEN` bytes
//! of each packet to stdout.
//!
//! Output: the 4-byte `READY` marker once privileges are gone, then records.
//! Record format (16-byte header, then `cap_len` bytes):
//! `ts_us: u64 LE | wire_len: u32 LE | ethertype: u16 BE | cap_len: u16 LE`
//! The data starts at the network layer (SOCK_DGRAM strips the link header).

use std::ffi::CString;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bytes kept per packet: enough for IPv6 + TCP with options. Payload is not kept.
const SNAPLEN: usize = 128;
const ETH_P_ALL: u16 = 0x0003;
/// Written once after the privilege drop. The GUI reads it before any record.
const READY: &[u8; 4] = b"WSRK";

fn main() {
    if let Err(e) = run() {
        eprintln!("wireshark-capture: {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(iface), None) = (args.next(), args.next()) else {
        return Err(io::Error::other("usage: wireshark-capture <interface>"));
    };
    let fd = open_socket(&iface)?;
    switch_to_pkexec_user()?;
    drop_privileges()?;

    let mut out = BufWriter::new(io::stdout().lock());
    out.write_all(READY)?;
    out.flush()?;
    let mut buf = [0u8; SNAPLEN];
    loop {
        // SAFETY: sockaddr_ll is a plain C struct; all-zero is a valid value.
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut addr_len = socklen::<libc::sockaddr_ll>();
        // SAFETY: buf and addr are valid for writes of the lengths passed.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut addr).cast(),
                &mut addr_len,
            )
        };
        // A negative return value fails the conversion and means errno is set.
        let Ok(wire_len) = usize::try_from(n) else {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        };
        // Loopback shows each packet twice (outgoing and incoming). Keep one copy, like libpcap.
        if addr.sll_pkttype == libc::PACKET_OUTGOING && addr.sll_hatype == libc::ARPHRD_LOOPBACK {
            continue;
        }
        let cap_len = wire_len.min(SNAPLEN);
        let ts_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));

        out.write_all(&ts_us.to_le_bytes())?;
        out.write_all(&u32::try_from(wire_len).unwrap_or(u32::MAX).to_le_bytes())?;
        // sll_protocol is already in network byte order.
        out.write_all(&addr.sll_protocol.to_ne_bytes())?;
        out.write_all(&u16::try_from(cap_len).unwrap_or(u16::MAX).to_le_bytes())?;
        out.write_all(&buf[..cap_len])?;
        // Write error (EPIPE) means the UI is gone: exit through `?`.
        out.flush()?;
    }
}

fn open_socket(iface: &str) -> io::Result<OwnedFd> {
    let name = CString::new(iface).map_err(|_| io::Error::other("invalid interface name"))?;
    // SAFETY: name is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }

    // Protocol 0: the socket receives nothing until bind(), so no packet
    // from another interface enters the queue before the bind.
    // SAFETY: plain syscall with constant arguments.
    let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a new, valid file descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: sockaddr_ll is a plain C struct; all-zero is a valid value.
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = i32::try_from(index).map_err(io::Error::other)?;
    // SAFETY: addr is a valid sockaddr_ll and the length matches its size.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            socklen::<libc::sockaddr_ll>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// When running as root, switches uid, gid and groups to the user who ran
/// pkexec. Leaving uid 0 also clears the capability sets.
fn switch_to_pkexec_user() -> io::Result<()> {
    // SAFETY: plain syscall without arguments.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let uid: libc::uid_t = std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            io::Error::other("running as root without PKEXEC_UID: start through pkexec")
        })?;
    // SAFETY: getpwuid returns NULL or a pointer to a static record. The process
    // is single-threaded and reads the record before any other passwd call.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(io::Error::other(format!("no passwd entry for uid {uid}")));
    }
    // SAFETY: pw is non-null and points to a valid passwd record.
    let gid = unsafe { (*pw).pw_gid };
    // Groups and gid first: only root may change them.
    // SAFETY: plain syscalls; a null list with length 0 clears the groups.
    let ok = unsafe {
        libc::setgroups(0, std::ptr::null()) == 0
            && libc::setresgid(gid, gid, gid) == 0
            && libc::setresuid(uid, uid, uid) == 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Clears the effective, permitted and inheritable capability sets and
/// blocks any later privilege gain (setuid or file capabilities) via exec.
fn drop_privileges() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    let mut header = Header {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [Data::default(); 2];
    // SAFETY: header and data match the kernel capset ABI for version 3 (two Data entries).
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain prctl call with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn socklen<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("struct size fits socklen_t")
}
