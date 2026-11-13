//! Packet capture inside the unprivileged shell.
//!
//! `request_socket` runs the helper once through pkexec and receives an
//! unbound AF_PACKET socket. A capture binds that socket to one interface
//! and reads it on a thread; stopping binds it to protocol 0 again, which
//! stops delivery. The shell never holds root or a capability.

use std::ffi::CString;
use std::io::{self, Read};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::owners::Owners;
use crate::parse::{self, Row};

const HELPER: &str = "wireshark-capture";
/// Absolute path: never search PATH for the program that grants root.
const PKEXEC: &str = "/usr/bin/pkexec";
/// Bytes kept per packet: enough for IPv6 + TCP with options. Payload is not kept.
const SNAPLEN: usize = 128;
const ETH_P_ALL: u16 = 0x0003;

pub struct Capture {
    pub iface: String,
    /// Captured rows, or the reason the capture failed.
    pub rx: Receiver<Result<Row, String>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket: Arc<OwnedFd>,
}

/// Runs the helper through pkexec and returns the socket it sends.
/// Blocks until the user answers the authorization dialog.
pub fn request_socket() -> io::Result<OwnedFd> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors socketpair writes.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors that nothing else owns.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    // Run only the helper installed next to this binary. pkexec needs an absolute path.
    let helper = std::env::current_exe()?.with_file_name(HELPER);
    // pkexec closes every descriptor above 2, so the socket goes in as stdout.
    let mut child = Command::new(PKEXEC)
        .arg(helper)
        .stdin(Stdio::null())
        .stdout(Stdio::from(theirs))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run {PKEXEC}: {e}")))?;
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_string(&mut stderr)?;
    let status = child.wait()?;

    match recv_fd(&ours) {
        Ok(fd) => Ok(fd),
        // pkexec exits 126 when the dialog is dismissed and 127 when not authorized.
        Err(_) if !status.success() => Err(io::Error::other(match stderr.trim() {
            "" => format!("capture permission not granted ({status})"),
            text => text.to_owned(),
        })),
        Err(e) => Err(e),
    }
}

impl Capture {
    pub fn start(socket: Arc<OwnedFd>, iface: &str) -> io::Result<Self> {
        let name = CString::new(iface).map_err(|_| io::Error::other("invalid interface name"))?;
        // SAFETY: name is a valid NUL-terminated string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        drain(&socket);
        bind(
            &socket,
            ETH_P_ALL,
            i32::try_from(index).map_err(io::Error::other)?,
        )?;
        // A receive timeout lets the thread see the stop flag without a packet.
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        // SAFETY: timeout is a valid timeval and the length matches its size.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                socklen::<libc::timeval>(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let thread = {
            let (socket, stop) = (Arc::clone(&socket), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut owners = Owners::default();
                let result = read_loop(&socket, &stop, |mut row| {
                    owners.annotate(&mut row);
                    tx.send(Ok(row)).is_ok()
                });
                if let Err(e) = result {
                    // Fails only when the capture was already stopped.
                    let _ = tx.send(Err(e.to_string()));
                }
            })
        };
        Ok(Self {
            iface: iface.to_owned(),
            rx,
            stop,
            thread: Some(thread),
            socket,
        })
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            // The thread wakes at least every receive timeout (100 ms).
            let _ = t.join();
        }
        if let Err(e) = bind(&self.socket, 0, 0) {
            eprintln!("unbind capture socket: {e}");
        }
    }
}

/// Reads packets until `stop` is set or `emit` returns false.
fn read_loop(
    socket: &OwnedFd,
    stop: &AtomicBool,
    mut emit: impl FnMut(Row) -> bool,
) -> io::Result<()> {
    let mut buf = [0u8; SNAPLEN];
    let mut first_us = None;
    let mut no = 0;
    while !stop.load(Ordering::Relaxed) {
        // SAFETY: sockaddr_ll is a plain C struct; all-zero is a valid value.
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut addr_len = socklen::<libc::sockaddr_ll>();
        // SAFETY: buf and addr are valid for writes of the lengths passed.
        let n = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
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
            match e.kind() {
                io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut => continue,
                _ => return Err(e),
            }
        };
        // Loopback shows each packet twice (outgoing and incoming). Keep one copy, like libpcap.
        if addr.sll_pkttype == libc::PACKET_OUTGOING && addr.sll_hatype == libc::ARPHRD_LOOPBACK {
            continue;
        }
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        no += 1;
        let rel_us = now_us.saturating_sub(*first_us.get_or_insert(now_us));
        // sll_protocol is in network byte order.
        let ethertype = u16::from_be(addr.sll_protocol);
        let len = u32::try_from(wire_len).unwrap_or(u32::MAX);
        if !emit(parse::row(
            no,
            rel_us,
            len,
            ethertype,
            &buf[..wire_len.min(SNAPLEN)],
        )) {
            break;
        }
    }
    Ok(())
}

/// Drops packets queued by an earlier capture.
fn drain(socket: &OwnedFd) {
    let mut buf = [0u8; 1];
    // SAFETY: buf is valid for writes of one byte.
    while unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            1,
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    } >= 0
    {}
}

/// Binds to `protocol` on interface `index`. Protocol 0 stops delivery.
fn bind(socket: &OwnedFd, protocol: u16, index: i32) -> io::Result<()> {
    // SAFETY: sockaddr_ll is a plain C struct; all-zero is a valid value.
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = protocol.to_be();
    addr.sll_ifindex = index;
    // SAFETY: addr is a valid sockaddr_ll and the length matches its size.
    let rc = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const addr).cast(),
            socklen::<libc::sockaddr_ll>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receives one descriptor sent with SCM_RIGHTS.
fn recv_fd(sock: &OwnedFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut control = [0u64; 4];
    // SAFETY: msghdr is a plain C struct; all-zero is a valid value.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control);
    // The helper has exited, so a missing message means it sent nothing.
    // SAFETY: msg and everything it points to stay valid during the call.
    let n = unsafe {
        libc::recvmsg(
            sock.as_raw_fd(),
            &raw mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: recvmsg filled msg; CMSG_FIRSTHDR returns null or a header inside control.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    // SAFETY: cmsg is checked for null before it is read.
    let ok = !cmsg.is_null()
        && unsafe {
            (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        };
    if !ok {
        return Err(io::Error::other("the capture helper sent no socket"));
    }
    // SAFETY: an SCM_RIGHTS header carries at least one int; the kernel installed
    // that descriptor in this process and nothing else owns it.
    Ok(unsafe {
        OwnedFd::from_raw_fd(libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned())
    })
}

fn socklen<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("struct size fits socklen_t")
}
