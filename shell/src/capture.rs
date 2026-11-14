//! Packet capture inside the unprivileged shell.
//!
//! `helper::launch` runs the helper once through pkexec and receives an
//! unbound AF_PACKET socket. A capture binds that socket to one interface
//! and reads it on a thread; stopping binds it to protocol 0 again, which
//! stops delivery. The shell never holds root or a capability.
//!
//! Whole packets are read: the parser looks into payloads for protocol
//! names and host names, and the recording keeps them for export.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::{Recording, SNAPLEN};
use crate::owners::Owners;
use crate::parse::{self, Row};

const ETH_P_ALL: u16 = 0x0003;

pub struct Capture {
    pub iface: String,
    /// Captured rows, or the reason the capture failed.
    pub rx: Receiver<Result<Row, String>>,
    /// Every packet of this capture, for "Save pcap". Outlives the capture.
    pub recording: Arc<Recording>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket: Arc<OwnedFd>,
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

        let recording = Arc::new(Recording::create()?);
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let thread = {
            let (socket, stop, rec) = (
                Arc::clone(&socket),
                Arc::clone(&stop),
                Arc::clone(&recording),
            );
            std::thread::spawn(move || {
                let mut owners = Owners::default();
                let result = read_loop(&socket, &stop, &rec, |mut row| {
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
            recording,
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

/// Reads packets until `stop` is set or `emit` returns false, and records
/// each one.
fn read_loop(
    socket: &OwnedFd,
    stop: &AtomicBool,
    recording: &Recording,
    mut emit: impl FnMut(Row) -> bool,
) -> io::Result<()> {
    let mut buf = vec![0u8; SNAPLEN];
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
        let data = &buf[..wire_len.min(SNAPLEN)];
        recording.write(now_us, &addr, data, wire_len)?;
        if !emit(parse::row(no, rel_us, len, ethertype, data)) {
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

fn socklen<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("struct size fits socklen_t")
}
