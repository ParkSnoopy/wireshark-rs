//! Packet capture inside the unprivileged shell.
//!
//! `helper::launch` runs the helper once through pkexec and receives an
//! `AF_PACKET` socket for all protocols whose filter drops every packet.
//! A capture swaps in a filter that passes one interface and reads the
//! socket on a thread; stopping puts the drop-all filter back. The shell
//! never holds root or a capability.
//!
//! Whole packets are read: the parser looks into payloads for protocol
//! names and host names, and the recording keeps them for export.

use std::io::{self, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::socket::{LinkAddr, MsgFlags};
use socket2::{SockFilter, SockRef};

use crate::export::{Link, Recording, SNAPLEN};
use crate::helper_proto::{BPF_RET_K, DROP_ALL};
use crate::owners::Owners;
use crate::parse::{self, Row};

/// How long a read waits, so the thread sees the stop flag without a packet.
const READ_WAIT: Duration = Duration::from_millis(100);
/// `BPF_LD | BPF_W | BPF_ABS`: load a 32-bit word.
const BPF_LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`: compare with a constant.
const BPF_JEQ_K: u16 = 0x15;
/// `SKF_AD_OFF + SKF_AD_IFINDEX`: where a filter reads the packet's interface.
const AD_IFINDEX: u32 = 0xFFFF_F000 + 8;

/// A running capture on one interface; dropping it stops the capture.
#[derive(Debug)]
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
    /// Starts capturing on `iface` with the helper's packet socket.
    pub fn start(socket: Arc<OwnedFd>, iface: &str) -> io::Result<Self> {
        let index = nix::net::if_::if_nametoindex(iface)?;
        let sock = SockRef::from(&*socket);
        drain(&sock);
        sock.attach_filter(&only_interface(index))?;
        sock.set_read_timeout(Some(READ_WAIT))?;

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
        if let Err(e) = SockRef::from(&*self.socket).attach_filter(&DROP_ALL) {
            let _ = writeln!(io::stderr(), "cannot stop the capture socket: {e}");
        }
    }
}

/// Classic BPF program that keeps whole packets of interface `index` only.
const fn only_interface(index: u32) -> [SockFilter; 4] {
    [
        SockFilter::new(BPF_LD_W_ABS, 0, 0, AD_IFINDEX),
        // Equal: next instruction (keep); otherwise skip one (drop).
        SockFilter::new(BPF_JEQ_K, 0, 1, index),
        SockFilter::new(BPF_RET_K, 0, 0, u32::MAX),
        SockFilter::new(BPF_RET_K, 0, 0, 0),
    ]
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
        // MSG_TRUNC: the result is the length on the wire, even when longer than buf.
        let received = nix::sys::socket::recvmsg::<LinkAddr>(
            socket.as_raw_fd(),
            &mut [IoSliceMut::new(&mut buf)],
            None,
            MsgFlags::MSG_TRUNC,
        )
        .map(|msg| (msg.bytes, msg.address));
        let (wire_len, addr) = match received {
            Ok((n, Some(addr))) => (n, addr),
            Ok((_, None)) => continue,
            Err(e) => match io::Error::from(e).kind() {
                io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut => continue,
                kind => return Err(kind.into()),
            },
        };
        // Loopback shows each packet twice (outgoing and incoming). Keep one copy, like libpcap.
        if addr.pkttype() == libc::PACKET_OUTGOING && addr.hatype() == libc::ARPHRD_LOOPBACK {
            continue;
        }
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        no += 1;
        let rel_us = now_us.saturating_sub(*first_us.get_or_insert(now_us));
        let link = link_of(&addr);
        let len = u32::try_from(wire_len).unwrap_or(u32::MAX);
        let data = buf.get(..wire_len.min(SNAPLEN)).unwrap_or(&buf);
        recording.write(now_us, &link, data, wire_len)?;
        let ethertype = link.protocol;
        if !emit(parse::row(no, rel_us, len, ethertype, data)) {
            break;
        }
    }
    Ok(())
}

/// The pcap link header fields of a received packet's address.
fn link_of(addr: &LinkAddr) -> Link {
    let mut link = Link {
        pkttype: addr.pkttype(),
        hatype: addr.hatype(),
        // The kernel's sll_protocol is in network byte order.
        protocol: u16::from_be(addr.protocol()),
        ..Link::default()
    };
    if let Some(mac) = addr.addr() {
        let halen = addr.halen().min(mac.len());
        link.halen = u8::try_from(halen).unwrap_or(0);
        link.addr[..mac.len()].copy_from_slice(&mac);
    }
    link
}

/// Drops packets queued by an earlier capture.
fn drain(socket: &SockRef<'_>) {
    let mut buf = [MaybeUninit::uninit(); 1];
    let flags = libc::MSG_DONTWAIT | libc::MSG_TRUNC;
    while socket.recv_with_flags(&mut buf, flags).is_ok() {}
}
