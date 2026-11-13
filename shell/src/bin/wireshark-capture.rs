//! Minimal privileged helper.
//!
//! The GUI runs it once at launch through pkexec, so it runs as root. It
//! creates one AF_PACKET socket, sends the descriptor to the GUI over stdout
//! (which must be a Unix socket) with SCM_RIGHTS, and exits. Root lasts a
//! few milliseconds and the helper reads no packet and no untrusted input.
//!
//! Only socket creation needs CAP_NET_RAW. The GUI binds the socket to an
//! interface when the user starts a capture; bind needs no privilege.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn main() {
    if let Err(e) = run() {
        eprintln!("wireshark-capture: {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    if std::env::args().len() != 1 {
        return Err(io::Error::other(
            "usage: wireshark-capture (takes no arguments)",
        ));
    }
    // Protocol 0: the socket receives nothing until the GUI binds it.
    // SAFETY: plain syscall with constant arguments.
    let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a new, valid file descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    send_fd(libc::STDOUT_FILENO, &fd)
}

/// Sends `fd` as SCM_RIGHTS ancillary data with a one-byte payload.
fn send_fd(sock: libc::c_int, fd: &OwnedFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut control = [0u64; 4];
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    assert!(
        space <= mem::size_of_val(&control),
        "control buffer fits one fd"
    );

    // SAFETY: msghdr is a plain C struct; all-zero is a valid value.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space;
    // SAFETY: msg points to a control buffer of `space` bytes, so the first
    // header and its data area are inside the buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize;
        libc::CMSG_DATA(cmsg)
            .cast::<libc::c_int>()
            .write_unaligned(fd.as_raw_fd());
    }
    // SAFETY: msg and everything it points to stay valid during the call.
    if unsafe { libc::sendmsg(sock, &raw const msg, 0) } != 1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
