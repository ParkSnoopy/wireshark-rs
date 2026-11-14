//! The privileged helper (`src/bin/wireshark-capture.rs`), seen from the GUI.
//!
//! `launch` runs it once through pkexec and receives an unbound AF_PACKET
//! socket. The helper then stays and answers the commands of
//! `helper_proto` over the same connection; dropping `Helper` closes it,
//! which makes the helper undo any interception and exit.

use std::io::{self, Read};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use crate::helper_proto::{PEM_BEGIN, PEM_END};

const HELPER: &str = "wireshark-capture";
/// Absolute path: never search PATH for the program that grants root.
const PKEXEC: &str = "/usr/bin/pkexec";
/// Longest reply line.
const REPLY_MAX: usize = 4096;

pub struct Helper {
    /// One command at a time: a reply belongs to the last request.
    control: Mutex<OwnedFd>,
}

/// Runs the helper through pkexec and returns the packet socket it sends,
/// and the connection for later commands. Blocks until the user answers
/// the authorization dialog.
pub fn launch() -> io::Result<(OwnedFd, Helper)> {
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
    // The Command, and with it our copy of `theirs`, is dropped after spawn:
    // a helper that exits early then shows as end of file.
    let mut child = Command::new(PKEXEC)
        .arg(helper)
        .stdin(Stdio::null())
        .stdout(Stdio::from(theirs))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run {PKEXEC}: {e}")))?;
    let mut stderr = child.stderr.take().expect("stderr is piped");

    match receive(&ours) {
        Ok((reply, Some(fd))) if reply == "ok" => {
            // The helper stays: pass on its messages and reap it when it exits.
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                eprint!("{text}");
                let _ = child.wait();
            });
            Ok((
                fd,
                Helper {
                    control: Mutex::new(ours),
                },
            ))
        }
        result => {
            let mut text = String::new();
            stderr.read_to_string(&mut text)?;
            let status = child.wait()?;
            // pkexec exits 126 when the dialog is dismissed and 127 when not authorized.
            Err(io::Error::other(match (text.trim(), result) {
                ("", Err(e)) if status.success() => e.to_string(),
                ("", _) => format!("capture permission not granted ({status})"),
                (text, _) => text.to_owned(),
            }))
        }
    }
}

impl Helper {
    /// A TCP socket that the interception rules let through, for the
    /// proxy's own connections.
    pub fn marked_socket(&self, v6: bool) -> io::Result<OwnedFd> {
        let (_, fd) = self.request(if v6 { "socket6\n" } else { "socket4\n" })?;
        fd.ok_or_else(|| io::Error::other("the helper sent no socket"))
    }

    /// Trusts `ca_pem` system-wide and redirects web traffic to the proxy.
    pub fn intercept_on(&self, ca_pem: &str) -> io::Result<()> {
        let pem = ca_pem.trim();
        if !(pem.starts_with(PEM_BEGIN) && pem.ends_with(PEM_END)) {
            return Err(io::Error::other("not a PEM certificate"));
        }
        self.request(&format!("on\n{pem}\n")).map(drop)
    }

    /// Removes the redirect rules and the CA.
    pub fn intercept_off(&self) -> io::Result<()> {
        self.request("off\n").map(drop)
    }

    fn request(&self, command: &str) -> io::Result<(String, Option<OwnedFd>)> {
        let control = self.control.lock().unwrap_or_else(PoisonError::into_inner);
        let mut sent = 0;
        while sent < command.len() {
            // SAFETY: the pointer and length describe the unsent part of `command`.
            let n = unsafe {
                libc::send(
                    control.as_raw_fd(),
                    command[sent..].as_ptr().cast(),
                    command.len() - sent,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                return Err(io::Error::other(format!(
                    "the capture helper is gone: {}",
                    io::Error::last_os_error()
                )));
            }
            sent += n.cast_unsigned();
        }
        match receive(&control)? {
            (reply, fd) if reply == "ok" => Ok((reply, fd)),
            (reply, _) => Err(io::Error::other(
                reply.strip_prefix("error: ").unwrap_or(&reply).to_owned(),
            )),
        }
    }
}

/// Receives one reply line and the descriptor sent with it, if any.
fn receive(sock: &OwnedFd) -> io::Result<(String, Option<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fd = None;
    while !line.ends_with(b"\n") {
        let mut buf = [0u8; 512];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // u64 storage keeps the control buffer aligned for cmsghdr.
        let mut control = [0u64; 4];
        // SAFETY: msghdr is a plain C struct; all-zero is a valid value.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control);
        // SAFETY: msg and everything it points to stay valid during the call.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::other("the capture helper exited"));
        }
        // SAFETY: recvmsg filled msg; CMSG_FIRSTHDR returns null or a header inside control.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        // SAFETY: cmsg is checked for null before it is read.
        if !cmsg.is_null()
            && unsafe {
                (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            }
        {
            // SAFETY: an SCM_RIGHTS header carries at least one int; the kernel
            // installed that descriptor in this process and nothing else owns it.
            fd = Some(unsafe {
                OwnedFd::from_raw_fd(libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned())
            });
        }
        line.extend_from_slice(&buf[..n.cast_unsigned()]);
        if line.len() > REPLY_MAX {
            return Err(io::Error::other("reply too long"));
        }
    }
    line.pop();
    Ok((String::from_utf8_lossy(&line).into_owned(), fd))
}
