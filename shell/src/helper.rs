//! The privileged helper (`src/bin/wireshark-capture.rs`), seen from the GUI.
//!
//! `launch` runs it once through pkexec and receives an `AF_PACKET` socket
//! that drops every packet until a capture starts. The helper then stays
//! and answers the commands of
//! `helper_proto` over the same connection; dropping `Helper` closes it,
//! which makes the helper undo any interception and exit.

use std::io::{self, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags};

use crate::helper_proto::{PEM_BEGIN, PEM_END};

const HELPER: &str = "wireshark-capture";
/// Absolute path: never search PATH for the program that grants root.
const PKEXEC: &str = "/usr/bin/pkexec";
/// Longest reply line.
const REPLY_MAX: usize = 4096;

/// The connection to the running helper.
#[derive(Debug)]
pub struct Helper {
    /// One command at a time: a reply belongs to the last request.
    control: Mutex<UnixStream>,
}

/// Runs the helper through pkexec and returns the packet socket it sends,
/// and the connection for later commands. Blocks until the user answers
/// the authorization dialog.
pub fn launch() -> io::Result<(OwnedFd, Helper)> {
    let (ours, theirs) = UnixStream::pair()?;

    // Run only the helper installed next to this binary. pkexec needs an absolute path.
    let helper = std::env::current_exe()?.with_file_name(HELPER);
    // pkexec closes every descriptor above 2, so the socket goes in as stdout.
    // The Command, and with it our copy of `theirs`, is dropped after spawn:
    // a helper that exits early then shows as end of file.
    let mut child = Command::new(PKEXEC)
        .arg(helper)
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(theirs)))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run {PKEXEC}: {e}")))?;
    let Some(mut stderr) = child.stderr.take() else {
        return Err(io::Error::other("the helper's error output is not piped"));
    };

    match receive(&ours) {
        Ok((reply, Some(fd))) if reply == "ok" => {
            // The helper stays: pass on its messages and reap it when it exits.
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                let _ = io::stderr().write_all(text.as_bytes());
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
            // Not `write`: without MSG_NOSIGNAL a gone helper raises SIGPIPE.
            sent += rustix::net::send(&*control, &command.as_bytes()[sent..], SendFlags::NOSIGNAL)
                .map_err(|e| io::Error::other(format!("the capture helper is gone: {e}")))?;
        }
        let answer = receive(&control)?;
        drop(control);
        match answer {
            (reply, fd) if reply == "ok" => Ok((reply, fd)),
            (reply, _) => Err(io::Error::other(
                reply.strip_prefix("error: ").unwrap_or(&reply).to_owned(),
            )),
        }
    }
}

/// Receives one reply line and the descriptor sent with it, if any.
fn receive(sock: &UnixStream) -> io::Result<(String, Option<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fd = None;
    while !line.ends_with(b"\n") {
        let mut buf = [0u8; 512];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let msg = rustix::net::recvmsg(
            sock,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        if msg.bytes == 0 {
            return Err(io::Error::other("the capture helper exited"));
        }
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(mut fds) = message {
                fd = fd.or_else(|| fds.next());
            }
        }
        line.extend_from_slice(buf.get(..msg.bytes).unwrap_or(&buf));
        if line.len() > REPLY_MAX {
            return Err(io::Error::other("reply too long"));
        }
    }
    line.pop();
    Ok((String::from_utf8_lossy(&line).into_owned(), fd))
}
