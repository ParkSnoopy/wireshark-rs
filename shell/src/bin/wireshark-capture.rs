//! Minimal privileged helper.
//!
//! The GUI runs it once at launch through pkexec, so it runs as root. It
//! creates one unbound AF_PACKET socket and sends the descriptor to the GUI
//! over stdout (which must be a Unix socket) with SCM_RIGHTS. The GUI binds
//! that socket to an interface when the user starts a capture; bind needs
//! no privilege.
//!
//! It then stays to serve the few commands of `helper_proto` that HTTPS
//! interception needs: firewall rules, trust store and marked sockets all
//! need root at the moment the user turns interception on.
//!
//! Interception is undone on every way out:
//! - the GUI closes the connection (it exits, crashes or is killed): the
//!   helper removes the rules and the CA, then exits;
//! - SIGTERM, SIGINT, SIGHUP or SIGQUIT to the helper: the same;
//! - the helper itself is killed: the rules live in an owner-flagged nft
//!   table held by an `nft -i` child, which exits when the helper's end of
//!   its input closes, and the kernel then deletes the table. Only the
//!   trusted CA stays; the next launch removes it, and its key died with
//!   the proxy.
//!
//! It reads no packet. Its only input is the GUI's command lines, taken
//! from a fixed list; the one argument is a checked PEM certificate.

#[path = "../helper_proto.rs"]
mod proto;

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use socket2::{Domain, Socket, Type};

/// The `nft -i` process that owns the rules table, while interception is
/// on. The lock also keeps `on` and `off` from running at the same time.
static RULES: Mutex<Option<Child>> = Mutex::new(None);
/// Signals that end the helper: cleanup runs first.
const ENDING: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT];
/// How long `nft -i` may take to create the table.
const RULES_WAIT: Duration = Duration::from_secs(3);

/// Absolute paths: root never searches PATH.
const NFT: &str = "/usr/sbin/nft";
/// Trust stores: update tool, its arguments and the file it reads the CA from.
/// The first one whose tool exists is used (Debian, then Fedora).
const STORES: [(&str, &[&str], &str); 2] = [
    (
        "/usr/sbin/update-ca-certificates",
        &[],
        "/usr/local/share/ca-certificates/wireshark-rs-interception.crt",
    ),
    (
        "/usr/bin/update-ca-trust",
        &["extract"],
        "/etc/pki/ca-trust/source/anchors/wireshark-rs-interception.pem",
    ),
];
/// Longest command line.
const LINE_MAX: u64 = 64;

fn main() {
    if let Err(e) = run() {
        // Not eprintln: it panics when the GUI, which reads stderr, is gone.
        let _ = writeln!(io::stderr(), "wireshark-capture: {e}");
        std::process::exit(1);
    }
}

/// Runs cleanup and exits when an ending signal arrives. The signals are
/// blocked in every thread and taken by one thread with sigwait, so the
/// cleanup runs as normal code, not in a signal handler.
fn watch_signals() -> io::Result<()> {
    // SAFETY: sigset_t is a plain C struct; sigemptyset initializes it.
    let mut set: libc::sigset_t = unsafe { mem::zeroed() };
    // SAFETY: set is a valid sigset_t; the signal numbers are valid.
    unsafe {
        libc::sigemptyset(&raw mut set);
        for s in ENDING {
            libc::sigaddset(&raw mut set, s);
        }
    }
    // SAFETY: set is initialized; the old mask is not needed.
    let err =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err));
    }
    std::thread::spawn(move || {
        let mut sig = 0;
        // SAFETY: set and sig are valid for the call.
        unsafe { libc::sigwait(&raw const set, &raw mut sig) };
        let _ = off();
        std::process::exit(128 + sig);
    });
    Ok(())
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
    let packet = unsafe { OwnedFd::from_raw_fd(raw) };
    // Before any thread starts, so every thread inherits the blocked mask.
    watch_signals()?;
    send(libc::STDOUT_FILENO, b"ok\n", Some(&packet))?;
    drop(packet);

    // Leftovers of an earlier helper that was killed before it cleaned up.
    if let Err(e) = off() {
        let _ = writeln!(io::stderr(), "wireshark-capture: cleanup: {e}");
    }
    let served = serve();
    // Whatever ended the loop, leave nothing redirected or trusted.
    off().and(served)
}

/// Answers commands until the GUI closes the connection.
fn serve() -> io::Result<()> {
    // SAFETY: stdout is the GUI's socket; nothing else in this process uses it.
    let control = File::from(unsafe { OwnedFd::from_raw_fd(libc::STDOUT_FILENO) });
    let fd = control.as_raw_fd();
    let mut input = BufReader::new(control);
    loop {
        let mut line = String::new();
        if input.by_ref().take(LINE_MAX).read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut socket = None;
        let result = match line.trim_end() {
            "socket4" => marked(Domain::IPV4).map(|s| socket = Some(s)),
            "socket6" => marked(Domain::IPV6).map(|s| socket = Some(s)),
            "on" => read_pem(&mut input).and_then(|pem| on(&pem)),
            "off" => off(),
            _ => return Err(io::Error::other("unknown command")),
        };
        let reply = match result {
            Ok(()) => "ok\n".to_owned(),
            // One line: tool output may hold newlines.
            Err(e) => format!("error: {}\n", e.to_string().replace('\n', " ")),
        };
        send(fd, reply.as_bytes(), socket.as_ref())?;
    }
}

/// TCP socket whose packets carry `MARK`, so the redirect rules skip them.
fn marked(domain: Domain) -> io::Result<OwnedFd> {
    let s = Socket::new(domain, Type::STREAM, None)?;
    s.set_mark(proto::MARK)?;
    Ok(s.into())
}

/// Reads one PEM certificate, line by line, and checks its shape: the
/// markers and base64 lines only, at most `PEM_MAX` bytes.
fn read_pem(input: &mut impl BufRead) -> io::Result<String> {
    let mut pem = String::new();
    loop {
        let start = pem.len();
        let room = (proto::PEM_MAX - start) as u64;
        if input.by_ref().take(room).read_line(&mut pem)? == 0 {
            return Err(io::Error::other("certificate cut short"));
        }
        if pem[start..].trim_end() == proto::PEM_END {
            break;
        }
        if pem.len() >= proto::PEM_MAX {
            return Err(io::Error::other("certificate too long"));
        }
    }
    check_pem(&pem)?;
    Ok(pem)
}

fn check_pem(pem: &str) -> io::Result<()> {
    let lines: Vec<&str> = pem.lines().collect();
    let base64 = |l: &&str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    };
    match lines.as_slice() {
        [first, body @ .., last]
            if *first == proto::PEM_BEGIN
                && *last == proto::PEM_END
                && !body.is_empty()
                && body.iter().all(base64) =>
        {
            Ok(())
        }
        _ => Err(io::Error::other("not one PEM certificate")),
    }
}

/// Trusts the CA system-wide, then redirects all TCP to the proxy.
fn on(pem: &str) -> io::Result<()> {
    let mut rules = RULES.lock().unwrap_or_else(PoisonError::into_inner);
    if rules.is_some() {
        return Err(io::Error::other("interception is already on"));
    }
    let applied = trust(pem).and_then(|()| hold_rules());
    match applied {
        Ok(child) => {
            *rules = Some(child);
            Ok(())
        }
        Err(e) => {
            drop(rules);
            let _ = off();
            Err(e)
        }
    }
}

/// Starts `nft -i` and has it create the owner-flagged table, which then
/// lives exactly as long as that process.
fn hold_rules() -> io::Result<Child> {
    let rules = proto::rules();
    // Check first: `nft -i` reports errors nowhere we can read in order.
    command(NFT, &["-c", "-f", "-"], Some(&rules))?;
    let mut child = Command::new(NFT)
        .arg("-i")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io::Error::other(format!("{NFT}: {e}")))?;
    let mut input = child.stdin.as_ref().expect("stdin is piped");
    let sent = input
        .write_all(rules.as_bytes())
        .and_then(|()| input.flush());
    let since = Instant::now();
    while sent.is_ok() && since.elapsed() < RULES_WAIT {
        if command(NFT, &["list", "table", proto::TABLE], None).is_ok() {
            return Ok(child);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(io::Error::other(match sent {
        Err(e) => format!("nft -i: {e}"),
        Ok(()) => "nft did not create the interception table".to_owned(),
    }))
}

/// Adds the CA to the system trust store.
fn trust(pem: &str) -> io::Result<()> {
    let (tool, args, file) = STORES
        .into_iter()
        .find(|(tool, ..)| Path::new(tool).exists())
        .ok_or_else(|| {
            io::Error::other("no trust store tool (update-ca-certificates or update-ca-trust)")
        })?;
    if let Some(dir) = Path::new(file).parent() {
        fs::create_dir_all(dir)?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(file)?
        .write_all(pem.as_bytes())?;
    command(tool, args, None)
}

/// Removes the rules, then the CA. Safe to call when nothing is set up.
fn off() -> io::Result<()> {
    let mut held = RULES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(mut child) = held.take() {
        // End of input ends `nft -i`, and the kernel drops its table.
        drop(child.stdin.take());
        let _ = child.wait();
    }
    // Also a table left by an older helper that did not own it.
    let rules = command(NFT, &["-f", "-"], Some(&proto::remove_rules()));
    let mut trust = Ok(());
    for (tool, args, file) in STORES {
        if Path::new(file).exists() {
            trust = trust
                .and(fs::remove_file(file))
                .and(command(tool, args, None));
        }
    }
    rules.and(trust)
}

/// Runs a fixed program with a clean environment; its error output becomes
/// the error text.
fn command(program: &str, args: &[&str], input: Option<&str>) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("{program}: {e}")))?;
    if let Some(text) = input {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    Err(io::Error::other(format!(
        "{program}: {} {}",
        out.status,
        why.trim()
    )))
}

/// Sends `payload`, with `fd` as SCM_RIGHTS ancillary data when given.
fn send(sock: libc::c_int, payload: &[u8], fd: Option<&OwnedFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
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
    if let Some(fd) = fd {
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
    }
    // SAFETY: msg and everything it points to stay valid during the call;
    // the kernel only reads the payload.
    let sent = unsafe { libc::sendmsg(sock, &raw const msg, libc::MSG_NOSIGNAL) };
    if usize::try_from(sent).ok() != Some(payload.len()) {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\nAb+/==\n-----END CERTIFICATE-----\n";

    #[test]
    fn pem_is_read_up_to_its_end_marker() {
        let text = format!("{PEM}off\n");
        let mut input = text.as_bytes();
        assert_eq!(read_pem(&mut input).unwrap(), PEM);
        let mut rest = String::new();
        input.read_line(&mut rest).unwrap();
        assert_eq!(rest, "off\n");
    }

    #[test]
    fn bad_pem_is_refused() {
        for bad in [
            "",
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nab cd\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END CERTIFICATE-----\n",
            "x\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ] {
            assert!(check_pem(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}\n{}\n", proto::PEM_BEGIN, "A".repeat(proto::PEM_MAX));
        assert!(read_pem(&mut long.as_bytes()).is_err());
    }

    #[test]
    fn rules_name_the_shared_values() {
        let r = proto::rules();
        assert!(r.contains("meta mark 0x57535253 return"));
        assert!(r.contains("redirect to :8899"));
    }
}
