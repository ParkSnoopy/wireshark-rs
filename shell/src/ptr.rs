//! Reverse DNS (PTR) names of addresses, through the system resolver.
//!
//! Lookups block for up to the resolver timeout, so a few worker threads
//! run them. Each address is looked up once per run.

use std::collections::HashSet;
use std::ffi::CStr;
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// Lookups that may wait on the resolver at the same time.
const WORKERS: usize = 4;
/// `NI_MAXHOST` of glibc.
const MAX_HOST: usize = 1025;

/// Answer for one address: `name` is `None` when it has no PTR record.
#[derive(Clone, Debug, Serialize)]
pub struct PtrInfo {
    pub ip: String,
    pub name: Option<String>,
}

pub struct Ptr {
    tx: Sender<IpAddr>,
    asked: HashSet<IpAddr>,
}

impl Ptr {
    /// Starts the workers. `emit` runs on a worker thread for each answer.
    pub fn spawn(emit: impl Fn(PtrInfo) + Send + Sync + 'static) -> Self {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let rx = Arc::new(Mutex::new(rx));
        let emit = Arc::new(emit);
        for _ in 0..WORKERS {
            let (rx, emit) = (Arc::clone(&rx), Arc::clone(&emit));
            std::thread::spawn(move || {
                loop {
                    // The guard drops before the lookup, so workers wait on it in turn.
                    let next = rx.lock().map(|r| r.recv());
                    let Ok(Ok(ip)) = next else { return };
                    emit(PtrInfo {
                        ip: ip.to_string(),
                        name: lookup(ip),
                    });
                }
            });
        }
        Self {
            tx,
            asked: HashSet::new(),
        }
    }

    /// Queues `ip` unless it was asked for before.
    pub fn check(&mut self, ip: IpAddr) {
        if self.asked.insert(ip) {
            // Fails only when every worker is gone.
            let _ = self.tx.send(ip);
        }
    }
}

/// PTR name of `ip`, or `None` when there is none or the lookup fails.
pub fn lookup(ip: IpAddr) -> Option<String> {
    // SAFETY: sockaddr_storage is plain data, valid when zeroed.
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match ip {
        IpAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in.
            unsafe { std::ptr::write((&raw mut sa).cast(), sin) };
            size_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: as above, for sockaddr_in6.
            unsafe { std::ptr::write((&raw mut sa).cast(), sin6) };
            size_of::<libc::sockaddr_in6>()
        }
    };
    let mut host = [0 as libc::c_char; MAX_HOST];
    // SAFETY: sa holds a sockaddr of `len` bytes; host is a writable buffer
    // of its stated size; no service buffer is requested.
    let rc = unsafe {
        libc::getnameinfo(
            (&raw const sa).cast(),
            len as libc::socklen_t,
            host.as_mut_ptr(),
            MAX_HOST as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            // Fail instead of returning the address as text.
            libc::NI_NAMEREQD,
        )
    };
    // SAFETY: on success getnameinfo wrote a NUL-terminated string.
    (rc == 0).then(|| {
        unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// glibc answers loopback from /etc/hosts, without the network.
    #[test]
    fn loopback_has_a_name() {
        assert!(lookup("127.0.0.1".parse().unwrap()).is_some());
    }
}
