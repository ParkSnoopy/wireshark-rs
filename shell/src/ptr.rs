//! Reverse DNS (PTR) names of addresses, through the system resolver.
//!
//! Lookups block for up to the resolver timeout, so a few worker threads
//! run them. Each address is looked up once per run.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// Lookups that may wait on the resolver at the same time.
const WORKERS: usize = 4;

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
                    let Some(ip) = rx.lock().ok().and_then(|r| r.recv().ok()) else {
                        return;
                    };
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
/// The lookup asks for a name (`NI_NAMEREQD`), so it fails rather than
/// return the address as text.
pub fn lookup(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// glibc answers loopback from /etc/hosts, without the network.
    #[test]
    fn loopback_has_a_name() {
        let name = lookup(IpAddr::from([127, 0, 0, 1]));
        assert!(name.is_some(), "127.0.0.1 has no PTR name");
    }
}
