//! What Shodan knows about a public address: open ports, host names,
//! software (CPE), tags and known vulnerabilities. Uses `InternetDB`, the
//! free Shodan API that needs no key. Lookups run only when the user asks,
//! one at a time on their own thread.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const BASE: &str = "https://internetdb.shodan.io";
const TIMEOUT: Duration = Duration::from_secs(10);

/// Answer for one address. All lists are empty when Shodan has no data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ShodanInfo {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub cpes: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vulns: Vec<String>,
    /// False when Shodan has no record of the address.
    #[serde(default)]
    pub found: bool,
    /// Why the lookup failed.
    #[serde(default)]
    pub error: Option<String>,
}

pub struct Shodan {
    tx: Sender<IpAddr>,
}

impl Shodan {
    /// Starts the lookup thread. `emit` gets one answer per request.
    pub fn spawn(emit: impl Fn(ShodanInfo) + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel::<IpAddr>();
        std::thread::spawn(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                .http_status_as_error(false)
                .build()
                .into();
            // Answers are kept for the run; a failed lookup is tried again.
            let mut known: HashMap<IpAddr, ShodanInfo> = HashMap::new();
            for ip in rx {
                let info = known.get(&ip).cloned().unwrap_or_else(|| {
                    let info = lookup(&agent, ip);
                    if info.error.is_none() {
                        known.insert(ip, info.clone());
                    }
                    info
                });
                emit(info);
            }
        });
        Self { tx }
    }

    /// Queues `ip`. Addresses that are not public never leave the machine.
    pub fn check(&self, ip: IpAddr) {
        if is_public(ip) {
            // Fails only when the thread is gone, i.e. during exit.
            let _ = self.tx.send(ip);
        }
    }
}

fn lookup(agent: &ureq::Agent, ip: IpAddr) -> ShodanInfo {
    let failed = |error: String| ShodanInfo {
        ip: ip.to_string(),
        error: Some(error),
        ..ShodanInfo::default()
    };
    let mut response = match agent.get(format!("{BASE}/{ip}")).call() {
        Ok(r) => r,
        Err(e) => return failed(e.to_string()),
    };
    match response.status().as_u16() {
        200 => {}
        // InternetDB answers 404 for an address it has no data on.
        404 => {
            return ShodanInfo {
                ip: ip.to_string(),
                ..ShodanInfo::default()
            };
        }
        code => return failed(format!("HTTP status {code}")),
    }
    match response.body_mut().read_json::<ShodanInfo>() {
        Ok(info) => ShodanInfo {
            ip: ip.to_string(),
            found: true,
            error: None,
            ..info
        },
        Err(e) => failed(e.to_string()),
    }
}

/// True unless `ip` is private, loopback, link-local, shared, multicast,
/// documentation or otherwise not reachable from the internet.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 100.64.0.0/10 (shared address space) and 240.0.0.0/4.
                || (a == 100 && b & 0xc0 == 64)
                || a >= 240
                || a == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local, 2001:db8::/32.
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
                || (first == 0x2001 && v6.segments()[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(text: &str) -> bool {
        text.parse().is_ok_and(is_public)
    }

    #[test]
    fn only_public_addresses_are_sent() {
        assert!(public("1.1.1.1"));
        assert!(public("2606:4700:4700::1111"));
        for local in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(local), "{local} would be sent to Shodan");
        }
    }

    #[test]
    fn answers_parse() {
        let text = r#"{"cpes":["cpe:/a:cloudflare:cloudflare"],"hostnames":["one.one.one.one"],
            "ip":"1.1.1.1","ports":[53,443],"tags":["cdn"],"vulns":[]}"#;
        let info: Result<ShodanInfo, _> = serde_json::from_str(text);
        assert!(
            info.is_ok_and(|i| i.ports == [53, 443] && i.tags == ["cdn"]),
            "InternetDB answer does not parse"
        );
    }

    /// Needs the internet: `cargo test -p wireshark-rs shodan -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_lookup() {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        let info = lookup(&agent, IpAddr::from([1, 1, 1, 1]));
        assert_eq!(info.error, None);
        assert!(info.found && info.ports.contains(&443), "{info:?}");
        let none = lookup(&agent, IpAddr::from([192, 0, 2, 1]));
        assert!(!none.found && none.error.is_none(), "{none:?}");
    }
}
