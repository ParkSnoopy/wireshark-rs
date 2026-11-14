//! Domain age over RDAP, to flag recently registered or transferred
//! domains. Lookups run one at a time on their own thread and go straight
//! to the registry's RDAP server, found through the IANA bootstrap file.

use std::collections::HashMap;
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

const BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
const TIMEOUT: Duration = Duration::from_secs(10);

/// `(top-level domains, RDAP base URL)` from the bootstrap file.
type Servers = Result<Vec<(Vec<String>, String)>, String>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Dates {
    /// `YYYY-MM-DD` of the latest registration, and its age in days.
    pub registered: Option<String>,
    pub registered_days: Option<i64>,
    /// `YYYY-MM-DD` of the latest registrar transfer, and its age in days.
    pub transferred: Option<String>,
    pub transferred_days: Option<i64>,
    /// Why the dates are unknown.
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DomainInfo {
    /// Host name seen in traffic.
    pub name: String,
    /// Registrable domain the dates belong to.
    pub site: String,
    #[serde(flatten)]
    pub dates: Dates,
}

#[derive(Clone)]
pub struct Rdap {
    tx: Sender<String>,
}

impl Rdap {
    /// Starts the lookup thread. `emit` gets one result per checked name.
    pub fn spawn(emit: impl Fn(DomainInfo) + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                .build()
                .into();
            let mut servers: Option<Servers> = None;
            // One successful lookup per registrable domain per run. A failed
            // one is tried again for the next new name of that domain.
            let mut sites: HashMap<String, Dates> = HashMap::new();
            for name in rx {
                let Some(site) = registrable(&name) else {
                    continue;
                };
                let dates = sites.get(&site).cloned().unwrap_or_else(|| {
                    // A failed bootstrap download is tried again too.
                    if servers.as_ref().is_some_and(Result::is_err) {
                        servers = None;
                    }
                    let list = servers.get_or_insert_with(|| bootstrap(&agent));
                    let d = lookup(&agent, list, &site);
                    if d.error.is_none() {
                        sites.insert(site.clone(), d.clone());
                    }
                    d
                });
                emit(DomainInfo { name, site, dates });
            }
        });
        Self { tx }
    }

    /// Queues a host name. Names of one registrable domain share one lookup.
    pub fn check(&self, name: String) {
        // Fails only when the thread is gone, i.e. during exit.
        let _ = self.tx.send(name);
    }
}

/// `www.example.co.uk` → `example.co.uk`; `None` without a known public suffix.
fn registrable(name: &str) -> Option<String> {
    let domain = psl::domain(name.as_bytes())?;
    domain
        .suffix()
        .is_known()
        .then(|| String::from_utf8_lossy(domain.as_bytes()).into_owned())
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, String> {
    let get = || {
        agent
            .get(url)
            .header("Accept", "application/rdap+json, application/json")
            .call()?
            .body_mut()
            .read_json::<Value>()
    };
    // Servers close idle pooled connections, sometimes without a TLS
    // close_notify; the request on such a connection fails. Retry once on a
    // new one. HTTP status errors are answers, not retried.
    match get() {
        Err(ureq::Error::StatusCode(code)) => Err(format!("HTTP status {code}")),
        Err(_) => get().map_err(|e| e.to_string()),
        Ok(v) => Ok(v),
    }
}

fn bootstrap(agent: &ureq::Agent) -> Servers {
    let v = get_json(agent, BOOTSTRAP)?;
    let services = v["services"]
        .as_array()
        .ok_or("unexpected bootstrap file")?;
    Ok(services
        .iter()
        .filter_map(|s| {
            let tlds = s[0]
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
            let url = s[1]
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .find(|u| u.starts_with("https://"))?;
            Some((tlds, url.to_owned()))
        })
        .collect())
}

fn lookup(agent: &ureq::Agent, servers: &Servers, site: &str) -> Dates {
    let failed = |error: String| Dates {
        error: Some(error),
        ..Dates::default()
    };
    let servers = match servers {
        Ok(s) => s,
        Err(e) => return failed(format!("RDAP bootstrap failed: {e}")),
    };
    let tld = site.rsplit('.').next().unwrap_or(site);
    let Some((_, base)) = servers
        .iter()
        .find(|(tlds, _)| tlds.iter().any(|t| t == tld))
    else {
        return failed(format!("no RDAP server for .{tld}"));
    };
    match get_json(
        agent,
        &format!("{}/domain/{site}", base.trim_end_matches('/')),
    ) {
        Ok(v) => dates(&v, today()),
        Err(e) => failed(e),
    }
}

/// Registration and transfer dates from an RDAP domain object.
fn dates(v: &Value, today: i64) -> Dates {
    let latest = |actions: &[&str]| {
        v["events"]
            .as_array()?
            .iter()
            .filter(|e| {
                e["eventAction"]
                    .as_str()
                    .is_some_and(|a| actions.contains(&a))
            })
            .filter_map(|e| e["eventDate"].as_str()?.get(..10))
            .max()
            .map(str::to_owned)
    };
    let registered = latest(&["registration", "reregistration"]);
    let transferred = latest(&["transfer"]);
    let age = |d: &Option<String>| d.as_deref().and_then(day_number).map(|n| today - n);
    Dates {
        registered_days: age(&registered),
        transferred_days: age(&transferred),
        registered,
        transferred,
        error: None,
    }
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date (H. Hinnant's `days_from_civil`).
fn day_number(date: &str) -> Option<i64> {
    let (y, m, d): (i64, i64, i64) = (
        date.get(0..4)?.parse().ok()?,
        date.get(5..7)?.parse().ok()?,
        date.get(8..10)?.parse().ok()?,
    );
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    Some(era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468)
}

fn today() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs() / 86_400).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_numbers() {
        assert_eq!(day_number("1970-01-01"), Some(0));
        assert_eq!(day_number("2000-03-01"), Some(11_017));
        assert_eq!(day_number("2026-11-13T00:00:00Z"), Some(20_770));
        assert_eq!(day_number("2026-1"), None);
    }

    #[test]
    fn dates_take_the_latest_event_of_each_kind() {
        let v = serde_json::json!({ "events": [
            { "eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z" },
            { "eventAction": "reregistration", "eventDate": "2026-11-01T00:00:00Z" },
            { "eventAction": "expiration", "eventDate": "2027-11-01T00:00:00Z" },
            { "eventAction": "transfer", "eventDate": "2026-10-30T00:00:00Z" },
        ]});
        // Unknown dates make every assertion below fail.
        let d = day_number("2026-11-13").map_or_else(Dates::default, |today| dates(&v, today));
        assert_eq!(
            (d.registered.as_deref(), d.registered_days),
            (Some("2026-11-01"), Some(12))
        );
        assert_eq!(d.transferred_days, Some(14));
        assert_eq!(dates(&serde_json::json!({}), 0), Dates::default());
    }

    /// Needs the internet: `cargo test -p wireshark-rs rdap -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_lookup() {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .build()
            .into();
        let servers = bootstrap(&agent);
        let name = std::env::var("RDAP_DOMAIN").unwrap_or_else(|_| "example.com".into());
        let d = lookup(&agent, &servers, &name);
        assert_eq!(d.error, None);
        assert!(d.registered.is_some(), "{d:?}");
        let _ = std::io::Write::write_fmt(&mut std::io::stderr(), format_args!("{name}: {d:?}\n"));
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(
            registrable("www.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(registrable("api.github.com").as_deref(), Some("github.com"));
        assert_eq!(registrable("printer.local"), None);
    }
}
