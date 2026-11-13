//! Data model without DOM access: packet rows, address scopes, the table
//! filter and sort, and the capture graph. Host-testable with
//! `cargo test -p wireshark-ui`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

/// One captured packet, as the shell sends it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Row {
    pub no: u64,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub len: u32,
    pub info: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// Interface that owns the address or whose network holds it.
    #[serde(default)]
    pub src_if: Option<IfRef>,
    #[serde(default)]
    pub dst_if: Option<IfRef>,
    /// Process that owns the local socket of each end.
    #[serde(default)]
    pub sproc: Option<String>,
    #[serde(default)]
    pub dproc: Option<String>,
    /// Lowercase text the filter searches. Filled by `Row::prepared`.
    #[serde(skip)]
    search: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct IfRef {
    pub name: String,
    /// True for an address of this host, false for one on the interface's network.
    pub local: bool,
}

impl Row {
    /// Fills the filter's search text once, so filtering a long capture
    /// allocates nothing per row.
    pub fn prepared(mut self) -> Self {
        let (src, dst) = self.endpoints();
        let names = [&self.sproc, &self.dproc].into_iter().flatten();
        let ifaces = [&self.src_if, &self.dst_if]
            .into_iter()
            .flatten()
            .map(|i| &i.name);
        let scopes = [scope(&self.src), scope(&self.dst)]
            .into_iter()
            .flatten()
            .map(|s| s.kind);
        let mut text = format!("#{} {src} {dst} {} {}", self.no, self.proto, self.info);
        for word in names.chain(ifaces).map(String::as_str).chain(scopes) {
            text.push(' ');
            text.push_str(word);
        }
        self.search = text.to_lowercase();
        self
    }

    /// Seconds since the first packet of the capture.
    pub fn secs(&self) -> f64 {
        self.time.parse().unwrap_or(0.0)
    }

    /// Source and destination as `addr` or `addr:port` (`[v6]:port`).
    pub fn endpoints(&self) -> (String, String) {
        (
            endpoint(&self.src, self.sport),
            endpoint(&self.dst, self.dport),
        )
    }

    /// Owning processes: `a → b`, or the one that is known.
    pub fn process(&self) -> String {
        match (&self.sproc, &self.dproc) {
            (Some(a), Some(b)) => format!("{a} → {b}"),
            (Some(p), None) | (None, Some(p)) => p.clone(),
            (None, None) => String::new(),
        }
    }

    /// True when `other` is in the same conversation: same protocol and the
    /// same two endpoints, in either direction.
    pub fn same_conversation(&self, other: &Row) -> bool {
        self.proto == other.proto
            && (self.same_direction(other) && self.dst == other.dst && self.dport == other.dport
                || self.src == other.dst
                    && self.sport == other.dport
                    && self.dst == other.src
                    && self.dport == other.sport)
    }

    /// True when `other` leaves from the same endpoint as this packet.
    pub fn same_direction(&self, other: &Row) -> bool {
        self.src == other.src && self.sport == other.sport
    }
}

/// Duration with a unit that keeps three significant digits for short spans.
pub fn duration(secs: f64) -> String {
    match secs.abs() {
        s if s < 1e-3 => format!("{:.0} µs", secs * 1e6),
        s if s < 1.0 => format!("{:.1} ms", secs * 1e3),
        _ => format!("{secs:.2} s"),
    }
}

/// Byte count with a binary unit.
pub fn bytes(n: u64) -> String {
    match n {
        n if n < 1024 => format!("{n} B"),
        n if n < 1024 * 1024 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0)),
    }
}

fn endpoint(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr.to_owned(),
    }
}

/// A special-purpose address block that holds an address.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Scope {
    pub cidr: &'static str,
    /// `private`, `loopback`, `link-local`, `shared`, `multicast` or `broadcast`.
    pub kind: &'static str,
}

/// IPv4 blocks of RFC 6890 that do not route on the public internet.
const V4_SCOPES: [(u32, u32, &str, &str); 8] = [
    (0x0a00_0000, 8, "10.0.0.0/8", "private"),
    (0xac10_0000, 12, "172.16.0.0/12", "private"),
    (0xc0a8_0000, 16, "192.168.0.0/16", "private"),
    (0x6440_0000, 10, "100.64.0.0/10", "shared"),
    (0x7f00_0000, 8, "127.0.0.0/8", "loopback"),
    (0xa9fe_0000, 16, "169.254.0.0/16", "link-local"),
    (0xe000_0000, 4, "224.0.0.0/4", "multicast"),
    (0xffff_ffff, 32, "255.255.255.255/32", "broadcast"),
];

/// Scope of `addr`, or `None` for a public (global) address or a non-IP value.
pub fn scope(addr: &str) -> Option<Scope> {
    let v4 = |ip: Ipv4Addr| {
        V4_SCOPES.iter().find_map(|&(net, prefix, cidr, kind)| {
            let mask = u32::MAX << (32 - prefix);
            (u32::from(ip) & mask == net).then_some(Scope { cidr, kind })
        })
    };
    let scope = |cidr, kind| Some(Scope { cidr, kind });
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => v4(ip),
        IpAddr::V6(ip) => match ip.segments()[0] {
            _ if ip.is_loopback() => scope("::1/128", "loopback"),
            _ if ip.to_ipv4_mapped().is_some() => ip.to_ipv4_mapped().and_then(v4),
            s if s & 0xfe00 == 0xfc00 => scope("fc00::/7", "private"),
            s if s & 0xffc0 == 0xfe80 => scope("fe80::/10", "link-local"),
            s if s & 0xff00 == 0xff00 => scope("ff00::/8", "multicast"),
            _ => None,
        },
    }
}

/// Choices of the protocol filter. The first one matches everything.
pub const PROTOCOLS: [&str; 6] = ["All protocols", "TCP", "UDP", "ICMP", "ARP", "Other"];

/// Table filter: every whitespace-separated term must occur in the row
/// (number, endpoints, protocol, info, process, interface or scope,
/// case-insensitive), and the protocol must match the chosen `PROTOCOLS` entry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filter {
    terms: Vec<String>,
    proto: String,
}

impl Filter {
    pub fn new(text: &str, proto: &str) -> Self {
        Self {
            terms: text.split_whitespace().map(str::to_lowercase).collect(),
            proto: proto.to_owned(),
        }
    }

    pub fn matches(&self, r: &Row) -> bool {
        let proto_ok = match self.proto.as_str() {
            "TCP" | "UDP" | "ARP" => r.proto == self.proto,
            "ICMP" => r.proto.starts_with("ICMP"),
            "Other" => {
                !matches!(r.proto.as_str(), "TCP" | "UDP" | "ARP") && !r.proto.starts_with("ICMP")
            }
            _ => true,
        };
        proto_ok && self.terms.iter().all(|t| r.search.contains(t.as_str()))
    }
}

/// Sortable table columns.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Col {
    No,
    Time,
    Source,
    Destination,
    Protocol,
    Length,
    Process,
    Info,
}

/// Compares two rows by `col` in ascending order.
pub fn compare(a: &Row, b: &Row, col: Col) -> Ordering {
    match col {
        // Rows arrive in number and time order.
        Col::No | Col::Time => a.no.cmp(&b.no),
        Col::Source => addr_key(&a.src, a.sport).cmp(&addr_key(&b.src, b.sport)),
        Col::Destination => addr_key(&a.dst, a.dport).cmp(&addr_key(&b.dst, b.dport)),
        Col::Protocol => a.proto.cmp(&b.proto),
        Col::Length => a.len.cmp(&b.len),
        Col::Process => (&a.sproc, &a.dproc).cmp(&(&b.sproc, &b.dproc)),
        Col::Info => a.info.cmp(&b.info),
    }
}

/// Numeric order for IP addresses (10.0.0.9 before 10.0.0.10), text order otherwise.
fn addr_key(addr: &str, port: Option<u16>) -> (Option<IpAddr>, &str, Option<u16>) {
    (addr.parse().ok(), addr, port)
}

/// Class of a graph node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// An IP address seen in traffic.
    Host,
    /// A protocol and port that the host at index `host` offers.
    Service { host: usize },
    /// A local program (`firefox`) with sockets on the host at index `host`.
    Process { host: usize },
}

/// Relation of a graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Rel {
    /// Host or process → the service it offers.
    Serves,
    /// Client host or process → service.
    Connects,
    /// Host → host, for traffic without ports (ICMP, ARP).
    Exchanges,
    /// Process → the host it runs on.
    RunsOn,
}

impl Rel {
    pub fn name(self) -> &'static str {
        match self {
            Rel::Serves => "serves",
            Rel::Connects => "connects to",
            Rel::Exchanges => "exchanges",
            Rel::RunsOn => "runs on",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub label: String,
    pub kind: Kind,
    pub packets: u64,
    pub bytes: u64,
    /// Hosts only: the related interface, when the shell named one.
    pub iface: Option<IfRef>,
    /// Hosts only: the special-purpose block that holds the address.
    pub scope: Option<Scope>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub rel: Rel,
    pub proto: String,
    pub packets: u64,
    pub bytes: u64,
}

/// One step of the graph build: when a node or edge first appeared.
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    pub time: String,
    pub text: String,
    /// Node the entry is about, for the inspector.
    pub node: usize,
}

/// Capture graph: hosts, services, processes and their relations, built
/// packet by packet over the whole capture.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub log: Vec<LogEntry>,
    nodes_by_key: HashMap<String, usize>,
    edges_by_key: HashMap<(usize, usize, Rel, String), usize>,
}

impl Graph {
    pub fn add(&mut self, r: &Row) {
        if r.src.is_empty() || r.dst.is_empty() {
            return;
        }
        let src = self.host(r, &r.src, &r.src_if);
        let dst = self.host(r, &r.dst, &r.dst_if);
        if let (Some(sport), Some(dport)) = (r.sport, r.dport) {
            // shortcut: the lower port is taken as the service, so traffic between two
            // high ports may pick the wrong side; track SYN direction if that matters.
            let (server, client, port, server_proc, client_proc) = if dport <= sport {
                (dst, src, dport, &r.dproc, &r.sproc)
            } else {
                (src, dst, sport, &r.sproc, &r.dproc)
            };
            let svc = self.service(r, server, &format!("{}/{port}", r.proto));
            let server = self.actor(r, server, server_proc);
            let client = self.actor(r, client, client_proc);
            self.edge(r, server, svc, Rel::Serves);
            self.edge(r, client, svc, Rel::Connects);
        } else {
            self.edge(r, src, dst, Rel::Exchanges);
        }
    }

    pub fn count(&self, rel: Rel) -> usize {
        self.edges.iter().filter(|e| e.rel == rel).count()
    }

    pub fn count_kind(&self, f: fn(&Kind) -> bool) -> usize {
        self.nodes.iter().filter(|n| f(&n.kind)).count()
    }

    pub fn hosts(&self) -> usize {
        self.count_kind(|k| *k == Kind::Host)
    }

    fn host(&mut self, r: &Row, addr: &str, iface: &Option<IfRef>) -> usize {
        let i = self.node(r, format!("h {addr}"), addr, Kind::Host, || {
            format!("New host {addr}")
        });
        let node = &mut self.nodes[i];
        if node.iface.is_none() {
            node.iface.clone_from(iface);
        }
        node.scope = scope(addr);
        i
    }

    fn service(&mut self, r: &Row, host: usize, label: &str) -> usize {
        let on = self.nodes[host].label.clone();
        let key = format!("s {host} {label}");
        self.node(r, key, label, Kind::Service { host }, || {
            format!("New service {label} on {on}")
        })
    }

    /// The process on `host` when the shell named one, else the host itself.
    fn actor(&mut self, r: &Row, host: usize, process: &Option<String>) -> usize {
        let Some(name) = process else { return host };
        let on = self.nodes[host].label.clone();
        let key = format!("p {host} {name}");
        let p = self.node(r, key, name, Kind::Process { host }, || {
            format!("New process {name} on {on}")
        });
        self.edge(r, p, host, Rel::RunsOn);
        p
    }

    fn node(
        &mut self,
        r: &Row,
        key: String,
        label: &str,
        kind: Kind,
        text: impl FnOnce() -> String,
    ) -> usize {
        let len = u64::from(r.len);
        if let Some(&i) = self.nodes_by_key.get(&key) {
            self.nodes[i].packets += 1;
            self.nodes[i].bytes += len;
            return i;
        }
        let i = self.nodes.len();
        self.nodes.push(Node {
            label: label.to_owned(),
            kind,
            packets: 1,
            bytes: len,
            iface: None,
            scope: None,
        });
        self.log(r, text(), i);
        self.nodes_by_key.insert(key, i);
        i
    }

    fn edge(&mut self, r: &Row, from: usize, to: usize, rel: Rel) {
        let len = u64::from(r.len);
        let proto = if rel == Rel::RunsOn {
            ""
        } else {
            r.proto.as_str()
        };
        let key = (from, to, rel, proto.to_owned());
        if let Some(&i) = self.edges_by_key.get(&key) {
            self.edges[i].packets += 1;
            self.edges[i].bytes += len;
            return;
        }
        let (a, b) = (&self.nodes[from].label, &self.nodes[to].label);
        let text = match (rel, self.nodes[to].kind) {
            (Rel::Connects, Kind::Service { host }) => {
                format!("{a} connects to {b} on {}", self.nodes[host].label)
            }
            (Rel::Exchanges, _) => format!("{a} exchanges {proto} with {b}"),
            _ => format!("{a} {} {b}", rel.name()),
        };
        self.edges.push(Edge {
            from,
            to,
            rel,
            proto: proto.to_owned(),
            packets: 1,
            bytes: len,
        });
        self.log(r, text, from);
        self.edges_by_key.insert(key, self.edges.len() - 1);
    }

    fn log(&mut self, r: &Row, text: String, node: usize) {
        self.log.push(LogEntry {
            time: r.time.clone(),
            text,
            node,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        no: u64,
        src: &str,
        sport: Option<u16>,
        dst: &str,
        dport: Option<u16>,
        proto: &str,
    ) -> Row {
        Row {
            no,
            time: format!("{no}.000000"),
            src: src.into(),
            dst: dst.into(),
            proto: proto.into(),
            len: 60,
            info: "hello".into(),
            sport,
            dport,
            ..Row::default()
        }
        .prepared()
    }

    #[test]
    fn conversation_matches_both_directions_only() {
        let a = row(1, "10.0.0.1", Some(51000), "10.0.0.2", Some(443), "TCP");
        let back = row(2, "10.0.0.2", Some(443), "10.0.0.1", Some(51000), "TCP");
        let other_port = row(3, "10.0.0.1", Some(51001), "10.0.0.2", Some(443), "TCP");
        let udp = row(4, "10.0.0.1", Some(51000), "10.0.0.2", Some(443), "UDP");
        assert!(a.same_conversation(&back) && back.same_conversation(&a));
        assert!(!a.same_conversation(&other_port) && !a.same_conversation(&udp));
        assert!(!a.same_direction(&back));
    }

    #[test]
    fn units() {
        assert_eq!(
            [duration(0.000166), duration(0.0425), duration(3.0)],
            ["166 µs", "42.5 ms", "3.00 s"]
        );
        assert_eq!(
            [bytes(512), bytes(1536), bytes(3 << 20)],
            ["512 B", "1.5 KiB", "3.0 MiB"]
        );
    }

    #[test]
    fn scopes() {
        let kind = |a: &str| scope(a).map(|s| (s.cidr, s.kind));
        assert_eq!(kind("172.31.255.1"), Some(("172.16.0.0/12", "private")));
        assert_eq!(kind("172.32.0.1"), None);
        assert_eq!(kind("100.64.1.1"), Some(("100.64.0.0/10", "shared")));
        assert_eq!(kind("8.8.8.8"), None);
        assert_eq!(kind("fd12::1"), Some(("fc00::/7", "private")));
        assert_eq!(kind("fe80::1"), Some(("fe80::/10", "link-local")));
        assert_eq!(
            kind("::ffff:192.168.1.2"),
            Some(("192.168.0.0/16", "private"))
        );
        assert_eq!(kind("2001:db8::1"), None);
        assert_eq!(kind(""), None);
    }

    #[test]
    fn filter_terms_process_and_protocol() {
        let mut r = row(7, "fe80::1", Some(53), "10.0.0.2", Some(5353), "UDP");
        r.dproc = Some("firefox".into());
        r.src_if = Some(IfRef {
            name: "podman0".into(),
            local: false,
        });
        let r = r.prepared();
        assert_eq!(r.endpoints().0, "[fe80::1]:53");
        assert!(Filter::new("", "All protocols").matches(&r));
        assert!(Filter::new("FE80 :5353", "UDP").matches(&r));
        assert!(Filter::new("#7 firefox podman0 link-local private", "All protocols").matches(&r));
        assert!(!Filter::new("fe80 tcp", "All protocols").matches(&r));
        assert!(!Filter::new("", "TCP").matches(&r));
        assert!(Filter::new("", "ICMP").matches(&row(1, "a", None, "b", None, "ICMPv6")));
        assert!(Filter::new("", "Other").matches(&row(1, "a", None, "b", None, "IP proto 2")));
    }

    #[test]
    fn sort_addresses_numerically() {
        let a = row(1, "10.0.0.9", None, "x", None, "ICMP");
        let b = row(2, "10.0.0.10", None, "x", None, "ICMP");
        assert_eq!(compare(&a, &b, Col::Source), Ordering::Less);
        assert_eq!(compare(&b, &a, Col::No), Ordering::Greater);
    }

    #[test]
    fn graph_builds_services_processes_and_logs_each_fact_once() {
        let mut g = Graph::default();
        let mut out = row(1, "10.0.0.1", Some(51000), "10.0.0.2", Some(443), "TCP");
        out.sproc = Some("firefox".into());
        g.add(&out);
        g.add(&row(
            2,
            "10.0.0.2",
            Some(443),
            "10.0.0.1",
            Some(51000),
            "TCP",
        ));
        g.add(&row(3, "10.0.0.1", None, "10.0.0.2", None, "ICMP"));
        g.add(&row(4, "", None, "", None, "0x88cc"));

        assert_eq!(g.hosts(), 2);
        assert_eq!(g.nodes.len(), 4);
        assert_eq!(g.nodes[2].label, "TCP/443");
        assert_eq!(g.nodes[2].kind, Kind::Service { host: 1 });
        assert_eq!((g.nodes[2].packets, g.nodes[2].bytes), (2, 120));
        assert_eq!(g.nodes[3].kind, Kind::Process { host: 0 });
        assert_eq!(g.nodes[0].scope.map(|s| s.kind), Some("private"));
        assert_eq!(
            [Rel::Serves, Rel::Connects, Rel::Exchanges, Rel::RunsOn].map(|r| g.count(r)),
            // The reply carries no process name, so the host connects as well.
            [1, 2, 1, 1]
        );
        let log: Vec<&str> = g.log.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(
            log,
            [
                "New host 10.0.0.1",
                "New host 10.0.0.2",
                "New service TCP/443 on 10.0.0.2",
                "New process firefox on 10.0.0.1",
                "firefox runs on 10.0.0.1",
                "10.0.0.2 serves TCP/443",
                "firefox connects to TCP/443 on 10.0.0.2",
                "10.0.0.1 connects to TCP/443 on 10.0.0.2",
                "10.0.0.1 exchanges ICMP with 10.0.0.2",
            ]
        );
    }
}
