//! Data model without DOM access: packet rows, address scopes, the table
//! filter and sort, and the capture graph. Host-testable with
//! `cargo test -p wireshark-ui`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// One captured packet, as the shell sends it. Serialize is for the JSON export.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
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
    /// Application protocol (`https`, `dns`) from ports and payload.
    #[serde(default)]
    pub app: Option<String>,
    /// Host name each address was reached by (DNS answer, TLS SNI, HTTP Host).
    #[serde(default)]
    pub src_name: Option<String>,
    #[serde(default)]
    pub dst_name: Option<String>,
    /// Lowercase text the filter searches. Filled by `Row::prepared`.
    #[serde(skip)]
    search: String,
    /// Parsed addresses, for the CIDR filter and grouping.
    #[serde(skip)]
    pub src_ip: Option<IpAddr>,
    #[serde(skip)]
    pub dst_ip: Option<IpAddr>,
}

/// Registration data of a domain seen in traffic, as the shell sends it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DomainInfo {
    pub name: String,
    /// Registrable domain the dates belong to.
    pub site: String,
    pub registered: Option<String>,
    pub registered_days: Option<i64>,
    pub transferred: Option<String>,
    pub transferred_days: Option<i64>,
    pub error: Option<String>,
}

/// A domain registered or transferred this many days ago or less is flagged.
pub const RECENT_DAYS: i64 = 30;

impl DomainInfo {
    /// Why the domain deserves a look, like `registered 12 d ago`.
    pub fn flag(&self) -> Option<String> {
        let recent = |d: Option<i64>| d.filter(|&d| (0..=RECENT_DAYS).contains(&d));
        match (recent(self.registered_days), recent(self.transferred_days)) {
            (Some(r), _) => Some(format!("registered {r} d ago")),
            (None, Some(t)) => Some(format!("transferred {t} d ago")),
            (None, None) => None,
        }
    }
}

/// Domain data by host name.
pub type Domains = HashMap<String, DomainInfo>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IfRef {
    pub name: String,
    /// True for an address of this host, false for one on the interface's network.
    pub local: bool,
}

impl Row {
    /// Fills the filter's search text once, so filtering a long capture
    /// allocates nothing per row.
    pub fn prepared(mut self) -> Self {
        self.src_ip = self.src.parse().ok();
        self.dst_ip = self.dst.parse().ok();
        let (src, dst) = self.endpoints();
        let names = [
            &self.sproc,
            &self.dproc,
            &self.app,
            &self.src_name,
            &self.dst_name,
        ]
        .into_iter()
        .flatten();
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

    /// Source and destination for display: `name (addr:port)` when the
    /// address was reached by a host name, else `addr:port`.
    pub fn labels(&self) -> (String, String) {
        let label = |name: &Option<String>, end: String| match name {
            Some(n) => format!("{n} ({end})"),
            None => end,
        };
        let (src, dst) = self.endpoints();
        (label(&self.src_name, src), label(&self.dst_name, dst))
    }

    /// Protocol for display: the application protocol when known.
    pub fn protocol(&self) -> &str {
        self.app.as_deref().unwrap_or(&self.proto)
    }

    /// Flag of the first end whose domain was registered or transferred recently.
    pub fn domain_flag(&self, domains: &Domains) -> Option<(String, String)> {
        [&self.src_name, &self.dst_name]
            .into_iter()
            .flatten()
            .find_map(|n| Some((n.clone(), domains.get(n)?.flag()?)))
    }

    /// Key of "the same traffic": protocol and both endpoints, one direction.
    /// Packets with one key differ only in size and content.
    pub fn flow_key(&self) -> (&str, &str, Option<u16>, &str, Option<u16>) {
        (
            self.protocol(),
            &self.src,
            self.sport,
            &self.dst,
            self.dport,
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

/// An address block like `10.88.0.0/16`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The block of `prefix` bits that holds `ip`.
    pub fn of(ip: IpAddr, prefix: u8) -> Self {
        let net = match ip {
            IpAddr::V4(a) => {
                let p = prefix.min(32);
                let mask = u32::MAX.checked_shl(32 - u32::from(p)).unwrap_or(0);
                IpAddr::V4((u32::from(a) & mask).into())
            }
            IpAddr::V6(a) => {
                let p = prefix.min(128);
                let mask = u128::MAX.checked_shl(128 - u32::from(p)).unwrap_or(0);
                IpAddr::V6((u128::from(a) & mask).into())
            }
        };
        Self {
            net,
            prefix: match ip {
                IpAddr::V4(_) => prefix.min(32),
                IpAddr::V6(_) => prefix.min(128),
            },
        }
    }

    /// Parses `addr/prefix`; the address need not be the first of the block.
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.split_once('/')?;
        let ip: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then(|| Self::of(ip, prefix))
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.net.is_ipv4() && Self::of(ip, self.prefix) == *self
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// Table filter: every whitespace-separated term must occur in the row
/// (number, endpoints, host names, protocols, info, process, interface or
/// scope, case-insensitive). A term like `10.0.0.0/8` matches rows with an
/// end in that block. The protocol must match the chosen `PROTOCOLS` entry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filter {
    terms: Vec<String>,
    nets: Vec<Cidr>,
    proto: String,
}

impl Filter {
    pub fn new(text: &str, proto: &str) -> Self {
        let (nets, terms): (Vec<&str>, Vec<&str>) = text
            .split_whitespace()
            .partition(|t| Cidr::parse(t).is_some());
        Self {
            terms: terms.into_iter().map(str::to_lowercase).collect(),
            nets: nets.into_iter().filter_map(Cidr::parse).collect(),
            proto: proto.to_owned(),
        }
    }

    pub fn matches(&self, r: &Row) -> bool {
        let in_net = |n: &Cidr| {
            [r.src_ip, r.dst_ip]
                .into_iter()
                .flatten()
                .any(|ip| n.contains(ip))
        };
        if !self.nets.iter().all(in_net) {
            return false;
        }
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
        Col::Protocol => (a.protocol(), &a.proto).cmp(&(b.protocol(), &b.proto)),
        Col::Length => a.len.cmp(&b.len),
        Col::Process => (&a.sproc, &a.dproc).cmp(&(&b.sproc, &b.dproc)),
        Col::Info => a.info.cmp(&b.info),
    }
}

/// Numeric order for IP addresses (10.0.0.9 before 10.0.0.10), text order otherwise.
fn addr_key(addr: &str, port: Option<u16>) -> (Option<IpAddr>, &str, Option<u16>) {
    (addr.parse().ok(), addr, port)
}

/// Packets of one flow folded into its newest row.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stack {
    pub count: u32,
    pub min_len: u32,
    pub max_len: u32,
    pub bytes: u64,
}

/// Rows the table shows: indices into the capture in display order and,
/// when repeats are collapsed, the stack each shown row stands for.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TableView {
    pub rows: Vec<usize>,
    pub stacks: HashMap<usize, Stack>,
}

/// Filters, optionally collapses and sorts `rows`. `keep` is the filter;
/// collapsed flows show their newest packet.
pub fn table_view(
    rows: &[Row],
    keep: impl Fn(&Row) -> bool,
    collapse: bool,
    (col, desc): (Col, bool),
) -> TableView {
    let mut shown: Vec<usize> = (0..rows.len()).filter(|&i| keep(&rows[i])).collect();
    let mut stacks = HashMap::new();
    if collapse {
        let mut slot: HashMap<_, usize> = HashMap::new();
        let mut groups: Vec<(usize, Stack)> = Vec::new();
        for i in shown {
            let r = &rows[i];
            let at = *slot.entry(r.flow_key()).or_insert_with(|| {
                groups.push((i, Stack::default()));
                groups.len() - 1
            });
            let (newest, s) = &mut groups[at];
            *newest = i;
            s.min_len = if s.count == 0 {
                r.len
            } else {
                s.min_len.min(r.len)
            };
            s.max_len = s.max_len.max(r.len);
            s.count += 1;
            s.bytes += u64::from(r.len);
        }
        shown = groups.iter().map(|g| g.0).collect();
        // Arrival order of the newest packet of each flow.
        shown.sort_unstable();
        stacks = groups.into_iter().filter(|g| g.1.count > 1).collect();
    }
    // Rows arrive in number order, so that order needs no sort.
    if !matches!(col, Col::No | Col::Time) {
        shown.sort_by(|&a, &b| compare(&rows[a], &rows[b], col));
    }
    if desc {
        shown.reverse();
    }
    TableView {
        rows: shown,
        stacks,
    }
}

/// Address prefix lengths the network view groups by: (IPv4, IPv6).
pub const GROUPINGS: [(&str, u8, u8); 3] = [
    ("/24 · /64", 24, 64),
    ("/16 · /48", 16, 48),
    ("/8 · /32", 8, 32),
];

/// Traffic of one address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostStat {
    pub packets: u64,
    pub bytes: u64,
    /// Latest host name the address was reached by.
    pub name: Option<String>,
    pub iface: Option<IfRef>,
}

/// Per-address totals, updated as rows arrive.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hosts(pub HashMap<IpAddr, HostStat>);

impl Hosts {
    pub fn add(&mut self, r: &Row) {
        let ends = [
            (r.src_ip, &r.src_name, &r.src_if),
            (r.dst_ip, &r.dst_name, &r.dst_if),
        ];
        for (ip, name, iface) in ends {
            let Some(ip) = ip else { continue };
            let h = self.0.entry(ip).or_default();
            h.packets += 1;
            h.bytes += u64::from(r.len);
            if name.is_some() {
                h.name.clone_from(name);
            }
            if h.iface.is_none() {
                h.iface.clone_from(iface);
            }
        }
    }
}

/// One address block and the addresses seen in it.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub cidr: Cidr,
    /// Special-purpose block (`private`, `loopback`) that holds it, if any.
    pub scope: Option<Scope>,
    pub packets: u64,
    pub bytes: u64,
    /// `(address, stats)`, busiest first.
    pub hosts: Vec<(IpAddr, HostStat)>,
}

/// Groups addresses into blocks of `v4`/`v6` prefix bits, busiest block first.
pub fn blocks(hosts: &Hosts, v4: u8, v6: u8) -> Vec<Block> {
    let mut by_cidr: HashMap<Cidr, Block> = HashMap::new();
    for (&ip, h) in &hosts.0 {
        let cidr = Cidr::of(ip, if ip.is_ipv4() { v4 } else { v6 });
        let b = by_cidr.entry(cidr).or_insert_with(|| Block {
            cidr,
            scope: scope(&ip.to_string()),
            packets: 0,
            bytes: 0,
            hosts: Vec::new(),
        });
        // A packet between two addresses of one block counts for both.
        b.packets += h.packets;
        b.bytes += h.bytes;
        b.hosts.push((ip, h.clone()));
    }
    let mut out: Vec<Block> = by_cidr.into_values().collect();
    for b in &mut out {
        b.hosts
            .sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(&b.0)));
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.cidr.net.cmp(&b.cidr.net)));
    out
}

/// Columns of the CSV export, in order.
const CSV_HEADER: &str = "no,time,source,source_port,source_name,destination,destination_port,\
destination_name,transport,protocol,length,source_process,destination_process,\
source_interface,destination_interface,info";

/// Rows as CSV (RFC 4180). Text cells that a spreadsheet would run as a
/// formula get a leading apostrophe: captured text is untrusted.
pub fn csv<'a>(rows: impl IntoIterator<Item = &'a Row>) -> String {
    fn text(s: &str) -> String {
        let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            format!("'{s}")
        } else {
            s.to_owned()
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    }
    let opt = |s: &Option<String>| text(s.as_deref().unwrap_or(""));
    let port = |p: Option<u16>| p.map_or(String::new(), |p| p.to_string());
    let iface = |i: &Option<IfRef>| text(i.as_ref().map_or("", |i| i.name.as_str()));
    let mut out = String::from(CSV_HEADER);
    out.push_str("\r\n");
    for r in rows {
        let cells = [
            r.no.to_string(),
            r.time.clone(),
            text(&r.src),
            port(r.sport),
            opt(&r.src_name),
            text(&r.dst),
            port(r.dport),
            opt(&r.dst_name),
            text(&r.proto),
            opt(&r.app),
            r.len.to_string(),
            opt(&r.sproc),
            opt(&r.dproc),
            iface(&r.src_if),
            iface(&r.dst_if),
            text(&r.info),
        ];
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }
    out
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
    /// Hosts only: the latest host name the address was reached by.
    pub name: Option<String>,
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
        let src = self.host(r, &r.src, &r.src_if, &r.src_name);
        let dst = self.host(r, &r.dst, &r.dst_if, &r.dst_name);
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

    fn host(&mut self, r: &Row, addr: &str, iface: &Option<IfRef>, name: &Option<String>) -> usize {
        let i = self.node(r, format!("h {addr}"), addr, Kind::Host, || match name {
            Some(n) => format!("New host {n} ({addr})"),
            None => format!("New host {addr}"),
        });
        let node = &mut self.nodes[i];
        if node.iface.is_none() {
            node.iface.clone_from(iface);
        }
        if name.is_some() {
            node.name.clone_from(name);
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
            name: None,
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
    fn cidr_blocks_and_filter() {
        let c = Cidr::parse("10.88.7.9/16").unwrap();
        assert_eq!(c.to_string(), "10.88.0.0/16");
        assert!(c.contains("10.88.255.1".parse().unwrap()));
        assert!(!c.contains("10.89.0.1".parse().unwrap()));
        assert!(!c.contains("::a58:1".parse().unwrap()));
        assert_eq!(Cidr::parse("fd00::1/64").unwrap().to_string(), "fd00::/64");
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().to_string(), "0.0.0.0/0");
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);

        let r = row(
            1,
            "10.88.0.2",
            Some(51000),
            "93.184.216.34",
            Some(443),
            "TCP",
        );
        assert!(Filter::new("10.88.0.0/16 :443", "TCP").matches(&r));
        assert!(Filter::new("93.184.0.0/16", "All protocols").matches(&r));
        assert!(!Filter::new("192.168.0.0/16", "All protocols").matches(&r));
    }

    #[test]
    fn names_and_application_protocol() {
        let mut r = row(
            1,
            "10.0.0.2",
            Some(51000),
            "93.184.216.34",
            Some(443),
            "TCP",
        );
        r.dst_name = Some("example.com".into());
        r.app = Some("https".into());
        let r = r.prepared();
        assert_eq!(r.labels().1, "example.com (93.184.216.34:443)");
        assert_eq!(r.labels().0, "10.0.0.2:51000");
        assert_eq!(r.protocol(), "https");
        assert!(Filter::new("example https", "TCP").matches(&r));

        let mut domains = Domains::new();
        let info = |reg: i64, xfer: i64| DomainInfo {
            registered_days: Some(reg),
            transferred_days: Some(xfer),
            ..DomainInfo::default()
        };
        domains.insert("example.com".into(), info(4000, 400));
        assert_eq!(r.domain_flag(&domains), None);
        domains.insert("example.com".into(), info(4000, 3));
        assert_eq!(
            r.domain_flag(&domains),
            Some(("example.com".into(), "transferred 3 d ago".into()))
        );
        assert_eq!(info(30, 999).flag().as_deref(), Some("registered 30 d ago"));
        assert_eq!(info(31, 999).flag(), None);
    }

    #[test]
    fn collapse_folds_one_flow_direction() {
        let mut rows = Vec::new();
        for (no, len) in [(1, 100), (2, 1500), (3, 60)] {
            let mut r = row(no, "10.0.0.1", Some(5000), "10.0.0.2", Some(443), "TCP");
            r.len = len;
            rows.push(r);
        }
        let mut reply = row(4, "10.0.0.2", Some(443), "10.0.0.1", Some(5000), "TCP");
        reply.len = 40;
        rows.push(reply);
        rows.push(row(5, "10.0.0.1", Some(5000), "10.0.0.2", Some(443), "UDP"));

        let all = table_view(&rows, |_| true, false, (Col::No, true));
        assert_eq!(all.rows, [4, 3, 2, 1, 0]);
        let v = table_view(&rows, |_| true, true, (Col::No, true));
        assert_eq!(v.rows, [4, 3, 2]);
        let s = v.stacks[&2];
        assert_eq!(
            (s.count, s.min_len, s.max_len, s.bytes),
            (3, 60, 1500, 1660)
        );
        assert_eq!(v.stacks.len(), 1);
        let by_len = table_view(&rows, |r| r.proto == "TCP", true, (Col::Length, false));
        assert_eq!(by_len.rows, [3, 2]);
    }

    #[test]
    fn blocks_group_addresses() {
        let mut hosts = Hosts::default();
        hosts.add(&row(1, "10.88.0.2", None, "10.88.1.3", None, "ICMP"));
        hosts.add(&row(2, "10.88.0.2", None, "8.8.8.8", None, "ICMP"));
        let b = blocks(&hosts, 16, 48);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].cidr.to_string(), "10.88.0.0/16");
        assert_eq!(b[0].scope.map(|s| s.kind), Some("private"));
        assert_eq!((b[0].packets, b[0].hosts.len()), (3, 2));
        assert_eq!(b[0].hosts[0].0.to_string(), "10.88.0.2");
        assert_eq!(blocks(&hosts, 24, 64).len(), 3);
    }

    #[test]
    fn csv_quotes_and_defuses_formulas() {
        let mut r = row(1, "10.0.0.1", Some(1), "10.0.0.2", Some(2), "TCP");
        r.info = "=HYPERLINK(\"x\"), b".into();
        let out = csv([&r]);
        let line = out.lines().nth(1).unwrap();
        assert!(out.starts_with("no,time,source,"));
        assert!(line.ends_with(",\"'=HYPERLINK(\"\"x\"\"), b\""), "{line}");
        assert_eq!(line.split(',').next(), Some("1"));
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
