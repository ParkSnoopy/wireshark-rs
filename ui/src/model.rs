//! Data model without DOM access: packet rows, address scopes, the table
//! filter and sort, and the capture graph. Host-testable with
//! `cargo test -p wireshark-ui`.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// One captured packet, as the shell sends it. Serialize is for the JSON export.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
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

    /// Registrable domain and its registration date, like
    /// `example.com · registered 1995-08-14`.
    pub fn summary(&self) -> String {
        match (&self.registered, &self.error) {
            (Some(date), _) => format!("{} · registered {date}", self.site),
            (None, Some(_)) => format!("{} · no registration data", self.site),
            (None, None) => self.site.clone(),
        }
    }
}

/// Domain data by host name.
pub type Domains = HashMap<String, DomainInfo>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    pub fn same_conversation(&self, other: &Self) -> bool {
        self.proto == other.proto
            && (self.same_direction(other) && self.dst == other.dst && self.dport == other.dport
                || self.src == other.dst
                    && self.sport == other.dport
                    && self.dst == other.src
                    && self.dport == other.sport)
    }

    /// True when `other` leaves from the same endpoint as this packet.
    pub fn same_direction(&self, other: &Self) -> bool {
        self.src == other.src && self.sport == other.sport
    }

    /// `addr:port` of each end, as the proxy writes socket addresses.
    fn sockets(&self) -> Option<(String, String)> {
        let sock = |a: &str, p: u16| {
            if a.contains(':') {
                format!("[{a}]:{p}")
            } else {
                format!("{a}:{p}")
            }
        };
        Some((sock(&self.src, self.sport?), sock(&self.dst, self.dport?)))
    }

    /// True when this packet belongs to the proxy's connection to the
    /// server for `ex`.
    pub fn carries(&self, ex: &Exchange) -> bool {
        let (Some((s, d)), Some(l), Some(r)) = (self.sockets(), &ex.local, &ex.remote) else {
            return false;
        };
        self.proto == "TCP" && (s == *l && d == *r || s == *r && d == *l)
    }
}

/// Packet detail from the shell, for the inspector.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Inspection {
    pub no: u64,
    /// Network-layer bytes, possibly cut short of `caplen`.
    pub bytes: Vec<u8>,
    pub caplen: usize,
    /// Where the TCP or UDP payload starts in `bytes`.
    pub payload_at: Option<usize>,
    /// The conversation's data in the order it was sent.
    pub turns: Vec<Turn>,
    /// Conversation bytes left out by the shell's limits.
    pub omitted: usize,
}

/// Data one side sent before the other answered.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Turn {
    /// Sent by the side that spoke first: the client, usually.
    pub client: bool,
    pub first: u64,
    pub last: u64,
    pub len: usize,
    /// Bytes the capture missed inside this turn.
    pub gaps: usize,
    pub data: Vec<u8>,
}

/// A request and its response, decrypted by the HTTPS proxy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Exchange {
    pub id: u64,
    pub conn: u64,
    pub at_ms: u64,
    pub ms: u64,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub reason: String,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Body,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Body,
    pub error: Option<String>,
    /// How a connection that is not HTTP was handled.
    #[serde(default)]
    pub note: Option<String>,
    /// Still open: a later event with the same id replaces this one.
    #[serde(default)]
    pub open: bool,
    /// Program that opened the connection.
    #[serde(default)]
    pub app: Option<String>,
    pub client: String,
    /// Proxy and server ends of the proxy's connection to the server.
    pub local: Option<String>,
    pub remote: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Body {
    pub size: usize,
    pub data: Vec<u8>,
    pub truncated: bool,
    pub note: Option<String>,
}

/// State of the HTTPS proxy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct MitmState {
    pub on: bool,
    /// Port the redirected traffic reaches the proxy on.
    pub port: u16,
    /// Path of the CA certificate file, trusted system-wide while on.
    pub ca: Option<String>,
    pub error: Option<String>,
}

/// True when `data` reads as text: UTF-8 with at most 2% control or
/// invalid characters (a character cut off at the end is one of those).
pub fn is_text(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);
    let odd = s
        .chars()
        .filter(|&c| c == '\u{fffd}' || c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    odd * 50 <= s.chars().count()
}

/// Bytes as a string: UTF-8 where it is valid, every other byte and every
/// control character except line breaks and tabs as `·`.
pub fn printable(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| {
            if c == '\u{fffd}' || c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
                '·'
            } else {
                c
            }
        })
        .collect()
}

/// Hex dump lines: offset (counted from `base`), 16 hex byte pairs and
/// their printable ASCII.
pub fn hexdump(data: &[u8], base: usize) -> Vec<(usize, String, String)> {
    data.chunks(16)
        .enumerate()
        .map(|(i, line)| {
            let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
            let ascii = line
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            (base + i * 16, hex.join(" "), ascii)
        })
        .collect()
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub cidr: &'static str,
    /// `private`, `loopback`, `link-local`, `shared`, `multicast` or `broadcast`.
    pub kind: &'static str,
}

/// `IPv4` blocks of RFC 6890 that do not route on the public internet.
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

/// What Shodan (`InternetDB`) knows about a public address, as the shell
/// sends it. The lists are empty when `found` is false.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ShodanInfo {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
    pub found: bool,
    pub error: Option<String>,
}

impl ShodanInfo {
    /// Label and text of each fact, for the node inspector.
    pub fn facts(&self) -> Vec<(&'static str, String)> {
        if let Some(e) = &self.error {
            return vec![("Shodan", format!("lookup failed: {e}"))];
        }
        if !self.found {
            return vec![("Shodan", "no data on this address".to_owned())];
        }
        let list = |items: &[String]| {
            if items.is_empty() {
                "none".to_owned()
            } else {
                items.join(", ")
            }
        };
        let ports: Vec<String> = self.ports.iter().map(ToString::to_string).collect();
        vec![
            ("Open ports", list(&ports)),
            ("Host names", list(&self.hostnames)),
            ("Software", list(&self.cpes)),
            ("Tags", list(&self.tags)),
            ("Vulns", list(&self.vulns)),
        ]
    }
}

/// Shodan answers by address.
pub type Shodans = HashMap<IpAddr, ShodanInfo>;

/// Reverse DNS answers by address: `None` when the address has no PTR record.
pub type Ptrs = HashMap<IpAddr, Option<String>>;

/// PTR name of `addr`, when it was looked up and has one.
pub fn ptr_of<'a>(ptrs: &'a Ptrs, addr: &str) -> Option<&'a str> {
    ptrs.get(&addr.parse().ok()?)?.as_deref()
}

/// Address scopes the filter dialog offers; `public` is any other address.
pub const SCOPES: [&str; 6] = [
    "public",
    "private",
    "loopback",
    "link-local",
    "multicast",
    "shared",
];

/// Filter dialog settings. An empty set or `None` places no limit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Rules {
    /// Protocols as the table shows them (`https`, `TCP`, `ARP`).
    pub protocols: BTreeSet<String>,
    /// Hide the chosen protocols instead of showing only them.
    pub exclude: bool,
    /// Either end is in one of these scopes.
    pub scopes: BTreeSet<String>,
    /// Port list like `443, 8000-8100`; either end's port must be in it.
    pub ports: String,
    pub min_len: Option<u32>,
    pub max_len: Option<u32>,
    /// Either end is on one of these interfaces.
    pub ifaces: BTreeSet<String>,
    /// Either end belongs to one of these processes.
    pub processes: BTreeSet<String>,
}

impl Rules {
    /// Number of settings that limit the table, for the button badge.
    pub fn active(&self) -> usize {
        [
            !self.protocols.is_empty(),
            !self.scopes.is_empty(),
            !port_ranges(&self.ports).is_empty(),
            self.min_len.is_some() || self.max_len.is_some(),
            !self.ifaces.is_empty(),
            !self.processes.is_empty(),
        ]
        .into_iter()
        .filter(|&b| b)
        .count()
    }

    fn matches(&self, r: &Row, ports: &[(u16, u16)]) -> bool {
        let any = |set: &BTreeSet<String>, ends: [Option<&str>; 2]| {
            set.is_empty() || ends.into_iter().flatten().any(|v| set.contains(v))
        };
        let proto = self.protocols.is_empty()
            || (self.protocols.contains(r.protocol()) || self.protocols.contains(&r.proto))
                != self.exclude;
        let scope_of = |a: &str| scope(a).map_or("public", |s| s.kind);
        let port_ok = ports.is_empty()
            || [r.sport, r.dport]
                .into_iter()
                .flatten()
                .any(|p| ports.iter().any(|&(lo, hi)| (lo..=hi).contains(&p)));
        proto
            && port_ok
            && self.min_len.is_none_or(|m| r.len >= m)
            && self.max_len.is_none_or(|m| r.len <= m)
            && any(
                &self.scopes,
                [Some(scope_of(&r.src)), Some(scope_of(&r.dst))],
            )
            && any(
                &self.ifaces,
                [
                    r.src_if.as_ref().map(|i| i.name.as_str()),
                    r.dst_if.as_ref().map(|i| i.name.as_str()),
                ],
            )
            && any(&self.processes, [r.sproc.as_deref(), r.dproc.as_deref()])
    }
}

/// Parses `443, 8000-8100` into inclusive ranges; bad parts are skipped.
pub fn port_ranges(text: &str) -> Vec<(u16, u16)> {
    text.split([',', ' '])
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.split_once('-') {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => p.trim().parse().ok().map(|n| (n, n)),
        })
        .filter(|(a, b)| a <= b)
        .collect()
}

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

/// Table filter: a search expression over the row's text (number,
/// endpoints, host names, protocols, info, process, interface and scope,
/// case-insensitive). The row must also pass the filter dialog's `Rules`.
///
/// - `a b` or `a & b`: both; `a | b`: either; `&` binds tighter than `|`.
/// - `!a`: not; `( )` groups; `"a b"` is one term with a space.
/// - `a`: occurs anywhere; `^a`: a word starts with it; `$a`: a word ends
///   with it; `=a`: a whole word.
/// - `10.0.0.0/8`: an end of the row is in that block.
///
/// Malformed input is read leniently: a missing `)` closes at the end,
/// a stray `)` or operator is skipped.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filter {
    expr: Expr,
    rules: Rules,
    ports: Vec<(u16, u16)>,
}

/// Parsed search expression.
#[derive(Clone, Debug, PartialEq)]
enum Expr {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Term(Term),
}

impl Default for Expr {
    fn default() -> Self {
        Self::All(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Term {
    Has(String),
    Starts(String),
    Ends(String),
    Word(String),
    Net(Cidr),
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Or,
    And,
    Not,
    Open,
    Close,
    Term(Term),
}

/// Characters that end an unquoted term.
const fn ends_term(c: char) -> bool {
    c.is_whitespace() || matches!(c, '|' | '&' | '(' | ')' | '"')
}

fn tokens(text: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '|' | '&' | '!' | '(' | ')' => {
                chars.next();
                out.push(match c {
                    '|' => Tok::Or,
                    '&' => Tok::And,
                    '!' => Tok::Not,
                    '(' => Tok::Open,
                    _ => Tok::Close,
                });
            }
            _ => {
                let mode = match c {
                    '^' | '$' | '=' => chars.next(),
                    _ => None,
                };
                let mut word = String::new();
                if chars.peek() == Some(&'"') {
                    chars.next();
                    word.extend(chars.by_ref().take_while(|&c| c != '"'));
                } else {
                    while let Some(c) = chars.next_if(|&c| !ends_term(c)) {
                        word.push(c);
                    }
                }
                let word = word.to_lowercase();
                let term = match mode {
                    Some('^') => Term::Starts(word),
                    Some('$') => Term::Ends(word),
                    Some(_) => Term::Word(word),
                    None => Cidr::parse(&word).map_or(Term::Has(word), Term::Net),
                };
                // A lone `^` or `""` searches for nothing: skip it.
                if !matches!(&term, Term::Has(w) | Term::Starts(w) | Term::Ends(w) | Term::Word(w) if w.is_empty())
                {
                    out.push(Tok::Term(term));
                }
            }
        }
    }
    out
}

/// Recursive descent over `tokens`: or := and ('|' and)*,
/// and := unary ('&'? unary)*, unary := '!' unary | '(' or ')' | term.
struct Parser {
    toks: Vec<Tok>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn or(&mut self) -> Expr {
        let mut any = vec![self.and()];
        while self.peek() == Some(&Tok::Or) {
            self.at += 1;
            any.push(self.and());
        }
        flatten(any, Expr::Any)
    }

    fn and(&mut self) -> Expr {
        let mut all = Vec::new();
        loop {
            match self.peek() {
                None | Some(Tok::Or | Tok::Close) => break,
                Some(Tok::And) => self.at += 1,
                Some(_) => all.extend(self.unary()),
            }
        }
        flatten(all, Expr::All)
    }

    fn unary(&mut self) -> Option<Expr> {
        let tok = self.peek()?.clone();
        self.at += 1;
        match tok {
            Tok::Not => self.unary().map(|e| Expr::Not(Box::new(e))),
            Tok::Open => {
                let e = self.or();
                if self.peek() == Some(&Tok::Close) {
                    self.at += 1;
                }
                Some(e)
            }
            Tok::Term(t) => Some(Expr::Term(t)),
            Tok::Or | Tok::And | Tok::Close => None,
        }
    }
}

/// Drops empty operands (as in `a |` or `()`); one operand stands for
/// itself; nothing left matches every row.
fn flatten(mut items: Vec<Expr>, make: fn(Vec<Expr>) -> Expr) -> Expr {
    items.retain(|e| *e != Expr::default());
    if items.len() > 1 {
        return make(items);
    }
    items.pop().unwrap_or_default()
}

impl Expr {
    fn parse(text: &str) -> Self {
        let mut p = Parser {
            toks: tokens(text),
            at: 0,
        };
        let mut all = Vec::new();
        // A stray `)` ends `or` early: skip it and read on.
        while p.peek().is_some() {
            all.push(p.or());
            if p.peek() == Some(&Tok::Close) {
                p.at += 1;
            }
        }
        flatten(all, Expr::All)
    }

    fn matches(&self, r: &Row) -> bool {
        match self {
            Self::All(v) => v.iter().all(|e| e.matches(r)),
            Self::Any(v) => v.iter().any(|e| e.matches(r)),
            Self::Not(e) => !e.matches(r),
            Self::Term(t) => t.matches(r),
        }
    }
}

impl Term {
    fn matches(&self, r: &Row) -> bool {
        // Word edges in the search text: spaces, brackets and `#`.
        let starts = |i: usize| i == 0 || r.search[..i].ends_with([' ', '[', '(', '#']);
        let ends = |j: usize| j == r.search.len() || r.search[j..].starts_with([' ', ']', ')']);
        let any_at = |w: &str, ok: &dyn Fn(usize, usize) -> bool| {
            r.search
                .char_indices()
                .any(|(i, _)| r.search[i..].starts_with(w) && ok(i, i + w.len()))
        };
        match self {
            Self::Has(w) => r.search.contains(w.as_str()),
            Self::Starts(w) => any_at(w, &|i, _| starts(i)),
            Self::Ends(w) => any_at(w, &|_, j| ends(j)),
            Self::Word(w) => any_at(w, &|i, j| starts(i) && ends(j)),
            Self::Net(n) => [r.src_ip, r.dst_ip]
                .into_iter()
                .flatten()
                .any(|ip| n.contains(ip)),
        }
    }
}

impl Filter {
    pub fn new(text: &str, rules: &Rules) -> Self {
        Self {
            expr: Expr::parse(text),
            ports: port_ranges(&rules.ports),
            rules: rules.clone(),
        }
    }

    pub fn matches(&self, r: &Row) -> bool {
        self.rules.matches(r, &self.ports) && self.expr.matches(r)
    }
}

/// Sortable table columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stack {
    pub count: u32,
    pub min_len: u32,
    pub max_len: u32,
    pub bytes: u64,
}

/// Rows the table shows: indices into the capture in display order and,
/// when repeats are collapsed, the stack each shown row stands for.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TableView {
    pub rows: Vec<usize>,
    pub stacks: HashMap<usize, Stack>,
}

/// Folds the `shown` rows of each flow into its newest row. Returns the
/// newest rows in arrival order, and the stacks of flows with more than one.
fn fold_flows(rows: &[Row], shown: Vec<usize>) -> (Vec<usize>, HashMap<usize, Stack>) {
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
    let mut newest: Vec<usize> = groups.iter().map(|g| g.0).collect();
    newest.sort_unstable();
    let stacks = groups.into_iter().filter(|g| g.1.count > 1).collect();
    (newest, stacks)
}

/// Filters, optionally collapses and sorts `rows`. `keep` is the filter;
/// collapsed flows show their newest packet.
pub fn table_view(
    rows: &[Row],
    keep: impl Fn(&Row) -> bool,
    collapse: bool,
    (col, desc): (Col, bool),
) -> TableView {
    let shown: Vec<usize> = (0..rows.len()).filter(|&i| keep(&rows[i])).collect();
    let (mut shown, stacks) = if collapse {
        fold_flows(rows, shown)
    } else {
        (shown, HashMap::new())
    };
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

/// Address prefix lengths the network view groups by: (`IPv4`, `IPv6`).
pub const GROUPINGS: [(&str, u8, u8); 3] = [
    ("/24 · /64", 24, 64),
    ("/16 · /48", 16, 48),
    ("/8 · /32", 8, 32),
];

/// Traffic of one address.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostStat {
    pub packets: u64,
    pub bytes: u64,
    /// Latest host name the address was reached by.
    pub name: Option<String>,
    pub iface: Option<IfRef>,
}

/// Per-address totals, updated as rows arrive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Relation of a graph edge between two hosts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Rel {
    /// Client host → server host, over one or more services.
    Connects,
    /// Host → host, for traffic without ports (ICMP, ARP).
    Exchanges,
}

impl Rel {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Connects => "connects to",
            Self::Exchanges => "exchanges",
        }
    }
}

/// Something a host card lists: a service it offers (`TCP/443`) or a
/// local program with sockets on it (`firefox`), with its traffic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Part {
    pub label: String,
    pub packets: u64,
    pub bytes: u64,
}

/// A host: one IP address seen in traffic, with everything known about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    /// The address.
    pub label: String,
    pub packets: u64,
    pub bytes: u64,
    /// The related interface, when the shell named one.
    pub iface: Option<IfRef>,
    /// The special-purpose block that holds the address.
    pub scope: Option<Scope>,
    /// The latest host name the address was reached by.
    pub name: Option<String>,
    /// Services the host offers, in order of first sight.
    pub services: Vec<Part>,
    /// Local programs with sockets on the host, in order of first sight.
    pub processes: Vec<Part>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub rel: Rel,
    /// Services (`TCP/443`) or protocols (`ICMP`) carried, in order of
    /// first sight.
    pub protos: Vec<String>,
    pub packets: u64,
    pub bytes: u64,
}

/// One step of the graph build: when a node or edge first appeared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntry {
    pub time: String,
    pub text: String,
    /// Node the entry is about, for the inspector.
    pub node: usize,
}

/// Capture graph: hosts, each with its services and processes, and the
/// relations between hosts, built packet by packet over the whole capture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub log: Vec<LogEntry>,
    nodes_by_key: HashMap<String, usize>,
    edges_by_key: HashMap<(usize, usize, Rel), usize>,
}

impl Graph {
    pub fn add(&mut self, r: &Row) {
        if r.src.is_empty() || r.dst.is_empty() {
            return;
        }
        let src = self.host(r, &r.src, r.src_if.as_ref(), r.src_name.as_ref());
        let dst = self.host(r, &r.dst, r.dst_if.as_ref(), r.dst_name.as_ref());
        if let (Some(sport), Some(dport)) = (r.sport, r.dport) {
            // shortcut: the lower port is taken as the service, so traffic between two
            // high ports may pick the wrong side; track SYN direction if that matters.
            let (server, client, port, server_proc, client_proc) = if dport <= sport {
                (dst, src, dport, &r.dproc, &r.sproc)
            } else {
                (src, dst, sport, &r.sproc, &r.dproc)
            };
            let svc = format!("{}/{port}", r.proto);
            self.part(r, server, &svc, true);
            for (host, process) in [(server, server_proc), (client, client_proc)] {
                if let Some(name) = process {
                    self.part(r, host, name, false);
                }
            }
            self.edge(r, client, server, Rel::Connects, &svc);
        } else {
            self.edge(r, src, dst, Rel::Exchanges, &r.proto);
        }
    }

    pub fn count(&self, rel: Rel) -> usize {
        self.edges.iter().filter(|e| e.rel == rel).count()
    }

    pub const fn hosts(&self) -> usize {
        self.nodes.len()
    }

    /// Services on all hosts.
    pub fn services(&self) -> usize {
        self.nodes.iter().map(|n| n.services.len()).sum()
    }

    /// Processes on all hosts.
    pub fn processes(&self) -> usize {
        self.nodes.iter().map(|n| n.processes.len()).sum()
    }

    fn host(&mut self, r: &Row, addr: &str, iface: Option<&IfRef>, name: Option<&String>) -> usize {
        let len = u64::from(r.len);
        let i = if let Some(&i) = self.nodes_by_key.get(addr) {
            self.nodes[i].packets += 1;
            self.nodes[i].bytes += len;
            i
        } else {
            let i = self.nodes.len();
            self.nodes.push(Node {
                label: addr.to_owned(),
                packets: 1,
                bytes: len,
                iface: None,
                scope: None,
                name: None,
                services: Vec::new(),
                processes: Vec::new(),
            });
            let text = name.map_or_else(
                || format!("New host {addr}"),
                |n| format!("New host {n} ({addr})"),
            );
            self.log(r, text, i);
            self.nodes_by_key.insert(addr.to_owned(), i);
            i
        };
        let node = &mut self.nodes[i];
        if node.iface.is_none() {
            node.iface = iface.cloned();
        }
        if name.is_some() {
            node.name = name.cloned();
        }
        node.scope = scope(addr);
        i
    }

    /// Counts the packet into a service (`service`) or process of `host`.
    fn part(&mut self, r: &Row, host: usize, label: &str, service: bool) {
        let len = u64::from(r.len);
        let node = &mut self.nodes[host];
        let parts = if service {
            &mut node.services
        } else {
            &mut node.processes
        };
        if let Some(p) = parts.iter_mut().find(|p| p.label == label) {
            p.packets += 1;
            p.bytes += len;
            return;
        }
        parts.push(Part {
            label: label.to_owned(),
            packets: 1,
            bytes: len,
        });
        let what = if service { "service" } else { "process" };
        let text = format!("New {what} {label} on {}", node.label);
        self.log(r, text, host);
    }

    fn edge(&mut self, r: &Row, from: usize, to: usize, rel: Rel, proto: &str) {
        let len = u64::from(r.len);
        let i = if let Some(&i) = self.edges_by_key.get(&(from, to, rel)) {
            self.edges[i].packets += 1;
            self.edges[i].bytes += len;
            i
        } else {
            self.edges.push(Edge {
                from,
                to,
                rel,
                protos: Vec::new(),
                packets: 1,
                bytes: len,
            });
            self.edges_by_key
                .insert((from, to, rel), self.edges.len() - 1);
            self.edges.len() - 1
        };
        if self.edges[i].protos.iter().any(|p| p == proto) {
            return;
        }
        self.edges[i].protos.push(proto.to_owned());
        let (a, b) = (&self.nodes[from].label, &self.nodes[to].label);
        let text = match rel {
            Rel::Connects => format!("{a} connects to {b} on {proto}"),
            Rel::Exchanges => format!("{a} exchanges {proto} with {b}"),
        };
        self.log(r, text, from);
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
    fn proxy_exchange_matches_its_server_connection() {
        let ex = Exchange {
            local: Some("10.0.0.1:51000".into()),
            remote: Some("[2001:db8::1]:443".into()),
            ..Exchange::default()
        };
        let back = row(1, "2001:db8::1", Some(443), "10.0.0.1", Some(51000), "TCP");
        let other = row(2, "10.0.0.1", Some(51001), "2001:db8::1", Some(443), "TCP");
        assert!(back.carries(&ex) && !other.carries(&ex));
        assert!(!back.carries(&Exchange::default()));
    }

    #[test]
    fn text_and_hex() {
        assert!(is_text(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(!is_text(&[0x16, 3, 1, 0, 0xa5, 1, 0, 0]));
        assert_eq!(
            printable(b"SSH-2.0\r\n\x00\x16\xff\xc3\xa9"),
            "SSH-2.0\r\n···é"
        );
        assert_eq!(
            hexdump(b"0123456789abcdefg\x01", 32),
            [
                (
                    32,
                    "30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66".into(),
                    "0123456789abcdef".into()
                ),
                (48, "67 01".into(), "g.".into()),
            ]
        );
    }

    #[test]
    fn units() {
        assert_eq!(
            [duration(0.000_166), duration(0.0425), duration(3.0)],
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
        let any = Rules::default();
        let only = |p: &str| Rules {
            protocols: BTreeSet::from([p.to_owned()]),
            ..Rules::default()
        };
        assert!(Filter::new("", &any).matches(&r));
        assert!(Filter::new("FE80 :5353", &only("UDP")).matches(&r));
        assert!(Filter::new("#7 firefox podman0 link-local private", &any).matches(&r));
        assert!(!Filter::new("fe80 tcp", &any).matches(&r));
        assert!(!Filter::new("", &only("TCP")).matches(&r));
        let hide_udp = Rules {
            exclude: true,
            ..only("UDP")
        };
        assert!(!Filter::new("", &hide_udp).matches(&r));
    }

    #[test]
    fn search_operators() {
        let mut r = row(7, "fe80::1", Some(53), "10.0.0.2", Some(5353), "UDP");
        r.dproc = Some("firefox".into());
        let r = r.prepared();
        let pass = |q: &str| Filter::new(q, &Rules::default()).matches(&r);
        // Or, and, precedence: `&` binds tighter than `|`.
        assert!(pass("tcp | udp"));
        assert!(!pass("tcp | ssh"));
        assert!(pass("tcp & ssh | firefox"));
        assert!(!pass("tcp & (ssh | firefox)"));
        assert!(pass("udp&firefox"));
        // Not, and grouping with it.
        assert!(pass("!tcp"));
        assert!(!pass("!(udp | tcp)"));
        assert!(pass("udp !chrome"));
        // Starts with, ends with and whole word, at bracket and port edges.
        assert!(pass("^10.0") && pass("^fe80") && pass("^fire"));
        assert!(!pass("^0.0.2") && !pass("^efox"));
        assert!(pass("$fox") && pass("$:5353") && pass("$fe80::1"));
        assert!(!pass("$fire"));
        assert!(pass("=udp") && pass("=fe80::1") && !pass("=fire"));
        // Quotes keep a space and the operator characters inside.
        assert!(pass("\":5353 udp\"") && !pass("\":5353 tcp\""));
        assert!(!pass("\"udp | tcp\""));
        // CIDR terms take part in the expression.
        assert!(pass("192.168.0.0/16 | 10.0.0.0/8"));
        assert!(!pass("!10.0.0.0/8"));
        // Lenient on malformed input.
        assert!(pass("(udp") && pass("udp )") && pass("| udp |") && pass("^"));
        assert!(pass("") && pass("()"));
    }

    #[test]
    fn filter_dialog_rules() {
        let mut r = row(1, "10.0.0.2", Some(51000), "8.8.8.8", Some(53), "UDP");
        r.app = Some("dns".into());
        r.len = 80;
        r.sproc = Some("curl".into());
        let r = r.prepared();
        let pass = |rules: Rules| Filter::new("", &rules).matches(&r);
        assert_eq!(
            port_ranges("443, 8000-8100 x 9-1"),
            [(443, 443), (8000, 8100)]
        );
        assert!(pass(Rules {
            ports: "50-60".into(),
            ..Rules::default()
        }));
        assert!(!pass(Rules {
            ports: "443".into(),
            ..Rules::default()
        }));
        // The application protocol or the transport.
        assert!(pass(Rules {
            protocols: BTreeSet::from(["dns".into()]),
            ..Rules::default()
        }));
        assert!(pass(Rules {
            scopes: BTreeSet::from(["public".into()]),
            ..Rules::default()
        }));
        assert!(!pass(Rules {
            scopes: BTreeSet::from(["loopback".into()]),
            ..Rules::default()
        }));
        assert!(!pass(Rules {
            min_len: Some(81),
            ..Rules::default()
        }));
        assert!(pass(Rules {
            processes: BTreeSet::from(["curl".into()]),
            max_len: Some(80),
            ..Rules::default()
        }));
        assert_eq!(
            Rules {
                ports: "nope".into(),
                min_len: Some(1),
                ..Rules::default()
            }
            .active(),
            1
        );
    }

    #[test]
    fn cidr_blocks_and_filter() {
        let text = |cidr: &str| Cidr::parse(cidr).map(|c| c.to_string());
        let inside = |ip: &str| {
            let ip = ip.parse().ok()?;
            Cidr::parse("10.88.7.9/16").map(|c| c.contains(ip))
        };
        assert_eq!(text("10.88.7.9/16").as_deref(), Some("10.88.0.0/16"));
        assert_eq!(inside("10.88.255.1"), Some(true));
        assert_eq!(inside("10.89.0.1"), Some(false));
        assert_eq!(inside("::a58:1"), Some(false));
        assert_eq!(text("fd00::1/64").as_deref(), Some("fd00::/64"));
        assert_eq!(text("0.0.0.0/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);

        let r = row(
            1,
            "10.88.0.2",
            Some(51000),
            "93.184.216.34",
            Some(443),
            "TCP",
        );
        let any = Rules::default();
        assert!(Filter::new("10.88.0.0/16 :443", &any).matches(&r));
        assert!(Filter::new("93.184.0.0/16", &any).matches(&r));
        assert!(!Filter::new("192.168.0.0/16", &any).matches(&r));
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
        assert!(Filter::new("example https", &Rules::default()).matches(&r));

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
        let line = out.lines().nth(1).unwrap_or_default();
        assert!(out.starts_with("no,time,source,"));
        assert!(line.ends_with(",\"'=HYPERLINK(\"\"x\"\"), b\""), "{line}");
        assert_eq!(line.split(',').next(), Some("1"));
    }

    #[test]
    fn shodan_facts_say_what_is_known() {
        let info = ShodanInfo {
            ports: vec![53, 443],
            tags: vec!["cdn".to_owned()],
            found: true,
            ..ShodanInfo::default()
        };
        let list = info.facts();
        assert_eq!(list.first(), Some(&("Open ports", "53, 443".to_owned())));
        assert!(list.contains(&("Vulns", "none".to_owned())));
        let missing = ShodanInfo::default().facts();
        assert_eq!(missing, [("Shodan", "no data on this address".to_owned())]);
    }

    #[test]
    fn sort_addresses_numerically() {
        let a = row(1, "10.0.0.9", None, "x", None, "ICMP");
        let b = row(2, "10.0.0.10", None, "x", None, "ICMP");
        assert_eq!(compare(&a, &b, Col::Source), Ordering::Less);
        assert_eq!(compare(&b, &a, Col::No), Ordering::Greater);
    }

    #[test]
    fn graph_puts_services_and_processes_on_host_cards() {
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
        g.add(&row(
            3,
            "10.0.0.1",
            Some(51001),
            "10.0.0.2",
            Some(80),
            "TCP",
        ));
        g.add(&row(4, "10.0.0.1", None, "10.0.0.2", None, "ICMP"));
        g.add(&row(5, "", None, "", None, "0x88cc"));

        // Only hosts are nodes; ports and programs are listed on them.
        assert_eq!(g.hosts(), 2);
        let services: Vec<_> = g.nodes[1]
            .services
            .iter()
            .map(|p| (p.label.as_str(), p.packets, p.bytes))
            .collect();
        assert_eq!(services, [("TCP/443", 2, 120), ("TCP/80", 1, 60)]);
        assert_eq!(g.nodes[0].processes[0].label, "firefox");
        assert!(g.nodes[0].services.is_empty() && g.nodes[1].processes.is_empty());
        assert_eq!(g.nodes[0].scope.map(|s| s.kind), Some("private"));
        // One edge per host pair and relation, naming every service used.
        assert_eq!([Rel::Connects, Rel::Exchanges].map(|r| g.count(r)), [1, 1]);
        assert_eq!(g.edges[0].protos, ["TCP/443", "TCP/80"]);
        assert_eq!(g.edges[0].packets, 3);
        let log: Vec<&str> = g.log.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(
            log,
            [
                "New host 10.0.0.1",
                "New host 10.0.0.2",
                "New service TCP/443 on 10.0.0.2",
                "New process firefox on 10.0.0.1",
                "10.0.0.1 connects to 10.0.0.2 on TCP/443",
                "New service TCP/80 on 10.0.0.2",
                "10.0.0.1 connects to 10.0.0.2 on TCP/80",
                "10.0.0.1 exchanges ICMP with 10.0.0.2",
            ]
        );
    }
}
