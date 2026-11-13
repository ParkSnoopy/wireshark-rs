//! Data model without DOM access: packet rows, the table filter, and the
//! capture graph. Host-testable with `cargo test -p wireshark-ui`.

use std::collections::HashMap;

use serde::Deserialize;

/// One captured packet, as the shell sends it.
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
}

impl Row {
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

fn endpoint(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr.to_owned(),
    }
}

/// Choices of the protocol filter. The first one matches everything.
pub const PROTOCOLS: [&str; 6] = ["All protocols", "TCP", "UDP", "ICMP", "ARP", "Other"];

/// Table filter: every whitespace-separated term must occur in the row
/// (number, endpoints, protocol or info, case-insensitive), and the protocol
/// must match the chosen `PROTOCOLS` entry.
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
        if !proto_ok {
            return false;
        }
        if self.terms.is_empty() {
            return true;
        }
        let (src, dst) = r.endpoints();
        let text = format!("#{} {src} {dst} {} {}", r.no, r.proto, r.info).to_lowercase();
        self.terms.iter().all(|t| text.contains(t.as_str()))
    }
}

/// Class of a graph node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// An IP address seen in traffic.
    Host,
    /// A protocol and port that the host at index `host` offers.
    Service { host: usize },
}

/// Relation of a graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Rel {
    /// Host → its service.
    Serves,
    /// Client host → service.
    Connects,
    /// Host → host, for traffic without ports (ICMP, ARP).
    Exchanges,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub label: String,
    pub kind: Kind,
    pub packets: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub rel: Rel,
    pub proto: String,
    pub packets: u64,
}

/// One step of the graph build: when a node or edge first appeared.
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    pub time: String,
    pub text: String,
}

/// Capture graph: hosts, services and their relations, built packet by
/// packet. It covers the whole capture, not only the rows the table keeps.
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
        let src = self.host(&r.time, &r.src);
        let dst = self.host(&r.time, &r.dst);
        if let (Some(sport), Some(dport)) = (r.sport, r.dport) {
            // shortcut: the lower port is taken as the service, so traffic between two
            // high ports may pick the wrong side; track SYN direction if that matters.
            let (server, client, port) = if dport <= sport {
                (dst, src, dport)
            } else {
                (src, dst, sport)
            };
            let svc = self.service(&r.time, server, &format!("{}/{port}", r.proto));
            self.edge(&r.time, server, svc, Rel::Serves, &r.proto);
            self.edge(&r.time, client, svc, Rel::Connects, &r.proto);
        } else {
            self.edge(&r.time, src, dst, Rel::Exchanges, &r.proto);
        }
    }

    pub fn count(&self, rel: Rel) -> usize {
        self.edges.iter().filter(|e| e.rel == rel).count()
    }

    pub fn hosts(&self) -> usize {
        self.nodes.iter().filter(|n| n.kind == Kind::Host).count()
    }

    fn host(&mut self, time: &str, addr: &str) -> usize {
        let text = format!("New host {addr}");
        self.node(time, format!("h {addr}"), addr, Kind::Host, text)
    }

    fn service(&mut self, time: &str, host: usize, label: &str) -> usize {
        let text = format!("New service {label} on {}", self.nodes[host].label);
        let key = format!("s {host} {label}");
        self.node(time, key, label, Kind::Service { host }, text)
    }

    fn node(&mut self, time: &str, key: String, label: &str, kind: Kind, text: String) -> usize {
        if let Some(&i) = self.nodes_by_key.get(&key) {
            self.nodes[i].packets += 1;
            return i;
        }
        self.nodes.push(Node {
            label: label.to_owned(),
            kind,
            packets: 1,
        });
        self.log(time, text);
        self.nodes_by_key.insert(key, self.nodes.len() - 1);
        self.nodes.len() - 1
    }

    fn edge(&mut self, time: &str, from: usize, to: usize, rel: Rel, proto: &str) {
        let key = (from, to, rel, proto.to_owned());
        if let Some(&i) = self.edges_by_key.get(&key) {
            self.edges[i].packets += 1;
            return;
        }
        let (a, b) = (&self.nodes[from].label, &self.nodes[to].label);
        let text = match rel {
            Rel::Serves => format!("{a} serves {b}"),
            Rel::Connects => {
                let Kind::Service { host } = self.nodes[to].kind else {
                    unreachable!("connects always targets a service")
                };
                format!("{a} connects to {b} on {}", self.nodes[host].label)
            }
            Rel::Exchanges => format!("{a} exchanges {proto} with {b}"),
        };
        self.edges.push(Edge {
            from,
            to,
            rel,
            proto: proto.to_owned(),
            packets: 1,
        });
        self.log(time, text);
        self.edges_by_key.insert(key, self.edges.len() - 1);
    }

    fn log(&mut self, time: &str, text: String) {
        self.log.push(LogEntry {
            time: time.to_owned(),
            text,
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
        }
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
    fn duration_units() {
        assert_eq!(
            [duration(0.000166), duration(0.0425), duration(3.0)],
            ["166 µs", "42.5 ms", "3.00 s"]
        );
    }

    #[test]
    fn filter_terms_and_protocol() {
        let r = row(7, "fe80::1", Some(53), "10.0.0.2", Some(5353), "UDP");
        assert_eq!(r.endpoints().0, "[fe80::1]:53");
        assert!(Filter::new("", "All protocols").matches(&r));
        assert!(Filter::new("FE80 :5353", "UDP").matches(&r));
        assert!(Filter::new("#7", "All protocols").matches(&r));
        assert!(!Filter::new("fe80 tcp", "All protocols").matches(&r));
        assert!(!Filter::new("", "TCP").matches(&r));
        assert!(Filter::new("", "ICMP").matches(&row(1, "a", None, "b", None, "ICMPv6")));
        assert!(Filter::new("", "Other").matches(&row(1, "a", None, "b", None, "IP proto 2")));
    }

    #[test]
    fn graph_builds_services_and_logs_each_new_fact_once() {
        let mut g = Graph::default();
        g.add(&row(
            1,
            "10.0.0.1",
            Some(51000),
            "10.0.0.2",
            Some(443),
            "TCP",
        ));
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
        assert_eq!(g.nodes.len(), 3);
        assert_eq!(g.nodes[2].label, "TCP/443");
        assert_eq!(g.nodes[2].kind, Kind::Service { host: 1 });
        assert_eq!(g.nodes[2].packets, 2);
        assert_eq!(
            (
                g.count(Rel::Serves),
                g.count(Rel::Connects),
                g.count(Rel::Exchanges)
            ),
            (1, 1, 1)
        );
        let log: Vec<&str> = g.log.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(
            log,
            [
                "New host 10.0.0.1",
                "New host 10.0.0.2",
                "New service TCP/443 on 10.0.0.2",
                "10.0.0.2 serves TCP/443",
                "10.0.0.1 connects to TCP/443 on 10.0.0.2",
                "10.0.0.1 exchanges ICMP with 10.0.0.2",
            ]
        );
    }
}
