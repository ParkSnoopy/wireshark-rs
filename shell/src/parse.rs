//! Turns one captured record (network-layer bytes) into one table row.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Row {
    pub no: u64,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub len: u32,
    pub info: String,
    /// TCP/UDP ports; `None` for other protocols. The UI groups conversations by them.
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// Interface that owns the address or whose network holds it. Set by `owners`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_if: Option<IfRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_if: Option<IfRef>,
    /// Process that owns the local socket of each end. Set by `owners`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sproc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dproc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IfRef {
    pub name: String,
    /// True for an address of this host, false for one on the interface's network.
    pub local: bool,
}

struct Summary {
    src: String,
    dst: String,
    proto: String,
    info: String,
    ports: Option<(u16, u16)>,
}

/// `rel_us` is the time since the first packet of the capture.
pub fn row(no: u64, rel_us: u64, len: u32, ethertype: u16, data: &[u8]) -> Row {
    let (name, summary) = match ethertype {
        0x0800 => ("IPv4", ipv4(data)),
        0x86dd => ("IPv6", ipv6(data)),
        0x0806 => ("ARP", arp(data)),
        other => ("", Some(Summary::other(format!("0x{other:04x}")))),
    };
    let s = summary.unwrap_or_else(|| Summary {
        info: "truncated".into(),
        ..Summary::other(name.into())
    });
    Row {
        no,
        time: format!("{}.{:06}", rel_us / 1_000_000, rel_us % 1_000_000),
        src: s.src,
        dst: s.dst,
        proto: s.proto,
        len,
        info: s.info,
        sport: s.ports.map(|p| p.0),
        dport: s.ports.map(|p| p.1),
        src_if: None,
        dst_if: None,
        sproc: None,
        dproc: None,
    }
}

impl Summary {
    fn other(proto: String) -> Self {
        Self {
            src: String::new(),
            dst: String::new(),
            proto,
            info: String::new(),
            ports: None,
        }
    }
}

fn ipv4(d: &[u8]) -> Option<Summary> {
    let ihl = usize::from(d.first()? & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(12..16)?).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(16..20)?).ok()?);
    let fragment_offset = be16(d, 6)? & 0x1fff;
    // Only the first fragment carries the transport header.
    let l4 = if fragment_offset == 0 {
        d.get(ihl..).unwrap_or_default()
    } else {
        &[]
    };
    let (proto, info, ports) = transport(d[9], l4);
    Some(Summary {
        src: src.to_string(),
        dst: dst.to_string(),
        proto,
        info,
        ports,
    })
}

fn ipv6(d: &[u8]) -> Option<Summary> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(24..40)?).ok()?);
    // shortcut: extension headers are not walked, so they show as "IP proto N"; walk them if that shows up often.
    let (proto, info, ports) = transport(d[6], &d[40..]);
    Some(Summary {
        src: src.to_string(),
        dst: dst.to_string(),
        proto,
        info,
        ports,
    })
}

fn arp(d: &[u8]) -> Option<Summary> {
    // Only Ethernet/IPv4 ARP: 6-byte hardware and 4-byte protocol addresses.
    if d.get(4..6)? != [6, 4] {
        return None;
    }
    let sender = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(14..18)?).ok()?);
    let target = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(24..28)?).ok()?);
    let info = match be16(d, 6)? {
        1 => format!("Who has {target}? Tell {sender}"),
        2 => {
            let mac: Vec<String> = d[8..14].iter().map(|b| format!("{b:02x}")).collect();
            format!("{sender} is at {}", mac.join(":"))
        }
        op => format!("opcode {op}"),
    };
    Some(Summary {
        src: sender.to_string(),
        dst: target.to_string(),
        proto: "ARP".into(),
        info,
        ports: None,
    })
}

/// Returns the protocol name, the info text and the TCP/UDP ports.
fn transport(proto: u8, d: &[u8]) -> (String, String, Option<(u16, u16)>) {
    let (name, info) = match proto {
        1 => ("ICMP", icmp(d)),
        6 => ("TCP", tcp(d)),
        17 => ("UDP", ports(d)),
        58 => ("ICMPv6", icmp(d)),
        p => return (format!("IP proto {p}"), String::new(), None),
    };
    let ports = match proto {
        6 | 17 => be16(d, 0).zip(be16(d, 2)),
        _ => None,
    };
    (
        name.into(),
        info.unwrap_or_else(|| "truncated".into()),
        ports,
    )
}

fn ports(d: &[u8]) -> Option<String> {
    Some(format!("{} → {}", be16(d, 0)?, be16(d, 2)?))
}

fn tcp(d: &[u8]) -> Option<String> {
    const FLAGS: [(u8, &str); 6] = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
    ];
    let bits = *d.get(13)?;
    let set: Vec<&str> = FLAGS
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    Some(format!("{} [{}]", ports(d)?, set.join(", ")))
}

fn icmp(d: &[u8]) -> Option<String> {
    Some(format!("type {} code {}", d.first()?, d.get(1)?))
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(proto: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, proto, 0, 0];
        h.extend([10, 0, 0, 1, 10, 0, 0, 2]);
        h
    }

    #[test]
    fn ipv4_tcp_syn_ack() {
        let mut d = ipv4_header(6);
        d.extend([0x01, 0xbb, 0xc8, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x12]);
        let r = row(3, 1_500_000, 60, 0x0800, &d);
        assert_eq!(
            (
                r.time.as_str(),
                r.src.as_str(),
                r.dst.as_str(),
                r.proto.as_str()
            ),
            ("1.500000", "10.0.0.1", "10.0.0.2", "TCP")
        );
        assert_eq!(r.info, "443 → 51234 [SYN, ACK]");
        assert_eq!((r.sport, r.dport), (Some(443), Some(51234)));
    }

    #[test]
    fn ipv4_later_fragment_has_no_ports() {
        let mut d = ipv4_header(17);
        d[7] = 0x10; // fragment offset != 0
        d.extend([0, 53, 0, 53]);
        let r = row(1, 0, 24, 0x0800, &d);
        assert_eq!((r.info.as_str(), r.sport), ("truncated", None));
    }

    #[test]
    fn ipv6_udp() {
        let mut d = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        d.extend(Ipv6Addr::LOCALHOST.octets());
        d.extend(Ipv6Addr::LOCALHOST.octets());
        d.extend([0, 53, 0x30, 0x39, 0, 8, 0, 0]);
        let r = row(1, 0, 48, 0x86dd, &d);
        assert_eq!(
            (r.src.as_str(), r.proto.as_str(), r.info.as_str()),
            ("::1", "UDP", "53 → 12345")
        );
        assert_eq!((r.sport, r.dport), (Some(53), Some(12345)));
    }

    #[test]
    fn arp_request() {
        let mut d = vec![0, 1, 8, 0, 6, 4, 0, 1];
        d.extend([0xaa; 6]);
        d.extend([192, 168, 0, 1]);
        d.extend([0; 6]);
        d.extend([192, 168, 0, 2]);
        assert_eq!(
            row(1, 0, 28, 0x0806, &d).info,
            "Who has 192.168.0.2? Tell 192.168.0.1"
        );
    }

    #[test]
    fn truncated_and_unknown_input_does_not_panic() {
        for len in 0..40 {
            let d = vec![0x4f; len];
            row(1, 0, 0, 0x0800, &d);
            row(1, 0, 0, 0x86dd, &d);
            row(1, 0, 0, 0x0806, &d);
        }
        let r = row(1, 0, 0, 0x88cc, &[]);
        assert_eq!(r.proto, "0x88cc");
        assert_eq!(row(1, 0, 0, 0x0800, &[0x45]).proto, "IPv4");
    }
}
