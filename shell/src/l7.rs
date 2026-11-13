//! Application-layer hints from the start of a TCP or UDP payload: the
//! protocol name, an info text, and host names the shell uses to label
//! addresses (DNS answers, TLS SNI, HTTP Host).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default, PartialEq)]
pub struct L7 {
    /// Lowercase protocol name, like `https` or `dns`.
    pub app: Option<&'static str>,
    /// Replaces the transport info when set.
    pub info: Option<String>,
    /// Name the client asked for (TLS SNI, HTTP Host): it labels the destination.
    pub server_name: Option<String>,
    /// Addresses from DNS answers and the name that resolved to them.
    pub answers: Vec<(IpAddr, String)>,
}

/// Longest first line shown as info.
const INFO_CHARS: usize = 96;
/// Bytes searched for the HTTP Host header.
const HTTP_HEAD: usize = 4096;

pub fn inspect(tcp: bool, sport: u16, dport: u16, payload: &[u8]) -> L7 {
    let mut l7 = L7 {
        app: by_port(tcp, sport.min(dport)).or_else(|| by_port(tcp, sport.max(dport))),
        ..L7::default()
    };
    if payload.is_empty() {
        return l7;
    }
    let either = |p: u16| sport == p || dport == p;
    if !tcp && (either(53) || either(5353) || either(5355)) {
        // mDNS answers name themselves; DNS answers belong to the question.
        if let Some((info, answers)) = dns(payload, either(5353)) {
            l7.info = Some(info);
            l7.answers = answers;
        }
    } else if tcp && payload.len() > 5 && (0x14..=0x17).contains(&payload[0]) && payload[1] == 3 {
        l7.app = Some(if either(443) { "https" } else { "tls" });
        if payload[0] == 0x16 {
            match payload.get(5) {
                Some(1) => {
                    l7.server_name = sni(payload);
                    l7.info = Some(match &l7.server_name {
                        Some(name) => format!("Client Hello, SNI {name}"),
                        None => "Client Hello".to_owned(),
                    });
                }
                Some(2) => l7.info = Some("Server Hello".to_owned()),
                _ => {}
            }
        }
    } else if tcp && is_http_request(payload) {
        l7.app = Some("http");
        l7.info = first_line(payload);
        l7.server_name = http_host(payload);
    } else if tcp && payload.starts_with(b"HTTP/1.") {
        l7.app = Some("http");
        l7.info = first_line(payload);
    } else if tcp && payload.starts_with(b"SSH-") {
        l7.app = Some("ssh");
        l7.info = first_line(payload);
    } else if tcp && either(21) {
        // Never show the FTP password.
        l7.info = first_line(payload).map(|l| {
            if l.to_ascii_uppercase().starts_with("PASS ") {
                "PASS ****".to_owned()
            } else {
                l
            }
        });
    } else if !tcp && either(443) && payload[0] & 0x80 != 0 {
        // QUIC v1 long header: the packet type is in bits 4-5.
        let kind = ["Initial", "0-RTT", "Handshake", "Retry"][usize::from(payload[0] >> 4 & 3)];
        l7.info = Some(format!("QUIC {kind}"));
    }
    l7
}

/// IANA service name for a well-known port.
fn by_port(tcp: bool, port: u16) -> Option<&'static str> {
    Some(match (tcp, port) {
        (true, 20) => "ftp-data",
        (true, 21) => "ftp",
        (true, 22) => "ssh",
        (true, 23) => "telnet",
        (true, 25) => "smtp",
        (_, 53) => "dns",
        (false, 67 | 68) => "dhcp",
        (false, 69) => "tftp",
        (true, 80 | 8080) => "http",
        (_, 88) => "kerberos",
        (true, 110) => "pop3",
        (false, 123) => "ntp",
        (false, 137) => "netbios-ns",
        (false, 138) => "netbios-dgm",
        (true, 139) => "netbios-ssn",
        (true, 143) => "imap",
        (false, 161 | 162) => "snmp",
        (_, 389) => "ldap",
        (true, 443 | 8443) => "https",
        (false, 443) => "quic",
        (true, 445) => "smb",
        (true, 465) => "smtps",
        (false, 514) => "syslog",
        (false, 546 | 547) => "dhcpv6",
        (_, 554) => "rtsp",
        (true, 587) => "submission",
        (_, 631) => "ipp",
        (true, 636) => "ldaps",
        (true, 853) => "dot",
        (true, 993) => "imaps",
        (true, 995) => "pop3s",
        (_, 1194) => "openvpn",
        (true, 1883) => "mqtt",
        (false, 1900) => "ssdp",
        (true, 3306) => "mysql",
        (_, 3389) => "rdp",
        (_, 5060) => "sip",
        (false, 5353) => "mdns",
        (false, 5355) => "llmnr",
        (true, 5432) => "postgresql",
        (true, 6379) => "redis",
        (false, 51820) => "wireguard",
        _ => return None,
    })
}

fn is_http_request(d: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| d.starts_with(m))
}

/// First line of a text protocol message, shortened to `INFO_CHARS`.
fn first_line(d: &[u8]) -> Option<String> {
    let line = d.split(|&b| b == b'\r' || b == b'\n').next()?;
    let text: String = String::from_utf8_lossy(line)
        .chars()
        .filter(|c| !c.is_control())
        .take(INFO_CHARS)
        .collect();
    (!text.is_empty()).then_some(text)
}

fn http_host(d: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(&d[..d.len().min(HTTP_HEAD)]);
    let value = head.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
    })?;
    // Drop the port: `example.com:8080` names example.com.
    let host = match value.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => value,
    };
    hostname(host.as_bytes())
}

/// Server name from a TLS ClientHello whose record starts at `d[0]`.
fn sni(d: &[u8]) -> Option<String> {
    // Record header (5), handshake header (4), version (2), random (32).
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(*d.get(at)?); // session id
    at += 2 + usize::from(be16(d, at)?); // cipher suites
    at += 1 + usize::from(*d.get(at)?); // compression methods
    let end = (at + 2 + usize::from(be16(d, at)?)).min(d.len());
    at += 2;
    while at + 4 <= end {
        let (kind, len) = (be16(d, at)?, usize::from(be16(d, at + 2)?));
        if kind == 0 {
            // server_name: list length (2), name type (1), name length (2), name.
            let n = usize::from(be16(d, at + 7)?);
            return hostname(d.get(at + 9..at + 9 + n)?);
        }
        at += 4 + len;
    }
    None
}

/// A lowercase DNS host name, or `None` for anything else (IP literals, junk).
fn hostname(b: &[u8]) -> Option<String> {
    let ok = !b.is_empty()
        && b.len() <= 253
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
        && b.iter().any(u8::is_ascii_alphabetic);
    ok.then(|| {
        String::from_utf8_lossy(b)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    })
}

/// Info text and A/AAAA answers of a DNS message.
fn dns(d: &[u8], mdns: bool) -> Option<(String, Vec<(IpAddr, String)>)> {
    let flags = be16(d, 2)?;
    let (questions, answers) = (be16(d, 4)?, be16(d, 6)?);
    let mut at = 12;
    let mut query = None;
    for _ in 0..questions {
        let (name, next) = read_name(d, at)?;
        query.get_or_insert((name, be16(d, next)?));
        at = next + 4;
    }
    let (qname, qtype) = query.clone().unwrap_or_default();
    if flags & 0x8000 == 0 {
        return Some((format!("query {} {qname}", record_type(qtype)), Vec::new()));
    }
    let mut found = Vec::new();
    for _ in 0..answers {
        // A truncated message keeps the answers read so far.
        let Some((owner, next)) = read_name(d, at) else {
            break;
        };
        let (Some(kind), Some(len)) = (be16(d, next), be16(d, next + 8)) else {
            break;
        };
        let Some(data) = d.get(next + 10..next + 10 + usize::from(len)) else {
            break;
        };
        at = next + 10 + usize::from(len);
        let ip = match (kind, data.len()) {
            (1, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?)),
            (28, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => continue,
        };
        let name = if mdns || qname.is_empty() {
            owner
        } else {
            qname.clone()
        };
        found.push((ip, name));
    }
    let info = match flags & 0x000f {
        0 => format!("response {qname}: {} address(es)", found.len()),
        3 => format!("response {qname}: no such name"),
        code => format!("response {qname}: error {code}"),
    };
    Some((info, found))
}

fn record_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        28 => "AAAA".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        t => format!("type {t}"),
    }
}

/// Reads a possibly compressed DNS name. Returns the name and the offset
/// after it in the message (after the first pointer, if any).
fn read_name(d: &[u8], start: usize) -> Option<(String, usize)> {
    let (mut at, mut next, mut jumps) = (start, None, 0);
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *d.get(at)?;
        match len {
            0 => break,
            l if l & 0xc0 == 0xc0 => {
                jumps += 1;
                if jumps > 16 {
                    return None;
                }
                next.get_or_insert(at + 2);
                at = usize::from(be16(d, at)? & 0x3fff);
            }
            l => {
                let label = d.get(at + 1..at + 1 + usize::from(l))?;
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                at += 1 + usize::from(l);
            }
        }
    }
    Some((labels.join("."), next.unwrap_or(at + 1)))
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.split('.') {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn dns_response_maps_answers_to_the_question() {
        let mut d = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        d.extend(name("WWW.Example.com"));
        d.extend([0, 1, 0, 1]);
        // CNAME answer (ignored), then an A answer with a compressed owner name.
        d.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        d.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let l7 = inspect(false, 53, 40000, &d);
        assert_eq!(l7.app, Some("dns"));
        assert_eq!(
            l7.info.as_deref(),
            Some("response www.example.com: 1 address(es)")
        );
        assert_eq!(
            l7.answers,
            [(
                "93.184.216.34".parse().unwrap(),
                "www.example.com".to_owned()
            )]
        );

        d[2] = 0x01; // a query
        assert_eq!(
            inspect(false, 40000, 53, &d[..33]).info.as_deref(),
            Some("query A www.example.com")
        );
    }

    #[test]
    fn compression_loop_is_rejected() {
        let d = [0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12];
        assert_eq!(inspect(false, 53, 1, &d).info, None);
    }

    #[test]
    fn tls_client_hello_sni() {
        let host = b"api.example.org";
        let mut ext = vec![0, 0];
        let list = 3 + host.len();
        ext.extend((list as u16 + 2).to_be_bytes());
        ext.extend((list as u16).to_be_bytes());
        ext.push(0);
        ext.extend((host.len() as u16).to_be_bytes());
        ext.extend(host);
        let mut hello = vec![3, 3];
        hello.extend([0; 32]);
        hello.extend([0, 0, 2, 0x13, 1, 1, 0]);
        hello.extend((ext.len() as u16).to_be_bytes());
        hello.extend(ext);
        let mut d = vec![0x16, 3, 1, 0, 0, 1, 0, 0, 0];
        d.extend(hello);
        let l7 = inspect(true, 51000, 443, &d);
        assert_eq!(l7.app, Some("https"));
        assert_eq!(l7.server_name.as_deref(), Some("api.example.org"));
        assert_eq!(inspect(true, 51000, 8000, &d).app, Some("tls"));
    }

    #[test]
    fn text_protocols() {
        let get = b"GET /index.html HTTP/1.1\r\nHost: Example.COM:8080\r\nAccept: */*\r\n\r\n";
        let l7 = inspect(true, 51000, 8000, get);
        assert_eq!(l7.app, Some("http"));
        assert_eq!(l7.info.as_deref(), Some("GET /index.html HTTP/1.1"));
        assert_eq!(l7.server_name.as_deref(), Some("example.com"));
        assert_eq!(
            inspect(true, 22, 51000, b"SSH-2.0-OpenSSH_9.9\r\n").app,
            Some("ssh")
        );
        assert_eq!(
            inspect(true, 51000, 21, b"PASS hunter2\r\n")
                .info
                .as_deref(),
            Some("PASS ****")
        );
        assert_eq!(
            inspect(false, 51000, 443, &[0xc3, 0, 0, 0, 1])
                .info
                .as_deref(),
            Some("QUIC Initial")
        );
        assert_eq!(inspect(true, 51000, 5432, &[]).app, Some("postgresql"));
        assert_eq!(inspect(true, 40000, 50000, &[]).app, None);
    }

    #[test]
    fn junk_does_not_panic() {
        for len in 0..80 {
            let d: Vec<u8> = (0..len).map(|i| (i * 37 + 0x16) as u8).collect();
            for (tcp, port) in [(true, 443), (false, 53), (true, 80), (false, 443)] {
                inspect(tcp, port, 50000, &d);
            }
        }
    }
}
