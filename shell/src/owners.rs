//! Names the local side of a packet: the interface an address belongs to
//! (`podman0`, `wlp3s0`) and the process that owns the socket (`firefox`).
//!
//! Sockets come from /proc/net/{tcp,udp}{,6}; their owners from the
//! `socket:[inode]` links in /proc/<pid>/fd. Without privilege only this
//! user's processes are readable, so sockets of other users stay unnamed.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::parse::{IfRef, Row};

/// Minimum time between two /proc scans. A scan runs only on a lookup miss.
const RESCAN: Duration = Duration::from_secs(1);

/// An interface address and its network prefix.
struct Net {
    name: String,
    addr: IpAddr,
    prefix: u32,
}

#[derive(Default)]
pub struct Owners {
    /// `(IP protocol, local address, local port)` → process name.
    sockets: HashMap<(u8, IpAddr, u16), String>,
    nets: Vec<Net>,
    scanned: Option<Instant>,
}

impl Owners {
    pub fn annotate(&mut self, row: &mut Row) {
        if self.scanned.is_none() {
            self.scan();
        }
        let (Ok(src), Ok(dst)) = (row.src.parse::<IpAddr>(), row.dst.parse::<IpAddr>()) else {
            return;
        };
        row.src_if = self.iface(src);
        row.dst_if = self.iface(dst);
        let proto = match row.proto.as_str() {
            "TCP" => 6,
            "UDP" => 17,
            _ => return,
        };
        let local = |i: &Option<IfRef>| i.as_ref().is_some_and(|i| i.local);
        let ends = [
            (local(&row.src_if), src, row.sport),
            (local(&row.dst_if), dst, row.dport),
        ];
        let mut names = [None, None];
        for retry in [false, true] {
            for (name, &(is_local, ip, port)) in names.iter_mut().zip(&ends) {
                if let (true, None, Some(port)) = (is_local, &name, port) {
                    *name = self.lookup(proto, ip, port);
                }
            }
            let missing = names.iter().zip(&ends).any(|(n, e)| e.0 && n.is_none());
            // shortcut: a connection that closes before the next scan stays unnamed;
            // use a netlink sock_diag subscription if short flows matter.
            if !missing || retry || self.scanned.is_some_and(|t| t.elapsed() < RESCAN) {
                break;
            }
            self.scan();
        }
        [row.sproc, row.dproc] = names;
    }

    fn lookup(&self, proto: u8, ip: IpAddr, port: u16) -> Option<String> {
        // Wildcard binds: v4 sockets on 0.0.0.0, and dual-stack sockets on ::.
        let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        [ip, if ip.is_ipv4() { any4 } else { any6 }, any6]
            .iter()
            .find_map(|&a| self.sockets.get(&(proto, a, port)).cloned())
    }

    /// The interface that owns `ip`, or else the one whose network holds it.
    fn iface(&self, ip: IpAddr) -> Option<IfRef> {
        if let Some(n) = self.nets.iter().find(|n| n.addr == ip) {
            return Some(IfRef {
                name: n.name.clone(),
                local: true,
            });
        }
        self.nets
            .iter()
            .filter(|n| n.prefix > 0 && in_network(ip, n.addr, n.prefix))
            .max_by_key(|n| n.prefix)
            .map(|n| IfRef {
                name: n.name.clone(),
                // 127.0.0.0/8 is all local, not only the address on lo.
                local: ip.is_loopback(),
            })
    }

    fn scan(&mut self) {
        self.scanned = Some(Instant::now());
        self.nets = networks().unwrap_or_default();

        let mut by_inode = HashMap::new();
        for (file, proto) in [
            ("/proc/net/tcp", 6),
            ("/proc/net/tcp6", 6),
            ("/proc/net/udp", 17),
            ("/proc/net/udp6", 17),
        ] {
            let Ok(text) = fs::read_to_string(file) else {
                continue;
            };
            for (ip, port, inode) in text.lines().skip(1).filter_map(parse_socket_line) {
                by_inode.insert(inode, (proto, ip, port));
            }
        }

        self.sockets.clear();
        let Ok(procs) = fs::read_dir("/proc") else {
            return;
        };
        for dir in procs.flatten() {
            if !dir
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
            {
                continue;
            }
            // Fails for processes of other users: their sockets stay unnamed.
            let Ok(fds) = fs::read_dir(dir.path().join("fd")) else {
                continue;
            };
            let mut name = None;
            for fd in fds.flatten() {
                let Ok(link) = fs::read_link(fd.path()) else {
                    continue;
                };
                let inode = link
                    .to_str()
                    .and_then(|l| l.strip_prefix("socket:["))
                    .and_then(|l| l.strip_suffix(']'))
                    .and_then(|l| l.parse::<u64>().ok());
                if let Some(key) = inode.and_then(|i| by_inode.get(&i)) {
                    let name = name.get_or_insert_with(|| process_name(&dir.path()));
                    self.sockets.insert(*key, name.clone());
                }
            }
        }
    }
}

/// Executable file name (`firefox`), or the thread name when the link is unreadable.
fn process_name(dir: &Path) -> String {
    fs::read_link(dir.join("exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .or_else(|| {
            fs::read_to_string(dir.join("comm"))
                .ok()
                .map(|c| c.trim().to_owned())
        })
        .unwrap_or_else(|| "?".to_owned())
}

/// Parses `local_address` and `inode` of one /proc/net/{tcp,udp}{,6} line.
/// Addresses are printed as native-endian 32-bit words in hex.
fn parse_socket_line(line: &str) -> Option<(IpAddr, u16, u64)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (addr, port) = fields.get(1)?.split_once(':')?;
    let inode = fields.get(9)?.parse().ok().filter(|&i| i != 0)?;
    let word = |i: usize| u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok();
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?.to_ne_bytes())),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(i)?.to_ne_bytes());
            }
            // Dual-stack sockets show IPv4 peers as ::ffff:a.b.c.d.
            let v6 = Ipv6Addr::from(bytes);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some((ip, u16::from_str_radix(port, 16).ok()?, inode))
}

fn in_network(ip: IpAddr, net: IpAddr, prefix: u32) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Addresses and prefixes of all interfaces, from getifaddrs(3).
fn networks() -> std::io::Result<Vec<Net>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: list is a valid out pointer; freeifaddrs releases it below.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut nets = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: cur is a node of the list getifaddrs returned and is not freed yet.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        // SAFETY: ifa_addr and ifa_netmask are null or point to a sockaddr of the
        // family in sa_family; ifa_name is a NUL-terminated string.
        let (addr, mask) = unsafe { (sock_ip(ifa.ifa_addr), sock_ip(ifa.ifa_netmask)) };
        let (Some(addr), Some(mask)) = (addr, mask) else {
            continue;
        };
        let prefix = match mask {
            IpAddr::V4(m) => u32::from(m).count_ones(),
            IpAddr::V6(m) => u128::from(m).count_ones(),
        };
        // SAFETY: see above.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        nets.push(Net { name, addr, prefix });
    }
    // SAFETY: list came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(nets)
}

/// # Safety
/// `sa` must be null or point to a valid sockaddr of the family it names.
unsafe fn sock_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the struct matches sa_family.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let v4 = &*sa.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes())))
            }
            libc::AF_INET6 => {
                let v6 = &*sa.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_lines() {
        // 127.0.0.1:8080, written as /proc does on this host's byte order.
        let v4 = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
        let line = format!(
            "   0: {v4}:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0"
        );
        assert_eq!(
            parse_socket_line(&line),
            Some(("127.0.0.1".parse().unwrap(), 8080, 4242))
        );

        let mapped: Vec<String> = Ipv4Addr::new(10, 0, 0, 7)
            .to_ipv6_mapped()
            .octets()
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes(c.try_into().unwrap())))
            .collect();
        let line = format!("   1: {}:0035 0 0A 0 0 0 1000 0 77 1", mapped.concat());
        assert_eq!(
            parse_socket_line(&line),
            Some(("10.0.0.7".parse().unwrap(), 53, 77))
        );

        // Inode 0 is a socket in TIME_WAIT without an owner.
        assert_eq!(parse_socket_line(&line.replace(" 77 ", " 0 ")), None);
        assert_eq!(parse_socket_line("sl local_address rem_address"), None);
    }

    #[test]
    fn interface_by_address_then_network() {
        let owners = Owners {
            nets: vec![
                Net {
                    name: "podman0".into(),
                    addr: "10.88.0.1".parse().unwrap(),
                    prefix: 16,
                },
                Net {
                    name: "lo".into(),
                    addr: "127.0.0.1".parse().unwrap(),
                    prefix: 8,
                },
            ],
            ..Owners::default()
        };
        let at = |ip: &str| owners.iface(ip.parse().unwrap()).map(|i| (i.name, i.local));
        assert_eq!(at("10.88.0.1"), Some(("podman0".into(), true)));
        assert_eq!(at("10.88.3.9"), Some(("podman0".into(), false)));
        assert_eq!(at("127.0.0.53"), Some(("lo".into(), true)));
        assert_eq!(at("8.8.8.8"), None);
    }
}
