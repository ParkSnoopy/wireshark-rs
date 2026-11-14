//! Host names for addresses, learned from the traffic itself: DNS answers,
//! TLS SNI and HTTP Host. Each address keeps the name it was last reached by.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::parse::Row;

#[derive(Default)]
pub struct Names {
    by_ip: HashMap<IpAddr, String>,
    seen: HashSet<String>,
}

impl Names {
    /// Stores the names the row teaches and labels its addresses. Returns
    /// names never seen before, for the domain age lookup.
    pub fn annotate(&mut self, row: &mut Row) -> Vec<String> {
        let mut new = Vec::new();
        for (ip, name) in row.learned.drain(..) {
            if self.seen.insert(name.clone()) {
                new.push(name.clone());
            }
            self.by_ip.insert(ip, name);
        }
        let name = |addr: &str| {
            addr.parse()
                .ok()
                .and_then(|ip: IpAddr| self.by_ip.get(&ip).cloned())
        };
        row.src_name = name(&row.src);
        row.dst_name = name(&row.dst);
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn answers_label_later_packets() {
        let ip = IpAddr::from([93, 184, 216, 34]);
        let mut names = Names::default();
        let mut dns = parse::row(1, 0, 0, 0x88cc, &[]);
        dns.learned = vec![(ip, "example.com".into())];
        assert_eq!(names.annotate(&mut dns), ["example.com"]);

        let mut r = parse::row(2, 0, 0, 0x88cc, &[]);
        r.dst = ip.to_string();
        r.learned = vec![(ip, "example.com".into())];
        assert_eq!(names.annotate(&mut r), Vec::<String>::new());
        assert_eq!(
            (r.src_name, r.dst_name.as_deref()),
            (None, Some("example.com"))
        );
    }
}
