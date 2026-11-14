//! Detail for the packet inspector: the bytes of one recorded packet, and
//! its conversation reassembled into the turns each side sent (a request,
//! then its response, and so on).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::ControlFlow;

use serde::Serialize;

use crate::export::Recording;

/// Packet bytes sent to the UI.
const PACKET_MAX: usize = 64 * 1024;
/// Bytes of one turn sent to the UI.
const TURN_MAX: usize = 64 * 1024;
/// Bytes of all turns sent to the UI. JSON spends about 4 characters on a byte.
const TOTAL_MAX: usize = 256 * 1024;
/// Turns sent to the UI.
const TURNS_MAX: usize = 200;

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub no: u64,
    /// Network-layer bytes of the packet, up to `PACKET_MAX`.
    pub bytes: Vec<u8>,
    /// Bytes captured of the packet.
    pub caplen: usize,
    /// Where the TCP or UDP payload starts in `bytes`.
    pub payload_at: Option<usize>,
    /// The conversation's data in the order it was sent.
    pub turns: Vec<Turn>,
    /// Bytes of the conversation left out by the limits above.
    pub omitted: usize,
}

/// Data one side sent before the other side answered. A UDP datagram is
/// a turn of its own.
#[derive(Debug, Serialize, PartialEq)]
pub struct Turn {
    /// Sent by the side that sent first in the capture: the client, usually.
    pub client: bool,
    /// First and last packet that carried it.
    pub first: u64,
    pub last: u64,
    /// Bytes sent, including those left out of `data`.
    pub len: usize,
    /// Bytes the capture did not see inside this turn.
    pub gaps: usize,
    pub data: Vec<u8>,
}

/// One TCP segment or UDP datagram.
struct Segment<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    tcp: bool,
    seq: u32,
    syn: bool,
    /// Offset of `payload` in the network-layer bytes.
    at: usize,
    payload: &'a [u8],
}

/// Inspects packet `no` of `rec`.
pub fn inspect(rec: &Recording, no: u64) -> std::io::Result<Inspection> {
    let mut packet = None;
    rec.scan(|n, ethertype, d| {
        if n != no {
            return ControlFlow::Continue(());
        }
        packet = Some((ethertype, d.to_vec()));
        ControlFlow::Break(())
    })?;
    let (ethertype, bytes) =
        packet.ok_or_else(|| std::io::Error::other(format!("packet {no} is not recorded")))?;
    let seg = segment(ethertype, &bytes);
    let payload_at = seg.as_ref().map(|s| s.at);
    let mut turns = Turns::default();
    if let Some(s) = seg {
        let (a, b, tcp) = (s.src, s.dst, s.tcp);
        rec.scan(|n, ethertype, d| {
            if let Some(s) = segment(ethertype, d)
                && s.tcp == tcp
                && ((s.src, s.dst) == (a, b) || (s.src, s.dst) == (b, a))
            {
                turns.add(n, &s);
            }
            ControlFlow::Continue(())
        })?;
    }
    Ok(Inspection {
        no,
        caplen: bytes.len(),
        payload_at,
        bytes: bytes.into_iter().take(PACKET_MAX).collect(),
        turns: turns.list,
        omitted: turns.omitted,
    })
}

#[derive(Default)]
struct Turns {
    list: Vec<Turn>,
    omitted: usize,
    /// Bytes kept in `list`.
    kept: usize,
    /// The side that sent first.
    client: Option<SocketAddr>,
    /// Next expected TCP sequence number, per direction (client first).
    next: [Option<u32>; 2],
}

impl Turns {
    fn add(&mut self, no: u64, s: &Segment) {
        let client = *self.client.get_or_insert(s.src) == s.src;
        let next = &mut self.next[usize::from(!client)];
        let mut data = s.payload;
        let mut gap = 0;
        if s.tcp {
            if s.syn {
                *next = Some(s.seq.wrapping_add(1));
            }
            let expected = *next.get_or_insert(s.seq);
            // Signed distance, so sequence numbers may wrap.
            let ahead = s.seq.wrapping_sub(expected).cast_signed();
            if ahead < 0 {
                // A retransmission: skip what was already delivered.
                data = data
                    .get(ahead.unsigned_abs() as usize..)
                    .unwrap_or_default();
            } else {
                // shortcut: out-of-order segments count as a gap and are appended where they arrive; reorder by sequence if captures show many.
                gap = ahead.unsigned_abs() as usize;
            }
            if !data.is_empty() {
                *next = Some(
                    s.seq
                        .wrapping_add(u32::try_from(s.payload.len()).unwrap_or(u32::MAX)),
                );
            }
        }
        if data.is_empty() {
            return;
        }
        let extend = s.tcp && self.list.last().is_some_and(|t| t.client == client);
        if !extend {
            if self.list.len() == TURNS_MAX {
                self.omitted += data.len();
                return;
            }
            self.list.push(Turn {
                client,
                first: no,
                last: no,
                len: 0,
                gaps: 0,
                data: Vec::new(),
            });
        }
        let t = self.list.last_mut().expect("a turn was pushed or extended");
        t.last = no;
        t.len += data.len();
        t.gaps += gap;
        let room = TURN_MAX
            .saturating_sub(t.data.len())
            .min(TOTAL_MAX - self.kept)
            .min(data.len());
        t.data.extend_from_slice(&data[..room]);
        self.kept += room;
        self.omitted += data.len() - room;
    }
}

/// The TCP or UDP part of an IPv4 or IPv6 packet. Ethernet padding past
/// the IP length is cut off.
fn segment(ethertype: u16, d: &[u8]) -> Option<Segment<'_>> {
    let (src, dst, proto, start, end): (IpAddr, IpAddr, u8, usize, usize) = match ethertype {
        0x0800 => {
            let ihl = usize::from(d.first()? & 0x0f) * 4;
            // A later fragment has no transport header.
            if ihl < 20 || be16(d, 6)? & 0x1fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(12..16)?).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(16..20)?).ok()?);
            (src.into(), dst.into(), d[9], ihl, usize::from(be16(d, 2)?))
        }
        0x86dd => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(8..24)?).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(24..40)?).ok()?);
            // shortcut: extension headers are not walked, like in parse.rs.
            (
                src.into(),
                dst.into(),
                d[6],
                40,
                40 + usize::from(be16(d, 4)?),
            )
        }
        _ => return None,
    };
    // Offloaded packets may claim length 0 or less than they hold.
    let end = if end > start {
        end.min(d.len())
    } else {
        d.len()
    };
    let l4 = d.get(start..end)?;
    let (tcp, at, seq, syn) = match proto {
        6 => {
            let off = usize::from(l4.get(12)? >> 4) * 4;
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(l4.get(4..8)?).ok()?);
            (true, off, seq, l4.get(13)? & 0x02 != 0)
        }
        17 => (false, 8, 0, false),
        _ => return None,
    };
    Some(Segment {
        src: SocketAddr::new(src, be16(l4, 0)?),
        dst: SocketAddr::new(dst, be16(l4, 2)?),
        tcp,
        seq,
        syn,
        at: start + at,
        payload: l4.get(at..)?,
    })
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4/TCP packet from `sport` to `dport` with `payload`.
    fn tcp(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(40 + payload.len()).unwrap();
        let (src, dst) = if sport < dport {
            ([10, 0, 0, 2], [10, 0, 0, 1])
        } else {
            ([10, 0, 0, 1], [10, 0, 0, 2])
        };
        let mut d = vec![0x45, 0];
        d.extend(total.to_be_bytes());
        d.extend([0, 0, 0x40, 0, 64, 6, 0, 0]);
        d.extend(src);
        d.extend(dst);
        d.extend(sport.to_be_bytes());
        d.extend(dport.to_be_bytes());
        d.extend(seq.to_be_bytes());
        d.extend([0, 0, 0, 0, 0x50, flags, 0, 0, 0, 0, 0, 0]);
        d.extend(payload);
        // Ethernet padding, which must not reach the stream.
        d.extend([0; 4]);
        d
    }

    fn run(packets: &[Vec<u8>]) -> Turns {
        let mut t = Turns::default();
        for (i, p) in packets.iter().enumerate() {
            if let Some(s) = segment(0x0800, p) {
                t.add(i as u64 + 1, &s);
            }
        }
        t
    }

    #[test]
    fn request_and_response_with_retransmission() {
        let t = run(&[
            tcp(40000, 80, 99, 0x02, b""),
            tcp(80, 40000, 499, 0x12, b""),
            tcp(40000, 80, 100, 0x18, b"GET / HTTP/1.1\r\n"),
            tcp(40000, 80, 116, 0x18, b"\r\n"),
            // Retransmission of the second part, plus new bytes.
            tcp(40000, 80, 116, 0x18, b"\r\nX"),
            tcp(80, 40000, 500, 0x18, b"HTTP/1.1 200 OK\r\n"),
        ]);
        let data: Vec<(&[u8], bool, u64, u64)> = t
            .list
            .iter()
            .map(|t| (&t.data[..], t.client, t.first, t.last))
            .collect();
        assert_eq!(
            data,
            [
                (&b"GET / HTTP/1.1\r\n\r\nX"[..], true, 3, 5),
                (&b"HTTP/1.1 200 OK\r\n"[..], false, 6, 6),
            ]
        );
        assert_eq!(t.list[0].gaps, 0);
    }

    #[test]
    fn missing_segment_counts_as_gap() {
        let t = run(&[
            tcp(40000, 80, 1, 0x18, b"ab"),
            tcp(40000, 80, 13, 0x18, b"cd"),
        ]);
        assert_eq!(
            (t.list[0].data.as_slice(), t.list[0].gaps),
            (&b"abcd"[..], 10)
        );
    }

    #[test]
    fn payload_offset_and_bad_input() {
        let p = tcp(40000, 80, 1, 0x18, b"hi");
        let s = segment(0x0800, &p).unwrap();
        assert_eq!((s.at, s.payload), (40, &b"hi"[..]));
        for len in 0..p.len() {
            segment(0x0800, &p[..len]);
            segment(0x86dd, &p[..len]);
        }
    }
}
