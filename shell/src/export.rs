//! Saving captures. While capturing, every packet is appended to a pcap file
//! in the user's cache directory, so "Save pcap" can copy the whole capture.
//! Other formats (CSV) come from the UI as text. Paths come from the
//! desktop's file chooser (a portal dialog when one is available).

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::ops::ControlFlow;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use gtk::prelude::*;

/// pcap link type `LINUX_SLL`: a 16-byte pseudo header built from `sockaddr_ll`.
const LINKTYPE_LINUX_SLL: u32 = 113;
/// Largest packet kept, also the receive buffer size. Offloaded (GSO/GRO)
/// packets can be far larger than the MTU.
pub const SNAPLEN: usize = 262_144;
const SLL_HEADER: usize = 16;

/// Link-layer facts of one packet, as the packet socket reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    /// `PACKET_HOST`, `PACKET_OUTGOING` and so on.
    pub pkttype: u8,
    /// ARP hardware type (`ARPHRD_*`).
    pub hatype: u16,
    /// Bytes of `addr` in use.
    pub halen: u8,
    /// Link-layer source address.
    pub addr: [u8; 8],
    /// Ethertype, in host byte order.
    pub protocol: u16,
}

/// The pcap file that records every packet of one capture.
#[derive(Debug)]
pub struct Recording {
    path: PathBuf,
    out: Mutex<BufWriter<File>>,
}

impl Recording {
    pub fn create() -> io::Result<Self> {
        let path = cache_dir()?.join(format!("capture-{}.pcap", std::process::id()));
        // Packets hold payloads: only this user may read the file.
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        let mut out = BufWriter::new(file);
        // Magic (microsecond stamps), version 2.4, zone, sigfigs, snaplen, link type.
        for word in [0xa1b2_c3d4_u32, 0x0004_0002, 0, 0] {
            out.write_all(&word.to_le_bytes())?;
        }
        out.write_all(
            &u32::try_from(SNAPLEN + SLL_HEADER)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        )?;
        out.write_all(&LINKTYPE_LINUX_SLL.to_le_bytes())?;
        Ok(Self {
            path,
            out: Mutex::new(out),
        })
    }

    /// Appends one packet: `data` is what was captured, `wire_len` its length on the wire.
    pub fn write(&self, ts_us: u64, link: &Link, data: &[u8], wire_len: usize) -> io::Result<()> {
        let len = |n: usize| u32::try_from(n + SLL_HEADER).unwrap_or(u32::MAX);
        let secs = u32::try_from(ts_us / 1_000_000).unwrap_or(u32::MAX);
        let micros = u32::try_from(ts_us % 1_000_000).unwrap_or(0);
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        for word in [secs, micros, len(data.len()), len(wire_len)] {
            out.write_all(&word.to_le_bytes())?;
        }
        // LINUX_SLL fields are big-endian.
        out.write_all(&u16::from(link.pkttype).to_be_bytes())?;
        out.write_all(&link.hatype.to_be_bytes())?;
        out.write_all(&u16::from(link.halen).to_be_bytes())?;
        out.write_all(&link.addr)?;
        out.write_all(&link.protocol.to_be_bytes())?;
        out.write_all(data)
    }

    /// Copies the capture so far to `dest`. Returns the bytes written.
    pub fn save_to(&self, dest: &Path) -> io::Result<u64> {
        self.flush()?;
        fs::copy(&self.path, dest)
    }

    /// Calls `f` with the number (from 1), ethertype and network-layer bytes
    /// of each recorded packet, in capture order, until it breaks.
    pub fn scan(&self, mut f: impl FnMut(u64, u16, &[u8]) -> ControlFlow<()>) -> io::Result<()> {
        self.flush()?;
        let mut file = BufReader::new(File::open(&self.path)?);
        file.seek_relative(24)?;
        let mut record = [0u8; 16];
        let mut data = Vec::new();
        for no in 1.. {
            // The capture thread may be mid-record at the end of the file.
            match file.read_exact(&mut record) {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                other => other?,
            }
            let caplen = u32::from_le_bytes([record[8], record[9], record[10], record[11]]);
            data.resize(usize::try_from(caplen).unwrap_or(usize::MAX), 0);
            match file.read_exact(&mut data) {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                other => other?,
            }
            let Some(packet) = data.get(SLL_HEADER..) else {
                continue;
            };
            let ethertype = u16::from_be_bytes([data[14], data[15]]);
            if f(no, ethertype, packet).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.out
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        // The cache file holds payloads: do not leave it behind.
        let _ = fs::remove_file(&self.path);
    }
}

/// `wireshark-rs` in the user's cache directory, created if missing.
pub fn cache_dir() -> io::Result<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| io::Error::other("no cache directory: HOME is not set"))?;
    let dir = cache.join("wireshark-rs");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Shows a save dialog without blocking the event loop. `on_path` runs with
/// the chosen path. Keep the returned dialog alive until it answers.
pub fn ask_path(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    file_name: &str,
    on_path: impl FnOnce(PathBuf) + 'static,
) -> gtk::FileChooserNative {
    let dialog = gtk::FileChooserNative::new(
        Some(title),
        Some(parent),
        gtk::FileChooserAction::Save,
        Some("_Save"),
        Some("_Cancel"),
    );
    dialog.set_do_overwrite_confirmation(true);
    dialog.set_current_name(file_name);
    let on_path = RefCell::new(Some(on_path));
    dialog.connect_response(move |d, response| {
        let path = (response == gtk::ResponseType::Accept)
            .then(|| d.filename())
            .flatten();
        if let (Some(path), Some(f)) = (path, on_path.take()) {
            f(path);
        }
    });
    dialog.show();
    dialog
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What one recorded packet leaves behind.
    #[derive(Debug, PartialEq, Eq)]
    struct Recorded {
        /// The saved pcap file.
        file: Vec<u8>,
        /// What `scan` reports: number, ethertype, network-layer bytes.
        seen: Vec<(u64, u16, Vec<u8>)>,
        /// Whether the recording file outlives the `Recording`.
        kept: bool,
    }

    /// Records one `IPv4` packet, saves the capture and scans it.
    fn record_one() -> io::Result<Recorded> {
        let rec = Recording::create()?;
        let link = Link {
            pkttype: 4,  // outgoing
            hatype: 772, // loopback
            protocol: 0x0800,
            ..Link::default()
        };
        rec.write(1_500_000, &link, &[0x45, 0, 0, 20], 60)?;
        let dir = std::env::temp_dir().join(format!("wsrk-test-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let dest = dir.join("out.pcap");
        rec.save_to(&dest)?;
        let file = fs::read(&dest)?;
        fs::remove_dir_all(dir)?;
        let mut seen = Vec::new();
        rec.scan(|no, ethertype, d| {
            seen.push((no, ethertype, d.to_vec()));
            ControlFlow::Continue(())
        })?;
        let path = rec.path.clone();
        drop(rec);
        Ok(Recorded {
            file,
            seen,
            kept: path.exists(),
        })
    }

    #[test]
    fn pcap_layout() {
        let file = [
            // Magic, version 2.4, zone, sigfigs.
            &[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
            // Snap length 262144 + 16, link type 113.
            &[0x10, 0, 4, 0, 113, 0, 0, 0],
            // Record header: 1 s, 500000 µs, caplen 20, wire length 76.
            &[1, 0, 0, 0, 0x20, 0xa1, 7, 0, 20, 0, 0, 0, 76, 0, 0, 0],
            // Link header: outgoing, loopback, no address, IPv4.
            &[0, 4, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0],
            &[0x45, 0, 0, 20],
        ]
        .concat();
        let expected = Recorded {
            file,
            seen: vec![(1, 0x0800, vec![0x45, 0, 0, 20])],
            kept: false,
        };
        assert_eq!(record_one().map_err(|e| e.to_string()), Ok(expected));
    }
}
