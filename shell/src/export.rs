//! Saving captures. While capturing, every packet is appended to a pcap file
//! in the user's cache directory, so "Save pcap" can copy the whole capture.
//! Other formats (CSV) come from the UI as text. Paths come from the
//! desktop's file chooser (a portal dialog when one is available).

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use gtk::prelude::*;

/// pcap link type LINUX_SLL: a 16-byte pseudo header built from `sockaddr_ll`.
const LINKTYPE_LINUX_SLL: u32 = 113;
/// Largest packet kept, also the receive buffer size. Offloaded (GSO/GRO)
/// packets can be far larger than the MTU.
pub const SNAPLEN: usize = 262_144;
const SLL_HEADER: usize = 16;

pub struct Recording {
    path: PathBuf,
    out: Mutex<BufWriter<File>>,
}

impl Recording {
    pub fn create() -> io::Result<Self> {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .ok_or_else(|| io::Error::other("no cache directory: HOME is not set"))?;
        let dir = cache.join("wireshark-rs");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("capture-{}.pcap", std::process::id()));
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
    pub fn write(
        &self,
        ts_us: u64,
        addr: &libc::sockaddr_ll,
        data: &[u8],
        wire_len: usize,
    ) -> io::Result<()> {
        let len = |n: usize| u32::try_from(n + SLL_HEADER).unwrap_or(u32::MAX);
        let secs = u32::try_from(ts_us / 1_000_000).unwrap_or(u32::MAX);
        let micros = u32::try_from(ts_us % 1_000_000).unwrap_or(0);
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        for word in [secs, micros, len(data.len()), len(wire_len)] {
            out.write_all(&word.to_le_bytes())?;
        }
        // LINUX_SLL fields are big-endian; sll_protocol is already in network order.
        out.write_all(&u16::from(addr.sll_pkttype).to_be_bytes())?;
        out.write_all(&addr.sll_hatype.to_be_bytes())?;
        out.write_all(&u16::from(addr.sll_halen).to_be_bytes())?;
        out.write_all(&addr.sll_addr)?;
        out.write_all(&addr.sll_protocol.to_ne_bytes())?;
        out.write_all(data)
    }

    /// Copies the capture so far to `dest`. Returns the bytes written.
    pub fn save_to(&self, dest: &Path) -> io::Result<u64> {
        self.out
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()?;
        fs::copy(&self.path, dest)
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        // The cache file holds payloads: do not leave it behind.
        let _ = fs::remove_file(&self.path);
    }
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

    #[test]
    fn pcap_layout() {
        let rec = Recording::create().expect("cache dir is writable");
        // SAFETY: sockaddr_ll is a plain C struct; all-zero is a valid value.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_pkttype = 4; // outgoing
        addr.sll_hatype = 772; // loopback
        addr.sll_protocol = 0x0800_u16.to_be();
        rec.write(1_500_000, &addr, &[0x45, 0, 0, 20], 60).unwrap();
        let dir = std::env::temp_dir().join(format!("wsrk-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("out.pcap");
        assert_eq!(rec.save_to(&dest).unwrap(), 24 + 16 + 16 + 4);
        let b = fs::read(&dest).unwrap();
        assert_eq!(b[..4], [0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(b[20..24], 113_u32.to_le_bytes());
        // Record header: 1 s, 500000 µs, caplen 20, wire length 76.
        assert_eq!(
            b[24..40],
            [1, 0, 0, 0, 0x20, 0xa1, 7, 0, 20, 0, 0, 0, 76, 0, 0, 0]
        );
        assert_eq!(b[40..56], [0, 4, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0]);
        let path = rec.path.clone();
        drop(rec);
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
