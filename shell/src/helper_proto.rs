//! What the GUI and the privileged helper share. Both binaries include this
//! file, so the two sides cannot disagree on the values.
//!
//! The GUI sends one command line at a time and waits for the reply, which
//! is one `ok` or `error: <text>` line. `socket4` and `socket6` replies
//! carry the new socket as `SCM_RIGHTS` data.
//!
//! - `socket4`, `socket6`: a TCP socket marked with `MARK`, which the
//!   interception rules let through. The proxy's own connections use it.
//! - `on` followed by one PEM certificate: trust that CA system-wide and
//!   redirect this machine's web traffic to the proxy.
//! - `off`: remove the rules and the CA. Closing the connection does the same.

/// Packet mark of the proxy's own connections ("WSRS").
pub const MARK: u32 = 0x5753_5253;
/// Port the proxy listens on, on `127.0.0.1` and `::1`.
pub const PROXY_PORT: u16 = 8899;
/// Longest PEM certificate the helper accepts.
pub const PEM_MAX: usize = 8192;
pub const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
pub const PEM_END: &str = "-----END CERTIFICATE-----";
/// nftables table that holds the interception rules.
pub const TABLE: &str = "inet wireshark_rs";

/// `ETH_P_ALL` from `linux/if_ether.h`: the packet socket takes every protocol.
pub const ETH_P_ALL: u16 = 0x0003;
/// `BPF_RET | BPF_K`: return a constant, the bytes of the packet to keep.
pub const BPF_RET_K: u16 = 0x06;
/// Classic BPF program that drops every packet: `ret #0`. The packet socket
/// holds it while no capture runs.
pub const DROP_ALL: [socket2::SockFilter; 1] = [socket2::SockFilter::new(BPF_RET_K, 0, 0, 0)];

/// nft command, on one line for `nft -i`, that redirects all of this
/// machine's outgoing TCP to the proxy and rejects QUIC (UDP 443) so
/// browsers fall back to TCP. The proxy's own connections carry `MARK` and
/// pass; loopback is left alone.
///
/// The table has the `owner` flag: the kernel deletes it when the process
/// that created it exits, however it exits, so traffic is never left
/// redirected to a proxy that is gone.
pub fn rules() -> String {
    format!(
        "table {TABLE} {{ flags owner; \
         chain to_proxy {{ type nat hook output priority dstnat; policy accept; \
         meta mark {MARK:#x} return; \
         ip daddr 127.0.0.0/8 return; \
         ip6 daddr ::1 return; \
         meta l4proto tcp redirect to :{PROXY_PORT}; }}; \
         chain block_quic {{ type filter hook output priority filter; policy accept; \
         meta mark {MARK:#x} return; \
         udp dport 443 reject; }}; }}\n"
    )
}

/// nft script that removes the table, and succeeds when it is missing.
pub fn remove_rules() -> String {
    format!("table {TABLE}\ndelete table {TABLE}\n")
}
