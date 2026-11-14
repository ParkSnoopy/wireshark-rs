//! What the GUI and the privileged helper share. Both binaries include this
//! file, so the two sides cannot disagree on the values.
//!
//! The GUI sends one command line at a time and waits for the reply, which
//! is one `ok` or `error: <text>` line. `socket4` and `socket6` replies
//! carry the new socket as SCM_RIGHTS data.
//!
//! - `socket4`, `socket6`: a TCP socket marked with `MARK`, which the
//!   interception rules let through. The proxy's own connections use it.
//! - `on` followed by one PEM certificate: trust that CA system-wide and
//!   redirect this machine's web traffic to the proxy.
//! - `off`: remove the rules and the CA. Closing the connection does the same.

/// Packet mark of the proxy's own connections ("WSRS").
pub const MARK: u32 = 0x5753_5253;
/// Port the proxy listens on, on 127.0.0.1 and ::1.
pub const PROXY_PORT: u16 = 8899;
/// Longest PEM certificate the helper accepts.
pub const PEM_MAX: usize = 8192;
pub const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
pub const PEM_END: &str = "-----END CERTIFICATE-----";
/// nftables table that holds the interception rules.
pub const TABLE: &str = "inet wireshark_rs";

/// nft script that redirects this machine's TCP to ports 80 and 443 to the
/// proxy, and rejects QUIC (UDP 443) so browsers fall back to TCP. The
/// proxy's own connections carry `MARK` and pass; loopback is left alone.
/// It replaces an earlier copy of the table.
pub fn rules() -> String {
    format!(
        "table {TABLE}
delete table {TABLE}
table {TABLE} {{
    chain web_to_proxy {{
        type nat hook output priority dstnat; policy accept;
        meta mark {MARK:#x} return
        ip daddr 127.0.0.0/8 return
        ip6 daddr ::1 return
        tcp dport {{ 80, 443 }} redirect to :{PROXY_PORT}
    }}
    chain block_quic {{
        type filter hook output priority filter; policy accept;
        meta mark {MARK:#x} return
        udp dport 443 reject
    }}
}}
"
    )
}

/// nft script that removes the table, and succeeds when it is missing.
pub fn remove_rules() -> String {
    format!("table {TABLE}\ndelete table {TABLE}\n")
}
