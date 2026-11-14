//! HTTPS interception: a transparent proxy for all of this machine's
//! outgoing TCP, which decrypts TLS with certificates signed by a CA made
//! when interception starts.
//!
//! Clients are not configured. The helper redirects all outgoing TCP to
//! `PORT` and adds the CA to the system trust store; the proxy reads where
//! each connection was going (`SO_ORIGINAL_DST`) and tells the protocol
//! from the client's first bytes:
//! - TLS on any port is decrypted, with the host name from the server
//!   name; HTTP/1.1 inside is parsed into requests, other protocols are
//!   recorded as two byte streams;
//! - a TLS hello rustls cannot take (old versions) and programs that
//!   rejected the CA once are passed through undecrypted, so they keep
//!   working;
//! - plain HTTP is parsed; anything else is relayed and recorded as is.
//!
//! Its own
//! connections to the servers use sockets marked so the redirect skips
//! them. The CA key lives only in memory, so the certificate is worthless
//! once the proxy stops. The proxy checks each server's real certificate
//! against the Mozilla roots, so it never hides a forged server.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::Acceptor;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use rustls::{StreamOwned, crypto::ring};
use serde::Serialize;
use socket2::{SockAddr, SockRef, Socket};

use crate::owners::Owners;

pub use crate::helper_proto::PROXY_PORT as PORT;

/// TLS record type of a handshake: the first byte a TLS client sends.
const TLS_HANDSHAKE: u8 = 0x16;
/// ALPN name of the only protocol whose messages the proxy parses.
const HTTP1: &[u8] = b"http/1.1";
/// Client bytes looked at to tell the protocol.
const SNIFF: usize = 8;
/// After one side of a relayed connection is done, how long the other may
/// stay silent before the connection is closed. A peer that never answers
/// a half-close would otherwise hold it open.
const LINGER: Duration = Duration::from_secs(10);
/// How long to wait for the client to speak first. Server-first protocols
/// (SSH, SMTP, FTP) send nothing until the server greets them.
const CLIENT_FIRST: Duration = Duration::from_millis(300);
/// Request lines that mark plain HTTP.
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
/// Body bytes kept for display, before and after decompression.
const BODY_MAX: usize = 64 * 1024;
/// Longest request or response head.
const HEAD_MAX: usize = 64 * 1024;
/// A connection with no traffic for this long is closed.
const IDLE: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout while relaying an upgraded (WebSocket) connection.
const POLL: Duration = Duration::from_millis(20);
/// Validity of the CA and the host certificates, from one day back.
const VALID_DAYS: i64 = 30;

/// One request and its response, as the client and server sent them.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Exchange {
    pub id: u64,
    /// Proxy connection it came through: one TLS session.
    pub conn: u64,
    /// Start, in milliseconds since the Unix epoch.
    pub at_ms: u64,
    /// Time to the end of the response.
    pub ms: u64,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub reason: String,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Body,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Body,
    /// Why the exchange failed, if it did.
    pub error: Option<String>,
    /// How a connection that is not HTTP was handled, such as passed
    /// through undecrypted.
    pub note: Option<String>,
    /// The connection is still open: a later event with the same id
    /// replaces this one.
    pub open: bool,
    /// Process that opened the connection, when it is readable.
    pub app: Option<String>,
    /// Client end of the client-to-proxy connection.
    pub client: String,
    /// Proxy end and server end of the proxy-to-server connection, to match
    /// the captured packets of that connection.
    pub local: Option<String>,
    pub remote: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Body {
    /// Bytes on the wire, without chunk framing.
    pub size: usize,
    /// The first bytes, decompressed when the encoding is gzip or deflate.
    pub data: Vec<u8>,
    /// `data` holds less than the whole body.
    pub truncated: bool,
    /// Content-Encoding left as it was (`br`), or why decoding failed.
    pub note: Option<String>,
}

/// Running proxy. Dropping it stops new connections and deletes the CA file.
pub struct Mitm {
    stop: Arc<AtomicBool>,
    /// PEM file of the CA certificate, for the user to inspect or import.
    pub ca_path: PathBuf,
    /// The same certificate, for the helper to trust.
    pub ca_pem: String,
}

/// Makes the TCP socket for a connection to a server: `IPv6` when `true`.
/// It must be marked so the redirect lets it through.
pub type Connector = dyn Fn(bool) -> io::Result<OwnedFd> + Send + Sync;

/// What every connection shares.
struct Shared {
    ca: CertifiedIssuer<'static, KeyPair>,
    /// Server configuration per host name, with a certificate for that name.
    hosts: Mutex<HashMap<String, Arc<ServerConfig>>>,
    upstream: Arc<ClientConfig>,
    connector: Arc<Connector>,
    stop: Arc<AtomicBool>,
    emit: Box<dyn Fn(Exchange) + Send + Sync>,
    ids: AtomicU64,
    owners: Mutex<Owners>,
    /// Programs (or, when the program is unknown, host names) whose TLS
    /// handshake with the proxy failed: their connections pass through
    /// undecrypted, so a client that does not trust the CA keeps working.
    untrusting: Mutex<HashSet<String>>,
}

impl Mitm {
    /// Listens on `PORT` of `127.0.0.1` and `::1`, where the redirect delivers,
    /// and writes the CA certificate next to the recordings. `emit` runs on
    /// a connection thread for each exchange.
    pub fn start(
        connector: Arc<Connector>,
        emit: impl Fn(Exchange) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let mut listeners = vec![TcpListener::bind((Ipv4Addr::LOCALHOST, PORT))?];
        // A machine without IPv6 has no ::1, and no IPv6 traffic to redirect.
        listeners.extend(TcpListener::bind((Ipv6Addr::LOCALHOST, PORT)).ok());
        for l in &listeners {
            l.set_nonblocking(true)?;
        }
        let ca = new_ca().map_err(io::Error::other)?;
        let ca_path = crate::export::cache_dir()?.join("mitm-ca.pem");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&ca_path)?;
        file.write_all(ca.pem().as_bytes())?;
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut upstream = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Each connection sets the ALPN list its client offered.
        upstream.alpn_protocols = Vec::new();
        let stop = Arc::new(AtomicBool::new(false));
        let ca_pem = ca.pem();
        let shared = Arc::new(Shared {
            ca,
            hosts: Mutex::default(),
            upstream: Arc::new(upstream),
            connector,
            stop: Arc::clone(&stop),
            emit: Box::new(emit),
            ids: AtomicU64::new(0),
            owners: Mutex::default(),
            untrusting: Mutex::default(),
        });
        std::thread::spawn(move || accept_loop(&listeners, &shared));
        Ok(Self {
            stop,
            ca_path,
            ca_pem,
        })
    }
}

impl Drop for Mitm {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = fs::remove_file(&self.ca_path);
    }
}

fn accept_loop(listeners: &[TcpListener], shared: &Arc<Shared>) {
    let mut conn = 0;
    while !shared.stop.load(Ordering::Relaxed) {
        let mut idle = true;
        for listener in listeners {
            match listener.accept() {
                Ok((stream, peer)) => {
                    idle = false;
                    conn += 1;
                    let shared = Arc::clone(shared);
                    std::thread::spawn(move || {
                        if let Err(e) = serve(stream, peer, conn, &shared) {
                            let _ = writeln!(io::stderr(), "mitm connection {conn}: {e}");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    let _ = writeln!(io::stderr(), "mitm accept: {e}");
                }
            }
        }
        if idle {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A byte stream with the TCP socket under it, for timeouts and addresses.
trait Sock: Read + Write {
    fn tcp(&self) -> &TcpStream;
}

impl Sock for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
}

impl Sock for StreamOwned<ServerConnection, TcpStream> {
    fn tcp(&self) -> &TcpStream {
        &self.sock
    }
}

impl Sock for StreamOwned<ClientConnection, TcpStream> {
    fn tcp(&self) -> &TcpStream {
        &self.sock
    }
}

/// Where requests on one connection go.
struct Target {
    scheme: &'static str,
    /// `host:port` as the client named it.
    authority: String,
}

fn serve(stream: TcpStream, peer: SocketAddr, conn: u64, shared: &Shared) -> io::Result<()> {
    // The client's socket exists by now: it was accepted.
    let since = Instant::now();
    stream.set_nonblocking(false)?;
    let dst = original_dst(&stream)?;
    let app = shared
        .owners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .tcp_owner(peer.ip(), peer.port(), since);
    let base = Exchange {
        conn,
        app,
        client: peer.to_string(),
        ..Exchange::default()
    };
    stream.set_read_timeout(Some(CLIENT_FIRST))?;
    let mut first = [0u8; SNIFF];
    let n = match stream.peek(&mut first) {
        Ok(0) => return Ok(()),
        Ok(n) => n,
        Err(e) if is_timeout(&e) => 0,
        Err(e) => return Err(e),
    };
    stream.set_read_timeout(Some(IDLE))?;
    let first = &first[..n];
    if first.first() == Some(&TLS_HANDSHAKE) {
        serve_tls(stream, dst, base, shared)
    } else if is_http_request(first) {
        let mut client = BufReader::new(stream);
        let Some(head) = read_head(&mut client)? else {
            return Ok(());
        };
        let req = parse_request(&head)?;
        let target = Target {
            scheme: "http",
            authority: header(&req.headers, "host").map_or_else(
                || authority(&dst.ip().to_string(), dst.port(), 80),
                str::to_owned,
            ),
        };
        let server = connect(dst, shared).map(BufReader::new);
        exchanges(client, server, Some(head), &target, base, shared)
    } else {
        // Any other protocol, or one where the server speaks first.
        let ex = Exchange {
            method: "TCP".to_owned(),
            url: format!("tcp://{}", authority(&dst.ip().to_string(), dst.port(), 0)),
            ..base
        };
        pass_through(&stream, dst, &[], ex, true, shared)
    }
}

/// Reads the `ClientHello`, then decrypts with a certificate for its server
/// name, or passes the connection through untouched when the hello cannot
/// be read or the program already rejected the CA.
fn serve_tls(
    mut stream: TcpStream,
    dst: SocketAddr,
    base: Exchange,
    shared: &Shared,
) -> io::Result<()> {
    let mut tee = Tee {
        inner: &mut stream,
        seen: Vec::new(),
    };
    let mut acceptor = Acceptor::default();
    let accepted = loop {
        if acceptor.read_tls(&mut tee)? == 0 {
            return Ok(());
        }
        match acceptor.accept() {
            Ok(Some(a)) => break Ok(a),
            Ok(None) => {}
            Err((e, _)) => break Err(e),
        }
    };
    let seen = tee.seen;
    let mut ex = Exchange {
        method: "TLS".to_owned(),
        url: format!("tls://{}", authority(&dst.ip().to_string(), dst.port(), 0)),
        ..base
    };
    let accepted = match accepted {
        Ok(a) => a,
        Err(e) => {
            // TLS versions or extensions rustls does not take: relay as is.
            ex.note = Some(format!("not decrypted: unreadable TLS hello ({e})"));
            return pass_through(&stream, dst, &seen, ex, false, shared);
        }
    };
    let hello = accepted.client_hello();
    let host = hello
        .server_name()
        .map_or_else(|| dst.ip().to_string(), str::to_owned);
    let offered: Vec<Vec<u8>> = hello
        .alpn()
        .map_or_else(Vec::new, |list| list.map(<[u8]>::to_vec).collect());
    ex.url = format!("tls://{}", authority(&host, dst.port(), 0));
    // The program, or the host when the program is unknown (another user's).
    let key = ex.app.clone().unwrap_or_else(|| host.clone());
    let rejected = shared
        .untrusting
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&key);
    if rejected {
        ex.note = Some(format!(
            "not decrypted: {key} rejected the interception certificate earlier"
        ));
        return pass_through(&stream, dst, &seen, ex, false, shared);
    }

    // HTTP/1.1 alone when the client takes it, since its messages are the
    // ones parsed; otherwise the client's own list, so h2-only or other
    // protocols still connect and are relayed decrypted.
    let wants_http1 = offered.iter().any(|p| p == HTTP1);
    let alpn = if wants_http1 {
        vec![HTTP1.to_vec()]
    } else {
        offered
    };
    let server = connect_tls(dst, &host, alpn, shared);
    let chosen = server.as_ref().map_or_else(
        // The client then gets a 502 over HTTP/1.1, or a closed connection.
        |_| wants_http1.then(|| HTTP1.to_vec()),
        |s| s.get_ref().conn.alpn_protocol().map(<[u8]>::to_vec),
    );
    let mut config = (*shared.host_config(&host)?).clone();
    config.alpn_protocols = chosen.iter().cloned().collect();
    let conn = match accepted.into_connection(Arc::new(config)) {
        Ok(c) => c,
        Err((e, _)) => {
            // Nothing went to the client yet: let the real server answer
            // a hello rustls will not (old versions or ciphers).
            drop(server);
            ex.note = Some(format!("not decrypted: {e}"));
            return pass_through(&stream, dst, &seen, ex, false, shared);
        }
    };
    let mut tls = StreamOwned::new(conn, stream);
    // Finish the handshake here: this is where a client that does not
    // trust the CA fails. Its next connections pass through.
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            shared
                .untrusting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key.clone());
            ex.error = Some(format!(
                "{key} does not trust the interception certificate ({e}); \
                 its next connections pass through undecrypted"
            ));
            shared.emit_new(ex);
            return Ok(());
        }
    }
    let decrypted = Decrypted {
        dst,
        host: &host,
        chosen,
    };
    relay_decrypted(tls, server, &decrypted, ex, shared)
}

/// A TLS connection whose handshake with the client is done.
struct Decrypted<'a> {
    dst: SocketAddr,
    /// The server name the client asked for.
    host: &'a str,
    /// The protocol agreed with the client through ALPN.
    chosen: Option<Vec<u8>>,
}

/// Relays a decrypted connection: as HTTP exchanges when it carries
/// HTTP/1.1, else as one record of the bytes each way.
fn relay_decrypted(
    tls: StreamOwned<ServerConnection, TcpStream>,
    server: io::Result<BufReader<StreamOwned<ClientConnection, TcpStream>>>,
    conn: &Decrypted<'_>,
    mut ex: Exchange,
    shared: &Shared,
) -> io::Result<()> {
    let Decrypted { dst, host, chosen } = conn;
    let http = chosen.as_deref() == Some(HTTP1) || (chosen.is_none() && is_web_port(dst.port()));
    if http {
        let target = Target {
            scheme: "https",
            authority: authority(host, dst.port(), 443),
        };
        return exchanges(
            BufReader::new(tls),
            server,
            None,
            &target,
            ex_base(ex),
            shared,
        );
    }
    let mut server = match server {
        Ok(s) => s,
        Err(e) => {
            ex.error = Some(format!("cannot reach {host}: {e}"));
            shared.emit_new(ex);
            return Ok(());
        }
    };
    if let Some(p) = chosen {
        ex.note = Some(format!("decrypted, {}", String::from_utf8_lossy(p)));
    }
    let mut client = BufReader::new(tls);
    ex.local = server
        .get_ref()
        .tcp()
        .local_addr()
        .ok()
        .map(|a| a.to_string());
    ex.remote = server
        .get_ref()
        .tcp()
        .peer_addr()
        .ok()
        .map(|a| a.to_string());
    let started = Instant::now();
    let id = shared.emit_new(Exchange {
        open: true,
        ..ex.clone()
    });
    let mut bodies = (
        std::mem::take(&mut ex.req_body),
        std::mem::take(&mut ex.resp_body),
    );
    let result = tunnel(&mut client, &mut server, &mut bodies, true);
    (ex.req_body, ex.resp_body) = bodies;
    shared.emit_end(id, ex, started);
    result
}

/// Answers the client's first request with a 502 that says why the server
/// cannot be reached, and records it. `first` is a request head already read.
fn unreachable_server<C: Sock>(
    client: &mut BufReader<C>,
    first: Option<Vec<u8>>,
    target: &Target,
    mut ex: Exchange,
    why: &io::Error,
    shared: &Shared,
) -> io::Result<()> {
    let head = match first {
        Some(h) => Some(h),
        None => read_head(client)?,
    };
    if let Some(req) = head.as_deref().map(parse_request).transpose()? {
        ex.method = req.method;
        ex.url = url(target, &req.target);
        ex.req_headers = req.headers;
    }
    let text = format!("cannot reach {}: {why}", target.authority);
    ex.error = Some(text.clone());
    ex.id = shared.ids.fetch_add(1, Ordering::Relaxed) + 1;
    ex.at_ms = now_ms();
    (shared.emit)(ex);
    client.get_mut().write_all(bad_gateway(&text).as_bytes())
}

/// Reads the server's response head, passing interim 1xx responses on to
/// the client. `None`, with `ex.error` set, when no response came.
fn read_response<C: Sock, S: Sock>(
    server: &mut BufReader<S>,
    client: &mut BufReader<C>,
    ex: &mut Exchange,
) -> io::Result<Option<Response>> {
    loop {
        let head = match read_head(server) {
            Ok(Some(h)) => h,
            Ok(None) => {
                ex.error = Some("the server closed the connection".to_owned());
                return Ok(None);
            }
            Err(e) => {
                ex.error = Some(format!("no response from the server: {e}"));
                return Ok(None);
            }
        };
        client.get_mut().write_all(&head)?;
        let resp = parse_response(&head)?;
        if !(100..200).contains(&resp.status) || resp.status == 101 {
            return Ok(Some(resp));
        }
    }
}

/// The fields of a TLS connection's record that its HTTP exchanges share.
fn ex_base(ex: Exchange) -> Exchange {
    Exchange {
        conn: ex.conn,
        app: ex.app,
        client: ex.client,
        ..Exchange::default()
    }
}

/// Ports where a TLS client without ALPN speaks HTTP.
const fn is_web_port(port: u16) -> bool {
    matches!(port, 443 | 4443 | 8443)
}

fn is_http_request(first: &[u8]) -> bool {
    // A short read is an HTTP prefix when a method starts with it.
    first.len() >= 3
        && METHODS
            .iter()
            .any(|m| m.starts_with(first) || first.starts_with(m))
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reader that keeps a copy of what it reads, to replay it upstream.
struct Tee<'a> {
    inner: &'a mut TcpStream,
    seen: Vec<u8>,
}

impl Read for Tee<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

/// Connects to the server and relays bytes both ways unchanged, after
/// sending `seen` (client bytes already read). `keep` records the first
/// bytes of each direction; it is off for ciphertext.
fn pass_through(
    client: &TcpStream,
    dst: SocketAddr,
    seen: &[u8],
    mut ex: Exchange,
    keep: bool,
    shared: &Shared,
) -> io::Result<()> {
    let server = match connect(dst, shared).and_then(|s| (&s).write_all(seen).map(|()| s)) {
        Ok(s) => s,
        Err(e) => {
            ex.error = Some(format!("cannot reach {dst}: {e}"));
            shared.emit_new(ex);
            return Ok(());
        }
    };
    ex.local = server.local_addr().ok().map(|a| a.to_string());
    ex.remote = server.peer_addr().ok().map(|a| a.to_string());
    record(&mut ex.req_body, seen, keep);
    let started = Instant::now();
    let id = shared.emit_new(Exchange {
        open: true,
        ..ex.clone()
    });
    // Sessions such as SSH may stay idle for hours.
    client.set_read_timeout(None)?;
    server.set_read_timeout(None)?;
    let (c, s) = (client.try_clone()?, server.try_clone()?);
    let last = Arc::new(AtomicU64::new(now_ms()));
    let down_done = Arc::new(AtomicBool::new(false));
    let (last_up, down_done_up) = (Arc::clone(&last), Arc::clone(&down_done));
    let mut up = std::mem::take(&mut ex.req_body);
    let upward = std::thread::spawn(move || {
        copy(&c, &s, &mut up, keep, &last_up);
        // The client is done; a server that stays silent is closed after LINGER.
        linger(&last_up, || down_done_up.load(Ordering::Relaxed), &s);
        up
    });
    copy(&server, client, &mut ex.resp_body, keep, &last);
    down_done.store(true, Ordering::Relaxed);
    // The server is done; a client that stays silent is closed after LINGER.
    linger(&last, || upward.is_finished(), client);
    ex.req_body = upward.join().unwrap_or_default();
    shared.emit_end(id, ex, started);
    Ok(())
}

/// Waits until `finished`, or until nothing moved for `LINGER`, and then
/// closes `sock` so the copy still reading from it ends.
fn linger(last: &AtomicU64, finished: impl Fn() -> bool, sock: &TcpStream) {
    while !finished() {
        if now_ms().saturating_sub(last.load(Ordering::Relaxed)) > LINGER.as_millis() as u64 {
            let _ = sock.shutdown(std::net::Shutdown::Both);
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Copies `from` to `to` until `from` ends, then half-closes `to`. A
/// failure on either side closes both, so the other direction ends too.
/// `last` takes the time of each transfer.
fn copy(from: &TcpStream, to: &TcpStream, body: &mut Body, keep: bool, last: &AtomicU64) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match (&*from).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if (&*to).write_all(&buf[..n]).is_err() {
                    let _ = from.shutdown(std::net::Shutdown::Both);
                    break;
                }
                last.store(now_ms(), Ordering::Relaxed);
                record(body, &buf[..n], keep);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                let _ = to.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// Counts `data` into `body`, and keeps it up to `BODY_MAX` when `keep`.
fn record(body: &mut Body, data: &[u8], keep: bool) {
    body.size += data.len();
    if keep {
        let room = BODY_MAX.saturating_sub(body.data.len()).min(data.len());
        body.data.extend_from_slice(&data[..room]);
        body.truncated |= room < data.len();
    } else {
        body.truncated = body.size > 0;
    }
}

/// Where a redirected connection was going.
fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    let sock = SockRef::from(stream);
    let local = stream.local_addr()?;
    let dst = if local.is_ipv6() {
        sock.original_dst_v6()
    } else {
        sock.original_dst_v4()
    }?
    .as_socket()
    .ok_or_else(|| io::Error::other("no original destination"))?;
    // A direct connection to the proxy would make it connect to itself.
    if dst == local {
        return Err(io::Error::other("the connection was not redirected"));
    }
    Ok(dst)
}

impl Shared {
    /// Emits a new record and returns its id.
    fn emit_new(&self, mut ex: Exchange) -> u64 {
        ex.id = self.ids.fetch_add(1, Ordering::Relaxed) + 1;
        ex.at_ms = now_ms();
        let id = ex.id;
        (self.emit)(ex);
        id
    }

    /// Emits the final state of the record `id`, opened at `started`.
    fn emit_end(&self, id: u64, ex: Exchange, started: Instant) {
        (self.emit)(Exchange {
            id,
            at_ms: now_ms().saturating_sub(elapsed_ms(started)),
            ms: elapsed_ms(started),
            open: false,
            ..ex
        });
    }

    /// Server configuration with a certificate for `host`, made once per host.
    fn host_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let hosts = || self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        let cached = hosts().get(host).cloned();
        if let Some(c) = cached {
            return Ok(c);
        }
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(io::Error::other)?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        set_validity(&mut params);
        let cert = params
            .signed_by(&key, &*self.ca)
            .map_err(io::Error::other)?;
        let chain = vec![cert.der().clone(), CertificateDer::clone(self.ca.der())];
        let key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(io::Error::other)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Two connections may make one at the same time: the first one kept wins.
        let kept = Arc::clone(
            hosts()
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(config)),
        );
        Ok(kept)
    }
}

fn new_ca() -> Result<CertifiedIssuer<'static, KeyPair>, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "wireshark-rs interception CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    set_validity(&mut params);
    CertifiedIssuer::self_signed(params, KeyPair::generate()?)
}

fn set_validity(params: &mut CertificateParams) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let day = 86_400;
    let at = |secs| {
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
    };
    params.not_before = at(now - day);
    params.not_after = at(now + VALID_DAYS * day);
}

/// Connects to the server the client was going to, on a socket the
/// redirect lets through.
fn connect(dst: SocketAddr, shared: &Shared) -> io::Result<TcpStream> {
    let sock = Socket::from((shared.connector)(dst.is_ipv6())?);
    sock.connect_timeout(&SockAddr::from(dst), CONNECT_TIMEOUT)?;
    let s = TcpStream::from(sock);
    s.set_read_timeout(Some(IDLE))?;
    Ok(s)
}

/// TLS connection to the real server, with its certificate checked for
/// the name the client asked for, offering the `alpn` protocols.
fn connect_tls(
    dst: SocketAddr,
    host: &str,
    alpn: Vec<Vec<u8>>,
    shared: &Shared,
) -> io::Result<BufReader<StreamOwned<ClientConnection, TcpStream>>> {
    let tcp = connect(dst, shared)?;
    let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
    let mut config = (*shared.upstream).clone();
    config.alpn_protocols = alpn;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, tcp);
    // Handshake now, so a bad server certificate shows as this exchange's error.
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(BufReader::new(tls))
}

/// Relays requests and responses until either side closes, recording each.
/// `first` is a request head already read from the client.
fn exchanges<C: Sock, S: Sock>(
    mut client: BufReader<C>,
    server: io::Result<BufReader<S>>,
    mut first: Option<Vec<u8>>,
    target: &Target,
    base: Exchange,
    shared: &Shared,
) -> io::Result<()> {
    let mut server = match server {
        Ok(s) => s,
        Err(e) => return unreachable_server(&mut client, first, target, base, &e, shared),
    };
    let local = server
        .get_ref()
        .tcp()
        .local_addr()
        .ok()
        .map(|a| a.to_string());
    let remote = server
        .get_ref()
        .tcp()
        .peer_addr()
        .ok()
        .map(|a| a.to_string());
    let mut requests = 0;
    while !shared.stop.load(Ordering::Relaxed) {
        let head = match first
            .take()
            .map_or_else(|| read_head(&mut client), |h| Ok(Some(h)))
        {
            Ok(Some(h)) => h,
            Ok(None) => break,
            // The TLS handshake with the client runs on this first read.
            Err(e) if requests == 0 && target.scheme == "https" => {
                (shared.emit)(Exchange {
                    id: shared.ids.fetch_add(1, Ordering::Relaxed) + 1,
                    at_ms: now_ms(),
                    method: "TLS".to_owned(),
                    url: url(target, "/"),
                    error: Some(format!(
                        "the client did not accept the interception certificate: {e}"
                    )),
                    local,
                    remote,
                    ..base
                });
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        requests += 1;
        let started = Instant::now();
        let req = parse_request(&head)?;
        let mut ex = Exchange {
            id: shared.ids.fetch_add(1, Ordering::Relaxed) + 1,
            at_ms: now_ms(),
            method: req.method.clone(),
            url: url(target, &req.target),
            req_headers: req.headers.clone(),
            local: local.clone(),
            remote: remote.clone(),
            ..base.clone()
        };
        server.get_mut().write_all(&head)?;
        let req_framing = framing(&req.headers, true);
        ex.req_body = copy_body(&mut client, server.get_mut(), req_framing, &req.headers)?;
        server.get_mut().flush()?;

        let Some(resp) = read_response(&mut server, &mut client, &mut ex)? else {
            ex.ms = elapsed_ms(started);
            let text = ex.error.clone().unwrap_or_default();
            (shared.emit)(ex);
            // The client got no answer: tell it why rather than close silently.
            let _ = client.get_mut().write_all(bad_gateway(&text).as_bytes());
            break;
        };
        ex.status = Some(resp.status);
        ex.reason.clone_from(&resp.reason);
        ex.resp_headers.clone_from(&resp.headers);
        let no_body =
            req.method.eq_ignore_ascii_case("HEAD") || matches!(resp.status, 101 | 204 | 304);
        let resp_framing = if no_body {
            Framing::Length(0)
        } else {
            framing(&resp.headers, false)
        };
        ex.resp_body = copy_body(&mut server, client.get_mut(), resp_framing, &resp.headers)?;
        client.get_mut().flush()?;
        ex.ms = elapsed_ms(started);
        (shared.emit)(ex);
        if resp.status == 101 {
            // An upgraded protocol (WebSocket) is relayed without parsing.
            let mut bodies = (Body::default(), Body::default());
            return tunnel(&mut client, &mut server, &mut bodies, false);
        }
        let close = |h: &[(String, String)]| {
            header(h, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"))
        };
        if resp_framing == Framing::UntilClose || close(&req.headers) || close(&resp.headers) {
            break;
        }
    }
    Ok(())
}

/// A 502 response that closes the connection, with `text` as its body.
fn bad_gateway(text: &str) -> String {
    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )
}

/// Copies bytes both ways until either side closes, counting (and, when
/// `keep`, keeping the first bytes of) `a` to `b` in `bodies.0` and `b` to
/// `a` in `bodies.1`.
fn tunnel<C: Sock, S: Sock>(
    a: &mut BufReader<C>,
    b: &mut BufReader<S>,
    bodies: &mut (Body, Body),
    keep: bool,
) -> io::Result<()> {
    a.get_ref().tcp().set_read_timeout(Some(POLL))?;
    b.get_ref().tcp().set_read_timeout(Some(POLL))?;
    let mut idle = Duration::ZERO;
    while idle < IDLE {
        match (
            pump(a, b.get_mut(), &mut bodies.0, keep)?,
            pump(b, a.get_mut(), &mut bodies.1, keep)?,
        ) {
            (None, _) | (_, None) => break,
            (Some(0), Some(0)) => idle += POLL * 2,
            _ => idle = Duration::ZERO,
        }
    }
    Ok(())
}

/// Moves what `from` has to `to`: `Some(0)` when nothing came in time,
/// `None` when `from` closed.
fn pump(
    from: &mut BufReader<impl Read>,
    to: &mut impl Write,
    body: &mut Body,
    keep: bool,
) -> io::Result<Option<usize>> {
    let n = match from.fill_buf() {
        Ok([]) => return Ok(None),
        Ok(buf) => {
            to.write_all(buf)?;
            record(body, buf, keep);
            buf.len()
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(Some(0));
        }
        Err(e) => return Err(e),
    };
    from.consume(n);
    to.flush()?;
    Ok(Some(n))
}

/// How a message body ends.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Framing {
    Length(u64),
    Chunked,
    /// A response without a length ends when the server closes.
    UntilClose,
}

fn framing(headers: &[(String, String)], request: bool) -> Framing {
    let chunked = header(headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return Framing::Chunked;
    }
    match header(headers, "content-length").map(|v| v.trim().parse()) {
        Some(Ok(n)) => Framing::Length(n),
        // A request without a length has no body.
        _ if request => Framing::Length(0),
        _ => Framing::UntilClose,
    }
}

/// Copies one body from `from` to `to` as it is on the wire, and returns
/// the start of its content for display.
fn copy_body(
    from: &mut BufReader<impl Read>,
    to: &mut impl Write,
    framing: Framing,
    headers: &[(String, String)],
) -> io::Result<Body> {
    let mut body = Body::default();
    let keep = |data: &[u8], body: &mut Body| {
        body.size += data.len();
        let room = BODY_MAX.saturating_sub(body.data.len()).min(data.len());
        body.data.extend_from_slice(&data[..room]);
        body.truncated |= room < data.len();
    };
    match framing {
        Framing::Length(n) => {
            let mut rest = n;
            let mut buf = [0u8; 16 * 1024];
            while rest > 0 {
                let want = usize::try_from(rest).unwrap_or(usize::MAX).min(buf.len());
                let got = from.read(&mut buf[..want])?;
                if got == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                to.write_all(&buf[..got])?;
                keep(&buf[..got], &mut body);
                rest -= got as u64;
            }
        }
        Framing::UntilClose => {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let got = match from.read(&mut buf) {
                    // Servers often close TLS without close_notify here.
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                    other => other?,
                };
                if got == 0 {
                    break;
                }
                to.write_all(&buf[..got])?;
                keep(&buf[..got], &mut body);
            }
        }
        Framing::Chunked => loop {
            let mut line = Vec::new();
            read_line(from, &mut line)?;
            to.write_all(&line)?;
            let size = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split(';').next())
                .and_then(|n| u64::from_str_radix(n.trim(), 16).ok())
                .ok_or_else(|| io::Error::other("bad chunk size"))?;
            if size == 0 {
                // Trailer fields, up to an empty line.
                loop {
                    line.clear();
                    read_line(from, &mut line)?;
                    to.write_all(&line)?;
                    if line == b"\r\n" || line == b"\n" {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; usize::try_from(size).map_err(io::Error::other)?];
            from.read_exact(&mut chunk)?;
            to.write_all(&chunk)?;
            keep(&chunk, &mut body);
            line.clear();
            read_line(from, &mut line)?;
            to.write_all(&line)?;
        },
    }
    decode(&mut body, header(headers, "content-encoding"));
    Ok(body)
}

/// Decompresses gzip, deflate, br and zstd bodies for display.
fn decode(body: &mut Body, encoding: Option<&str>) {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use ruzstd::decoding::StreamingDecoder;
    let Some(enc) = encoding.map(|e| e.trim().to_ascii_lowercase()) else {
        return;
    };
    if body.truncated {
        body.note = Some(format!("{enc}, not decoded: body too long"));
        return;
    }
    let mut out = Vec::new();
    let limit = u64::try_from(BODY_MAX).unwrap_or(u64::MAX);
    let read = match enc.as_str() {
        "gzip" | "x-gzip" => GzDecoder::new(&body.data[..])
            .take(limit)
            .read_to_end(&mut out),
        "deflate" => ZlibDecoder::new(&body.data[..])
            .take(limit)
            .read_to_end(&mut out),
        "br" => brotli_decompressor::Decompressor::new(&body.data[..], 4096)
            .take(limit)
            .read_to_end(&mut out),
        "zstd" => StreamingDecoder::new(&body.data[..])
            .map_err(io::Error::other)
            .and_then(|d| d.take(limit).read_to_end(&mut out)),
        "identity" => return,
        _ => {
            body.note = Some(format!("{enc}, not decoded"));
            return;
        }
    };
    match read {
        Ok(_) => {
            body.truncated = out.len() >= BODY_MAX;
            body.data = out;
            body.note = Some(format!("{enc}, decoded"));
        }
        Err(e) => body.note = Some(format!("{enc}, cannot decode: {e}")),
    }
}

/// Reads one line, ending with `\n`, of at most `HEAD_MAX` bytes.
fn read_line(from: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<()> {
    let n = from
        .by_ref()
        .take(HEAD_MAX as u64)
        .read_until(b'\n', line)?;
    if n == 0 || line.last() != Some(&b'\n') {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// Reads a message head up to and including the empty line. `None` when
/// the peer closed before sending anything.
fn read_head(from: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    loop {
        let start = head.len();
        let n = match from
            .by_ref()
            .take(HEAD_MAX as u64)
            .read_until(b'\n', &mut head)
        {
            // A TLS peer that closes without close_notify, between messages.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && head.is_empty() => 0,
            other => other?,
        };
        if n == 0 {
            return if head.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        let line = &head[start..];
        if line == b"\r\n" || line == b"\n" {
            if start == 0 {
                // Empty lines before a request are allowed and skipped.
                head.clear();
                continue;
            }
            return Ok(Some(head));
        }
        if head.len() > HEAD_MAX {
            return Err(io::Error::other("message head too long"));
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

struct Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

fn parse_request(head: &[u8]) -> io::Result<Request> {
    let mut fields = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut fields);
    req.parse(head).map_err(io::Error::other)?;
    Ok(Request {
        method: req.method.unwrap_or_default().to_owned(),
        target: req.path.unwrap_or_default().to_owned(),
        headers: pairs(req.headers),
    })
}

fn parse_response(head: &[u8]) -> io::Result<Response> {
    let mut fields = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut fields);
    resp.parse(head).map_err(io::Error::other)?;
    Ok(Response {
        status: resp.code.unwrap_or_default(),
        reason: resp.reason.unwrap_or_default().to_owned(),
        headers: pairs(resp.headers),
    })
}

fn pairs(fields: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn url(target: &Target, path: &str) -> String {
    if path.starts_with('/') {
        let default = if target.scheme == "https" {
            ":443"
        } else {
            ":80"
        };
        let authority = target
            .authority
            .strip_suffix(default)
            .unwrap_or(&target.authority);
        format!("{}://{authority}{path}", target.scheme)
    } else {
        path.to_owned()
    }
}

/// `host` or `host:port` as a URL names it: `IPv6` in brackets, the port
/// only when it is not the scheme's default.
fn authority(host: &str, port: u16, default: u16) -> String {
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_owned(),
    };
    if port == default {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body `copy_body` records and the bytes it forwards. A failure
    /// shows as the body's note.
    fn body(wire: &[u8], framing: Framing, headers: &[(String, String)]) -> (Body, Vec<u8>) {
        let mut out = Vec::new();
        let b =
            copy_body(&mut BufReader::new(wire), &mut out, framing, headers).unwrap_or_else(|e| {
                Body {
                    note: Some(format!("copy failed: {e}")),
                    ..Body::default()
                }
            });
        (b, out)
    }

    #[test]
    fn chunked_body_is_forwarded_raw_and_shown_decoded() {
        let wire = b"4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nT: 1\r\n\r\nNEXT";
        let (b, out) = body(wire, Framing::Chunked, &[]);
        assert_eq!(out, &wire[..wire.len() - 4]);
        assert_eq!((b.data.as_slice(), b.size), (&b"Wikipedia"[..], 9));
    }

    #[test]
    fn brotli_and_zstd_bodies_are_decoded() {
        // `printf hello | brotli` and `printf hello | zstd`.
        let br = [0x0b, 0x02, 0x80, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x03];
        let zst = [
            0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            0xa3, 0x6d, 0x9f, 0x88,
        ];
        for (enc, wire) in [("br", &br[..]), ("zstd", &zst[..])] {
            let headers = [("Content-Encoding".to_owned(), enc.to_owned())];
            let (b, _) = body(wire, Framing::Length(wire.len() as u64), &headers);
            assert_eq!(b.data, b"hello", "{enc}: {:?}", b.note);
        }
    }

    #[test]
    fn gzip_body_is_decoded() {
        use flate2::{Compression, write::GzEncoder};
        let mut z = GzEncoder::new(Vec::new(), Compression::default());
        // A failed encoding leaves `gz` empty, which fails the check below.
        let gz = z
            .write_all(b"hello")
            .and_then(|()| z.finish())
            .unwrap_or_default();
        let headers = [("Content-Encoding".to_owned(), "gzip".to_owned())];
        let (b, out) = body(&gz, Framing::Length(gz.len() as u64), &headers);
        assert_eq!((out, b.data.as_slice()), (gz, &b"hello"[..]));
    }

    /// Loads the helper's rules the way the helper does: the owner-flagged
    /// table lives as long as the returned `nft -i`.
    fn hold_rules() -> io::Result<std::process::Child> {
        let child = std::process::Command::new("nft")
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()?;
        let Some(mut input) = child.stdin.as_ref() else {
            return Err(io::Error::other("nft input is not piped"));
        };
        input.write_all(crate::helper_proto::rules().as_bytes())?;
        std::thread::sleep(Duration::from_millis(500));
        Ok(child)
    }

    /// Ends `nft -i` and returns the tables left after it.
    fn drop_rules(mut child: std::process::Child) -> io::Result<String> {
        drop(child.stdin.take());
        child.wait()?;
        let out = std::process::Command::new("nft")
            .args(["list", "tables"])
            .output()?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// What the live run saw.
    #[derive(Debug)]
    struct Live {
        /// curl with the CA, through the proxy.
        trusting: std::process::Output,
        /// Two curls without the CA, one after the other.
        untrusting: [std::process::Output; 2],
        /// The first bytes the SSH server sent through the redirect.
        banner: Result<[u8; 4], String>,
        /// nft tables after the rules' owner ended.
        tables: String,
        /// What the proxy recorded.
        seen: Vec<Exchange>,
        /// Whether the CA file outlived the proxy.
        ca_kept: bool,
    }

    /// Runs the proxy and the redirect against `url` and `ssh`.
    fn run_live(url: &str, ssh: &str) -> io::Result<Live> {
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let connector: Arc<Connector> = Arc::new(|v6| {
            let domain = if v6 {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            };
            let s = Socket::new(domain, socket2::Type::STREAM, None)?;
            s.set_mark(crate::helper_proto::MARK)?;
            Ok(s.into())
        });
        let mitm = Mitm::start(connector, move |ex| {
            if let Ok(tx) = tx.lock() {
                let _ = tx.send(ex);
            }
        })?;
        let rules = hold_rules()?;
        let trusting = std::process::Command::new("curl")
            .args(["-sS", "--compressed", "--cacert"])
            .arg(&mitm.ca_path)
            .arg(url)
            .output()?;
        let untrusting = || {
            std::process::Command::new("curl")
                .args(["-sS", "-o", "/dev/null", "-w", "%{http_code}"])
                .arg(url)
                .output()
        };
        let untrusting = [untrusting()?, untrusting()?];
        let mut banner = [0u8; 4];
        let banner = std::net::TcpStream::connect(ssh)
            .and_then(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                s.read_exact(&mut banner)
            })
            .map(|()| banner)
            .map_err(|e| e.to_string());
        let tables = drop_rules(rules)?;
        let mut seen = Vec::new();
        while let Ok(ex) = rx.recv_timeout(Duration::from_secs(5)) {
            seen.push(ex);
        }
        let ca = mitm.ca_path.clone();
        drop(mitm);
        Ok(Live {
            trusting,
            untrusting,
            banner,
            tables,
            seen,
            ca_kept: ca.exists(),
        })
    }

    /// Installs the helper's redirect rules, runs a plain curl (no proxy
    /// option) to `MITM_URL` (default `https://example.com/`) and prints
    /// what the proxy recorded. Then checks a protocol where the server
    /// speaks first (SSH to `MITM_SSH`, default github.com:22) still works.
    /// Needs root in a network namespace, e.g.
    /// `pasta --config-net -- cargo test ... live_proxy -- --ignored`.
    #[test]
    #[ignore = "network and a root network namespace"]
    fn live_proxy() {
        let url = std::env::var("MITM_URL").unwrap_or_else(|_| "https://example.com/".into());
        let ssh = std::env::var("MITM_SSH").unwrap_or_else(|_| "github.com:22".into());
        let live = run_live(&url, &ssh);
        assert!(live.is_ok(), "{live:?}");
        let Ok(live) = live else { return };
        let mut log = io::stderr();
        for ex in &live.seen {
            let _ = writeln!(
                log,
                "{} {} -> {:?} open={} app={:?} note={:?} error={:?} body {} B",
                ex.method, ex.url, ex.status, ex.open, ex.app, ex.note, ex.error, ex.resp_body.size
            );
        }
        let stderr = |out: &std::process::Output| String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            live.trusting.status.success(),
            "curl: {}",
            stderr(&live.trusting)
        );
        // The namespace's trust store lacks the CA, as Firefox's does: the
        // first try fails, later ones pass through undecrypted.
        let [first, second] = &live.untrusting;
        assert!(
            !first.status.success(),
            "a client without the CA fails once"
        );
        assert_eq!(
            (second.status.success(), &second.stdout[..]),
            (true, &b"200"[..]),
            "then passes through: {}",
            stderr(second)
        );
        assert_eq!(
            live.banner,
            Ok(*b"SSH-"),
            "the server greeting passes through"
        );
        assert!(
            live.seen
                .iter()
                .any(|e| e.method == "TCP" && !e.open && e.resp_body.data.starts_with(b"SSH-")),
            "the SSH connection is recorded"
        );
        let http = live.seen.iter().find(|e| e.status.is_some());
        assert_eq!(
            http.map(|e| (e.status, &e.resp_body.data)),
            Some((Some(200), &live.trusting.stdout)),
            "the proxy shows what curl got"
        );
        assert!(
            !live.tables.contains("wireshark_rs"),
            "the table goes with its owner"
        );
        assert!(!live.ca_kept, "the CA file is deleted when the proxy stops");
    }

    #[test]
    fn heads_targets_and_framing() {
        let mut r = BufReader::new(&b"\r\nGET /x?y HTTP/1.1\r\nHost: a.test\r\n\r\nrest"[..]);
        let head = read_head(&mut r).ok().flatten();
        assert_eq!(
            head.as_deref(),
            Some(&b"GET /x?y HTTP/1.1\r\nHost: a.test\r\n\r\n"[..])
        );
        let req = head.as_deref().and_then(|h| parse_request(h).ok());
        assert_eq!(
            req.as_ref().map(|r| (r.method.as_str(), r.target.as_str())),
            Some(("GET", "/x?y"))
        );
        assert_eq!(
            req.as_ref().and_then(|r| header(&r.headers, "HOST")),
            Some("a.test")
        );
        assert_eq!(
            req.as_ref().map(|r| framing(&r.headers, true)),
            Some(Framing::Length(0))
        );
        assert_eq!(framing(&[], false), Framing::UntilClose);
        assert_eq!(authority("example.com", 443, 443), "example.com");
        assert_eq!(authority("2001:db8::1", 8443, 443), "[2001:db8::1]:8443");
        assert!(matches!(read_head(&mut BufReader::new(&b""[..])), Ok(None)));
    }
}
