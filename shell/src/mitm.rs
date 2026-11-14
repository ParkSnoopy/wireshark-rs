//! HTTPS interception: a transparent proxy that decrypts the web traffic
//! the kernel redirects to it, with certificates signed by a CA made when
//! interception starts.
//!
//! Clients are not configured. The helper redirects this machine's TCP to
//! ports 80 and 443 to `PORT` and adds the CA to the system trust store;
//! the proxy reads where each connection was going (`SO_ORIGINAL_DST`) and
//! the host name from the TLS server name or the `Host` header. Its own
//! connections to the servers use sockets marked so the redirect skips
//! them. The CA key lives only in memory, so the certificate is worthless
//! once the proxy stops. The proxy checks each server's real certificate
//! against the Mozilla roots, so it never hides a forged server.

use std::collections::HashMap;
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

pub use crate::helper_proto::PROXY_PORT as PORT;

/// TLS record type of a handshake: the first byte a TLS client sends.
const TLS_HANDSHAKE: u8 = 0x16;
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

/// Makes the TCP socket for a connection to a server: IPv6 when `true`.
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
}

impl Mitm {
    /// Listens on `PORT` of 127.0.0.1 and ::1, where the redirect delivers,
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
        // HTTP/2 frames are not parsed: both sides speak HTTP/1.1.
        upstream.alpn_protocols = vec![b"http/1.1".to_vec()];
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
                            eprintln!("mitm connection {conn}: {e}");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("mitm accept: {e}"),
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

fn serve(mut stream: TcpStream, peer: SocketAddr, conn: u64, shared: &Shared) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IDLE))?;
    let dst = original_dst(&stream)?;
    let base = Exchange {
        conn,
        client: peer.to_string(),
        ..Exchange::default()
    };
    let mut first = [0u8; 1];
    if stream.peek(&mut first)? == 0 {
        return Ok(());
    }
    if first[0] == TLS_HANDSHAKE {
        // Read the ClientHello first: its server name picks the certificate.
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            if acceptor.read_tls(&mut stream)? == 0 {
                return Ok(());
            }
            match acceptor.accept() {
                Ok(Some(a)) => break a,
                Ok(None) => {}
                Err((e, mut alert)) => {
                    let _ = alert.write_all(&mut stream);
                    return Err(io::Error::other(e));
                }
            }
        };
        let host = accepted
            .client_hello()
            .server_name()
            .map_or_else(|| dst.ip().to_string(), str::to_owned);
        let config = shared.host_config(&host)?;
        let tls = match accepted.into_connection(config) {
            Ok(c) => StreamOwned::new(c, stream),
            Err((e, mut alert)) => {
                let _ = alert.write_all(&mut stream);
                return Err(io::Error::other(e));
            }
        };
        let server = connect_tls(dst, &host, shared);
        let target = Target {
            scheme: "https",
            authority: authority(&host, dst.port(), 443),
        };
        exchanges(BufReader::new(tls), server, None, &target, base, shared)
    } else {
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
    /// Server configuration with a certificate for `host`, made once per host.
    fn host_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = hosts.get(host) {
            return Ok(Arc::clone(c));
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
        let config = Arc::new(config);
        hosts.insert(host.to_owned(), Arc::clone(&config));
        Ok(config)
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
/// the name the client asked for.
fn connect_tls(
    dst: SocketAddr,
    host: &str,
    shared: &Shared,
) -> io::Result<BufReader<StreamOwned<ClientConnection, TcpStream>>> {
    let tcp = connect(dst, shared)?;
    let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
    let conn =
        ClientConnection::new(Arc::clone(&shared.upstream), name).map_err(io::Error::other)?;
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
        Err(e) => {
            // Answer the client's first request with the reason.
            let head = match first.take() {
                Some(h) => Some(h),
                None => read_head(&mut client)?,
            };
            let mut ex = base;
            if let Some(req) = head.as_deref().map(parse_request).transpose()? {
                ex.method = req.method;
                ex.url = url(target, &req.target);
                ex.req_headers = req.headers;
            }
            ex.error = Some(format!("cannot reach {}: {e}", target.authority));
            ex.id = shared.ids.fetch_add(1, Ordering::Relaxed) + 1;
            ex.at_ms = now_ms();
            let text = ex.error.clone().unwrap_or_default();
            (shared.emit)(ex);
            return client.get_mut().write_all(bad_gateway(&text).as_bytes());
        }
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
    let mut served = 0;
    while !shared.stop.load(Ordering::Relaxed) {
        let head = match first
            .take()
            .map_or_else(|| read_head(&mut client), |h| Ok(Some(h)))
        {
            Ok(Some(h)) => h,
            Ok(None) => break,
            // The TLS handshake with the client runs on this first read.
            Err(e) if served == 0 && target.scheme == "https" => {
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
        served += 1;
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

        // Interim 1xx responses go to the client as they come.
        let resp = loop {
            let head = match read_head(&mut server) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    ex.error = Some("the server closed the connection".to_owned());
                    break None;
                }
                Err(e) => {
                    ex.error = Some(format!("no response from the server: {e}"));
                    break None;
                }
            };
            client.get_mut().write_all(&head)?;
            let resp = parse_response(&head)?;
            if !(100..200).contains(&resp.status) || resp.status == 101 {
                break Some(resp);
            }
        };
        let Some(resp) = resp else {
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
            return tunnel(&mut client, &mut server);
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

/// Copies bytes both ways until either side closes.
fn tunnel<C: Sock, S: Sock>(a: &mut BufReader<C>, b: &mut BufReader<S>) -> io::Result<()> {
    a.get_ref().tcp().set_read_timeout(Some(POLL))?;
    b.get_ref().tcp().set_read_timeout(Some(POLL))?;
    let mut idle = Duration::ZERO;
    while idle < IDLE {
        match (pump(a, b.get_mut())?, pump(b, a.get_mut())?) {
            (None, _) | (_, None) => break,
            (Some(0), Some(0)) => idle += POLL * 2,
            _ => idle = Duration::ZERO,
        }
    }
    Ok(())
}

/// Moves what `from` has to `to`: `Some(0)` when nothing came in time,
/// `None` when `from` closed.
fn pump(from: &mut BufReader<impl Read>, to: &mut impl Write) -> io::Result<Option<usize>> {
    let n = match from.fill_buf() {
        Ok([]) => return Ok(None),
        Ok(buf) => {
            to.write_all(buf)?;
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

fn pairs(fields: &[httparse::Header]) -> Vec<(String, String)> {
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

/// `host` or `host:port` as a URL names it: IPv6 in brackets, the port
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

    fn body(wire: &[u8], framing: Framing, headers: &[(String, String)]) -> (Body, Vec<u8>) {
        let mut out = Vec::new();
        let b = copy_body(&mut BufReader::new(wire), &mut out, framing, headers).unwrap();
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
        z.write_all(b"hello").unwrap();
        let gz = z.finish().unwrap();
        let headers = [("Content-Encoding".to_owned(), "gzip".to_owned())];
        let (b, out) = body(&gz, Framing::Length(gz.len() as u64), &headers);
        assert_eq!((out, b.data.as_slice()), (gz, &b"hello"[..]));
    }

    /// Runs `nft` with `script` on stdin.
    fn nft(script: &str) {
        let mut child = std::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "nft failed");
    }

    /// Installs the helper's redirect rules, runs a plain curl (no proxy
    /// option) to `MITM_URL` (default `https://example.com/`) and prints
    /// what the proxy recorded. Needs root in a network namespace, e.g.
    /// `pasta --config-net -- cargo test ... live_proxy -- --ignored`.
    #[test]
    #[ignore = "network and a root network namespace"]
    fn live_proxy() {
        let url = std::env::var("MITM_URL").unwrap_or_else(|_| "https://example.com/".into());
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
        let mitm = Mitm::start(connector, move |ex| drop(tx.lock().unwrap().send(ex))).unwrap();
        nft(&crate::helper_proto::rules());
        let out = std::process::Command::new("curl")
            .args(["-sS", "--compressed", "--cacert"])
            .arg(&mitm.ca_path)
            .arg(&url)
            .output()
            .unwrap();
        nft(&crate::helper_proto::remove_rules());
        assert!(
            out.status.success(),
            "curl: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let ex = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        println!(
            "{} {} -> {:?} {} | body {} B ({:?}) | server {:?} via {:?}\n{}",
            ex.method,
            ex.url,
            ex.status,
            ex.reason,
            ex.resp_body.size,
            ex.resp_body.note,
            ex.remote,
            ex.local,
            String::from_utf8_lossy(&ex.resp_body.data)
                .chars()
                .take(200)
                .collect::<String>(),
        );
        assert_eq!(ex.status, Some(200));
        assert_eq!(
            ex.resp_body.data, out.stdout,
            "the proxy shows what curl got"
        );
        let ca = mitm.ca_path.clone();
        drop(mitm);
        assert!(!ca.exists(), "the CA file is deleted when the proxy stops");
    }

    #[test]
    fn heads_targets_and_framing() {
        let mut r = BufReader::new(&b"\r\nGET /x?y HTTP/1.1\r\nHost: a.test\r\n\r\nrest"[..]);
        let head = read_head(&mut r).unwrap().unwrap();
        assert_eq!(head, b"GET /x?y HTTP/1.1\r\nHost: a.test\r\n\r\n");
        let req = parse_request(&head).unwrap();
        assert_eq!((req.method.as_str(), req.target.as_str()), ("GET", "/x?y"));
        assert_eq!(header(&req.headers, "HOST"), Some("a.test"));
        assert_eq!(framing(&req.headers, true), Framing::Length(0));
        assert_eq!(framing(&[], false), Framing::UntilClose);
        assert_eq!(authority("example.com", 443, 443), "example.com");
        assert_eq!(authority("2001:db8::1", 8443, 443), "[2001:db8::1]:8443");
        assert!(read_head(&mut BufReader::new(&b""[..])).unwrap().is_none());
    }
}
