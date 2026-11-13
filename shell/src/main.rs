//! Unprivileged desktop shell: hosts the Leptos UI in a WebKitGTK webview and
//! runs the `wireshark-capture` helper (the only binary with CAP_NET_RAW).

mod parse;

use std::borrow::Cow;
use std::io::{self, BufReader, Read};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::unix::WindowExtUnix;
use tao::window::WindowBuilder;
use wry::http::{Response, header::CONTENT_TYPE};
use wry::{WebView, WebViewBuilder, WebViewBuilderExtUnix};

use parse::Row;

const HELPER: &str = "wireshark-capture";
const ORIGIN: &str = "app://localhost/";
/// How often captured rows are pushed to the UI.
const TICK: Duration = Duration::from_millis(100);
/// Upper bound of rows pushed per tick; the UI keeps the same number.
const MAX_ROWS: usize = 1000;

// Built by build.rs.
const INDEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dist/index.html"));
const JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dist/wireshark-ui.js"));
const WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dist/wireshark-ui_bg.wasm"));

enum Msg {
    Row(Row),
    /// The helper stopped. The text is its error output, empty on a clean stop.
    Done(String),
}

struct Capture {
    child: Child,
    rx: Receiver<Msg>,
}

fn main() -> wry::Result<()> {
    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("wireshark-rs")
        .build(&event_loop)
        .expect("create window");

    let ifaces = serde_json::to_string(&interfaces()?).expect("string list serializes");
    let webview = WebViewBuilder::new()
        .with_custom_protocol("app".into(), |_, req| asset(req.uri().path()))
        // Keep the webview on the bundled UI: no remote page ever gets the IPC channel.
        .with_navigation_handler(|url| url.starts_with(ORIGIN))
        .with_ipc_handler(move |req| {
            // Fails only when the event loop is gone, i.e. during exit.
            let _ = proxy.send_event(req.into_body());
        })
        .with_initialization_script(format!("window.IFACES = () => {ifaces};"))
        .with_url(ORIGIN)
        .build_gtk(window.default_vbox().expect("tao creates a default vbox"))?;

    let mut capture: Option<Capture> = None;
    event_loop.run(move |event, _, control_flow| {
        let _ = &window; // The window must live as long as the loop.
        match event {
            Event::NewEvents(StartCause::Init) => *control_flow = ControlFlow::Wait,
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                drain(&webview, &mut capture);
                *control_flow = next_wake(capture.is_some());
            }
            Event::UserEvent(msg) => {
                handle_ipc(&webview, &msg, &mut capture);
                *control_flow = next_wake(capture.is_some());
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                stop(&mut capture);
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    })
}

fn next_wake(capturing: bool) -> ControlFlow {
    if capturing {
        ControlFlow::WaitUntil(Instant::now() + TICK)
    } else {
        ControlFlow::Wait
    }
}

/// IPC messages from the UI: `start <interface>` or `stop`.
fn handle_ipc(webview: &WebView, msg: &str, capture: &mut Option<Capture>) {
    stop(capture);
    let status = match msg.split_once(' ') {
        Some(("start", iface)) if interfaces().is_ok_and(|all| all.iter().any(|i| i == iface)) => {
            match start(iface) {
                Ok(c) => {
                    *capture = Some(c);
                    format!("capturing on {iface}")
                }
                Err(e) => format!("cannot start {HELPER}: {e}"),
            }
        }
        _ if msg == "stop" => "stopped".to_owned(),
        _ => format!("unknown request: {msg}"),
    };
    emit(webview, "status", &status);
}

fn start(iface: &str) -> io::Result<Capture> {
    // Never search PATH: run only the helper installed next to this binary.
    let helper = std::env::current_exe()?.with_file_name(HELPER);
    let mut child = Command::new(helper)
        .arg(iface)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = pump(stdout, &tx);
        // The helper writes to stderr only just before it exits.
        let mut text = String::new();
        if let Err(e) = stderr.read_to_string(&mut text) {
            text = e.to_string();
        }
        if let Err(e) = result {
            text = format!("{} {e}", text.trim());
        }
        // Fails only when this capture was already replaced or stopped.
        let _ = tx.send(Msg::Done(text.trim().to_owned()));
    });
    Ok(Capture { child, rx })
}

/// Reads helper records until EOF. Returns early when nobody receives the rows anymore.
fn pump(stdout: ChildStdout, tx: &Sender<Msg>) -> io::Result<()> {
    let mut src = BufReader::new(stdout);
    let mut header = [0u8; 16];
    let mut data = vec![0u8; usize::from(u16::MAX)];
    let mut first_ts = None;
    for no in 1.. {
        match src.read_exact(&mut header) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            r => r?,
        }
        let [ts, wire_len, ethertype, cap_len] = [0..8, 8..12, 12..14, 14..16].map(|r| &header[r]);
        let ts = u64::from_le_bytes(ts.try_into().expect("8 bytes"));
        let wire_len = u32::from_le_bytes(wire_len.try_into().expect("4 bytes"));
        let ethertype = u16::from_be_bytes(ethertype.try_into().expect("2 bytes"));
        let cap_len = usize::from(u16::from_le_bytes(cap_len.try_into().expect("2 bytes")));
        src.read_exact(&mut data[..cap_len])?;

        let rel_us = ts.saturating_sub(*first_ts.get_or_insert(ts));
        let row = parse::row(no, rel_us, wire_len, ethertype, &data[..cap_len]);
        if tx.send(Msg::Row(row)).is_err() {
            break;
        }
    }
    Ok(())
}

fn drain(webview: &WebView, capture: &mut Option<Capture>) {
    let Some(c) = capture else { return };
    let mut rows = Vec::new();
    let mut done = None;
    for msg in c.rx.try_iter() {
        match msg {
            Msg::Row(row) => rows.push(row),
            Msg::Done(text) => done = Some(text),
        }
    }
    if !rows.is_empty() {
        let keep = rows.len().saturating_sub(MAX_ROWS);
        emit(webview, "pkts", &rows[keep..]);
    }
    if let Some(text) = done {
        stop(capture);
        let status = if text.is_empty() {
            "capture ended".to_owned()
        } else {
            text
        };
        emit(webview, "status", &status);
    }
}

fn stop(capture: &mut Option<Capture>) {
    if let Some(mut c) = capture.take() {
        // kill() fails only when the helper already exited; wait() then reaps it.
        let _ = c.child.kill();
        if let Err(e) = c.child.wait() {
            eprintln!("wait for {HELPER}: {e}");
        }
    }
}

/// Sends `payload` to the UI as a `CustomEvent` whose `detail` is a JSON string.
fn emit<T: serde::Serialize + ?Sized>(webview: &WebView, name: &str, payload: &T) {
    let json = serde_json::to_string(payload).expect("payload serializes");
    let literal = serde_json::to_string(&json).expect("string serializes");
    let script =
        format!("window.dispatchEvent(new CustomEvent({name:?}, {{ detail: {literal} }}));");
    if let Err(e) = webview.evaluate_script(&script) {
        eprintln!("evaluate_script: {e}");
    }
}

fn interfaces() -> io::Result<Vec<String>> {
    let mut names = std::fs::read_dir("/sys/class/net")?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn asset(path: &str) -> Response<Cow<'static, [u8]>> {
    let (body, mime): (&'static [u8], &str) = match path {
        "/" | "/index.html" => (INDEX, "text/html"),
        "/wireshark-ui.js" => (JS, "text/javascript"),
        "/wireshark-ui_bg.wasm" => (WASM, "application/wasm"),
        _ => (&[], ""),
    };
    let status = if mime.is_empty() { 404 } else { 200 };
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, mime)
        .body(Cow::Borrowed(body))
        .expect("static response is valid")
}
