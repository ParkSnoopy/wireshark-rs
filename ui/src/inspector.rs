//! Side panel for the clicked packet: its related traffic, the requests and
//! responses of its conversation, and its bytes. HTTPS content comes from
//! the proxy, when the client used it.

use std::fmt::Write as _;

use leptos::prelude::*;

use crate::model::{
    Body, Exchange, Inspection, Ptrs, Row, Turn, bytes, duration, hexdump, is_text, printable,
    ptr_of,
};

/// Bytes shown as a hex dump before the rest is left out.
const HEX_MAX: usize = 4096;
/// Related packets listed.
const RELATED_MAX: usize = 200;

#[derive(Clone, Copy, PartialEq)]
enum Part {
    Related,
    Messages,
    Payload,
}

/// Side panel with the selected packet's conversation, messages and payload.
pub fn inspector(
    rows: RwSignal<Vec<Row>>,
    selected: RwSignal<Option<usize>>,
    // Detail of the selected packet, once the shell sent it.
    inspection: RwSignal<Option<Inspection>>,
    // Requests decrypted by the HTTPS proxy.
    exchanges: RwSignal<Vec<Exchange>>,
    ptrs: RwSignal<Ptrs>,
    // Asks the shell for the detail of a packet number.
    request: Callback<u64>,
) -> impl IntoView {
    let part = RwSignal::new(Part::Messages);
    let chosen = Memo::new(move |_| {
        let idx = selected.get()?;
        rows.with(|r| r.get(idx).cloned())
    });
    // Select another packet by number, e.g. from the related list.
    let jump = Callback::new(move |no: u64| {
        if let Ok(idx) = rows.with_untracked(|r| r.binary_search_by_key(&no, |r| r.no)) {
            selected.set(Some(idx));
        }
    });

    move || {
        let current = chosen.get()?;
        let (src, dst) = current.labels();
        let title = format!("{} #{}", current.protocol().to_uppercase(), current.no);
        let tab = move |p: Part, label: &'static str| {
            view! {
                <button
                    type="button"
                    role="tab"
                    aria-selected=move || (part.get() == p).to_string()
                    on:click=move |_| part.set(p)
                >
                    {label}
                </button>
            }
        };
        let no = current.no;
        let body = move || {
            let current = chosen.get()?;
            Some(match part.get() {
                Part::Related => related(&current, rows, ptrs, jump).into_any(),
                Part::Messages => {
                    let proxied: Vec<Exchange> = exchanges
                        .with(|e| e.iter().filter(|e| current.carries(e)).cloned().collect());
                    let detail =
                        inspection.with(|i| i.as_ref().filter(|i| i.no == current.no).cloned());
                    messages(&current, detail, &proxied, jump).into_any()
                }
                Part::Payload => {
                    let detail =
                        inspection.with(|i| i.as_ref().filter(|i| i.no == current.no).cloned());
                    payload(detail).into_any()
                }
            })
        };
        Some(view! {
            <aside class="inspector-panel" aria-label="Packet inspector">
                <header class="inspector-head">
                    <div>
                        <h3>{title}</h3>
                        <p class="inspector-route">{format!("{src} → {dst}")}</p>
                    </div>
                    <div class="inspector-actions">
                        <button
                            type="button"
                            class="btn btn-secondary btn-sm"
                            title="Read the conversation again from the capture"
                            on:click=move |_| request.run(no)
                        >
                            "Refresh"
                        </button>
                        <button
                            type="button"
                            class="btn btn-ghost btn-sm"
                            aria-label="Close the inspector"
                            on:click=move |_| selected.set(None)
                        >
                            "✕"
                        </button>
                    </div>
                </header>
                <div class="segmented inspector-tabs" role="tablist">
                    {tab(Part::Messages, "Request / response")}
                    {tab(Part::Related, "Related")}
                    {tab(Part::Payload, "Payload")}
                </div>
                <div class="inspector-body">{body}</div>
            </aside>
        })
    }
}

/// Other flows between the two hosts of `current`, newest first, by protocol
/// and ports: `(flow, packets, bytes, newest packet number)`.
fn other_flows(rows: &[Row], current: &Row) -> Vec<(String, u64, u64, u64)> {
    let mut flows: Vec<(String, u64, u64, u64)> = Vec::new();
    let same_hosts = |r: &Row| {
        (r.src == current.src && r.dst == current.dst
            || r.src == current.dst && r.dst == current.src)
            && !r.same_conversation(current)
    };
    let port = |p: Option<u16>| p.map_or_else(|| "-".into(), |p| p.to_string());
    for r in rows.iter().rev().filter(|r| same_hosts(r)) {
        let key = format!(
            "{} {}:{} → {}:{}",
            r.protocol(),
            r.src,
            port(r.sport),
            r.dst,
            port(r.dport),
        );
        if let Some(f) = flows.iter_mut().find(|f| f.0 == key) {
            f.1 += 1;
            f.2 += u64::from(r.len);
        } else {
            flows.push((key, 1, u64::from(r.len), r.no));
        }
    }
    flows
}

/// Packets of the same conversation, and other flows between the two hosts.
fn related(
    current: &Row,
    rows: RwSignal<Vec<Row>>,
    ptrs: RwSignal<Ptrs>,
    jump: Callback<u64>,
) -> impl IntoView + use<> {
    let (conversation, flows) = rows.with(|rows| {
        let conversation: Vec<Row> = rows
            .iter()
            .filter(|r| r.same_conversation(current))
            .cloned()
            .collect();
        (conversation, other_flows(rows, current))
    });
    let t0 = conversation.first().map_or(0.0, Row::secs);
    let total: u64 = conversation.iter().map(|r| u64::from(r.len)).sum();
    let span = conversation.last().map_or(0.0, Row::secs) - t0;
    let shown = conversation.len().min(RELATED_MAX);
    let names = ptrs.with(|p| {
        [&current.src, &current.dst]
            .map(|a| ptr_of(p, a).map(|n| format!("{a} is {n}")))
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    });
    let current_no = current.no;
    let out = current.clone();
    view! {
        <section class="inspector-section">
            <h4>"Conversation"</h4>
            <p class="inspector-note">
                {format!("{} packets · {} · {}", conversation.len(), bytes(total), duration(span))}
                {(shown < conversation.len()).then(|| format!(" · newest {shown} listed"))}
            </p>
            {names.into_iter().map(|n| view! { <p class="inspector-note">{n}</p> }).collect_view()}
            <ul class="related-list">
                {conversation
                    .iter()
                    .rev()
                    .take(RELATED_MAX)
                    .map(|r| {
                        let no = r.no;
                        let arrow = if r.same_direction(&out) { "→" } else { "←" };
                        view! {
                            <li>
                                <button
                                    type="button"
                                    class="related-item"
                                    class:is-current=no == current_no
                                    on:click=move |_| jump.run(no)
                                >
                                    <span class="related-no">{format!("#{no}")}</span>
                                    <span class="related-time">{format!("+{}", duration(r.secs() - t0))}</span>
                                    <span>{arrow}</span>
                                    <span class="related-len">{format!("{} B", r.len)}</span>
                                    <span class="related-info">{r.info.clone()}</span>
                                </button>
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
        </section>
        <section class="inspector-section">
            <h4>"Other flows between these hosts"</h4>
            {flows.is_empty().then(|| view! { <p class="inspector-note">"None captured."</p> })}
            <ul class="related-list">
                {flows
                    .into_iter()
                    .map(|(key, count, size, newest)| {
                        view! {
                            <li>
                                <button
                                    type="button"
                                    class="related-item"
                                    title="Inspect the newest packet of this flow"
                                    on:click=move |_| jump.run(newest)
                                >
                                    <span class="related-info">{key}</span>
                                    <span class="related-len">{format!("{count} pkt · {}", bytes(size))}</span>
                                </button>
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
        </section>
    }
}

/// The conversation as requests and responses: decrypted by the proxy when
/// it carried this connection, else as captured.
fn messages(
    current: &Row,
    detail: Option<Inspection>,
    proxied: &[Exchange],
    jump: Callback<u64>,
) -> impl IntoView + use<> {
    let encrypted = matches!(current.protocol(), "https" | "tls" | "quic" | "ssh" | "dot");
    let proxy_view = (!proxied.is_empty()).then(|| {
        view! {
            <section class="inspector-section">
                <h4>"Through the interception proxy"</h4>
                {proxied.iter().map(|e| exchange_view(e, true)).collect_view()}
            </section>
        }
    });
    let captured = match detail {
        None => {
            view! { <p class="inspector-note">"Reading the conversation from the capture…"</p> }
                .into_any()
        }
        Some(d) if d.turns.is_empty() => {
            view! { <p class="inspector-note">"No payload in this conversation."</p> }.into_any()
        }
        Some(d) => {
            let omitted = d.omitted;
            view! {
                <section class="inspector-section">
                    <h4>"As captured"</h4>
                    {encrypted.then(|| view! {
                        <p class="inspector-note">
                            "This traffic is encrypted. Turn on the HTTPS proxy to read the content of new connections."
                        </p>
                    })}
                    {d.turns.iter().map(|t| turn(t, jump)).collect_view()}
                    {(omitted > 0).then(|| view! {
                        <p class="inspector-note">{format!("{} more not shown.", bytes(omitted as u64))}</p>
                    })}
                </section>
            }
            .into_any()
        }
    };
    view! { {proxy_view} {captured} }
}

fn turn(t: &Turn, jump: Callback<u64>) -> impl IntoView + use<> {
    let label = if t.client { "Request" } else { "Response" };
    let packets = if t.first == t.last {
        format!("#{}", t.first)
    } else {
        format!("#{}–#{}", t.first, t.last)
    };
    let mut facts = vec![bytes(t.len as u64)];
    if t.gaps > 0 {
        facts.push(format!("{} not captured", bytes(t.gaps as u64)));
    }
    if t.data.len() < t.len {
        facts.push(format!("first {} shown", bytes(t.data.len() as u64)));
    }
    let first = t.first;
    view! {
        <div class="message" class:is-response=!t.client>
            <p class="message-head">
                <span class="chip" class:chip-info=t.client>{label}</span>
                <button type="button" class="link" on:click=move |_| jump.run(first)>{packets}</button>
                <span class="inspector-note">{facts.join(" · ")}</span>
            </p>
            {data_view(&t.data)}
        </div>
    }
}

/// The bytes as a string, with the hex dump folded away below.
fn data_view(data: &[u8]) -> impl IntoView + use<> {
    let note = (!is_text(data)).then(|| {
        view! { <p class="inspector-note">"Mostly binary: unreadable bytes show as ·."</p> }
    });
    view! {
        {note}
        <pre class="payload-text">{printable(data)}</pre>
        {hex_details(data, 0)}
    }
}

/// Hex dump in a closed disclosure, so the string view comes first.
fn hex_details(data: &[u8], mark: usize) -> impl IntoView + use<> {
    view! {
        <details class="hex-details">
            <summary>"Hex"</summary>
            {hex_view(data, 0, mark)}
        </details>
    }
}

/// Hex dump of at most `HEX_MAX` bytes. Bytes before `mark` (a header)
/// are muted.
fn hex_view(data: &[u8], base: usize, mark: usize) -> impl IntoView + use<> {
    let shown = &data[..data.len().min(HEX_MAX)];
    let rest = data.len() - shown.len();
    view! {
        <pre class="hexdump">
            {hexdump(shown, base)
                .into_iter()
                .map(|(off, hex, ascii)| {
                    // Bytes on the line: two hex digits each, space separated.
                    let header = off + hex.len().div_ceil(3) <= mark;
                    view! {
                        <span class:is-header=header>{format!("{off:06x}  {hex:<47}  {ascii}\n")}</span>
                    }
                })
                .collect_view()}
        </pre>
        {(rest > 0).then(|| view! { <p class="inspector-note">{format!("{} more not shown.", bytes(rest as u64))}</p> })}
    }
}

/// The packet's bytes: headers, then the payload as text or hex.
fn payload(detail: Option<Inspection>) -> impl IntoView + use<> {
    let Some(d) = detail else {
        return view! { <p class="inspector-note">"Reading the packet from the capture…"</p> }
            .into_any();
    };
    let at = d.payload_at.unwrap_or(d.bytes.len()).min(d.bytes.len());
    let data = &d.bytes[at..];
    let cut = (d.bytes.len() < d.caplen)
        .then(|| format!(" · first {} kept", bytes(d.bytes.len() as u64)));
    view! {
        <section class="inspector-section">
            <h4>"Payload"</h4>
            <p class="inspector-note">
                {format!("{} of payload after {} of headers", bytes(data.len() as u64), bytes(at as u64))}
                {cut}
            </p>
            {data.is_empty().then(|| view! { <p class="inspector-note">"This packet carries no payload."</p> })}
            {(!data.is_empty()).then(|| view! {
                {(!is_text(data)).then(|| view! {
                    <p class="inspector-note">"Mostly binary: unreadable bytes show as ·."</p>
                })}
                <pre class="payload-text">{printable(data)}</pre>
            })}
        </section>
        <section class="inspector-section">
            <h4>"Packet bytes"</h4>
            <p class="inspector-note">"From the IP header on. Header lines are muted."</p>
            {hex_details(&d.bytes, at)}
        </section>
    }
    .into_any()
}

/// One decrypted request and its response; `open` shows it unfolded.
pub fn exchange_view(ex: &Exchange, open: bool) -> impl IntoView + use<> {
    // TLS and TCP rows are whole connections relayed as bytes.
    let relayed = ex.status.is_none() && matches!(ex.method.as_str(), "TLS" | "TCP");
    let status = match (&ex.error, ex.status) {
        (Some(_), _) => "failed".to_owned(),
        (None, Some(s)) => format!("{s} {}", ex.reason),
        (None, None) if ex.open => "open".to_owned(),
        (None, None) if relayed => "closed".to_owned(),
        (None, None) => "no response".to_owned(),
    };
    let tone = match ex.status {
        _ if ex.error.is_some() => "chip-error",
        Some(s) if s >= 400 => "chip-warning",
        Some(_) => "chip-success",
        None if ex.open => "chip-info",
        None if relayed => "",
        None => "chip-error",
    };
    let time = if ex.open {
        String::new()
    } else {
        format!("{} ms", ex.ms)
    };
    view! {
        <details class="exchange" open=open>
            <summary>
                <span class="exchange-method">{ex.method.clone()}</span>
                <span class="exchange-url">{ex.url.clone()}</span>
                <span class=format!("chip {tone}")>{status}</span>
                {ex.app.clone().map(|a| view! { <span class="chip">{a}</span> })}
                <span class="inspector-note">{time}</span>
            </summary>
            {ex.error.clone().map(|e| view! { <p class="tip-flag">{e}</p> })}
            {ex.note.clone().map(|n| view! { <p class="inspector-note">{n}</p> })}
            {message_part(
                if relayed { "Client → server" } else { "Request" },
                &ex.req_headers,
                &ex.req_body,
            )}
            {(ex.status.is_some() || relayed).then(|| message_part(
                if relayed { "Server → client" } else { "Response" },
                &ex.resp_headers,
                &ex.resp_body,
            ))}
        </details>
    }
}

fn message_part(
    label: &'static str,
    headers: &[(String, String)],
    body: &Body,
) -> impl IntoView + use<> {
    let mut facts = vec![format!("body {}", bytes(body.size as u64))];
    facts.extend(body.note.clone());
    // Ciphertext passed through is counted, not kept.
    if body.truncated && !body.data.is_empty() {
        facts.push(format!("first {} shown", bytes(body.data.len() as u64)));
    }
    let head = headers.iter().fold(String::new(), |mut head, (n, v)| {
        let _ = writeln!(head, "{n}: {v}");
        head
    });
    let data = body.data.clone();
    let request = matches!(label, "Request" | "Client → server");
    view! {
        <div class="message" class:is-response=!request>
            <p class="message-head">
                <span class="chip" class:chip-info=request>{label}</span>
                <span class="inspector-note">{facts.join(" · ")}</span>
            </p>
            {(!head.is_empty()).then(|| view! { <pre class="payload-text payload-headers">{head}</pre> })}
            {(!data.is_empty()).then(|| data_view(&data))}
        </div>
    }
}
