//! Leptos UI. Runs inside the shell's webview and talks to it only through
//! `window.ipc.postMessage` (out) and `pkts` / `status` window events (in).

use leptos::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

/// Rows kept in the table. The shell sends at most this many per batch.
const MAX_ROWS: usize = 1000;

#[derive(Clone, Deserialize)]
struct Row {
    no: u64,
    time: String,
    src: String,
    dst: String,
    proto: String,
    len: u32,
    info: String,
}

/// `state` is `idle`, `pending`, `capturing`, `stopped` or `error`.
/// style.css colors the status chip by it.
#[derive(Clone, Deserialize)]
struct Status {
    state: String,
    text: String,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "ipc"], js_name = postMessage)]
    fn post_message(msg: &str);

    /// Function defined by the shell's initialization script.
    #[wasm_bindgen(js_namespace = window, js_name = IFACES)]
    fn interfaces() -> Vec<String>;
}

fn main() {
    leptos::mount::mount_to_body(App);
}

/// Reads the JSON string the shell puts in `CustomEvent.detail`.
fn detail<T: DeserializeOwned>(ev: web_sys::Event) -> Option<T> {
    let text = ev
        .unchecked_into::<web_sys::CustomEvent>()
        .detail()
        .as_string()?;
    serde_json::from_str(&text).ok()
}

#[component]
fn App() -> impl IntoView {
    let ifaces = interfaces();
    let iface = RwSignal::new(ifaces.first().cloned().unwrap_or_default());
    let rows = RwSignal::new(Vec::<Row>::new());
    let status = RwSignal::new(Status {
        state: "idle".to_owned(),
        text: "ready".to_owned(),
    });
    let busy = move || status.with(|s| matches!(s.state.as_str(), "pending" | "capturing"));
    let seen = move || rows.with(|r| r.last().map_or(0, |r| r.no));

    // The handles live as long as the page, so they are never removed.
    window_event_listener_untyped("pkts", move |ev| {
        let Some(batch) = detail::<Vec<Row>>(ev) else {
            return;
        };
        rows.update(|r| {
            r.extend(batch);
            let extra = r.len().saturating_sub(MAX_ROWS);
            r.drain(..extra);
        });
    });
    window_event_listener_untyped("status", move |ev| {
        if let Some(s) = detail::<Status>(ev) {
            status.set(s);
        }
    });

    let start = move |_| {
        rows.set(Vec::new());
        post_message(&format!("start {}", iface.get()));
    };

    view! {
        <div class="app">
            <header class="toolbar">
                <div class="brand">
                    <h1>"wireshark-rs"</h1>
                    <p>"Live packet capture"</p>
                </div>
                <div class="controls">
                    <label class="field">
                        <span class="field-label">"Interface"</span>
                        <select
                            class="input"
                            disabled=busy
                            on:change=move |ev| iface.set(event_target_value(&ev))
                        >
                            {ifaces
                                .into_iter()
                                .map(|i| view! { <option>{i}</option> })
                                .collect_view()}
                        </select>
                    </label>
                    <button class="btn btn-primary" disabled=busy on:click=start>
                        "Start"
                    </button>
                    <button
                        class="btn btn-secondary"
                        disabled=move || !busy()
                        on:click=move |_| post_message("stop")
                    >
                        "Stop"
                    </button>
                </div>
                <div class="status-line">
                    <span
                        class="chip status"
                        role="status"
                        aria-live="polite"
                        data-state=move || status.with(|s| s.state.clone())
                    >
                        {move || status.with(|s| s.text.clone())}
                    </span>
                    <span class="count">{seen} " packets"</span>
                </div>
            </header>
            <main class="packets">
                <div class="table-scroll" tabindex="0" aria-label="Captured packets">
                    <table>
                        <thead>
                            <tr>
                                <th class="num">"No."</th>
                                <th>"Time"</th>
                                <th>"Source"</th>
                                <th>"Destination"</th>
                                <th>"Protocol"</th>
                                <th class="num">"Length"</th>
                                <th>"Info"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <Show when=move || rows.with(Vec::is_empty)>
                                <tr class="empty">
                                    <td colspan="7">
                                        "No packets yet. Choose an interface and press Start."
                                    </td>
                                </tr>
                            </Show>
                            <For
                                each=move || rows.get()
                                key=|r| r.no
                                children=|r: Row| {
                                    let proto = r.proto.clone();
                                    view! {
                                        <tr>
                                            <td class="num">{r.no}</td>
                                            <td>{r.time}</td>
                                            <td>{r.src}</td>
                                            <td>{r.dst}</td>
                                            <td>
                                                <span class="chip proto" data-proto=proto>
                                                    {r.proto}
                                                </span>
                                            </td>
                                            <td class="num">{r.len}</td>
                                            <td>{r.info}</td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    }
}
