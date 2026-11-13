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
    let status = RwSignal::new("idle".to_owned());

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
        if let Some(text) = detail::<String>(ev) {
            status.set(text);
        }
    });

    let start = move |_| {
        rows.set(Vec::new());
        post_message(&format!("start {}", iface.get()));
    };

    view! {
        <header>
            <select on:change=move |ev| iface.set(event_target_value(&ev))>
                {ifaces.into_iter().map(|i| view! { <option>{i}</option> }).collect_view()}
            </select>
            <button on:click=start>"Start"</button>
            <button on:click=move |_| post_message("stop")>"Stop"</button>
            <span>{move || status.get()}</span>
        </header>
        <table>
            <thead>
                <tr>
                    <th>"No."</th>
                    <th>"Time"</th>
                    <th>"Source"</th>
                    <th>"Destination"</th>
                    <th>"Protocol"</th>
                    <th>"Length"</th>
                    <th>"Info"</th>
                </tr>
            </thead>
            <tbody>
                <For
                    each=move || rows.get()
                    key=|r| r.no
                    children=|r: Row| {
                        view! {
                            <tr>
                                <td>{r.no}</td>
                                <td>{r.time}</td>
                                <td>{r.src}</td>
                                <td>{r.dst}</td>
                                <td>{r.proto}</td>
                                <td>{r.len}</td>
                                <td>{r.info}</td>
                            </tr>
                        }
                    }
                />
            </tbody>
        </table>
    }
}
