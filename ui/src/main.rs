//! Leptos UI. Runs inside the shell's webview and talks to it only through
//! `window.ipc.postMessage` (out) and `pkts` / `status` window events (in).

mod graph;
mod model;
mod packets;
mod select;

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

use graph::GraphPage;
use model::{Filter, Graph, PROTOCOLS, Row};
use packets::PacketTable;
use select::Select;

/// Rows kept in the table. The shell sends at most this many per batch.
const MAX_ROWS: usize = 1000;

/// `state` is `idle`, `pending`, `capturing`, `stopped` or `error`.
/// style.css colors the status dot by it.
#[derive(Clone, Deserialize)]
struct Status {
    state: String,
    text: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Packets,
    Graph,
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
    let graph = RwSignal::new(Graph::default());
    let status = RwSignal::new(Status {
        state: "idle".to_owned(),
        text: "ready".to_owned(),
    });
    let tab = RwSignal::new(Tab::Packets);
    let query = RwSignal::new(String::new());
    let proto = RwSignal::new(PROTOCOLS[0].to_owned());

    let busy = Signal::derive(move || {
        status.with(|s| matches!(s.state.as_str(), "pending" | "capturing"))
    });
    let seen = move || rows.with(|r| r.last().map_or(0, |r| r.no));
    let filter = Memo::new(move |_| Filter::new(&query.get(), &proto.get()));
    // Newest first: new packets enter at the top, the oldest leave at the bottom.
    let visible = Memo::new(move |_| {
        let f = filter.get();
        rows.with(|r| {
            r.iter()
                .rev()
                .filter(|r| f.matches(r))
                .cloned()
                .collect::<Vec<_>>()
        })
    });

    // The handles live as long as the page, so they are never removed.
    window_event_listener_untyped("pkts", move |ev| {
        let Some(batch) = detail::<Vec<Row>>(ev) else {
            return;
        };
        graph.update(|g| batch.iter().for_each(|r| g.add(r)));
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
        graph.set(Graph::default());
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
                    <Select
                        id="iface"
                        label="Interface"
                        options=Signal::stored(ifaces)
                        value=iface
                        disabled=busy
                    />
                    <button class="btn btn-primary" disabled=busy on:click=start>
                        "Start"
                    </button>
                    <button
                        class="btn btn-secondary"
                        disabled=move || !busy.get()
                        on:click=move |_| post_message("stop")
                    >
                        "Stop"
                    </button>
                </div>
                <div class="status-line">
                    <span
                        class="status"
                        role="status"
                        aria-live="polite"
                        data-state=move || status.with(|s| s.state.clone())
                    >
                        <span class="dot"></span>
                        {move || status.with(|s| s.text.clone())}
                    </span>
                    <span class="count">{seen} " packets"</span>
                </div>
            </header>
            <div class="sheet-bar">
                <SheetTabs
                    tab
                    packets=Signal::derive(move || rows.with(Vec::len))
                    hosts=Signal::derive(move || graph.with(Graph::hosts))
                />
                <Show when=move || tab.get() == Tab::Packets>
                    <div class="filter" role="search">
                        <input
                            class="input"
                            type="search"
                            placeholder="Filter: address, port, protocol, info"
                            aria-label="Filter packets"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                        />
                        <Select
                            id="proto"
                            label="Protocol"
                            hide_label=true
                            options=Signal::stored(PROTOCOLS.map(str::to_owned).to_vec())
                            value=proto
                        />
                        <span class="filter-count">
                            {move || format!("{} of {}", visible.with(Vec::len), rows.with(Vec::len))}
                        </span>
                    </div>
                </Show>
            </div>
            <main class="card sheet" data-first-tab=move || (tab.get() == Tab::Packets).to_string()>
                <div
                    role="tabpanel"
                    id="panel-packets"
                    aria-labelledby="tab-packets"
                    hidden=move || tab.get() != Tab::Packets
                >
                    <PacketTable
                        visible
                        all=rows
                        capture_empty=Signal::derive(move || rows.with(Vec::is_empty))
                    />
                </div>
                <div
                    role="tabpanel"
                    id="panel-graph"
                    aria-labelledby="tab-graph"
                    hidden=move || tab.get() != Tab::Graph
                >
                    <GraphPage graph active=Signal::derive(move || tab.get() == Tab::Graph) />
                </div>
            </main>
        </div>
    }
}

/// Worksheet-style tabs on top of the sheet card. Arrow keys move between them.
#[component]
fn SheetTabs(tab: RwSignal<Tab>, packets: Signal<usize>, hosts: Signal<usize>) -> impl IntoView {
    let select = move |t: Tab| {
        tab.set(t);
        let id = if t == Tab::Packets {
            "tab-packets"
        } else {
            "tab-graph"
        };
        if let Some(el) = document().get_element_by_id(id) {
            let _ = el.unchecked_into::<web_sys::HtmlElement>().focus();
        }
    };
    let on_key = move |ev: KeyboardEvent| match ev.key().as_str() {
        "ArrowLeft" | "Home" => select(Tab::Packets),
        "ArrowRight" | "End" => select(Tab::Graph),
        _ => {}
    };
    let tab_button = move |t: Tab,
                           id: &'static str,
                           panel: &'static str,
                           label: &'static str,
                           count: Signal<String>| {
        view! {
            <button
                type="button"
                class="tab"
                role="tab"
                id=id
                aria-controls=panel
                aria-selected=move || (tab.get() == t).to_string()
                tabindex=move || if tab.get() == t { "0" } else { "-1" }
                on:click=move |_| tab.set(t)
                on:keydown=on_key
            >
                {label}
                <span class="tab-count">{count}</span>
            </button>
        }
    };
    view! {
        <div class="tabs" role="tablist" aria-label="Views">
            {tab_button(
                Tab::Packets,
                "tab-packets",
                "panel-packets",
                "Packets",
                Signal::derive(move || packets.get().to_string()),
            )}
            {tab_button(
                Tab::Graph,
                "tab-graph",
                "panel-graph",
                "Network graph",
                Signal::derive(move || format!("{} hosts", hosts.get())),
            )}
        </div>
    }
}
