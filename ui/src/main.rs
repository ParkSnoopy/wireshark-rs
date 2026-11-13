//! Leptos UI. Runs inside the shell's webview and talks to it only through
//! `window.ipc.postMessage` (out) and `pkts` / `status` / `domain` /
//! `notice` window events (in).

mod filters;
mod graph;
mod model;
mod networks;
mod packets;
mod select;
mod tip;

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

use filters::FilterDialog;
use graph::GraphPage;
use model::{
    Col, DomainInfo, Domains, Filter, Graph, Hosts, Ptrs, Row, Rules, TableView, table_view,
};
use networks::NetworksPage;
use packets::PacketTable;
use select::Select;

/// Outcome of a save, from the shell.
#[derive(Clone, Deserialize)]
struct Notice {
    ok: bool,
    text: String,
}

/// How long a notice stays, in milliseconds.
const NOTICE_MS: u64 = 6000;

/// `state` is `pending`, `idle`, `capturing`, `stopped` or `error`.
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
    Networks,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Packets, Tab::Graph, Tab::Networks];

    fn id(self) -> &'static str {
        match self {
            Tab::Packets => "tab-packets",
            Tab::Graph => "tab-graph",
            Tab::Networks => "tab-networks",
        }
    }
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
    let hosts = RwSignal::new(Hosts::default());
    // Domain data outlives a capture: it describes the domain, not the traffic.
    let domains = RwSignal::new(Domains::new());
    // PTR names, and whether to look them up for every address seen.
    let ptrs = RwSignal::new(Ptrs::new());
    let ptr_on = RwSignal::new(false);
    // On by default: under load, repeats of one flow fill the table.
    let collapse = RwSignal::new(true);
    let recent_only = RwSignal::new(false);
    let notice = RwSignal::new(None::<Notice>);
    let status = RwSignal::new(Status {
        state: "pending".to_owned(),
        text: "waiting for capture permission".to_owned(),
    });
    let tab = RwSignal::new(Tab::Packets);
    let query = RwSignal::new(String::new());
    let rules = RwSignal::new(Rules::default());
    // Newest first: new packets enter at the top, the oldest end up at the bottom.
    let sort = RwSignal::new((Col::No, true));

    let busy = Signal::derive(move || {
        status.with(|s| matches!(s.state.as_str(), "pending" | "capturing"))
    });
    let seen = move || rows.with(|r| r.last().map_or(0, |r| r.no));
    let filter = Memo::new(move |_| rules.with(|r| Filter::new(&query.get(), r)));
    let view = Memo::new(move |_| -> TableView {
        let f = filter.get();
        let recent = recent_only.get();
        domains.with(|d| {
            rows.with(|r| {
                let keep = |row: &Row| f.matches(row) && (!recent || row.domain_flag(d).is_some());
                table_view(r, keep, collapse.get(), sort.get())
            })
        })
    });
    let flagged_names =
        Memo::new(move |_| domains.with(|d| d.values().filter(|i| i.flag().is_some()).count()));

    // The handles live as long as the page, so they are never removed.
    window_event_listener_untyped("pkts", move |ev| {
        let Some(batch) = detail::<Vec<Row>>(ev) else {
            return;
        };
        let batch: Vec<Row> = batch.into_iter().map(Row::prepared).collect();
        graph.update(|g| batch.iter().for_each(|r| g.add(r)));
        hosts.update(|h| batch.iter().for_each(|r| h.add(r)));
        rows.update(|r| r.extend(batch));
    });
    window_event_listener_untyped("status", move |ev| {
        if let Some(s) = detail::<Status>(ev) {
            status.set(s);
        }
    });
    window_event_listener_untyped("domain", move |ev| {
        if let Some(d) = detail::<DomainInfo>(ev) {
            domains.update(|m| {
                m.insert(d.name.clone(), d);
            });
        }
    });
    window_event_listener_untyped("ptr", move |ev| {
        #[derive(Deserialize)]
        struct Answer {
            ip: String,
            name: Option<String>,
        }
        if let Some(a) = detail::<Answer>(ev)
            && let Ok(ip) = a.ip.parse()
        {
            ptrs.update(|p| {
                p.insert(ip, a.name);
            });
        }
    });
    // While PTR lookup is on, ask the shell once for every new address.
    let asked = StoredValue::new(std::collections::HashSet::new());
    Effect::new(move |_| {
        if !ptr_on.get() {
            return;
        }
        let new: Vec<String> = hosts.with(|h| {
            asked
                .try_update_value(|a| {
                    h.0.keys()
                        .filter(|ip| a.insert(**ip))
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default()
        });
        if !new.is_empty() {
            post_message(&format!("ptr {}", new.join(" ")));
        }
    });
    let notice_seq = StoredValue::new(0_u64);
    window_event_listener_untyped("notice", move |ev| {
        if let Some(n) = detail::<Notice>(ev) {
            notice.set(Some(n));
            notice_seq.update_value(|s| *s += 1);
            let mine = notice_seq.get_value();
            // Hide it later, unless a newer notice replaced it.
            set_timeout(
                move || {
                    if notice_seq.try_get_value() == Some(mine) {
                        notice.set(None);
                    }
                },
                std::time::Duration::from_millis(NOTICE_MS),
            );
        }
    });

    // Shown rows in arrival order, without collapsing: every packet that passes the filter.
    let shown_rows = move || -> Vec<Row> {
        let f = filter.get_untracked();
        let recent = recent_only.get_untracked();
        domains.with_untracked(|d| {
            rows.with_untracked(|r| {
                r.iter()
                    .filter(|row| f.matches(row) && (!recent || row.domain_flag(d).is_some()))
                    .cloned()
                    .collect()
            })
        })
    };
    let export = move |format: String| match format.as_str() {
        "CSV" => post_message(&format!("save packets.csv\n{}", model::csv(&shown_rows()))),
        "JSON" => {
            let json = serde_json::to_string_pretty(&shown_rows()).expect("rows serialize");
            post_message(&format!("save packets.json\n{json}"));
        }
        _ => post_message("save-pcap"),
    };
    let show_in_table = Callback::new(move |term: String| {
        query.set(term);
        tab.set(Tab::Packets);
    });
    // The shell may have finished the launch authorization before this page loaded.
    post_message("hello");

    let start = move |_| {
        rows.set(Vec::new());
        graph.set(Graph::default());
        hosts.set(Hosts::default());
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
                    <ExportMenu
                        disabled=Signal::derive(move || rows.with(Vec::is_empty))
                        on_pick=Callback::new(export)
                    />
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
                    {move || {
                        notice.get().map(|n| view! {
                            <span class="notice" class:is-error=!n.ok role="status">{n.text}</span>
                        })
                    }}
                    <Show when=move || { flagged_names.get() > 0 }>
                        <button
                            type="button"
                            class="chip chip-warning recent-alert"
                            title="Domains registered or transferred in the last 30 days. Click to list their packets."
                            on:click=move |_| {
                                recent_only.set(true);
                                tab.set(Tab::Packets);
                            }
                        >
                            {move || match flagged_names.get() {
                                1 => "⚠ 1 recent domain".to_owned(),
                                n => format!("⚠ {n} recent domains"),
                            }}
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="chip chip-filter ptr-toggle"
                        aria-pressed=move || ptr_on.get().to_string()
                        title="Look up the reverse DNS (PTR) name of every address seen, through the system resolver. The lookups show up in the capture as DNS traffic."
                        on:click=move |_| ptr_on.update(|p| *p = !*p)
                    >
                        "PTR names"
                    </button>
                    <span class="count">{seen} " packets"</span>
                </div>
            </header>
            <div class="sheet-bar">
                <SheetTabs
                    tab
                    packets=Signal::derive(move || rows.with(Vec::len))
                    hosts=Signal::derive(move || graph.with(Graph::hosts))
                    blocks=Signal::derive(move || hosts.with(|h| h.0.len()))
                />
                <Show when=move || tab.get() == Tab::Packets>
                    <div class="filter" role="search">
                        <button
                            type="button"
                            class="chip chip-filter"
                            aria-pressed=move || collapse.get().to_string()
                            title="Show each flow (protocol, source, destination) once, with its packet count and size range"
                            on:click=move |_| collapse.update(|c| *c = !*c)
                        >
                            "Collapse repeats"
                        </button>
                        <button
                            type="button"
                            class="chip chip-filter"
                            aria-pressed=move || recent_only.get().to_string()
                            title="Only packets to or from domains registered or transferred in the last 30 days"
                            on:click=move |_| recent_only.update(|c| *c = !*c)
                        >
                            "Recent domains"
                        </button>
                        <input
                            class="input"
                            type="search"
                            placeholder="Filter: address, name, port, https, 10.0.0.0/8"
                            aria-label="Filter packets"
                            prop:value=move || query.get()
                            on:input=move |ev| query.set(event_target_value(&ev))
                        />
                        <FilterDialog
                            rules
                            rows
                            counts=Signal::derive(move || (view.with(|v| v.rows.len()), rows.with(Vec::len)))
                        />
                        <span class="filter-count">
                            {move || format!("{} of {}", view.with(|v| v.rows.len()), rows.with(Vec::len))}
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
                    <PacketTable rows view sort domains ptrs />
                </div>
                <div
                    role="tabpanel"
                    id="panel-graph"
                    aria-labelledby="tab-graph"
                    hidden=move || tab.get() != Tab::Graph
                >
                    <GraphPage graph domains ptrs active=Signal::derive(move || tab.get() == Tab::Graph) />
                </div>
                <div
                    role="tabpanel"
                    id="panel-networks"
                    aria-labelledby="tab-networks"
                    hidden=move || tab.get() != Tab::Networks
                >
                    <NetworksPage
                        hosts
                        domains
                        ptrs
                        active=Signal::derive(move || tab.get() == Tab::Networks)
                        on_show=show_in_table
                    />
                </div>
            </main>
        </div>
    }
}

/// Export button with a menu of formats. CSV and JSON hold the packets the
/// table shows (every packet that passes the filter); pcap holds the whole
/// capture, payloads included.
#[component]
fn ExportMenu(disabled: Signal<bool>, on_pick: Callback<String>) -> impl IntoView {
    const ITEMS: [(&str, &str); 3] = [
        ("CSV", "Shown packets as CSV"),
        ("JSON", "Shown packets as JSON"),
        ("pcap", "Whole capture as pcap (Wireshark)"),
    ];
    let open = RwSignal::new(false);
    view! {
        <div class="select export" on:focusout=move |ev| {
            // Close when focus leaves the menu and its button.
            let inside = ev
                .related_target()
                .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
                .zip(ev.current_target().and_then(|t| t.dyn_into::<web_sys::Node>().ok()))
                .is_some_and(|(to, root)| root.contains(Some(&to)));
            if !inside {
                open.set(false);
            }
        }>
            <button
                type="button"
                class="btn btn-secondary"
                aria-haspopup="menu"
                aria-expanded=move || open.get().to_string()
                disabled=disabled
                on:click=move |_| open.update(|o| *o = !*o)
                on:keydown=move |ev: KeyboardEvent| {
                    if ev.key() == "Escape" {
                        open.set(false);
                    }
                }
            >
                "Export"
            </button>
            <Show when=move || open.get()>
                <ul class="menu" role="menu">
                    {ITEMS
                        .into_iter()
                        .map(|(format, text)| {
                            view! {
                                <li role="none">
                                    <button
                                        type="button"
                                        class="menu-item"
                                        role="menuitem"
                                        on:click=move |_| {
                                            open.set(false);
                                            on_pick.run(format.to_owned());
                                        }
                                    >
                                        {text}
                                    </button>
                                </li>
                            }
                        })
                        .collect_view()}
                </ul>
            </Show>
        </div>
    }
}

/// Worksheet-style tabs on top of the sheet card. Arrow keys move between them.
#[component]
fn SheetTabs(
    tab: RwSignal<Tab>,
    packets: Signal<usize>,
    hosts: Signal<usize>,
    blocks: Signal<usize>,
) -> impl IntoView {
    let select = move |t: Tab| {
        tab.set(t);
        if let Some(el) = document().get_element_by_id(t.id()) {
            let _ = el.unchecked_into::<web_sys::HtmlElement>().focus();
        }
    };
    let on_key = move |ev: KeyboardEvent| {
        let at = Tab::ALL
            .iter()
            .position(|&t| t == tab.get_untracked())
            .unwrap_or(0);
        let last = Tab::ALL.len() - 1;
        match ev.key().as_str() {
            "ArrowLeft" => select(Tab::ALL[at.saturating_sub(1)]),
            "ArrowRight" => select(Tab::ALL[(at + 1).min(last)]),
            "Home" => select(Tab::ALL[0]),
            "End" => select(Tab::ALL[last]),
            _ => {}
        }
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
            {tab_button(
                Tab::Networks,
                "tab-networks",
                "panel-networks",
                "Networks",
                Signal::derive(move || format!("{} addresses", blocks.get())),
            )}
        </div>
    }
}
