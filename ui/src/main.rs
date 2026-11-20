//! Leptos UI. Runs inside the shell's webview and talks to it only through
//! `window.ipc.postMessage` (out) and `pkts` / `status` / `domain` /
//! `ptr` / `shodan` / `notice` / `inspect` / `http` / `mitm` window events (in).

mod filters;
mod graph;
mod inspector;
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

use filters::filter_dialog;
use graph::graph_page;
use inspector::{exchange_view, inspector};
use model::{
    Col, DomainInfo, Domains, Exchange, Filter, Graph, Hosts, Inspection, MitmState, Ptrs, Row,
    Rules, ShodanInfo, Shodans, TableView, table_view,
};
use networks::networks_page;
use packets::packet_table;
use select::select;

/// Outcome of a save, from the shell.
#[derive(Clone, Deserialize)]
struct Notice {
    ok: bool,
    text: String,
}

/// How long a notice stays, in milliseconds.
const NOTICE_MS: u64 = 6000;
/// Decrypted requests kept; each holds up to 128 kibibytes of bodies.
const EXCHANGES_MAX: usize = 500;

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
    Https,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Packets, Self::Graph, Self::Networks, Self::Https];

    const fn id(self) -> &'static str {
        match self {
            Self::Packets => "tab-packets",
            Self::Graph => "tab-graph",
            Self::Networks => "tab-networks",
            Self::Https => "tab-https",
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
    leptos::mount::mount_to_body(app);
}

/// Reads the JSON string the shell puts in `CustomEvent.detail`.
fn detail<T: DeserializeOwned>(ev: web_sys::Event) -> Option<T> {
    let text = ev
        .unchecked_into::<web_sys::CustomEvent>()
        .detail()
        .as_string()?;
    serde_json::from_str(&text).ok()
}

/// Copyable handles to the window's state.
#[derive(Clone, Copy)]
struct App {
    iface: RwSignal<String>,
    rows: RwSignal<Vec<Row>>,
    graph: RwSignal<Graph>,
    hosts: RwSignal<Hosts>,
    /// Domain data outlives a capture: it describes the domain, not the traffic.
    domains: RwSignal<Domains>,
    /// PTR names, and whether to look them up for every address seen.
    ptrs: RwSignal<Ptrs>,
    ptr_on: RwSignal<bool>,
    /// Shodan answers for the addresses the user looked up.
    shodan: RwSignal<Shodans>,
    collapse: RwSignal<bool>,
    recent_only: RwSignal<bool>,
    notice: RwSignal<Option<Notice>>,
    status: RwSignal<Status>,
    tab: RwSignal<Tab>,
    query: RwSignal<String>,
    rules: RwSignal<Rules>,
    sort: RwSignal<(Col, bool)>,
    /// Clicked row (index into `rows`) and its detail from the shell.
    selected: RwSignal<Option<usize>>,
    inspection: RwSignal<Option<Inspection>>,
    /// HTTPS proxy state and what it decrypted, newest last.
    mitm: RwSignal<MitmState>,
    exchanges: RwSignal<Vec<Exchange>>,
    /// A capture is starting or running.
    busy: Signal<bool>,
    filter: Memo<Filter>,
    /// Rows the table shows.
    table: Memo<TableView>,
    /// Number of domains registered or transferred recently.
    flagged_names: Memo<usize>,
}

impl App {
    fn new(iface: String) -> Self {
        let rows = RwSignal::new(Vec::<Row>::new());
        let domains = RwSignal::new(Domains::new());
        let status = RwSignal::new(Status {
            state: "pending".to_owned(),
            text: "waiting for capture permission".to_owned(),
        });
        let query = RwSignal::new(String::new());
        let rules = RwSignal::new(Rules::default());
        // On by default: under load, repeats of one flow fill the table.
        let collapse = RwSignal::new(true);
        let recent_only = RwSignal::new(false);
        // Newest first: new packets enter at the top, the oldest end up at the bottom.
        let sort = RwSignal::new((Col::No, true));
        let filter = Memo::new(move |_| rules.with(|r| Filter::new(&query.get(), r)));
        let table = Memo::new(move |_| -> TableView {
            let f = filter.get();
            let recent = recent_only.get();
            domains.with(|d| {
                rows.with(|r| {
                    let keep =
                        |row: &Row| f.matches(row) && (!recent || row.domain_flag(d).is_some());
                    table_view(r, keep, collapse.get(), sort.get())
                })
            })
        });
        Self {
            iface: RwSignal::new(iface),
            rows,
            graph: RwSignal::new(Graph::default()),
            hosts: RwSignal::new(Hosts::default()),
            domains,
            ptrs: RwSignal::new(Ptrs::new()),
            ptr_on: RwSignal::new(true),
            shodan: RwSignal::new(Shodans::new()),
            collapse,
            recent_only,
            notice: RwSignal::new(None),
            status,
            tab: RwSignal::new(Tab::Packets),
            query,
            rules,
            sort,
            selected: RwSignal::new(None),
            inspection: RwSignal::new(None),
            mitm: RwSignal::new(MitmState::default()),
            exchanges: RwSignal::new(Vec::new()),
            busy: Signal::derive(move || {
                status.with(|s| matches!(s.state.as_str(), "pending" | "capturing"))
            }),
            filter,
            table,
            flagged_names: Memo::new(move |_| {
                domains.with(|d| d.values().filter(|i| i.flag().is_some()).count())
            }),
        }
    }
}

/// The whole window: toolbar, tabs and the sheet of the chosen tab.
fn app() -> impl IntoView {
    let ifaces = interfaces();
    let app = App::new(ifaces.first().cloned().unwrap_or_default());
    listen_capture(&app);
    listen_results(&app);
    let inspect = Callback::new(move |no: u64| post_message(&format!("inspect {no}")));
    // Ask for the detail of each newly clicked packet.
    Effect::new(move |_| {
        if let Some(no) = app
            .selected
            .get()
            .and_then(|i| app.rows.with_untracked(|r| r.get(i).map(|r| r.no)))
        {
            inspect.run(no);
        }
    });
    // The shell may have finished the launch authorization before this page loaded.
    post_message("hello");
    view! {
        <div class="app">
            <header class="toolbar">
                <div class="brand">
                    <h1>"wireshark-rs"</h1>
                    <p>"Live packet capture"</p>
                </div>
                {controls(&app, ifaces)}
                {status_line(&app)}
                {mitm_banner(app.mitm)}
            </header>
            {sheet_bar(&app)}
            {sheet(&app, inspect)}
        </div>
    }
}

/// Follows the capture: packets, its status, domain data and PTR names.
fn listen_capture(app: &App) {
    let App {
        rows,
        graph,
        hosts,
        status,
        domains,
        ptrs,
        ptr_on,
        ..
    } = *app;
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
}

/// Follows what the shell answers: Shodan data, packet detail, proxy
/// state, decrypted requests and notices.
fn listen_results(app: &App) {
    let App {
        inspection,
        mitm,
        exchanges,
        notice,
        shodan,
        ..
    } = *app;
    window_event_listener_untyped("shodan", move |ev| {
        if let Some(s) = detail::<ShodanInfo>(ev)
            && let Ok(ip) = s.ip.parse()
        {
            shodan.update(|m| {
                m.insert(ip, s);
            });
        }
    });
    window_event_listener_untyped("inspect", move |ev| {
        if let Some(i) = detail::<Inspection>(ev) {
            inspection.set(Some(i));
        }
    });
    window_event_listener_untyped("mitm", move |ev| {
        if let Some(m) = detail::<MitmState>(ev) {
            mitm.set(m);
        }
    });
    window_event_listener_untyped("http", move |ev| {
        if let Some(e) = detail::<Exchange>(ev) {
            exchanges.update(|x| {
                // An open connection's record is sent again when it ends.
                if let Some(old) = x.iter_mut().rev().find(|o| o.id == e.id) {
                    *old = e;
                    return;
                }
                if x.len() == EXCHANGES_MAX {
                    x.remove(0);
                }
                x.push(e);
            });
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
}

/// Shown rows in arrival order, without collapsing: every packet that passes the filter.
fn shown_rows(app: &App) -> Vec<Row> {
    let f = app.filter.get_untracked();
    let recent = app.recent_only.get_untracked();
    app.domains.with_untracked(|d| {
        app.rows.with_untracked(|r| {
            r.iter()
                .filter(|row| f.matches(row) && (!recent || row.domain_flag(d).is_some()))
                .cloned()
                .collect()
        })
    })
}

/// Asks the shell to save the capture as `format`: `CSV`, `JSON` or pcap.
fn export(app: &App, format: &str) {
    match format {
        "CSV" => post_message(&format!(
            "save packets.csv\n{}",
            model::csv(&shown_rows(app))
        )),
        "JSON" => match serde_json::to_string_pretty(&shown_rows(app)) {
            Ok(json) => post_message(&format!("save packets.json\n{json}")),
            Err(e) => app.notice.set(Some(Notice {
                ok: false,
                text: format!("JSON export failed: {e}"),
            })),
        },
        _ => post_message("save-pcap"),
    }
}

/// Clears the last capture and starts one on the chosen interface.
fn start(app: &App) {
    app.selected.set(None);
    app.inspection.set(None);
    app.rows.set(Vec::new());
    app.graph.set(Graph::default());
    app.hosts.set(Hosts::default());
    post_message(&format!("start {}", app.iface.get()));
}

/// Interface choice, Start, Stop and Export.
fn controls(app: &App, ifaces: Vec<String>) -> impl IntoView + use<> {
    let app = *app;
    let busy = app.busy;
    view! {
        <div class="controls">
            {select("iface", "Interface", Signal::stored(ifaces), app.iface, busy)}
            <button class="btn btn-primary" disabled=busy on:click=move |_| start(&app)>
                "Start"
            </button>
            <button
                class="btn btn-secondary"
                disabled=move || !busy.get()
                on:click=move |_| post_message("stop")
            >
                "Stop"
            </button>
            {export_menu(
                Signal::derive(move || app.rows.with(Vec::is_empty)),
                Callback::new(move |format: String| export(&app, &format)),
            )}
        </div>
    }
}

/// Capture status, the last notice, and the toggles of the lookups and the proxy.
fn status_line(app: &App) -> impl IntoView + use<> {
    let App {
        status,
        notice,
        ptr_on,
        mitm,
        rows,
        ..
    } = *app;
    view! {
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
            {recent_alert(app)}
            <button
                type="button"
                class="chip chip-filter ptr-toggle"
                aria-pressed=move || ptr_on.get().to_string()
                title="Look up the reverse DNS (PTR) name of every address seen, through the system resolver. The lookups show up in the capture as DNS traffic."
                on:click=move |_| ptr_on.update(|p| *p = !*p)
            >
                "PTR names"
            </button>
            <button
                type="button"
                class="chip chip-filter mitm-toggle"
                aria-pressed=move || mitm.with(|m| m.on).to_string()
                title="Intercept this machine's outgoing TCP and decrypt TLS on any port: redirects all TCP to this app and trusts its certificate system-wide while on. Off by default."
                on:click=move |_| {
                    let on = !mitm.with_untracked(|m| m.on);
                    post_message(if on { "mitm on" } else { "mitm off" });
                }
            >
                "HTTPS proxy"
            </button>
            <span class="count">{move || rows.with(|r| r.last().map_or(0, |r| r.no))} " packets"</span>
        </div>
    }
}

/// Count of recently registered domains; a click lists their packets.
fn recent_alert(app: &App) -> impl IntoView + use<> {
    let App {
        flagged_names,
        recent_only,
        tab,
        ..
    } = *app;
    view! {
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
    }
}

/// Tabs, and the search and filters of the packet table.
fn sheet_bar(app: &App) -> impl IntoView + use<> {
    let App {
        tab,
        rows,
        graph,
        hosts,
        exchanges,
        collapse,
        recent_only,
        query,
        rules,
        table,
        ..
    } = *app;
    view! {
        <div class="sheet-bar">
            {sheet_tabs(
                tab,
                Signal::derive(move || rows.with(Vec::len)),
                Signal::derive(move || graph.with(Graph::hosts)),
                Signal::derive(move || hosts.with(|h| h.0.len())),
                Signal::derive(move || exchanges.with(Vec::len)),
            )}
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
                        placeholder="Filter: dns | ^10.0 & !udp, 10.0.0.0/8"
                        title="Terms side by side or joined by & must all match; | means or; ! negates; ( ) groups; ^term starts a word, $term ends a word, =term is a whole word; \"quoted text\" keeps spaces; 10.0.0.0/8 matches an address block."
                        aria-label="Filter packets"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(event_target_value(&ev))
                    />
                    {filter_dialog(
                        rules,
                        rows,
                        Signal::derive(move || (table.with(|v| v.rows.len()), rows.with(Vec::len))),
                    )}
                    <span class="filter-count">
                        {move || format!("{} of {}", table.with(|v| v.rows.len()), rows.with(Vec::len))}
                    </span>
                </div>
            </Show>
        </div>
    }
}

/// The sheet of the chosen tab; the other sheets stay mounted but hidden.
fn sheet(app: &App, inspect: Callback<u64>) -> impl IntoView + use<> {
    let App {
        tab,
        rows,
        graph,
        hosts,
        domains,
        ptrs,
        selected,
        inspection,
        exchanges,
        query,
        table,
        sort,
        shodan,
        ..
    } = *app;
    let show_in_table = Callback::new(move |term: String| {
        query.set(term);
        tab.set(Tab::Packets);
    });
    view! {
        <main class="card sheet" data-first-tab=move || (tab.get() == Tab::Packets).to_string()>
            <div
                role="tabpanel"
                id="panel-packets"
                aria-labelledby="tab-packets"
                hidden=move || tab.get() != Tab::Packets
            >
                <div class="packets-split">
                    {packet_table(rows, table, sort, domains, ptrs, selected)}
                    {inspector(rows, selected, inspection, exchanges, ptrs, inspect)}
                </div>
            </div>
            <div
                role="tabpanel"
                id="panel-graph"
                aria-labelledby="tab-graph"
                hidden=move || tab.get() != Tab::Graph
            >
                {graph_page(graph, Signal::derive(move || tab.get() == Tab::Graph), domains, ptrs, shodan)}
            </div>
            <div
                role="tabpanel"
                id="panel-networks"
                aria-labelledby="tab-networks"
                hidden=move || tab.get() != Tab::Networks
            >
                {networks_page(
                    hosts,
                    domains,
                    ptrs,
                    Signal::derive(move || tab.get() == Tab::Networks),
                    show_in_table,
                )}
            </div>
            <div
                role="tabpanel"
                id="panel-https"
                aria-labelledby="tab-https"
                hidden=move || tab.get() != Tab::Https
            >
                {https_list(exchanges)}
            </div>
        </main>
    }
}

/// Requests the proxy decrypted, newest first like the packet table.
fn https_list(exchanges: RwSignal<Vec<Exchange>>) -> impl IntoView {
    view! {
        <div class="https-list">
            <Show when=move || exchanges.with(Vec::is_empty)>
                <p class="inspector-note">
                    "No decrypted requests. Turn on the HTTPS proxy: web traffic from this machine shows here."
                </p>
            </Show>
            <For
                each=move || exchanges.with(|x| x.iter().rev().cloned().collect::<Vec<_>>())
                key=|e| e.id
                let:ex
            >
                {exchange_view(&ex, false)}
            </For>
        </div>
    }
}

/// Export button with a menu of formats. CSV and JSON hold the packets the
/// table shows (every packet that passes the filter); pcap holds the whole
/// capture, payloads included.
fn export_menu(disabled: Signal<bool>, on_pick: Callback<String>) -> impl IntoView {
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

/// Worksheet-style tabs on top of the sheet card, each with its count.
/// Arrow keys move between them.
fn sheet_tabs(
    tab: RwSignal<Tab>,
    packets: Signal<usize>,
    hosts: Signal<usize>,
    blocks: Signal<usize>,
    requests: Signal<usize>,
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
            {tab_button(
                Tab::Https,
                "tab-https",
                "panel-https",
                "HTTPS proxy",
                Signal::derive(move || format!("{} requests", requests.get())),
            )}
        </div>
    }
}

/// Warning shown while the HTTPS proxy runs, with how to use it.
fn mitm_banner(mitm: RwSignal<MitmState>) -> impl IntoView {
    move || {
        let m = mitm.get();
        if let Some(e) = m.error {
            return Some(view! { <p class="mitm-banner is-error" role="alert">{e}</p> }.into_any());
        }
        if !m.on {
            return None;
        }
        let ca = m.ca.unwrap_or_default();
        Some(
            view! {
                <div class="mitm-banner" role="status">
                    <p>
                        <strong>"HTTPS interception is on."</strong>
                        " All outgoing TCP of this machine goes through this app, which can read it. "
                        "Its certificate is trusted system-wide until you turn this off or close the app; its key never leaves memory. "
                        "QUIC is blocked so browsers use TCP. "
                        "A program that rejects the certificate (Firefox and Chrome use their own lists) fails once, "
                        "then its connections pass through undecrypted. Import the certificate below to decrypt them too."
                    </p>
                    <p class="mitm-example">
                        "Certificate: " <code>{ca}</code>
                        " · Firefox and Chrome keep their own trust lists: import this file there to decrypt them."
                    </p>
                </div>
            }
            .into_any(),
        )
    }
}
