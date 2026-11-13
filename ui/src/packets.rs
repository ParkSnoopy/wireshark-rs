//! Packet table and the hover card with conversation detail.
//!
//! The table holds every packet of the capture, so it is virtualized: only
//! the rows in view (plus `OVERSCAN` above and below) are in the DOM, and
//! two spacer rows keep the scroll height right.

use leptos::ev::MouseEvent;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::model::{
    Col, Domains, IfRef, Ptrs, Row, Stack, TableView, bytes, duration, ptr_of, scope,
};
use crate::tip::Tip;

/// Packets listed under "Recent in conversation".
const RECENT: usize = 5;
/// Rows rendered beyond each edge of the view.
const OVERSCAN: usize = 12;
/// Row height before the first measurement; style.css sets 41px.
const ROW_HEIGHT: f64 = 41.0;

const COLUMNS: [(Col, &str, bool); 8] = [
    (Col::No, "No.", true),
    (Col::Time, "Time", false),
    (Col::Source, "Source", false),
    (Col::Destination, "Destination", false),
    (Col::Protocol, "Protocol", false),
    (Col::Length, "Length", true),
    (Col::Process, "Process", false),
    (Col::Info, "Info", false),
];

/// True when new rows enter at the top: the view then keeps its place.
pub fn newest_first(sort: (Col, bool)) -> bool {
    matches!(sort, (Col::No | Col::Time, true))
}

#[component]
pub fn PacketTable(
    /// Every row of the capture, in arrival order.
    rows: RwSignal<Vec<Row>>,
    /// Rows that pass the filter, in display order, with collapsed stacks.
    view: Memo<TableView>,
    /// Sorted column and whether the order is descending.
    sort: RwSignal<(Col, bool)>,
    /// Registration data of the host names seen, for the recent-domain flag.
    domains: RwSignal<Domains>,
    /// Reverse DNS names, shown after addresses.
    ptrs: RwSignal<Ptrs>,
) -> impl IntoView {
    let visible = Memo::new(move |_| view.with(|v| v.rows.clone()));
    let scroller = NodeRef::<html::Div>::new();
    let scroll_top = RwSignal::new(0.0);
    let view_height = RwSignal::new(1200.0);
    let row_height = RwSignal::new(ROW_HEIGHT);
    let hover = RwSignal::new(None::<usize>);
    let selected = RwSignal::new(None::<usize>);
    let cursor = RwSignal::new((0, 0));

    let range = Memo::new(move |_| {
        let n = visible.with(Vec::len);
        let h = row_height.get();
        let first = ((scroll_top.get() / h) as usize)
            .saturating_sub(OVERSCAN)
            .min(n);
        let count = (view_height.get() / h) as usize + 2 * OVERSCAN;
        (first, (first + count).min(n))
    });
    let window_rows = move || {
        let (a, b) = range.get();
        visible.with(|v| v[a..b].to_vec())
    };

    // Newest-first view: when packets arrive while the user reads further
    // down, scroll by their height so the rows in view stay where they are.
    let seen = StoredValue::new((0_usize, None::<usize>));
    Effect::new(move |_| {
        let top = visible.with(|v| v.first().copied());
        let total = rows.with(Vec::len);
        let (old_total, old_top) = seen.get_value();
        seen.set_value((total, top));
        let Some(el) = scroller.get_untracked() else {
            return;
        };
        if total <= old_total || el.scroll_top() <= 0 || !newest_first(sort.get_untracked()) {
            return;
        }
        // Rows now above the old top row. A collapsed flow whose newest row
        // was the top moves to a new index: then nothing is shifted.
        let added = old_top.map_or(0, |t| {
            visible.with_untracked(|v| v.iter().position(|&i| i == t).unwrap_or(0))
        });
        let shift = added as f64 * row_height.get_untracked();
        // After this update reaches the DOM, before the next paint.
        request_animation_frame(move || {
            el.set_scroll_top(el.scroll_top() + shift as i32);
            scroll_top.set(f64::from(el.scroll_top()));
        });
    });

    // Measure the real row height once rows exist.
    Effect::new(move |_| {
        range.track();
        let Some(el) = scroller.get() else { return };
        let row = el.query_selector("tbody tr[data-idx]").ok().flatten();
        if let Some(h) = row
            .map(|r| r.get_bounding_client_rect().height())
            .filter(|&h| h > 0.0 && (h - row_height.get_untracked()).abs() > 0.1)
        {
            row_height.set(h);
        }
        view_height.set(f64::from(el.client_height()));
    });

    // One delegated handler for all rows: reads the row index from data-idx.
    let row_at = |ev: &MouseEvent| {
        ev.target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .and_then(|e| e.closest("tr[data-idx]").ok().flatten())
            .and_then(|tr| tr.get_attribute("data-idx"))
            .and_then(|v| v.parse::<usize>().ok())
    };
    let on_move = move |ev: MouseEvent| {
        let idx = row_at(&ev);
        if hover.get_untracked() != idx {
            hover.set(idx);
        }
        cursor.set((ev.client_x(), ev.client_y()));
    };

    let empty_text = move || {
        if rows.with(Vec::is_empty) {
            "No packets yet. Choose an interface and press Start."
        } else {
            "No packet matches the filter."
        }
    };
    let spacer = move |height: f64| format!("height: {height}px");

    view! {
        <div
            class="table-scroll"
            tabindex="0"
            aria-label="Captured packets"
            node_ref=scroller
            on:scroll=move |_| {
                if let Some(el) = scroller.get_untracked() {
                    scroll_top.set(f64::from(el.scroll_top()));
                    view_height.set(f64::from(el.client_height()));
                }
            }
        >
            <table class="packets" aria-rowcount=move || visible.with(Vec::len) + 1>
                <thead>
                    <tr>
                        {COLUMNS
                            .into_iter()
                            .map(|(col, label, num)| view! { <SortHeader col label num sort /> })
                            .collect_view()}
                    </tr>
                </thead>
                <tbody
                    on:mousemove=on_move
                    on:mouseleave=move |_| hover.set(None)
                    on:click=move |ev| selected.set(row_at(&ev))
                >
                    <Show when=move || visible.with(Vec::is_empty)>
                        <tr class="empty">
                            <td colspan="8">{empty_text}</td>
                        </tr>
                    </Show>
                    <tr class="spacer" aria-hidden="true" style=move || spacer(range.get().0 as f64 * row_height.get())>
                        <td colspan="8"></td>
                    </tr>
                    <For each=window_rows key=|i| *i let:idx>
                        {move || {
                            let stack = view.with(|v| v.stacks.get(&idx).copied());
                            let flag = domains.with(|d| rows.with(|r| r[idx].domain_flag(d)));
                            let names = ptrs.with(|p| rows.with(|r| ptr_names(p, &r[idx])));
                            rows.with(|r| packet_row(&r[idx], idx, stack, flag, names, selected))
                        }}
                    </For>
                    <tr
                        class="spacer"
                        aria-hidden="true"
                        style=move || {
                            let (_, end) = range.get();
                            spacer((visible.with(Vec::len) - end) as f64 * row_height.get())
                        }
                    >
                        <td colspan="8"></td>
                    </tr>
                </tbody>
            </table>
        </div>
        {move || {
            let idx = hover.get()?;
            let stack = view.with(|v| v.stacks.get(&idx).copied());
            let flag = domains.with(|d| rows.with(|r| r.get(idx)?.domain_flag(d)));
            rows.with(|rows| {
                let current = rows.get(idx)?.clone();
                let conversation: Vec<Row> = rows.iter().filter(|r| r.same_conversation(&current)).cloned().collect();
                let ptrs = ptrs.with(|p| ptr_names(p, &current));
                Some(view! { <HoverCard current conversation stack flag ptrs cursor /> })
            })
        }}
    }
}

fn packet_row(
    r: &Row,
    idx: usize,
    stack: Option<Stack>,
    flag: Option<(String, String)>,
    (src_ptr, dst_ptr): (Option<String>, Option<String>),
    selected: RwSignal<Option<usize>>,
) -> impl IntoView + use<> {
    let (src, dst) = r.labels();
    // A collapsed flow shows the size range of its packets.
    let len = match stack {
        Some(s) if s.min_len != s.max_len => format!("{}–{}", s.min_len, s.max_len),
        _ => r.len.to_string(),
    };
    let flagged = flag.is_some();
    view! {
        <tr data-idx=idx class:selected=move || selected.get() == Some(idx) class:flagged=flagged>
            <td class="num">
                {stack.map(|s| view! { <span class="stack-count" title="Packets collapsed into this row">{format!("×{}", s.count)}</span> })}
                {r.no}
            </td>
            <td>{r.time.clone()}</td>
            <td>
                <span class="addr-label">{src}</span>
                {addr_tag(&r.src, r.src_if.as_ref(), src_ptr)}
            </td>
            <td>
                <span class="addr-label">{dst}</span>
                {addr_tag(&r.dst, r.dst_if.as_ref(), dst_ptr)}
            </td>
            <td class="proto">
                {r.protocol().to_owned()}
                {r.app.is_some().then(|| view! { <span class="addr-tag">{r.proto.clone()}</span> })}
            </td>
            <td class="num">{len}</td>
            <td class="process">{r.process()}</td>
            <td>
                {flag.map(|(name, why)| {
                    let title = format!("{name} was {why}");
                    view! { <span class="chip chip-warning domain-flag" title=title>"⚠ "{why}</span> }
                })}
                {r.info.clone()}
            </td>
        </tr>
    }
}

/// Muted note after an address: its PTR name, scope (`private`) and
/// related interface.
fn addr_tag(
    addr: &str,
    iface: Option<&IfRef>,
    ptr: Option<String>,
) -> Option<impl IntoView + use<>> {
    let parts: Vec<&str> = ptr
        .as_deref()
        .into_iter()
        .chain(scope(addr).map(|s| s.kind))
        .chain(iface.map(|i| i.name.as_str()))
        .collect();
    (!parts.is_empty()).then(|| view! { <span class="addr-tag">{parts.join(" · ")}</span> })
}

/// PTR names of a row's source and destination, when known.
fn ptr_names(ptrs: &Ptrs, r: &Row) -> (Option<String>, Option<String>) {
    let name = |a: &str| ptr_of(ptrs, a).map(str::to_owned);
    (name(&r.src), name(&r.dst))
}

#[component]
fn SortHeader(
    col: Col,
    label: &'static str,
    num: bool,
    sort: RwSignal<(Col, bool)>,
) -> impl IntoView {
    let aria = move || match sort.get() {
        (c, true) if c == col => "descending",
        (c, false) if c == col => "ascending",
        _ => "none",
    };
    let toggle = move |_| {
        sort.update(|(c, desc)| {
            if *c == col {
                *desc = !*desc;
            } else {
                // Numbers and time start with the newest or largest first.
                *desc = matches!(col, Col::No | Col::Time | Col::Length);
                *c = col;
            }
        });
    };
    view! {
        <th class:num=num aria-sort=aria>
            <button type="button" class="th-sort" on:click=toggle>
                {label}
                <span class="sort-mark" aria-hidden="true">
                    {move || match aria() {
                        "descending" => "▼",
                        "ascending" => "▲",
                        _ => "",
                    }}
                </span>
            </button>
        </th>
    }
}

#[component]
fn HoverCard(
    current: Row,
    conversation: Vec<Row>,
    stack: Option<Stack>,
    flag: Option<(String, String)>,
    /// PTR names of the source and destination.
    ptrs: (Option<String>, Option<String>),
    cursor: RwSignal<(i32, i32)>,
) -> impl IntoView {
    let (src, dst) = current.labels();
    let forward = conversation
        .iter()
        .filter(|r| r.same_direction(&current))
        .count();
    let backward = conversation.len() - forward;
    let total: u64 = conversation.iter().map(|r| u64::from(r.len)).sum();
    let t0 = conversation.first().map_or(0.0, Row::secs);
    let span = conversation.last().map_or(0.0, Row::secs) - t0;
    let recent: Vec<Row> = conversation.iter().rev().take(RECENT).cloned().collect();
    let chart = chart(&current, &conversation);
    let end = |addr: &str, iface: &Option<IfRef>, process: &Option<String>, ptr: Option<String>| {
        let mut parts = Vec::new();
        if let Some(s) = scope(addr) {
            parts.push(format!("{} {}", s.kind, s.cidr));
        }
        if let Some(i) = iface {
            parts.push(if i.local {
                format!("local on {}", i.name)
            } else {
                format!("via {}", i.name)
            });
        }
        if let Some(p) = process {
            parts.push(p.clone());
        }
        let text = if parts.is_empty() {
            "public".to_owned()
        } else {
            parts.join(" · ")
        };
        match ptr {
            Some(p) => format!("PTR {p} · {text}"),
            None => text,
        }
    };

    view! {
        <Tip cursor>
            <h4>{format!("{} {src} → {dst}", current.protocol().to_uppercase())}</h4>
            {flag.map(|(name, why)| view! {
                <p class="tip-flag">{format!("⚠ {name} was {why}. Check that this traffic is expected.")}</p>
            })}
            <dl class="tip-grid">
                <dt>"Packet"</dt>
                <dd>{format!("#{} at {} s, {} bytes, {}", current.no, current.time, current.len, current.proto)}</dd>
                {stack.map(|s| view! {
                    <dt>"Collapsed"</dt>
                    <dd>{format!("{} packets, {}–{} bytes each, {} total", s.count, s.min_len, s.max_len, bytes(s.bytes))}</dd>
                })}
                <dt>"Source"</dt>
                <dd>{end(&current.src, &current.src_if, &current.sproc, ptrs.0)}</dd>
                <dt>"Destination"</dt>
                <dd>{end(&current.dst, &current.dst_if, &current.dproc, ptrs.1)}</dd>
                <dt>"Info"</dt>
                <dd>{current.info.clone()}</dd>
            </dl>
            <div class="tip-section">
                <p class="tip-title">"Conversation"</p>
                <p>{format!("{} packets · {} · {}", conversation.len(), bytes(total), duration(span))}</p>
                {chart}
                <p class="tip-legend">
                    <span style="--legend: var(--surface-inset)">{format!("{src} → {forward}")}</span>
                    <span style="--legend: var(--secondary)">{format!("← {backward}")}</span>
                </p>
            </div>
            <div class="tip-section">
                <p class="tip-title">"Recent in conversation"</p>
                <ul class="tip-related">
                    {recent
                        .into_iter()
                        .map(|r| {
                            let arrow = if r.same_direction(&current) { "→" } else { "←" };
                            let line = format!(
                                "#{} +{} {arrow} {}B {}",
                                r.no,
                                duration(r.secs() - t0),
                                r.len,
                                r.info,
                            );
                            view! { <li class:is-current={r.no == current.no}>{line}</li> }
                        })
                        .collect_view()}
                </ul>
            </div>
        </Tip>
    }
}

/// Bytes over time for the conversation as two overlaid area series: cream
/// for the hovered packet's direction, caramel for replies. A dashed guide
/// and a dot mark the hovered packet.
fn chart(current: &Row, conversation: &[Row]) -> impl IntoView + use<> {
    const W: f64 = 352.0;
    const X0: f64 = 40.0;
    const X1: f64 = W - 4.0;
    const TOP: f64 = 8.0;
    const BASE: f64 = 64.0;
    const BUCKETS: usize = 48;

    let t0 = conversation.first().map_or(0.0, Row::secs);
    let span = conversation.last().map_or(0.0, Row::secs) - t0;
    // All packets at one instant: center them.
    let bucket_of = |r: &Row| {
        let f = if span > 0.0 {
            (r.secs() - t0) / span
        } else {
            0.5
        };
        ((f * (BUCKETS - 1) as f64).round() as usize).min(BUCKETS - 1)
    };
    let mut series = [[0_u64; BUCKETS]; 2];
    for r in conversation {
        series[usize::from(!r.same_direction(current))][bucket_of(r)] += u64::from(r.len);
    }
    let peak = series.iter().flatten().copied().max().unwrap_or(1).max(1);
    let x = |b: usize| X0 + b as f64 / (BUCKETS - 1) as f64 * (X1 - X0);
    let y = |v: u64| BASE - v as f64 / peak as f64 * (BASE - TOP);
    let area = |s: &[u64; BUCKETS]| {
        let mut d = format!("M{X0},{BASE}");
        for (b, &v) in s.iter().enumerate() {
            d.push_str(&format!(" L{:.1},{:.1}", x(b), y(v)));
        }
        d + &format!(" L{X1},{BASE} Z")
    };
    let [fwd, back] = &series;
    let hb = bucket_of(current);
    let (gx, gy) = (x(hb), y(fwd[hb]));

    view! {
        <svg
            class="tip-chart"
            viewBox=format!("0 0 {W} 80")
            role="img"
            aria-label="Bytes over time in this conversation, per direction"
        >
            <line x1=X0 y1=BASE x2=X1 y2=BASE stroke="rgb(255 255 255 / 30%)" />
            <path d=area(back) fill="#c4956a" fill-opacity="0.75" stroke="#c4956a" stroke-width="1.5" />
            <path d=area(fwd) fill="#f0e6d6" fill-opacity="0.45" stroke="#f0e6d6" stroke-width="1.5" />
            <line x1=gx y1={TOP - 4.0} x2=gx y2=BASE stroke="rgb(255 255 255 / 55%)" stroke-dasharray="2 2" />
            <circle cx=gx cy=gy r="3" fill="#ffffff" />
            <text x="0" y={TOP + 4.0}>
                {bytes(peak)}
            </text>
            <text x="0" y=BASE>
                "0"
            </text>
            <text x=X0 y="78">
                {format!("0 s · {} per step", duration(span / (BUCKETS - 1) as f64))}
            </text>
            <text x=X1 y="78" text-anchor="end">
                {format!("+{}", duration(span))}
            </text>
        </svg>
    }
}
