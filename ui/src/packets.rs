//! Packet table (newest first) and the hover card with conversation detail.

use leptos::ev::MouseEvent;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::model::{Row, duration};

/// Width of `.tooltip-rich` in style.css.
const CARD_WIDTH: i32 = 380;
/// Distance from the arrow tip to the cursor, and from the arrow to the card edge.
const CARD_GAP: i32 = 18;
const ARROW_INSET: i32 = 22;
/// Packets listed under "Recent in conversation".
const RECENT: usize = 5;

#[component]
pub fn PacketTable(
    /// Rows to show, newest first.
    visible: Memo<Vec<Row>>,
    /// Every kept row, oldest first. The hover card looks up the conversation here.
    all: RwSignal<Vec<Row>>,
    capture_empty: Signal<bool>,
) -> impl IntoView {
    let hover = RwSignal::new(None::<u64>);
    let cursor = RwSignal::new((0, 0));

    // One delegated handler for all rows: reads the packet number from data-no.
    let on_move = move |ev: MouseEvent| {
        let no = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .and_then(|e| e.closest("tr[data-no]").ok().flatten())
            .and_then(|tr| tr.get_attribute("data-no"))
            .and_then(|v| v.parse().ok());
        if hover.get_untracked() != no {
            hover.set(no);
        }
        cursor.set((ev.client_x(), ev.client_y()));
    };

    let empty_text = move || {
        if capture_empty.get() {
            "No packets yet. Choose an interface and press Start."
        } else {
            "No packet matches the filter."
        }
    };

    view! {
        <div class="table-scroll" tabindex="0" aria-label="Captured packets, newest first">
            <table class="packets">
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
                <tbody on:mousemove=on_move on:mouseleave=move |_| hover.set(None)>
                    <Show when=move || visible.with(Vec::is_empty)>
                        <tr class="empty">
                            <td colspan="7">{empty_text}</td>
                        </tr>
                    </Show>
                    <For
                        each=move || visible.get()
                        key=|r| r.no
                        children=|r: Row| {
                            let (src, dst) = r.endpoints();
                            view! {
                                <tr data-no=r.no>
                                    <td class="num">{r.no}</td>
                                    <td>{r.time}</td>
                                    <td>{src}</td>
                                    <td>{dst}</td>
                                    <td class="proto">{r.proto}</td>
                                    <td class="num">{r.len}</td>
                                    <td>{r.info}</td>
                                </tr>
                            }
                        }
                    />
                </tbody>
            </table>
        </div>
        {move || {
            let no = hover.get()?;
            all.with(|rows| {
                let current = rows.iter().find(|r| r.no == no)?.clone();
                let conversation: Vec<Row> = rows
                    .iter()
                    .filter(|r| r.same_conversation(&current))
                    .cloned()
                    .collect();
                Some(view! { <HoverCard current conversation cursor /> })
            })
        }}
    }
}

#[component]
fn HoverCard(current: Row, conversation: Vec<Row>, cursor: RwSignal<(i32, i32)>) -> impl IntoView {
    // Below and right of the cursor; flips when that would leave the window.
    let placement = move || {
        let (x, y) = cursor.get();
        let (width, height) = viewport();
        let below = y < height / 2;
        let start = x + CARD_WIDTH < width;
        let left = if start {
            x - ARROW_INSET
        } else {
            x + ARROW_INSET
        };
        let top = if below { y + CARD_GAP } else { y - CARD_GAP };
        let shift = (
            if start { "0" } else { "-100%" },
            if below { "0" } else { "-100%" },
        );
        (
            format!(
                "left:{left}px;top:{top}px;transform:translate({},{})",
                shift.0, shift.1
            ),
            if below { "bottom" } else { "top" },
            if start { "start" } else { "end" },
        )
    };

    let (src, dst) = current.endpoints();
    let forward = conversation
        .iter()
        .filter(|r| r.same_direction(&current))
        .count();
    let backward = conversation.len() - forward;
    let bytes: u64 = conversation.iter().map(|r| u64::from(r.len)).sum();
    let span =
        conversation.last().map_or(0.0, Row::secs) - conversation.first().map_or(0.0, Row::secs);
    let recent: Vec<Row> = conversation.iter().rev().take(RECENT).cloned().collect();
    let t0 = conversation.first().map_or(0.0, Row::secs);
    let chart = chart(&current, &conversation);

    view! {
        <div
            class="tooltip tooltip-rich"
            role="tooltip"
            style=move || placement().0
            data-side=move || placement().1
            data-align=move || placement().2
        >
            <h4>{format!("{} {src} → {dst}", current.proto)}</h4>
            <dl class="tip-grid">
                <dt>"Packet"</dt>
                <dd>{format!("#{} at {} s", current.no, current.time)}</dd>
                <dt>"Length"</dt>
                <dd>{format!("{} bytes", current.len)}</dd>
                <dt>"Info"</dt>
                <dd>{current.info.clone()}</dd>
            </dl>
            <div class="tip-section">
                <p class="tip-title">"Conversation"</p>
                <p>
                    {format!(
                        "{} packets · {bytes} bytes · {}",
                        conversation.len(),
                        duration(span),
                    )}
                </p>
                {chart}
                <p class="tip-legend">
                    <span style="--legend: var(--surface-inset)">
                        {format!("{src} → {forward}")}
                    </span>
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
        </div>
    }
}

/// Packet length over time for the conversation. Bars leaving from the
/// hovered packet's source are cream, replies are caramel, the hovered
/// packet is white with a guide line.
fn chart(current: &Row, conversation: &[Row]) -> impl IntoView + use<> {
    const W: f64 = 352.0;
    const X0: f64 = 34.0;
    const X1: f64 = W - 4.0;
    const TOP: f64 = 8.0;
    const BASE: f64 = 64.0;

    let t0 = conversation.first().map_or(0.0, Row::secs);
    let span = conversation.last().map_or(0.0, Row::secs) - t0;
    let max_len = conversation.iter().map(|r| r.len).max().unwrap_or(1).max(1);
    let count = conversation.len().max(2) - 1;
    let x_of = |i: usize, r: &Row| {
        // Equal spacing when every packet has the same timestamp.
        let f = if span > 0.0 {
            (r.secs() - t0) / span
        } else {
            i as f64 / count as f64
        };
        X0 + f * (X1 - X0)
    };
    let bars = conversation
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let x = x_of(i, r);
            let h = (f64::from(r.len) / f64::from(max_len) * (BASE - TOP)).max(1.0);
            let fill = if r.no == current.no {
                "#ffffff"
            } else if r.same_direction(current) {
                "#f0e6d6"
            } else {
                "#c4956a"
            };
            view! { <rect x={x - 1.5} y={BASE - h} width="3" height=h rx="1" fill=fill /> }
        })
        .collect_view();
    let guide = conversation
        .iter()
        .position(|r| r.no == current.no)
        .map(|i| x_of(i, &conversation[i]));

    view! {
        <svg
            class="tip-chart"
            viewBox=format!("0 0 {W} 80")
            role="img"
            aria-label="Packet length over time in this conversation"
        >
            <line x1=X0 y1=BASE x2=X1 y2=BASE stroke="rgb(255 255 255 / 30%)" />
            {guide
                .map(|x| {
                    view! {
                        <line
                            x1=x
                            y1={TOP - 4.0}
                            x2=x
                            y2=BASE
                            stroke="rgb(255 255 255 / 45%)"
                            stroke-dasharray="2 2"
                        />
                    }
                })}
            {bars}
            <text x="0" y={TOP + 4.0}>
                {format!("{max_len}B")}
            </text>
            <text x="0" y=BASE>
                "0"
            </text>
            <text x=X0 y="78">
                "0 s"
            </text>
            <text x=X1 y="78" text-anchor="end">
                {format!("+{}", duration(span))}
            </text>
        </svg>
    }
}

fn viewport() -> (i32, i32) {
    let w = window();
    let size =
        |v: Result<wasm_bindgen::JsValue, _>| v.ok().and_then(|v| v.as_f64()).unwrap_or(0.0) as i32;
    (size(w.inner_width()), size(w.inner_height()))
}
