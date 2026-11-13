//! Network graph page: the capture graph as an interactive force layout
//! (drag nodes or the background, wheel to zoom, click a node to inspect),
//! its ontology, a node inspector and the build log.
//!
//! Hosts in the same special-purpose address block (10.0.0.0/8, fe80::/10,
//! ...) are pulled together and framed with the block's CIDR.

use std::collections::{BTreeMap, HashSet};

use leptos::ev::{KeyboardEvent, MouseEvent, PointerEvent, WheelEvent};
use leptos::prelude::*;
use leptos::svg::Svg;
use wasm_bindgen::JsCast;

use crate::model::{Domains, Graph, Kind, Node, Rel, Scope, bytes};

/// Build log entries rendered, newest first.
const LOG_ROWS: usize = 300;
/// Relations listed in the inspector, busiest first.
const RELATION_ROWS: usize = 40;
const ZOOM_MIN: f64 = 0.1;
const ZOOM_MAX: f64 = 4.0;
/// The layout stops once its energy (alpha) falls below this.
const ALPHA_MIN: f64 = 0.004;
const ALPHA_DECAY: f64 = 0.0228;
/// Share of velocity kept per tick.
const FRICTION: f64 = 0.6;
const REPULSION: f64 = 700.0;
/// Bodies farther apart than this do not repel each other.
const REPULSION_RANGE: f64 = 480.0;
const SPRING: f64 = 0.3;
const GRAVITY: f64 = 0.02;
/// Pull of hosts toward the middle of their address block.
const CLUSTER: f64 = 0.05;
/// Pointer travel in px that turns a click into a drag.
const DRAG_SLOP: f64 = 3.0;
/// Space between an address block frame and its nodes.
const HULL_PAD: f64 = 36.0;
/// Height of the CIDR label band at the top of a frame.
const HULL_LABEL: f64 = 24.0;

#[derive(Clone, Copy, Default)]
struct Body {
    x: f64,
    y: f64,
    vx: f64,
    vy: f64,
    /// Set by dragging: the layout leaves the body where the user put it.
    pinned: bool,
}

#[derive(Default)]
struct Sim {
    bodies: Vec<Body>,
    alpha: f64,
    /// Alpha the layout moves toward: above zero while a node is dragged.
    target: f64,
    running: bool,
}

/// Screen position = world position × k + (x, y).
#[derive(Clone, Copy, PartialEq)]
struct Camera {
    x: f64,
    y: f64,
    k: f64,
}

#[derive(Clone, Copy)]
enum Grab {
    Pan {
        from: (f64, f64),
        start: Camera,
        moved: bool,
    },
    Node {
        i: usize,
        from: (f64, f64),
        moved: bool,
    },
}

/// Copyable handles for the animation loop.
#[derive(Clone, Copy)]
struct Layout {
    graph: RwSignal<Graph>,
    sim: StoredValue<Sim>,
    /// Bumped after each layout step; positions are read under it.
    frame: RwSignal<u64>,
    active: Signal<bool>,
}

impl Layout {
    /// Adds energy, and starts the animation loop if it is not running.
    fn kick(self, alpha: f64) {
        let start = self.sim.try_update_value(|s| {
            s.alpha = s.alpha.max(alpha);
            !std::mem::replace(&mut s.running, true)
        });
        if start == Some(true) {
            self.tick();
        }
    }

    fn tick(self) {
        let more = self.active.try_get_untracked().unwrap_or(false)
            && self
                .graph
                .try_with_untracked(|g| self.sim.try_update_value(|s| step(s, g)))
                .flatten()
                .unwrap_or(false);
        self.frame.try_update(|f| *f += 1);
        if more {
            request_animation_frame(move || self.tick());
        } else {
            self.sim.try_update_value(|s| s.running = false);
        }
    }
}

/// One layout step. Returns false once the layout has settled.
fn step(s: &mut Sim, g: &Graph) -> bool {
    place_new(s, g);
    let a = s.alpha;
    let b = &mut s.bodies;

    // shortcut: all-pairs repulsion is O(n²); fine for a few hundred nodes.
    // Use a Barnes-Hut quadtree if captures with thousands of hosts matter.
    for i in 0..b.len() {
        for j in i + 1..b.len() {
            let (mut dx, mut dy) = (b[j].x - b[i].x, b[j].y - b[i].y);
            let mut d2 = dx * dx + dy * dy;
            if d2 > REPULSION_RANGE * REPULSION_RANGE {
                continue;
            }
            if d2 < 1.0 {
                // Bodies on the same spot: separate along a fixed direction.
                (dx, dy, d2) = (1.0, 0.0, 1.0);
            }
            let f = REPULSION * a / d2;
            b[i].vx -= dx * f;
            b[i].vy -= dy * f;
            b[j].vx += dx * f;
            b[j].vy += dy * f;
        }
    }
    for e in &g.edges {
        let (dx, dy) = (b[e.to].x - b[e.from].x, b[e.to].y - b[e.from].y);
        let len = dx.hypot(dy).max(1.0);
        let f = (len - rest_length(e.rel)) / len * a * SPRING / 2.0;
        b[e.to].vx -= dx * f;
        b[e.to].vy -= dy * f;
        b[e.from].vx += dx * f;
        b[e.from].vy += dy * f;
    }
    let mut blocks: BTreeMap<&str, (f64, f64, f64)> = BTreeMap::new();
    for (n, body) in g.nodes.iter().zip(b.iter()) {
        if let Some(s) = block(n) {
            let c = blocks.entry(s.cidr).or_default();
            *c = (c.0 + body.x, c.1 + body.y, c.2 + 1.0);
        }
    }
    for (n, body) in g.nodes.iter().zip(b.iter_mut()) {
        body.vx -= body.x * GRAVITY * a;
        body.vy -= body.y * GRAVITY * a;
        if let Some(&(sx, sy, count)) = block(n).and_then(|s| blocks.get(s.cidr)) {
            body.vx += (sx / count - body.x) * CLUSTER * a;
            body.vy += (sy / count - body.y) * CLUSTER * a;
        }
    }
    for body in b.iter_mut() {
        if body.pinned {
            (body.vx, body.vy) = (0.0, 0.0);
            continue;
        }
        body.vx *= FRICTION;
        body.vy *= FRICTION;
        body.x += body.vx;
        body.y += body.vy;
    }
    s.alpha += (s.target - s.alpha) * ALPHA_DECAY;
    s.alpha >= ALPHA_MIN || s.target > 0.0
}

/// Gives new nodes a start position: services and processes next to their
/// host, hosts on a golden-angle spiral so none lands on another.
fn place_new(s: &mut Sim, g: &Graph) {
    for (i, node) in g.nodes.iter().enumerate().skip(s.bodies.len()) {
        let anchor = match node.kind {
            Kind::Host => None,
            Kind::Service { host } | Kind::Process { host } => s.bodies.get(host).copied(),
        };
        let angle = i as f64 * 2.399_963;
        let (cx, cy, r) = anchor.map_or((0.0, 0.0, 30.0 * (i as f64).sqrt()), |h| (h.x, h.y, 60.0));
        s.bodies.push(Body {
            x: cx + r * angle.cos(),
            y: cy + r * angle.sin(),
            ..Body::default()
        });
    }
}

fn rest_length(rel: Rel) -> f64 {
    match rel {
        Rel::RunsOn => 50.0,
        Rel::Serves => 60.0,
        Rel::Exchanges => 140.0,
        Rel::Connects => 170.0,
    }
}

/// Address block a host is framed in. Multicast and broadcast are not networks a host is in.
fn block(n: &Node) -> Option<Scope> {
    n.scope
        .filter(|s| n.kind == Kind::Host && !matches!(s.kind, "multicast" | "broadcast"))
}

/// Frames around each address block: `(label, x, y, width, height)` in world units.
fn hulls(g: &Graph, bodies: &[Body]) -> Vec<(String, f64, f64, f64, f64)> {
    let mut boxes: BTreeMap<&str, (&str, f64, f64, f64, f64)> = BTreeMap::new();
    for (n, b) in g.nodes.iter().zip(bodies) {
        // A service or process sits inside the frame of its host.
        let owner = match n.kind {
            Kind::Host => n,
            Kind::Service { host } | Kind::Process { host } => &g.nodes[host],
        };
        let Some(s) = block(owner) else { continue };
        let e = boxes.entry(s.cidr).or_insert((s.kind, b.x, b.y, b.x, b.y));
        *e = (e.0, e.1.min(b.x), e.2.min(b.y), e.3.max(b.x), e.4.max(b.y));
    }
    boxes
        .into_iter()
        .map(|(cidr, (kind, x0, y0, x1, y1))| {
            // A label band on top, and room below for the host label and note.
            let (x, y) = (x0 - HULL_PAD, y0 - HULL_PAD - HULL_LABEL);
            (
                format!("{cidr} · {kind}"),
                x,
                y,
                x1 - x0 + 2.0 * HULL_PAD,
                y1 - y0 + 2.0 * HULL_PAD + 2.0 * HULL_LABEL,
            )
        })
        .collect()
}

#[component]
pub fn GraphPage(
    graph: RwSignal<Graph>,
    active: Signal<bool>,
    /// Registration data of host names, for the recent-domain mark.
    domains: RwSignal<Domains>,
) -> impl IntoView {
    let flagged = move |i: usize| {
        let name = graph.with(|g| g.nodes.get(i).and_then(|n| n.name.clone()));
        name.is_some_and(|n| domains.with(|d| d.get(&n).and_then(|d| d.flag()).is_some()))
    };
    let sim = StoredValue::new(Sim::default());
    let frame = RwSignal::new(0_u64);
    let layout = Layout {
        graph,
        sim,
        frame,
        active,
    };
    let camera = RwSignal::new(Camera {
        x: 0.0,
        y: 0.0,
        k: 1.0,
    });
    let selected = RwSignal::new(None::<usize>);
    let grab = StoredValue::new(None::<Grab>);
    let svg = NodeRef::<Svg>::new();
    let centered = StoredValue::new(false);

    let size = move || {
        let r = svg.get_untracked()?.get_bounding_client_rect();
        (r.width() > 0.0).then(|| (r.width(), r.height()))
    };
    let local = move |ev: &MouseEvent| {
        let r = svg.get_untracked().map(|s| s.get_bounding_client_rect());
        let (left, top) = r.map_or((0.0, 0.0), |r| (r.left(), r.top()));
        (
            f64::from(ev.client_x()) - left,
            f64::from(ev.client_y()) - top,
        )
    };
    let center_on = move |i: usize| {
        let (Some((w, h)), Some(b)) = (size(), sim.with_value(|s| s.bodies.get(i).copied())) else {
            return;
        };
        camera.update(|c| (c.x, c.y) = (w / 2.0 - b.x * c.k, h / 2.0 - b.y * c.k));
    };
    let fit = move || {
        let Some((w, h)) = size() else { return };
        let bounds = sim.with_value(|s| {
            s.bodies
                .iter()
                .fold(None, |acc: Option<(f64, f64, f64, f64)>, b| {
                    Some(acc.map_or((b.x, b.y, b.x, b.y), |(x0, y0, x1, y1)| {
                        (x0.min(b.x), y0.min(b.y), x1.max(b.x), y1.max(b.y))
                    }))
                })
        });
        let Some((x0, y0, x1, y1)) = bounds else {
            return;
        };
        // Room for address block frames and labels around the outer nodes.
        let pad = 2.0 * (HULL_PAD + 48.0);
        let k = ((w - pad) / (x1 - x0).max(1.0))
            .min((h - pad) / (y1 - y0).max(1.0))
            .clamp(ZOOM_MIN, 1.5);
        camera.set(Camera {
            k,
            x: w / 2.0 - (x0 + x1) / 2.0 * k,
            y: h / 2.0 - (y0 + y1) / 2.0 * k,
        });
    };
    let zoom = move |(px, py): (f64, f64), factor: f64| {
        camera.update(|c| {
            let k = (c.k * factor).clamp(ZOOM_MIN, ZOOM_MAX);
            let r = k / c.k;
            *c = Camera {
                x: px - (px - c.x) * r,
                y: py - (py - c.y) * r,
                k,
            };
        });
    };
    let zoom_center = move |factor: f64| {
        if let Some((w, h)) = size() {
            zoom((w / 2.0, h / 2.0), factor);
        }
    };

    // New nodes or edges, or a shown tab, restart the layout.
    let seen = StoredValue::new((0_usize, 0_usize));
    Effect::new(move |_| {
        let counts = graph.with(|g| (g.nodes.len(), g.edges.len()));
        if !active.get() {
            return;
        }
        if counts.0 < seen.get_value().0 {
            // A new capture: forget the old layout.
            selected.set(None);
            sim.update_value(|s| s.bodies.clear());
            centered.set_value(false);
        }
        seen.set_value(counts);
        if !centered.get_value()
            && let Some((w, h)) = size()
        {
            camera.set(Camera {
                x: w / 2.0,
                y: h / 2.0,
                k: 1.0,
            });
            centered.set_value(true);
        }
        layout.kick(0.3);
    });

    let node_at = |ev: &MouseEvent| {
        ev.target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .and_then(|e| e.closest("[data-node]").ok().flatten())
            .and_then(|e| e.get_attribute("data-node"))
            .and_then(|v| v.parse::<usize>().ok())
    };
    let on_down = move |ev: PointerEvent| {
        if ev.button() != 0 {
            return;
        }
        let from = local(&ev);
        grab.set_value(Some(match node_at(&ev) {
            Some(i) => Grab::Node {
                i,
                from,
                moved: false,
            },
            None => Grab::Pan {
                from,
                start: camera.get_untracked(),
                moved: false,
            },
        }));
        if let Some(el) = svg.get_untracked() {
            // Keep receiving moves when the pointer leaves the graph.
            let _ = el.set_pointer_capture(ev.pointer_id());
        }
    };
    let on_move = move |ev: PointerEvent| {
        let Some(g) = grab.get_value() else { return };
        let p = local(&ev);
        let far = |from: (f64, f64)| (p.0 - from.0).hypot(p.1 - from.1) > DRAG_SLOP;
        grab.set_value(Some(match g {
            Grab::Pan { from, start, moved } => {
                let moved = moved || far(from);
                if moved {
                    camera.set(Camera {
                        x: start.x + p.0 - from.0,
                        y: start.y + p.1 - from.1,
                        k: start.k,
                    });
                }
                Grab::Pan { from, start, moved }
            }
            Grab::Node { i, from, moved } => {
                let moved = moved || far(from);
                if moved {
                    let c = camera.get_untracked();
                    sim.update_value(|s| {
                        if let Some(b) = s.bodies.get_mut(i) {
                            *b = Body {
                                x: (p.0 - c.x) / c.k,
                                y: (p.1 - c.y) / c.k,
                                pinned: true,
                                ..Body::default()
                            };
                        }
                        s.target = 0.3;
                    });
                    layout.kick(0.3);
                }
                Grab::Node { i, from, moved }
            }
        }));
    };
    let on_up = move |_: PointerEvent| {
        let Some(g) = grab.get_value() else { return };
        grab.set_value(None);
        sim.update_value(|s| s.target = 0.0);
        match g {
            // A click: inspect the node, or close the inspector when it is open on it.
            Grab::Node {
                i, moved: false, ..
            } => selected.set((selected.get_untracked() != Some(i)).then_some(i)),
            Grab::Pan { moved: false, .. } => selected.set(None),
            _ => {}
        }
    };
    let release = move |i: usize| {
        sim.update_value(|s| {
            if let Some(b) = s.bodies.get_mut(i) {
                b.pinned = false;
            }
        });
        layout.kick(0.15);
    };
    let on_wheel = move |ev: WheelEvent| {
        ev.prevent_default();
        // Line mode (1) reports lines; count a line as 16px.
        let dy = ev.delta_y() * if ev.delta_mode() == 1 { 16.0 } else { 1.0 };
        zoom(local(&ev), (-dy * 0.0015).exp());
    };
    let on_key = move |ev: KeyboardEvent| match ev.key().as_str() {
        "+" | "=" => zoom_center(1.25),
        "-" => zoom_center(0.8),
        "0" => fit(),
        "Escape" => selected.set(None),
        _ => {}
    };

    let pos = move |i: usize| {
        frame.track();
        sim.with_value(|s| s.bodies.get(i).map_or((0.0, 0.0), |b| (b.x, b.y)))
    };
    let pinned = move |i: usize| {
        frame.track();
        sim.with_value(|s| s.bodies.get(i).is_some_and(|b| b.pinned))
    };
    let neighbors = Memo::new(move |_| {
        let sel = selected.get()?;
        Some(graph.with(|g| {
            g.edges
                .iter()
                .filter_map(|e| match (e.from == sel, e.to == sel) {
                    (true, _) => Some(e.to),
                    (_, true) => Some(e.from),
                    _ => None,
                })
                .chain([sel])
                .collect::<HashSet<usize>>()
        }))
    });
    let dim = move |i: usize| neighbors.with(|n| n.as_ref().is_some_and(|n| !n.contains(&i)));
    let select_and_center = move |i: usize| {
        selected.set(Some(i));
        center_on(i);
    };

    view! {
        <div class="graph-page">
            <div class="graph-canvas">
                <svg
                    node_ref=svg
                    class="graph-svg"
                    tabindex="0"
                    role="img"
                    aria-label="Capture graph. Drag to move, scroll or plus and minus keys to zoom, 0 to fit."
                    on:pointerdown=on_down
                    on:pointermove=on_move
                    on:pointerup=on_up
                    on:pointercancel=on_up
                    on:dblclick=move |ev| {
                        if let Some(i) = node_at(&ev) {
                            release(i);
                        }
                    }
                    on:wheel=on_wheel
                    on:keydown=on_key
                >
                    <g transform=move || {
                        let c = camera.get();
                        format!("translate({:.1},{:.1}) scale({:.4})", c.x, c.y, c.k)
                    }>
                        <g class="hulls">
                            {move || {
                                frame.track();
                                graph
                                    .with(|g| sim.with_value(|s| hulls(g, &s.bodies)))
                                    .into_iter()
                                    .map(|(label, x, y, w, h)| {
                                        view! {
                                            <g class="hull">
                                                <rect x=x y=y width=w height=h rx="18" />
                                                <text x={x + 14.0} y={y + 18.0}>
                                                    {label}
                                                </text>
                                            </g>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </g>
                        <g class="edges">
                            <For
                                each=move || graph.with(|g| 0..g.edges.len())
                                key=|i| *i
                                children=move |i| {
                                    let (from, to, rel) = graph
                                        .with_untracked(|g| {
                                            let e = &g.edges[i];
                                            (e.from, e.to, e.rel)
                                        });
                                    let width = move || {
                                        graph
                                            .with(|g| {
                                                g.edges
                                                    .get(i)
                                                    .map_or(
                                                        1.0,
                                                        |e| 1.0 + (e.packets as f64).log2().clamp(0.0, 8.0) / 2.0,
                                                    )
                                            })
                                    };
                                    view! {
                                        <line
                                            class="edge"
                                            data-rel=rel_attr(rel)
                                            class:dim=move || selected.get().is_some_and(|s| s != from && s != to)
                                            x1=move || pos(from).0
                                            y1=move || pos(from).1
                                            x2=move || pos(to).0
                                            y2=move || pos(to).1
                                            stroke-width=width
                                        />
                                    }
                                }
                            />
                        </g>
                        <g class="nodes">
                            <For
                                each=move || graph.with(|g| 0..g.nodes.len())
                                key=|i| *i
                                children=move |i| {
                                    view! {
                                        <g
                                            class=graph.with_untracked(|g| kind_class(g.nodes[i].kind))
                                            data-node=i
                                            transform=move || {
                                                let (x, y) = pos(i);
                                                format!("translate({x:.1},{y:.1})")
                                            }
                                            class:dim=move || dim(i)
                                            class:selected=move || selected.get() == Some(i)
                                            class:pinned=move || pinned(i)
                                            class:flagged=move || flagged(i)
                                        >
                                            {node_shape(graph, i)}
                                        </g>
                                    }
                                }
                            />
                        </g>
                    </g>
                </svg>
                <Show when=move || graph.with(|g| g.nodes.is_empty())>
                    <p class="graph-empty">"The graph builds itself as packets arrive."</p>
                </Show>
                <div class="graph-tools">
                    <button class="btn btn-secondary btn-sm" aria-label="Zoom in" on:click=move |_| zoom_center(1.25)>
                        "+"
                    </button>
                    <button class="btn btn-secondary btn-sm" aria-label="Zoom out" on:click=move |_| zoom_center(0.8)>
                        "−"
                    </button>
                    <button class="btn btn-secondary btn-sm" on:click=move |_| fit()>
                        "Fit"
                    </button>
                    <span class="zoom-level">{move || format!("{:.0}%", camera.get().k * 100.0)}</span>
                </div>
                <p class="graph-hint">
                    "Drag a node to pin it, double-click to release it. Drag the background to pan, scroll to zoom, click a node to inspect it."
                </p>
            </div>
            <aside class="graph-side">
                // The inspector comes first: it answers the click the user just made.
                <Show when=move || selected.get().is_some()>
                    <Inspector
                        graph
                        selected
                        pinned=Signal::derive(move || selected.get().is_some_and(pinned))
                        on_select=Callback::new(select_and_center)
                        on_center=Callback::new(move |()| {
                            if let Some(i) = selected.get_untracked() {
                                center_on(i);
                            }
                        })
                        on_pin=Callback::new(move |()| {
                            let Some(i) = selected.get_untracked() else { return };
                            if pinned(i) {
                                release(i);
                            } else {
                                sim.update_value(|s| {
                                    if let Some(b) = s.bodies.get_mut(i) {
                                        b.pinned = true;
                                    }
                                });
                                frame.update(|f| *f += 1);
                            }
                        })
                    />
                </Show>
                <section class="ontology" aria-label="Ontology">
                    <h3>"Ontology"</h3>
                    {move || graph.with(ontology)}
                </section>
                <div class="log-head">
                    <h3>"Build log"</h3>
                    <p class="text-small text-muted">"Each fact the graph learned, newest first. Click to show its node."</p>
                </div>
                <ol class="list log">
                    <For
                        each=move || {
                            graph.with(|g| g.log.iter().cloned().enumerate().rev().take(LOG_ROWS).collect::<Vec<_>>())
                        }
                        key=|(i, _)| *i
                        children=move |(_, entry)| {
                            let node = entry.node;
                            view! {
                                <li class="list-item">
                                    <button type="button" class="log-entry" on:click=move |_| select_and_center(node)>
                                        <time>{entry.time}</time>
                                        <span>{entry.text}</span>
                                    </button>
                                </li>
                            }
                        }
                    />
                </ol>
            </aside>
        </div>
    }
}

fn kind_class(kind: Kind) -> &'static str {
    match kind {
        Kind::Host => "node node-host",
        Kind::Service { .. } => "node node-service",
        Kind::Process { .. } => "node node-process",
    }
}

fn rel_attr(rel: Rel) -> &'static str {
    match rel {
        Rel::Serves => "serves",
        Rel::Connects => "connects",
        Rel::Exchanges => "direct",
        Rel::RunsOn => "runs-on",
    }
}

/// Width of a service box: IBM Plex Mono at 12px advances 7.2px per glyph.
fn label_width(label: &str) -> f64 {
    label.chars().count() as f64 * 7.2 + 16.0
}

fn node_shape(graph: RwSignal<Graph>, i: usize) -> AnyView {
    let (label, kind) = graph.with_untracked(|g| (g.nodes[i].label.clone(), g.nodes[i].kind));
    match kind {
        Kind::Host => {
            let r =
                move || graph.with(|g| 7.0 + (g.nodes[i].packets as f64).log2().clamp(0.0, 10.0));
            // A host reached by name shows the name, and the address in the note.
            let name = move || graph.with(|g| g.nodes[i].name.clone());
            let note = move || {
                graph.with(|g| {
                    let n = &g.nodes[i];
                    let parts: Vec<String> = n
                        .name
                        .as_ref()
                        .map(|_| n.label.clone())
                        .into_iter()
                        .chain(n.iface.as_ref().map(|f| iface_text(f.local, &f.name)))
                        .collect();
                    parts.join(" · ")
                })
            };
            view! {
                <circle r=r />
                <text class="node-label" y=move || r() + 14.0 text-anchor="middle">
                    {move || name().unwrap_or_else(|| label.clone())}
                </text>
                <text class="node-note" y=move || r() + 27.0 text-anchor="middle">
                    {note}
                </text>
            }
            .into_any()
        }
        Kind::Service { .. } => {
            let w = label_width(&label);
            view! {
                <rect x={-w / 2.0} y="-12" width=w height="24" rx="6" />
                <text class="node-label" y="4" text-anchor="middle">
                    {label}
                </text>
            }
            .into_any()
        }
        Kind::Process { .. } => view! {
            <rect x="-6" y="-6" width="12" height="12" rx="2" transform="rotate(45)" />
            <text class="node-label" x="13" y="4">
                {label}
            </text>
        }
        .into_any(),
    }
}

fn iface_text(local: bool, name: &str) -> String {
    if local {
        format!("local · {name}")
    } else {
        format!("via {name}")
    }
}

#[component]
fn Inspector(
    graph: RwSignal<Graph>,
    selected: RwSignal<Option<usize>>,
    pinned: Signal<bool>,
    on_select: Callback<usize>,
    on_center: Callback<()>,
    on_pin: Callback<()>,
) -> impl IntoView {
    let node = move || {
        selected
            .get()
            .and_then(|i| graph.with(|g| g.nodes.get(i).cloned()))
    };
    let field = move |f: fn(&Graph, usize, &Node) -> Option<String>| {
        move || {
            let i = selected.get()?;
            graph.with(|g| g.nodes.get(i).and_then(|n| f(g, i, n)))
        }
    };
    let kind = field(|g, _, n| {
        Some(match n.kind {
            Kind::Host => "Host".to_owned(),
            Kind::Service { host } => format!("Service on {}", g.nodes[host].label),
            Kind::Process { host } => format!("Process on {}", g.nodes[host].label),
        })
    });
    let traffic = field(|_, _, n| Some(format!("{} packets · {}", n.packets, bytes(n.bytes))));
    let block = field(|_, _, n| match (n.kind, n.scope) {
        (Kind::Host, Some(s)) => Some(format!("{} · {}", s.cidr, s.kind)),
        (Kind::Host, None) => Some("public".to_owned()),
        _ => None,
    });
    let iface = field(|_, _, n| n.iface.as_ref().map(|f| iface_text(f.local, &f.name)));
    let first = field(|g, i, _| {
        g.log
            .iter()
            .find(|e| e.node == i)
            .map(|e| format!("{} s", e.time))
    });
    let relations = move || {
        let Some(i) = selected.get() else {
            return Vec::new();
        };
        graph.with(|g| {
            // (other node, relation text, packets)
            let mut list: Vec<(usize, String, u64)> = g
                .edges
                .iter()
                .filter_map(|e| {
                    let (text, other) = if e.from == i {
                        (format!("{} →", e.rel.name()), e.to)
                    } else if e.to == i {
                        (format!("← {}", e.rel.name()), e.from)
                    } else {
                        return None;
                    };
                    let text = if e.proto.is_empty() || e.rel != Rel::Exchanges {
                        text
                    } else {
                        format!("{text} {}", e.proto)
                    };
                    Some((other, text, e.packets))
                })
                .collect();
            list.sort_by_key(|r| std::cmp::Reverse(r.2));
            list.truncate(RELATION_ROWS);
            list
        })
    };
    view! {
        <section class="inspector" aria-label="Selected node" aria-live="polite">
            <div class="inspector-head">
                <h3>
                    {move || {
                        node().map(|n| match n.name {
                            Some(name) => format!("{name} ({})", n.label),
                            None => n.label,
                        })
                    }}
                </h3>
                <button type="button" class="btn btn-ghost btn-sm" on:click=move |_| selected.set(None)>
                    "Close"
                </button>
            </div>
            <dl class="facts">
                <dt>"Class"</dt>
                <dd>{kind}</dd>
                <dt>"Traffic"</dt>
                <dd>{traffic}</dd>
                <dt>"First seen"</dt>
                <dd>{first}</dd>
                <Show when=move || block().is_some()>
                    <dt>"Address"</dt>
                    <dd>{block}</dd>
                </Show>
                <Show when=move || iface().is_some()>
                    <dt>"Interface"</dt>
                    <dd>{iface}</dd>
                </Show>
            </dl>
            <p class="tip-title">"Relations"</p>
            <ul class="relations">
                <For
                    each=relations
                    key=|r| (r.0, r.1.clone())
                    children=move |(other, text, _)| {
                        let label = graph.with_untracked(|g| g.nodes[other].label.clone());
                        let count = move || {
                            let i = selected.get()?;
                            Some(
                                graph
                                    .with(|g| {
                                        g.edges
                                            .iter()
                                            .filter(|e| (e.from, e.to) == (i, other) || (e.from, e.to) == (other, i))
                                            .map(|e| e.packets)
                                            .sum::<u64>()
                                    }),
                            )
                        };
                        view! {
                            <li>
                                <span class="rel">{text}</span>
                                <button type="button" class="link" on:click=move |_| on_select.run(other)>
                                    {label}
                                </button>
                                <span class="num">{count}</span>
                            </li>
                        }
                    }
                />
            </ul>
            <div class="inspector-actions">
                <button type="button" class="btn btn-secondary btn-sm" on:click=move |_| on_center.run(())>
                    "Center"
                </button>
                <button type="button" class="btn btn-secondary btn-sm" on:click=move |_| on_pin.run(())>
                    {move || if pinned.get() { "Release" } else { "Pin" }}
                </button>
            </div>
        </section>
    }
}

fn ontology(g: &Graph) -> impl IntoView + use<> {
    let glyph_line = |rel: &'static str| {
        view! {
            <svg width="28" height="12" aria-hidden="true">
                <line class="edge" data-rel=rel x1="2" y1="6" x2="26" y2="6" stroke-width="2" />
            </svg>
        }
        .into_any()
    };
    let row = |glyph: AnyView, term: &'static str, def: &'static str, total: usize| {
        view! {
            <dt>{glyph}</dt>
            <dd>
                <span class="term">{term}</span>
                <br />
                <span class="def">{def}</span>
            </dd>
            <dd class="total">{total}</dd>
        }
    };
    let host = view! {
        <svg width="28" height="20" aria-hidden="true" class="node-host">
            <circle cx="14" cy="10" r="7" />
        </svg>
    }
    .into_any();
    let service = view! {
        <svg width="28" height="20" aria-hidden="true" class="node-service">
            <rect x="2" y="4" width="24" height="12" rx="4" />
        </svg>
    }
    .into_any();
    let process = view! {
        <svg width="28" height="20" aria-hidden="true" class="node-process">
            <rect x="9" y="5" width="10" height="10" rx="2" transform="rotate(45 14 10)" />
        </svg>
    }
    .into_any();
    let hull = view! {
        <svg width="28" height="20" aria-hidden="true" class="hull">
            <rect x="2" y="2" width="24" height="16" rx="5" />
        </svg>
    }
    .into_any();
    let blocks: HashSet<&str> = g.nodes.iter().filter_map(block).map(|s| s.cidr).collect();
    view! {
        <dl>
            {row(host, "Host", "IP address seen in traffic", g.hosts())}
            {row(
                service,
                "Service",
                "Protocol and port a host offers",
                g.count_kind(|k| matches!(k, Kind::Service { .. })),
            )}
            {row(
                process,
                "Process",
                "Local program that owns a socket",
                g.count_kind(|k| matches!(k, Kind::Process { .. })),
            )}
            {row(hull, "Address block", "Private, loopback or link-local CIDR", blocks.len())}
            {row(glyph_line("serves"), "serves", "Host or process to its service", g.count(Rel::Serves))}
            {row(glyph_line("connects"), "connects to", "Client to a service", g.count(Rel::Connects))}
            {row(glyph_line("direct"), "exchanges", "Traffic without ports (ICMP, ARP)", g.count(Rel::Exchanges))}
            {row(glyph_line("runs-on"), "runs on", "Process to its host", g.count(Rel::RunsOn))}
        </dl>
    }
}
