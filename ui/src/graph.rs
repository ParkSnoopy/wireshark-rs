//! Network graph page: the capture graph as an interactive force layout
//! (drag nodes or the background, wheel to zoom, click a node to inspect),
//! its ontology, a node inspector and the build log.
//!
//! Each host is one card that lists what is known about it: names,
//! address block, interface, traffic, the services it offers and the
//! programs on it. Edges join hosts and name the services they carry.
//! Hosts in the same special-purpose address block (10.0.0.0/8, fe80::/10,
//! ...) are pulled together and framed with the block's CIDR.

use std::collections::{BTreeMap, HashSet};

use leptos::ev::{KeyboardEvent, MouseEvent, PointerEvent, WheelEvent};
use leptos::prelude::*;
use leptos::svg::Svg;
use wasm_bindgen::JsCast;

use crate::model::{Domains, Graph, Node, Part, Ptrs, Rel, Scope, bytes, ptr_of};
use crate::tip::{Card, Tip, facts};

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
const REPULSION: f64 = 2500.0;
/// Bodies farther apart than this do not repel each other.
const REPULSION_RANGE: f64 = 800.0;
const SPRING: f64 = 0.3;
const GRAVITY: f64 = 0.02;
/// Pull of hosts toward the middle of their address block.
const CLUSTER: f64 = 0.05;
/// Share of an overlap between two cards removed per tick.
const COLLIDE: f64 = 0.5;
/// Least space between two cards.
const CARD_GAP: f64 = 24.0;
/// Pointer travel in px that turns a click into a drag.
const DRAG_SLOP: f64 = 3.0;
/// Space between an address block frame and its cards.
const HULL_PAD: f64 = 16.0;
/// Height of the CIDR label band at the top of a frame.
const HULL_LABEL: f64 = 24.0;
/// Card width, and the characters a line holds at 11px IBM Plex Mono
/// (6.6px each) inside the padding.
const CARD_W: f64 = 220.0;
const CARD_CHARS: usize = 30;
const CARD_PAD: f64 = 10.0;
/// Baseline of the title from the card top, and the step between lines.
const CARD_TITLE: f64 = 22.0;
const CARD_LINE: f64 = 15.0;
/// Services and processes listed on a card before "+N more".
const SERVICE_ROWS: usize = 6;
const PROCESS_ROWS: usize = 4;
/// Services named on an edge before "+N".
const EDGE_PROTOS: usize = 2;

#[derive(Clone, Copy, Default)]
struct Body {
    x: f64,
    y: f64,
    vx: f64,
    vy: f64,
    /// Set by the Pin button: the layout leaves the body where it is.
    pinned: bool,
}

#[derive(Default)]
struct Sim {
    bodies: Vec<Body>,
    /// Body under the pointer during a drag: it follows the pointer, not the
    /// layout, and moves freely again on release.
    held: Option<usize>,
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
    let held = s.held;
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
    // Cards are wide: push overlapping ones apart along the shorter way out.
    let sizes: Vec<(f64, f64)> = g.nodes.iter().map(card_size).collect();
    let fixed = |i: usize, b: &[Body]| b[i].pinned || held == Some(i);
    for i in 0..b.len().min(sizes.len()) {
        for j in i + 1..b.len().min(sizes.len()) {
            let (dx, dy) = (b[j].x - b[i].x, b[j].y - b[i].y);
            let ox = (sizes[i].0 + sizes[j].0) / 2.0 + CARD_GAP - dx.abs();
            let oy = (sizes[i].1 + sizes[j].1) / 2.0 + CARD_GAP - dy.abs();
            if ox <= 0.0 || oy <= 0.0 {
                continue;
            }
            let (px, py) = if ox < oy {
                (ox.copysign(dx) * COLLIDE, 0.0)
            } else {
                (0.0, oy.copysign(dy) * COLLIDE)
            };
            let (fi, fj) = match (fixed(i, b), fixed(j, b)) {
                (true, true) => continue,
                (true, false) => (0.0, 1.0),
                (false, true) => (1.0, 0.0),
                (false, false) => (0.5, 0.5),
            };
            b[i].x -= px * fi;
            b[i].y -= py * fi;
            b[j].x += px * fj;
            b[j].y += py * fj;
        }
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
    for (i, body) in b.iter_mut().enumerate() {
        if body.pinned || held == Some(i) {
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

/// Gives new hosts a start position on a golden-angle spiral, so none
/// lands on another.
fn place_new(s: &mut Sim, g: &Graph) {
    for i in s.bodies.len()..g.nodes.len() {
        let angle = i as f64 * 2.399_963;
        let r = 160.0 * (i as f64).sqrt();
        s.bodies.push(Body {
            x: r * angle.cos(),
            y: r * angle.sin(),
            ..Body::default()
        });
    }
}

fn rest_length(rel: Rel) -> f64 {
    match rel {
        Rel::Exchanges => 300.0,
        Rel::Connects => 340.0,
    }
}

/// Address block a host is framed in. Multicast and broadcast are not networks a host is in.
fn block(n: &Node) -> Option<Scope> {
    n.scope
        .filter(|s| !matches!(s.kind, "multicast" | "broadcast"))
}

/// Lines a card shows under its title: three fixed ones, then services
/// and processes, each list cut to its row limit plus a "+N more" line.
fn card_rows(n: &Node) -> usize {
    let shown = |len: usize, max: usize| if len > max { max + 1 } else { len };
    3 + shown(n.services.len(), SERVICE_ROWS) + shown(n.processes.len(), PROCESS_ROWS)
}

fn card_height(rows: usize) -> f64 {
    CARD_TITLE + 6.0 + CARD_LINE * rows as f64 + CARD_PAD
}

/// Width and height of the card of `n`, in world units.
fn card_size(n: &Node) -> (f64, f64) {
    (CARD_W, card_height(card_rows(n)))
}

/// `s` cut to `max` characters, with an ellipsis when cut.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// One card line: class, text, and a count shown at the right edge.
type CardLine = (&'static str, String, String);

/// Title and lines of the card of `n`. Every line is present whatever is
/// known, so the size matches `card_rows`.
fn card_content(n: &Node, ptr: Option<&str>) -> (String, Vec<CardLine>) {
    let title = n.name.clone().unwrap_or_else(|| n.label.clone());
    let names: Vec<&str> = n
        .name
        .as_ref()
        .map(|_| n.label.as_str())
        .into_iter()
        .chain(ptr)
        .collect();
    let names = if names.is_empty() {
        "no reverse name".to_owned()
    } else {
        names.join(" · ")
    };
    let block = n
        .scope
        .map_or("public".to_owned(), |s| format!("{} {}", s.kind, s.cidr));
    let place = match &n.iface {
        Some(f) => format!("{block} · {}", iface_text(f.local, &f.name)),
        None => block,
    };
    let mut lines: Vec<CardLine> = vec![
        ("card-sub", clip(&names, CARD_CHARS), String::new()),
        ("card-sub", clip(&place, CARD_CHARS), String::new()),
        (
            "card-sub",
            format!("{} packets · {}", n.packets, bytes(n.bytes)),
            String::new(),
        ),
    ];
    let mut list = |parts: &[Part], mark: &str, class: &'static str, max: usize, what: &str| {
        for p in parts.iter().take(max) {
            let count = p.packets.to_string();
            // Room for the mark, a space, a gap and the count.
            let label = clip(&p.label, CARD_CHARS.saturating_sub(count.len() + 3));
            lines.push((class, format!("{mark} {label}"), count));
        }
        if parts.len() > max {
            let more = format!("+{} more {what}", parts.len() - max);
            lines.push(("card-more", more, String::new()));
        }
    };
    list(&n.services, "▸", "card-service", SERVICE_ROWS, "services");
    list(&n.processes, "◆", "card-process", PROCESS_ROWS, "processes");
    (clip(&title, CARD_CHARS - 2), lines)
}

/// Services on an edge: the first `EDGE_PROTOS`, then "+N".
fn edge_label(protos: &[String]) -> String {
    let mut text = protos
        .iter()
        .take(EDGE_PROTOS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if protos.len() > EDGE_PROTOS {
        text.push_str(&format!(" +{}", protos.len() - EDGE_PROTOS));
    }
    text
}

/// Corners of the area the cards cover: `(x0, y0, x1, y1)`.
fn extent(n: &Node, b: &Body) -> (f64, f64, f64, f64) {
    let (w, h) = card_size(n);
    (b.x - w / 2.0, b.y - h / 2.0, b.x + w / 2.0, b.y + h / 2.0)
}

/// Frames around each address block: `(label, x, y, width, height)` in world units.
fn hulls(g: &Graph, bodies: &[Body]) -> Vec<(String, f64, f64, f64, f64)> {
    let mut boxes: BTreeMap<&str, (&str, f64, f64, f64, f64)> = BTreeMap::new();
    for (n, b) in g.nodes.iter().zip(bodies) {
        let Some(s) = block(n) else { continue };
        let (x0, y0, x1, y1) = extent(n, b);
        let e = boxes.entry(s.cidr).or_insert((s.kind, x0, y0, x1, y1));
        *e = (e.0, e.1.min(x0), e.2.min(y0), e.3.max(x1), e.4.max(y1));
    }
    boxes
        .into_iter()
        .map(|(cidr, (kind, x0, y0, x1, y1))| {
            // A label band on top.
            let (x, y) = (x0 - HULL_PAD, y0 - HULL_PAD - HULL_LABEL);
            (
                format!("{cidr} · {kind}"),
                x,
                y,
                x1 - x0 + 2.0 * HULL_PAD,
                y1 - y0 + 2.0 * HULL_PAD + HULL_LABEL,
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
    ptrs: RwSignal<Ptrs>,
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
    // Node under the pointer and the pointer, for the hover card.
    let hover = RwSignal::new(None::<usize>);
    let cursor = RwSignal::new((0, 0));
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
        let bounds = graph.with_untracked(|g| {
            sim.with_value(|s| {
                g.nodes
                    .iter()
                    .zip(&s.bodies)
                    .map(|(n, b)| extent(n, b))
                    .reduce(|a, b| (a.0.min(b.0), a.1.min(b.1), a.2.max(b.2), a.3.max(b.3)))
            })
        });
        let Some((x0, y0, x1, y1)) = bounds else {
            return;
        };
        // Room for address block frames and their labels around the outer cards.
        let pad = 2.0 * (HULL_PAD + HULL_LABEL + 8.0);
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
        hover.set(None);
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
        let Some(g) = grab.get_value() else {
            let i = node_at(&ev);
            if hover.get_untracked() != i {
                hover.set(i);
            }
            cursor.set((ev.client_x(), ev.client_y()));
            return;
        };
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
                            // A pinned node stays pinned at its new place.
                            *b = Body {
                                x: (p.0 - c.x) / c.k,
                                y: (p.1 - c.y) / c.k,
                                pinned: b.pinned,
                                ..Body::default()
                            };
                        }
                        s.held = Some(i);
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
        sim.update_value(|s| {
            s.target = 0.0;
            s.held = None;
        });
        // Let the released node settle among its neighbors.
        layout.kick(0.15);
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
                    on:pointerleave=move |_| hover.set(None)
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
                                    let dim_edge = move || selected.get().is_some_and(|s| s != from && s != to);
                                    let mid = move || {
                                        let (a, b) = (pos(from), pos(to));
                                        ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0)
                                    };
                                    let label = move || graph.with(|g| g.edges.get(i).map(|e| edge_label(&e.protos)));
                                    view! {
                                        <line
                                            class="edge"
                                            data-rel=rel_attr(rel)
                                            class:dim=dim_edge
                                            x1=move || pos(from).0
                                            y1=move || pos(from).1
                                            x2=move || pos(to).0
                                            y2=move || pos(to).1
                                            stroke-width=width
                                        />
                                        <text
                                            class="edge-label"
                                            class:dim=dim_edge
                                            x=move || mid().0
                                            y=move || mid().1 + 4.0
                                            text-anchor="middle"
                                        >
                                            {label}
                                        </text>
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
                                            class="node node-card"
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
                                            {node_card_view(graph, ptrs, i)}
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
                    "Drag a node to move it. Click it to inspect it; Pin there keeps it in place, double-click releases it. Drag the background to pan, scroll to zoom."
                </p>
            </div>
            {move || {
                let i = hover.get()?;
                let (title, list, flag) = graph
                    .with(|g| ptrs.with(|p| domains.with(|d| node_card(g, i, p, d))))?;
                Some(view! {
                    <Tip cursor>
                        <h4>{title}</h4>
                        {flag.map(|why| view! { <p class="tip-flag">{why}</p> })}
                        {facts("tip-grid", list)}
                        <p class="tip-hint">"Click to inspect"</p>
                    </Tip>
                })
            }}
            <aside class="graph-side">
                // The inspector comes first: it answers the click the user just made.
                <Show when=move || selected.get().is_some()>
                    <Inspector
                        graph
                        domains
                        ptrs
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

fn rel_attr(rel: Rel) -> &'static str {
    match rel {
        Rel::Connects => "connects",
        Rel::Exchanges => "direct",
    }
}

/// The card of host `i`, centred on its position: title, names, address
/// block and interface, traffic, services and processes.
fn node_card_view(graph: RwSignal<Graph>, ptrs: RwSignal<Ptrs>, i: usize) -> impl IntoView {
    let content = move || {
        graph.with(|g| ptrs.with(|p| card_content(&g.nodes[i], ptr_of(p, &g.nodes[i].label))))
    };
    let h = move || graph.with(|g| card_size(&g.nodes[i]).1);
    let (x0, x1) = (-CARD_W / 2.0, CARD_W / 2.0);
    view! {
        <rect
            class="card-box"
            x=x0
            y=move || -h() / 2.0
            width=CARD_W
            height=h
            rx="8"
        />
        <rect class="card-band" x=x0 y=move || -h() / 2.0 width="4" height=h rx="2" />
        {move || {
            let (title, lines) = content();
            let top = -h() / 2.0;
            let lines = lines
                .into_iter()
                .enumerate()
                .map(|(row, (class, text, count))| {
                    let y = top + CARD_TITLE + 6.0 + CARD_LINE * (row as f64 + 0.75);
                    view! {
                        <text class=class x=x0 + CARD_PAD + 2.0 y=y>
                            {text}
                        </text>
                        <text class="card-count" x=x1 - CARD_PAD y=y text-anchor="end">
                            {count}
                        </text>
                    }
                })
                .collect_view();
            view! {
                <text class="card-title" x=x0 + CARD_PAD + 2.0 y=top + CARD_TITLE>
                    {title}
                </text>
                {lines}
            }
        }}
    }
}

fn iface_text(local: bool, name: &str) -> String {
    if local {
        format!("local · {name}")
    } else {
        format!("via {name}")
    }
}

/// `parts` as "label (packets)", busiest first, or "none".
fn parts_text(parts: &[Part]) -> String {
    let mut list: Vec<&Part> = parts.iter().collect();
    list.sort_by_key(|p| std::cmp::Reverse(p.packets));
    if list.is_empty() {
        return "none".to_owned();
    }
    list.iter()
        .map(|p| format!("{} ({})", p.label, p.packets))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Facts about node `i`, for the inspector and the hover card.
fn node_facts(g: &Graph, i: usize, ptrs: &Ptrs, domains: &Domains) -> Vec<(&'static str, String)> {
    let n = &g.nodes[i];
    let mut list = vec![(
        "Traffic",
        format!("{} packets · {}", n.packets, bytes(n.bytes)),
    )];
    if let Some(e) = g.log.iter().find(|e| e.node == i) {
        list.push(("First seen", format!("{} s", e.time)));
    }
    let block = n
        .scope
        .map_or("public".to_owned(), |s| format!("{} · {}", s.cidr, s.kind));
    list.push(("Address", block));
    if let Some(p) = ptr_of(ptrs, &n.label) {
        list.push(("PTR", p.to_owned()));
    }
    list.push(("Services", parts_text(&n.services)));
    list.push(("Processes", parts_text(&n.processes)));
    if let Some(f) = &n.iface {
        list.push(("Interface", iface_text(f.local, &f.name)));
    }
    if let Some(d) = n.name.as_ref().and_then(|name| domains.get(name)) {
        list.push(("Domain", d.summary()));
    }
    list
}

/// Title, facts and recent-domain warning of the hover card for node `i`.
fn node_card(g: &Graph, i: usize, ptrs: &Ptrs, domains: &Domains) -> Option<Card> {
    let n = g.nodes.get(i)?;
    let title = match &n.name {
        Some(name) => format!("{name} ({})", n.label),
        None => n.label.clone(),
    };
    let flag = n
        .name
        .as_ref()
        .and_then(|name| Some(format!("⚠ {name} was {}", domains.get(name)?.flag()?)));
    let mut list = node_facts(g, i, ptrs, domains);
    let relations = g.edges.iter().filter(|e| e.from == i || e.to == i).count();
    list.push(("Relations", relations.to_string()));
    Some((title, list, flag))
}

#[component]
fn Inspector(
    graph: RwSignal<Graph>,
    domains: RwSignal<Domains>,
    ptrs: RwSignal<Ptrs>,
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
    let fact_list = move || {
        let i = selected.get()?;
        let list = graph.with(|g| {
            ptrs.with(|p| domains.with(|d| (i < g.nodes.len()).then(|| node_facts(g, i, p, d))))
        })?;
        Some(facts("facts", list))
    };
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
                    Some((
                        other,
                        format!("{text} {}", edge_label(&e.protos)),
                        e.packets,
                    ))
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
            {fact_list}
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
        <svg width="28" height="20" aria-hidden="true" class="node">
            <rect class="card-box" x="2" y="2" width="24" height="16" rx="3" />
            <rect class="card-band" x="2" y="2" width="3" height="16" rx="1.5" />
        </svg>
    }
    .into_any();
    let mark = |glyph: &'static str, class: &'static str| {
        view! {
            <svg width="28" height="20" aria-hidden="true">
                <text class=class x="14" y="14" text-anchor="middle">
                    {glyph}
                </text>
            </svg>
        }
        .into_any()
    };
    let hull = view! {
        <svg width="28" height="20" aria-hidden="true" class="hull">
            <rect x="2" y="2" width="24" height="16" rx="5" />
        </svg>
    }
    .into_any();
    let blocks: HashSet<&str> = g.nodes.iter().filter_map(block).map(|s| s.cidr).collect();
    view! {
        <dl>
            {row(host, "Host", "Card for an IP address seen in traffic", g.hosts())}
            {row(
                mark("▸", "card-service"),
                "Service",
                "Protocol and port a host offers, listed on its card",
                g.services(),
            )}
            {row(
                mark("◆", "card-process"),
                "Process",
                "Local program with a socket on the host, listed on its card",
                g.processes(),
            )}
            {row(hull, "Address block", "Private, loopback or link-local CIDR", blocks.len())}
            {row(glyph_line("connects"), "connects to", "Client host to server host, labelled with the services", g.count(Rel::Connects))}
            {row(glyph_line("direct"), "exchanges", "Traffic without ports (ICMP, ARP)", g.count(Rel::Exchanges))}
        </dl>
    }
}
