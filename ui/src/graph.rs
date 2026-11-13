//! Network graph page: the capture graph drawn as hosts and services, its
//! ontology (node classes and relations), and the build log.

use std::f64::consts::{PI, TAU};

use leptos::prelude::*;

use crate::model::{Graph, Kind, Rel};

const W: f64 = 760.0;
const H: f64 = 560.0;
const HOST_RING: f64 = 160.0;
const SERVICE_RING: f64 = 235.0;
/// shortcut: only the busiest hosts and services are drawn so labels stay
/// readable; add zoom and pan if bigger graphs matter.
const MAX_HOSTS: usize = 16;
const MAX_SERVICES: usize = 3;
/// Build log entries rendered, newest first.
const LOG_ROWS: usize = 300;

#[component]
pub fn GraphPage(graph: RwSignal<Graph>, active: Signal<bool>) -> impl IntoView {
    view! {
        <div class="graph-page">
            <div class="graph-canvas">
                // Drawn only while the tab is visible: the layout runs on every packet batch.
                {move || active.get().then(|| graph.with(draw))}
            </div>
            <aside class="graph-side">
                <section class="ontology" aria-label="Ontology">
                    <h3>"Ontology"</h3>
                    {move || graph.with(ontology)}
                </section>
                <div class="log-head">
                    <h3>"Build log"</h3>
                    <p class="text-small text-muted">"Each fact the graph learned, newest first."</p>
                </div>
                <ol class="list log">
                    <For
                        each=move || {
                            graph
                                .with(|g| {
                                    g.log
                                        .iter()
                                        .cloned()
                                        .enumerate()
                                        .rev()
                                        .take(LOG_ROWS)
                                        .collect::<Vec<_>>()
                                })
                        }
                        key=|(i, _)| *i
                        children=|(_, entry)| {
                            view! {
                                <li class="list-item">
                                    <time>{entry.time}</time>
                                    <span>{entry.text}</span>
                                </li>
                            }
                        }
                    />
                </ol>
            </aside>
        </div>
    }
}

fn ontology(g: &Graph) -> impl IntoView + use<> {
    let services = g.nodes.len() - g.hosts();
    let glyph_line = |class: &'static str, rel: &'static str| {
        view! {
            <svg width="28" height="12" aria-hidden="true">
                <line class=class data-rel=rel x1="2" y1="6" x2="26" y2="6" stroke-width="2" />
            </svg>
        }
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
            <circle cx="14" cy="10" r="8" />
        </svg>
    }
    .into_any();
    let service = view! {
        <svg width="28" height="20" aria-hidden="true" class="node-service">
            <rect x="2" y="4" width="24" height="12" rx="4" />
        </svg>
    }
    .into_any();
    view! {
        <dl>
            {row(host, "Host", "IP address seen in traffic", g.hosts())}
            {row(service, "Service", "Protocol and port a host offers", services)}
            {row(
                glyph_line("edge", "serves").into_any(),
                "serves",
                "Host to its service",
                g.count(Rel::Serves),
            )}
            {row(
                glyph_line("edge", "connects").into_any(),
                "connects to",
                "Client host to a service",
                g.count(Rel::Connects),
            )}
            {row(
                glyph_line("edge", "direct").into_any(),
                "exchanges",
                "Traffic without ports (ICMP, ARP)",
                g.count(Rel::Exchanges),
            )}
        </dl>
    }
}

/// Width of a service box: IBM Plex Mono at 12px advances 7.2px per glyph.
fn label_width(label: &str) -> f64 {
    label.len() as f64 * 7.2 + 16.0
}

/// Places hosts on a ring and each host's services just outside it.
fn layout(g: &Graph) -> Vec<Option<(f64, f64)>> {
    let mut pos = vec![None; g.nodes.len()];
    let mut hosts: Vec<usize> = (0..g.nodes.len())
        .filter(|&i| g.nodes[i].kind == Kind::Host)
        .collect();
    hosts.sort_by_key(|&i| std::cmp::Reverse(g.nodes[i].packets));
    hosts.truncate(MAX_HOSTS);
    let (cx, cy) = (W / 2.0, H / 2.0);
    let n = hosts.len() as f64;
    for (k, &h) in hosts.iter().enumerate() {
        let angle = TAU * k as f64 / n - PI / 2.0;
        let ring = if hosts.len() == 1 { 0.0 } else { HOST_RING };
        pos[h] = Some((cx + ring * angle.cos(), cy + ring * angle.sin()));

        let mut services: Vec<usize> = (0..g.nodes.len())
            .filter(|&i| g.nodes[i].kind == Kind::Service { host: h })
            .collect();
        services.sort_by_key(|&i| std::cmp::Reverse(g.nodes[i].packets));
        services.truncate(MAX_SERVICES);
        // Neighbours sit one label width (plus a gap) apart along the arc.
        let widest = services
            .iter()
            .map(|&s| label_width(&g.nodes[s].label))
            .fold(0.0, f64::max);
        let (ring, spread) = if hosts.len() == 1 {
            (110.0, TAU / services.len().max(1) as f64)
        } else {
            (SERVICE_RING, (widest + 12.0) / SERVICE_RING)
        };
        let middle = (services.len() as f64 - 1.0) / 2.0;
        for (j, &s) in services.iter().enumerate() {
            let a = angle + (j as f64 - middle) * spread;
            pos[s] = Some((cx + ring * a.cos(), cy + ring * a.sin()));
        }
    }
    pos
}

fn draw(g: &Graph) -> AnyView {
    if g.nodes.is_empty() {
        return view! { <p class="graph-empty">"The graph builds itself as packets arrive."</p> }
            .into_any();
    }
    let pos = layout(g);
    let edges = g
        .edges
        .iter()
        .filter_map(|e| {
            let ((x1, y1), (x2, y2)) = (pos[e.from]?, pos[e.to]?);
            let rel = match e.rel {
                Rel::Serves => "serves",
                Rel::Connects => "connects",
                Rel::Exchanges => "direct",
            };
            let width = 1.0 + (e.packets as f64).log2().clamp(0.0, 8.0) / 2.0;
            Some(view! {
                <line class="edge" data-rel=rel x1=x1 y1=y1 x2=x2 y2=y2 stroke-width=width />
            })
        })
        .collect_view();
    let nodes = g
        .nodes
        .iter()
        .zip(&pos)
        .filter_map(|(n, p)| {
            let (x, y) = (*p)?;
            let label = n.label.clone();
            Some(match n.kind {
                Kind::Host => {
                    let r = 8.0 + (n.packets as f64).log2().clamp(0.0, 10.0);
                    // Label on the side facing the centre: services and their edges go outward.
                    let (dx, dy) = (x - W / 2.0, y - H / 2.0);
                    let d = dx.hypot(dy);
                    let (ux, uy) = if d > 0.0 {
                        (-dx / d, -dy / d)
                    } else {
                        (0.0, 1.0)
                    };
                    let (lx, ly) = (x + ux * (r + 14.0), y + uy * (r + 14.0) + 4.0);
                    view! {
                        <g class="node-host">
                            <circle cx=x cy=y r=r />
                            <text class="node-label" x=lx y=ly text-anchor="middle">
                                {label}
                            </text>
                        </g>
                    }
                    .into_any()
                }
                Kind::Service { .. } => {
                    let w = label_width(&label);
                    view! {
                        <g class="node-service">
                            <rect x={x - w / 2.0} y={y - 12.0} width=w height="24" rx="6" />
                            <text class="node-label" x=x y={y + 4.0} text-anchor="middle">
                                {label}
                            </text>
                        </g>
                    }
                    .into_any()
                }
            })
        })
        .collect_view();
    let hidden = g.hosts().saturating_sub(MAX_HOSTS);
    view! {
        <svg viewBox=format!("0 0 {W} {H}") role="img" aria-label="Capture graph of hosts and services">
            {edges}
            {nodes}
            {(hidden > 0)
                .then(|| {
                    view! {
                        <text class="node-label" x="8" y={H - 8.0}>
                            {format!("{hidden} quieter hosts hidden")}
                        </text>
                    }
                })}
        </svg>
    }
    .into_any()
}
