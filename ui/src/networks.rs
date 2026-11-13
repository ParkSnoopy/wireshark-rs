//! Networks page: addresses grouped into CIDR blocks, and the domains seen
//! in traffic with their registration dates.

use std::collections::HashSet;
use std::net::IpAddr;

use leptos::ev::MouseEvent;
use leptos::prelude::*;

use crate::model::{Block, Cidr, DomainInfo, Domains, GROUPINGS, Hosts, Ptrs, blocks, bytes};
use crate::select::Select;
use crate::tip::{Card, Tip, facts};

/// Row under the pointer, for the hover card.
#[derive(Clone, PartialEq)]
enum Hover {
    Block(Cidr),
    Host(IpAddr),
    Domain(String),
}

/// Hovered row and pointer position.
#[derive(Clone, Copy)]
struct Pointer {
    hover: RwSignal<Option<Hover>>,
    cursor: RwSignal<(i32, i32)>,
}

impl Pointer {
    /// Mouse-move handler of a row.
    fn track(self, h: Hover) -> impl Fn(MouseEvent) + 'static {
        move |ev| {
            if self.hover.with_untracked(|cur| cur.as_ref() != Some(&h)) {
                self.hover.set(Some(h.clone()));
            }
            self.cursor.set((ev.client_x(), ev.client_y()));
        }
    }
}

#[component]
pub fn NetworksPage(
    hosts: RwSignal<Hosts>,
    domains: RwSignal<Domains>,
    ptrs: RwSignal<Ptrs>,
    /// The page is visible: grouping runs only then.
    active: Signal<bool>,
    /// Shows the packets of a block (`10.0.0.0/8`) or a name in the packet table.
    on_show: Callback<String>,
) -> impl IntoView {
    let grouping = RwSignal::new(GROUPINGS[0].0.to_owned());
    let open = RwSignal::new(HashSet::<String>::new());
    let pointer = Pointer {
        hover: RwSignal::new(None),
        cursor: RwSignal::new((0, 0)),
    };
    let list = Memo::new(move |_| {
        if !active.get() {
            return Vec::new();
        }
        let label = grouping.get();
        let (_, v4, v6) = GROUPINGS
            .into_iter()
            .find(|g| g.0 == label)
            .unwrap_or(GROUPINGS[0]);
        hosts.with(|h| blocks(h, v4, v6))
    });
    let domain_rows = Memo::new(move |_| {
        if !active.get() {
            return Vec::new();
        }
        let mut v: Vec<DomainInfo> = domains.with(|d| d.values().cloned().collect());
        // Flagged first, then by name.
        v.sort_by(|a, b| (a.flag().is_none(), &a.name).cmp(&(b.flag().is_none(), &b.name)));
        v
    });
    let leave = move |_| pointer.hover.set(None);

    view! {
        <div class="networks" on:mouseleave=leave>
            <section class="net-section" aria-labelledby="blocks-title">
                <div class="net-head">
                    <h3 id="blocks-title">"Address blocks"</h3>
                    <Select
                        id="grouping"
                        label="Group by"
                        options=Signal::stored(GROUPINGS.map(|g| g.0.to_owned()).to_vec())
                        value=grouping
                    />
                    <span class="filter-count">{move || format!("{} blocks", list.with(Vec::len))}</span>
                </div>
                <table class="data-table" on:mouseleave=leave>
                    <thead>
                        <tr>
                            <th>"Block"</th>
                            <th>"Scope"</th>
                            <th class="num">"Addresses"</th>
                            <th class="num">"Packets"</th>
                            <th class="num">"Bytes"</th>
                            <th>"Names"</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <Show when=move || list.with(Vec::is_empty)>
                            <tr class="empty">
                                <td colspan="7">"No addresses yet."</td>
                            </tr>
                        </Show>
                        <For
                            each=move || list.get()
                            key=|b| (b.cidr, b.packets, b.hosts.len())
                            children=move |b| block_rows(b, open, domains, ptrs, pointer, on_show)
                        />
                    </tbody>
                </table>
            </section>
            <section class="net-section" aria-labelledby="domains-title">
                <div class="net-head">
                    <h3 id="domains-title">"Domains"</h3>
                    <span class="net-note">
                        "Registration and transfer dates from RDAP. Flagged when 30 days old or less."
                    </span>
                </div>
                <table class="data-table" on:mouseleave=leave>
                    <thead>
                        <tr>
                            <th>"Name"</th>
                            <th>"Registered domain"</th>
                            <th>"Registered"</th>
                            <th>"Transferred"</th>
                            <th>"Status"</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <Show when=move || domain_rows.with(Vec::is_empty)>
                            <tr class="empty">
                                <td colspan="6">"No host names yet. They come from DNS answers, TLS and HTTP."</td>
                            </tr>
                        </Show>
                        <For
                            each=move || domain_rows.get()
                            key=|d| (d.name.clone(), d.registered.clone(), d.error.clone())
                            children=move |d| domain_row(d, pointer, on_show)
                        />
                    </tbody>
                </table>
            </section>
            {move || {
                let h = pointer.hover.get()?;
                let (title, list, flag) = list.with(|l| {
                    hosts.with(|hs| ptrs.with(|p| domains.with(|d| card(l, hs, &h, p, d))))
                })?;
                Some(view! {
                    <Tip cursor=pointer.cursor>
                        <h4>{title}</h4>
                        {flag.map(|why| view! { <p class="tip-flag">{why}</p> })}
                        {facts("tip-grid", list)}
                    </Tip>
                })
            }}
        </div>
    }
}

/// Hover card of the row under the pointer.
fn card(
    blocks: &[Block],
    hosts: &Hosts,
    h: &Hover,
    ptrs: &Ptrs,
    domains: &Domains,
) -> Option<Card> {
    let flag_of = |name: &str| Some(format!("⚠ {name} was {}", domains.get(name)?.flag()?));
    let ptr_text = |ip: &IpAddr| {
        ptrs.get(ip)
            .map(|p| p.clone().unwrap_or_else(|| "no record".to_owned()))
    };
    let traffic = |packets: u64, n: u64| format!("{packets} packets · {}", bytes(n));
    match h {
        Hover::Block(cidr) => {
            let b = blocks.iter().find(|b| b.cidr == *cidr)?;
            let names = unique_names(b);
            let mut list = vec![
                ("Scope", scope_text(b)),
                ("Addresses", b.hosts.len().to_string()),
                ("Traffic", traffic(b.packets, b.bytes)),
            ];
            if !names.is_empty() {
                list.push(("Names", names.join(", ")));
            }
            // The busiest addresses, with their names when known.
            for (n, (ip, host)) in b.hosts.iter().take(BUSIEST).enumerate() {
                let label = host
                    .name
                    .clone()
                    .or_else(|| ptrs.get(ip).cloned().flatten())
                    .map_or(ip.to_string(), |n| format!("{n} ({ip})"));
                let term = if n == 0 { "Busiest" } else { "" };
                list.push((term, format!("{label} · {}", bytes(host.bytes))));
            }
            let flag = names.iter().find_map(|n| flag_of(n));
            Some((cidr.to_string(), list, flag))
        }
        Hover::Host(ip) => {
            let (b, host) = blocks
                .iter()
                .find_map(|b| Some((b, &b.hosts.iter().find(|(a, _)| a == ip)?.1)))?;
            let title = host
                .name
                .as_ref()
                .map_or(ip.to_string(), |n| format!("{n} ({ip})"));
            let mut list = vec![
                ("Block", b.cidr.to_string()),
                ("Scope", scope_text(b)),
                ("Traffic", traffic(host.packets, host.bytes)),
            ];
            if let Some(i) = &host.iface {
                let how = if i.local { "local on" } else { "via" };
                list.push(("Interface", format!("{how} {}", i.name)));
            }
            if let Some(p) = ptr_text(ip) {
                list.push(("PTR", p));
            }
            let domain = host.name.as_ref().and_then(|n| domains.get(n));
            if let Some(d) = domain {
                list.push(("Domain", d.summary()));
            }
            let flag = host.name.as_deref().and_then(flag_of);
            Some((title, list, flag))
        }
        Hover::Domain(name) => {
            let d = domains.get(name)?;
            let date = |date: &Option<String>| date.clone().unwrap_or_else(|| "–".to_owned());
            let mut list = vec![
                ("Registered domain", d.site.clone()),
                ("Registered", date(&d.registered)),
                ("Transferred", date(&d.transferred)),
            ];
            if let Some(e) = &d.error {
                list.push(("Lookup", e.clone()));
            }
            let mut addrs: Vec<&IpAddr> = hosts
                .0
                .iter()
                .filter(|(_, h)| h.name.as_ref() == Some(name))
                .map(|(ip, _)| ip)
                .collect();
            addrs.sort();
            for (n, ip) in addrs.into_iter().enumerate() {
                let text = match ptr_text(ip) {
                    Some(p) => format!("{ip} · PTR {p}"),
                    None => ip.to_string(),
                };
                list.push((if n == 0 { "Addresses" } else { "" }, text));
            }
            Some((name.clone(), list, flag_of(name)))
        }
    }
}

/// Addresses listed in a block's hover card.
const BUSIEST: usize = 5;

/// Host names in a block, in address order of first appearance.
fn unique_names(b: &Block) -> Vec<String> {
    let mut seen = HashSet::new();
    b.hosts
        .iter()
        .filter_map(|(_, h)| h.name.clone())
        .filter(|n| seen.insert(n.clone()))
        .collect()
}

fn scope_text(b: &Block) -> String {
    b.scope
        .map_or("public".to_owned(), |s| format!("{} ({})", s.kind, s.cidr))
}

fn block_rows(
    b: Block,
    open: RwSignal<HashSet<String>>,
    domains: RwSignal<Domains>,
    ptrs: RwSignal<Ptrs>,
    pointer: Pointer,
    on_show: Callback<String>,
) -> impl IntoView {
    let cidr = b.cidr.to_string();
    let key = StoredValue::new(cidr.clone());
    let is_open = move || key.with_value(|k| open.with(|o| o.contains(k)));
    let toggle = {
        let cidr = cidr.clone();
        move |_| {
            open.update(|o| {
                if !o.remove(&cidr) {
                    o.insert(cidr.clone());
                }
            });
        }
    };
    let names = unique_names(&b);
    let flagged = {
        let names = names.clone();
        move || {
            domains.with(|d| {
                names
                    .iter()
                    .any(|n| d.get(n).and_then(DomainInfo::flag).is_some())
            })
        }
    };
    let shown_names = match names.len() {
        0 => String::new(),
        1..=2 => names.join(", "),
        n => format!("{}, {} and {} more", names[0], names[1], n - 2),
    };
    let scope = scope_text(&b);
    let show = {
        let cidr = cidr.clone();
        move |_| on_show.run(cidr.clone())
    };
    let hosts = b.hosts.clone();
    view! {
        <tr class="block-row" class:flagged=flagged on:mousemove=pointer.track(Hover::Block(b.cidr))>
            <td>
                <button type="button" class="disclosure" aria-expanded=move || is_open().to_string() on:click=toggle>
                    {cidr.clone()}
                </button>
            </td>
            <td>{scope}</td>
            <td class="num">{b.hosts.len()}</td>
            <td class="num">{b.packets}</td>
            <td class="num">{bytes(b.bytes)}</td>
            <td class="names">
                <span>{shown_names}</span>
            </td>
            <td class="actions">
                <button type="button" class="btn btn-ghost btn-sm" on:click=show>
                    "Show packets"
                </button>
            </td>
        </tr>
        <Show when=is_open>
            {hosts
                .iter()
                .map(|(addr, h)| {
                    let addr = *addr;
                    let ip = addr.to_string();
                    let label = match &h.name {
                        Some(n) => format!("{n} ({ip})"),
                        None => ip.clone(),
                    };
                    let iface = h.iface.as_ref().map(|i| i.name.clone()).unwrap_or_default();
                    let ptr = move || ptrs.with(|p| p.get(&addr).cloned().flatten().map(|n| format!("PTR {n}")));
                    let show = move |_| on_show.run(ip.clone());
                    view! {
                        <tr class="host-row" on:mousemove=pointer.track(Hover::Host(addr))>
                            <td colspan="2">{label}</td>
                            <td class="muted">{iface}</td>
                            <td class="num">{h.packets}</td>
                            <td class="num">{bytes(h.bytes)}</td>
                            <td class="names muted">
                                <span>{ptr}</span>
                            </td>
                            <td class="actions">
                                <button type="button" class="btn btn-ghost btn-sm" on:click=show>
                                    "Show packets"
                                </button>
                            </td>
                        </tr>
                    }
                })
                .collect_view()}
        </Show>
    }
}

fn domain_row(d: DomainInfo, pointer: Pointer, on_show: Callback<String>) -> impl IntoView {
    let status = match (d.flag(), &d.error) {
        (Some(why), _) => {
            view! { <span class="chip chip-warning">{format!("⚠ {why}")}</span> }.into_any()
        }
        // The hover card shows the lookup error.
        (None, Some(_)) => view! { <span class="muted">"unknown"</span> }.into_any(),
        (None, None) => view! { <span class="muted">"established"</span> }.into_any(),
    };
    let date = |date: &Option<String>, days: Option<i64>| match (date, days) {
        (Some(date), Some(days)) => format!("{date} ({days} d)"),
        (Some(date), None) => date.clone(),
        _ => "–".to_owned(),
    };
    let name = d.name.clone();
    view! {
        <tr class:flagged=d.flag().is_some() on:mousemove=pointer.track(Hover::Domain(d.name.clone()))>
            <td>{d.name.clone()}</td>
            <td>{d.site.clone()}</td>
            <td>{date(&d.registered, d.registered_days)}</td>
            <td>{date(&d.transferred, d.transferred_days)}</td>
            <td>{status}</td>
            <td class="actions">
                <button type="button" class="btn btn-ghost btn-sm" on:click=move |_| on_show.run(name.clone())>
                    "Show packets"
                </button>
            </td>
        </tr>
    }
}
