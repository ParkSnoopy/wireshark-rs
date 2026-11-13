//! Networks page: addresses grouped into CIDR blocks, and the domains seen
//! in traffic with their registration dates.

use std::collections::HashSet;

use leptos::prelude::*;

use crate::model::{Block, DomainInfo, Domains, GROUPINGS, Hosts, blocks, bytes};
use crate::select::Select;

#[component]
pub fn NetworksPage(
    hosts: RwSignal<Hosts>,
    domains: RwSignal<Domains>,
    /// The page is visible: grouping runs only then.
    active: Signal<bool>,
    /// Shows the packets of a block (`10.0.0.0/8`) or a name in the packet table.
    on_show: Callback<String>,
) -> impl IntoView {
    let grouping = RwSignal::new(GROUPINGS[0].0.to_owned());
    let open = RwSignal::new(HashSet::<String>::new());
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

    view! {
        <div class="networks">
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
                <table class="data-table">
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
                            children=move |b| block_rows(b, open, domains, on_show)
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
                <table class="data-table">
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
                            children=move |d| domain_row(d, on_show)
                        />
                    </tbody>
                </table>
            </section>
        </div>
    }
}

fn block_rows(
    b: Block,
    open: RwSignal<HashSet<String>>,
    domains: RwSignal<Domains>,
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
    let names: Vec<String> = {
        let mut seen = HashSet::new();
        b.hosts
            .iter()
            .filter_map(|(_, h)| h.name.clone())
            .filter(|n| seen.insert(n.clone()))
            .collect()
    };
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
    let scope = b
        .scope
        .map_or("public".to_owned(), |s| format!("{} ({})", s.kind, s.cidr));
    let show = {
        let cidr = cidr.clone();
        move |_| on_show.run(cidr.clone())
    };
    let hosts = b.hosts.clone();
    view! {
        <tr class="block-row" class:flagged=flagged>
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
                <span title=names.join("\n")>{shown_names}</span>
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
                .map(|(ip, h)| {
                    let ip = ip.to_string();
                    let label = match &h.name {
                        Some(n) => format!("{n} ({ip})"),
                        None => ip.clone(),
                    };
                    let iface = h.iface.as_ref().map(|i| i.name.clone()).unwrap_or_default();
                    let show = move |_| on_show.run(ip.clone());
                    view! {
                        <tr class="host-row">
                            <td colspan="2">{label}</td>
                            <td class="muted">{iface}</td>
                            <td class="num">{h.packets}</td>
                            <td class="num">{bytes(h.bytes)}</td>
                            <td></td>
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

fn domain_row(d: DomainInfo, on_show: Callback<String>) -> impl IntoView {
    let status = match (d.flag(), &d.error) {
        (Some(why), _) => {
            view! { <span class="chip chip-warning">{format!("⚠ {why}")}</span> }.into_any()
        }
        (None, Some(e)) => {
            view! { <span class="muted" title=e.clone()>"unknown"</span> }.into_any()
        }
        (None, None) => view! { <span class="muted">"established"</span> }.into_any(),
    };
    let date = |date: &Option<String>, days: Option<i64>| match (date, days) {
        (Some(date), Some(days)) => format!("{date} ({days} d)"),
        (Some(date), None) => date.clone(),
        _ => "–".to_owned(),
    };
    let name = d.name.clone();
    view! {
        <tr class:flagged=d.flag().is_some()>
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
