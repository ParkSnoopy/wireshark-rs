//! Filter dialog: protocols, address scopes, ports, sizes, interfaces and
//! processes. Settings apply as they change.

use std::collections::{BTreeMap, BTreeSet};

use leptos::html;
use leptos::prelude::*;

use crate::model::{Row, Rules, SCOPES, port_ranges};

/// A multi-choice setting of `Rules`.
#[derive(Clone, Copy)]
enum Group {
    Protocols,
    Scopes,
    Ifaces,
    Processes,
}

impl Group {
    fn of(self, r: &Rules) -> &BTreeSet<String> {
        match self {
            Group::Protocols => &r.protocols,
            Group::Scopes => &r.scopes,
            Group::Ifaces => &r.ifaces,
            Group::Processes => &r.processes,
        }
    }

    fn of_mut(self, r: &mut Rules) -> &mut BTreeSet<String> {
        match self {
            Group::Protocols => &mut r.protocols,
            Group::Scopes => &mut r.scopes,
            Group::Ifaces => &mut r.ifaces,
            Group::Processes => &mut r.processes,
        }
    }
}

/// Values seen in the capture, with their packet counts.
#[derive(Clone, Default, PartialEq)]
struct Choices {
    apps: BTreeMap<String, usize>,
    transports: BTreeMap<String, usize>,
    ifaces: BTreeMap<String, usize>,
    processes: BTreeMap<String, usize>,
}

fn choices(rows: &[Row]) -> Choices {
    let mut c = Choices::default();
    let bump = |map: &mut BTreeMap<String, usize>, v: &str| {
        *map.entry(v.to_owned()).or_default() += 1;
    };
    for r in rows {
        if let Some(app) = &r.app {
            bump(&mut c.apps, app);
        }
        bump(&mut c.transports, &r.proto);
        // A packet between two ends of one interface or process counts once.
        let ifaces: BTreeSet<&str> = [&r.src_if, &r.dst_if]
            .into_iter()
            .flatten()
            .map(|i| i.name.as_str())
            .collect();
        ifaces.into_iter().for_each(|i| bump(&mut c.ifaces, i));
        let procs: BTreeSet<&str> = [&r.sproc, &r.dproc]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        procs.into_iter().for_each(|p| bump(&mut c.processes, p));
    }
    c
}

/// "Filters" button with the number of active settings, and its dialog.
#[component]
pub fn FilterDialog(
    rules: RwSignal<Rules>,
    rows: RwSignal<Vec<Row>>,
    /// Table rows that pass every filter, and all packets.
    counts: Signal<(usize, usize)>,
) -> impl IntoView {
    let dialog = NodeRef::<html::Dialog>::new();
    let open = RwSignal::new(false);
    // Counted only while the dialog is open: a long capture has many rows.
    let seen = Memo::new(move |_| {
        if open.get() {
            rows.with(|r| choices(r))
        } else {
            Choices::default()
        }
    });
    let show = move |_| {
        if let Some(d) = dialog.get_untracked() {
            let _ = d.show_modal();
            open.set(true);
        }
    };
    let close = move || {
        if let Some(d) = dialog.get_untracked() {
            d.close();
        }
    };
    let active = move || rules.with(Rules::active);
    let num = |v: String| v.trim().parse::<u32>().ok();
    let bad_ports = move || {
        rules.with(|r| {
            let parts = r.ports.split([',', ' ']).filter(|p| !p.is_empty()).count();
            port_ranges(&r.ports).len() < parts
        })
    };

    view! {
        <button
            type="button"
            class="btn btn-secondary filter-button"
            aria-haspopup="dialog"
            on:click=show
        >
            "Filters"
            <Show when=move || { active() > 0 }>
                <span class="filter-badge">{active}</span>
            </Show>
        </button>
        <dialog
            node_ref=dialog
            class="modal filter-dialog"
            aria-labelledby="filter-title"
            on:close=move |_| open.set(false)
            on:click=move |ev| {
                // The body fills the dialog: a click on the dialog element
                // itself is a click on the backdrop.
                if ev.target() == ev.current_target() {
                    close();
                }
            }
        >
            <div class="filter-dialog-body">
                <div class="filter-dialog-head">
                    <h3 id="filter-title">"Filter packets"</h3>
                    <button type="button" class="btn btn-ghost btn-sm" on:click=move |_| close()>
                        "Close"
                    </button>
                </div>

                <fieldset class="filter-group">
                    <legend>"Protocols"</legend>
                    <div class="segmented" role="group" aria-label="Protocol mode">
                        <button
                            type="button"
                            class="chip chip-filter"
                            aria-pressed=move || rules.with(|r| !r.exclude).to_string()
                            on:click=move |_| rules.update(|r| r.exclude = false)
                        >
                            "Show only selected"
                        </button>
                        <button
                            type="button"
                            class="chip chip-filter"
                            aria-pressed=move || rules.with(|r| r.exclude).to_string()
                            on:click=move |_| rules.update(|r| r.exclude = true)
                        >
                            "Hide selected"
                        </button>
                    </div>
                    <p class="field-helper">"Application"</p>
                    {chips(rules, Group::Protocols, Signal::derive(move || seen.with(|s| s.apps.clone())), true)}
                    <p class="field-helper">"Transport"</p>
                    {chips(
                        rules,
                        Group::Protocols,
                        Signal::derive(move || seen.with(|s| s.transports.clone())),
                        false,
                    )}
                </fieldset>

                <fieldset class="filter-group">
                    <legend>"Address scope"</legend>
                    <p class="field-helper">"Either end of the packet is in a selected scope."</p>
                    {chips(
                        rules,
                        Group::Scopes,
                        Signal::stored(SCOPES.iter().map(|s| ((*s).to_owned(), 0)).collect()),
                        false,
                    )}
                </fieldset>

                <div class="filter-row">
                    <label class="field">
                        <span class="field-label">"Ports"</span>
                        <input
                            class="input"
                            type="text"
                            placeholder="443, 8000-8100"
                            class:is-error=bad_ports
                            prop:value=move || rules.with(|r| r.ports.clone())
                            on:input=move |ev| rules.update(|r| r.ports = event_target_value(&ev))
                        />
                        <span class="field-helper">
                            {move || {
                                if bad_ports() {
                                    "Some parts are not ports or ranges; they are ignored."
                                } else {
                                    "Source or destination port."
                                }
                            }}
                        </span>
                    </label>
                    <label class="field">
                        <span class="field-label">"Min length"</span>
                        <input
                            class="input"
                            type="number"
                            min="0"
                            prop:value=move || rules.with(|r| r.min_len.map(|n| n.to_string()).unwrap_or_default())
                            on:input=move |ev| rules.update(|r| r.min_len = num(event_target_value(&ev)))
                        />
                    </label>
                    <label class="field">
                        <span class="field-label">"Max length"</span>
                        <input
                            class="input"
                            type="number"
                            min="0"
                            prop:value=move || rules.with(|r| r.max_len.map(|n| n.to_string()).unwrap_or_default())
                            on:input=move |ev| rules.update(|r| r.max_len = num(event_target_value(&ev)))
                        />
                    </label>
                </div>

                <fieldset class="filter-group">
                    <legend>"Interfaces"</legend>
                    {chips(rules, Group::Ifaces, Signal::derive(move || seen.with(|s| s.ifaces.clone())), true)}
                </fieldset>

                <fieldset class="filter-group">
                    <legend>"Processes"</legend>
                    {chips(
                        rules,
                        Group::Processes,
                        Signal::derive(move || seen.with(|s| s.processes.clone())),
                        true,
                    )}
                </fieldset>

                <div class="filter-dialog-foot">
                    <span class="filter-count">
                        {move || {
                            let (shown, all) = counts.get();
                            // Rows, not packets: a collapsed row holds many packets.
                            format!("{shown} rows shown of {all} packets")
                        }}
                    </span>
                    <button
                        type="button"
                        class="btn btn-ghost"
                        on:click=move |_| rules.set(Rules::default())
                    >
                        "Reset"
                    </button>
                    <button type="button" class="btn btn-primary" on:click=move |_| close()>
                        "Done"
                    </button>
                </div>
            </div>
        </dialog>
    }
}

/// Toggle chips for `values` (value, packet count; 0 hides the count).
/// With `keep_picked`, selected values no longer seen (after a new capture)
/// stay listed, so they can be cleared.
fn chips(
    rules: RwSignal<Rules>,
    group: Group,
    values: Signal<BTreeMap<String, usize>>,
    keep_picked: bool,
) -> impl IntoView {
    let all = move || {
        let mut v = values.get();
        if keep_picked {
            rules.with(|r| {
                for picked in group.of(r) {
                    v.entry(picked.clone()).or_default();
                }
            });
        }
        v.into_iter().collect::<Vec<_>>()
    };
    view! {
        <div class="chip-set">
            <Show when=move || values.with(BTreeMap::is_empty)>
                <span class="field-helper">"None seen yet."</span>
            </Show>
            <For
                each=all
                key=|(v, n)| (v.clone(), *n)
                children=move |(value, count)| {
                    let v = value.clone();
                    let label = value.clone();
                    let pressed = move || rules.with(|r| group.of(r).contains(&v));
                    let toggle = move |_| {
                        rules.update(|r| {
                            let set = group.of_mut(r);
                            if !set.remove(&value) {
                                set.insert(value.clone());
                            }
                        });
                    };
                    view! {
                        <button
                            type="button"
                            class="chip chip-filter"
                            aria-pressed=move || pressed().to_string()
                            on:click=toggle
                        >
                            {label}
                            {(count > 0).then(|| view! { <span class="chip-count">{count}</span> })}
                        </button>
                    }
                }
            />
        </div>
    }
}
