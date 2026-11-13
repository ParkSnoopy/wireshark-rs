//! Themed dropdown. WebKitGTK draws the popup of a native `<select>` with
//! GTK, so CSS cannot style it. This listbox uses the `.select` and `.menu`
//! classes of style.css instead.

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;

#[component]
pub fn Select(
    /// DOM id of the trigger button. Also the prefix of the menu and option ids.
    id: &'static str,
    label: &'static str,
    #[prop(into)] options: Signal<Vec<String>>,
    value: RwSignal<String>,
    #[prop(into, optional)] disabled: Signal<bool>,
    /// Keeps the label for screen readers only.
    #[prop(optional)]
    hide_label: bool,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let active = RwSignal::new(0_usize);

    let choose = move |i: usize| {
        if let Some(v) = options.with(|o| o.get(i).cloned()) {
            value.set(v);
        }
        open.set(false);
    };
    let show = move || {
        let current = value.get_untracked();
        active.set(
            options
                .with(|o| o.iter().position(|v| *v == current))
                .unwrap_or(0),
        );
        open.set(true);
    };
    let on_key = move |ev: KeyboardEvent| {
        let last = options.with(Vec::len).saturating_sub(1);
        let is_open = open.get_untracked();
        match ev.key().as_str() {
            "ArrowDown" | "ArrowUp" | "Home" | "End" if !is_open => {
                ev.prevent_default();
                show();
            }
            "ArrowDown" => {
                ev.prevent_default();
                active.update(|a| *a = (*a + 1).min(last));
            }
            "ArrowUp" => {
                ev.prevent_default();
                active.update(|a| *a = a.saturating_sub(1));
            }
            "Home" => active.set(0),
            "End" => active.set(last),
            "Enter" | " " if is_open => {
                ev.prevent_default();
                choose(active.get_untracked());
            }
            "Escape" | "Tab" => open.set(false),
            _ => {}
        }
    };

    view! {
        <div class="field">
            <span class="field-label" class:visually-hidden=hide_label id=format!("{id}-label")>
                {label}
            </span>
            <div class="select">
                <button
                    type="button"
                    class="input select-trigger"
                    id=id
                    aria-haspopup="listbox"
                    aria-controls=format!("{id}-menu")
                    aria-labelledby=format!("{id}-label {id}")
                    aria-expanded=move || open.get().to_string()
                    aria-activedescendant=move || {
                        open.get().then(|| format!("{id}-opt-{}", active.get()))
                    }
                    disabled=move || disabled.get()
                    on:click=move |_| if open.get_untracked() { open.set(false) } else { show() }
                    on:keydown=on_key
                    on:blur=move |_| open.set(false)
                >
                    <span class="select-value">{move || value.get()}</span>
                </button>
                <Show when=move || open.get()>
                    <ul
                        class="menu"
                        role="listbox"
                        id=format!("{id}-menu")
                        aria-labelledby=format!("{id}-label")
                    >
                        {move || {
                            options
                                .get()
                                .into_iter()
                                .enumerate()
                                .map(|(i, option)| {
                                    let selected = value.get_untracked() == option;
                                    view! {
                                        <li
                                            class="menu-item"
                                            class:is-active=move || active.get() == i
                                            role="option"
                                            id=format!("{id}-opt-{i}")
                                            aria-selected=selected.to_string()
                                            // mousedown, not click: keeps focus on the trigger.
                                            on:mousedown=move |ev| {
                                                ev.prevent_default();
                                                choose(i);
                                            }
                                            on:mouseenter=move |_| active.set(i)
                                        >
                                            {option}
                                        </li>
                                    }
                                })
                                .collect_view()
                        }}
                    </ul>
                </Show>
            </div>
        </div>
    }
}
