//! Rich tooltip that follows the pointer, shared by every tab.

use leptos::prelude::*;

/// Width of `.tooltip-rich` in style.css.
const CARD_WIDTH: i32 = 380;
/// Distance from the arrow tip to the cursor, and from the arrow to the card edge.
const CARD_GAP: i32 = 18;
const ARROW_INSET: i32 = 22;

/// Card below and right of `cursor` (client px); flips when that would
/// leave the window.
#[component]
pub fn Tip(cursor: RwSignal<(i32, i32)>, children: Children) -> impl IntoView {
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
    view! {
        <div
            class="tooltip tooltip-rich"
            role="tooltip"
            style=move || placement().0
            data-side=move || placement().1
            data-align=move || placement().2
        >
            {children()}
        </div>
    }
}

/// Hover card content: title, `(term, value)` facts and a warning.
pub type Card = (String, Vec<(&'static str, String)>, Option<String>);

/// `(term, value)` pairs as a definition list of `class`.
pub fn facts(class: &'static str, list: Vec<(&'static str, String)>) -> impl IntoView {
    view! {
        <dl class=class>
            {list
                .into_iter()
                .map(|(term, value)| view! {
                    <dt>{term}</dt>
                    <dd>{value}</dd>
                })
                .collect_view()}
        </dl>
    }
}

fn viewport() -> (i32, i32) {
    let w = window();
    let size =
        |v: Result<wasm_bindgen::JsValue, _>| v.ok().and_then(|v| v.as_f64()).unwrap_or(0.0) as i32;
    (size(w.inner_width()), size(w.inner_height()))
}
