// Visual helpers for the packet table: row selection and follow-the-tail
// scrolling. Leptos owns the rows; this file only adds classes and scrolls.

/** Distance in px from the bottom that still counts as "at the bottom". */
const FOLLOW_SLACK = 8;

function setup() {
    const scroller = document.querySelector(".table-scroll");
    const rows = scroller?.querySelector("tbody");
    if (!scroller || !rows) {
        return false;
    }

    // Follow new packets only while the user is at the bottom of the list.
    let following = true;
    scroller.addEventListener(
        "scroll",
        () => {
            const bottom = scroller.scrollHeight - scroller.clientHeight;
            following = scroller.scrollTop >= bottom - FOLLOW_SLACK;
        },
        { passive: true },
    );
    new MutationObserver(() => {
        if (following) {
            scroller.scrollTop = scroller.scrollHeight;
        }
    }).observe(rows, { childList: true });

    rows.addEventListener("click", (event) => {
        const row = event.target.closest("tr");
        if (!row || row.classList.contains("empty")) {
            return;
        }
        rows.querySelector("tr.selected")?.classList.remove("selected");
        row.classList.add("selected");
    });
    return true;
}

// Trunk fires this event after the wasm app has mounted its DOM.
if (!setup()) {
    window.addEventListener("TrunkApplicationStarted", setup, { once: true });
}
