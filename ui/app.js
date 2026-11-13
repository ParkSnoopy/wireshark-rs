// Visual helpers for the packet table: row selection, and a stable view while
// new packets enter at the top. Leptos owns the rows; this file only adds
// classes and scrolls.

/** Scroll offset in px that still counts as "at the top". */
const TOP_SLACK = 4;

function setup() {
    const scroller = document.querySelector(".table-scroll");
    const rows = scroller?.querySelector("tbody");
    if (!scroller || !rows) {
        return false;
    }

    // At the top, new packets push the list down so the newest stay visible.
    // Scrolled down, the first visible row stays where the user left it.
    let anchor = null;
    let anchorTop = 0;
    const pickAnchor = () => {
        anchor = null;
        if (scroller.scrollTop <= TOP_SLACK) {
            return;
        }
        const viewTop =
            scroller.scrollTop + scroller.querySelector("thead").offsetHeight;
        for (const row of rows.rows) {
            if (row.offsetTop + row.offsetHeight > viewTop) {
                anchor = row;
                anchorTop = row.offsetTop;
                return;
            }
        }
    };
    scroller.addEventListener("scroll", pickAnchor, { passive: true });
    new MutationObserver(() => {
        if (anchor?.isConnected) {
            scroller.scrollTop += anchor.offsetTop - anchorTop;
            anchorTop = anchor.offsetTop;
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
