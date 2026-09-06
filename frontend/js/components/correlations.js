/**
 * Correlations page.
 *
 * Wired to: correlation.list (full recent list; takes optional
 * pattern_id/since/until/limit — no rule_id filter exists).
 *
 * correlation.confirm / correlation.dismiss are NOT promoted wire ops
 * in the Phase 4.8 contract, so no action buttons are rendered —
 * firing 400s against a placeholder was worse than a clear, truthful
 * empty actions column. Analysts act on the parent case.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = { correlations: [], filter: "", pattern: "all" };

    async function load() {
        state.correlations = [];
        try {
            const d = await PSAPI.callOrThrow("correlation.list", {
                limit: 500,
            });
            state.correlations = d.correlations || [];
        } catch (e) {
            PSFmt.toast("Failed to load correlations: " + e.message, "err");
        }
        I.registerAll("CORR", state.correlations.map((c) => ({
            id: c.correlation_id, sortKey: c.window_start || c.correlated_at || "",
        })));
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        return state.correlations.filter((c) => {
            if (state.pattern !== "all"
                && (c.pattern_id || "") !== state.pattern) return false;
            if (q) {
                const blob = [c.correlation_id, I.display("CORR", c.correlation_id),
                    c.pattern_id, c.trigger].join(" ").toLowerCase();
                if (!blob.includes(q)) return false;
            }
            return true;
        });
    }

    function rowFor(c) {
        const tr = el("tr", null);
        tr.appendChild(el("td", null,
            el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                el("span", { class: "display-id" }, I.display("CORR", c.correlation_id)),
                el("span", { style: { fontWeight: "600" } },
                    F.titleCase(c.trigger) || "Cluster"),
            ),
            el("div", { class: "muted" },
                (c.detection_ids || []).length + " detections · " +
                (c.event_ids || []).length + " events"),
        ));
        tr.appendChild(el("td", null,
            el("span", { class: "mono" },
                (c.pattern_id || "—") + " v" + (c.pattern_version || "?"))));
        tr.appendChild(el("td", { class: "num" }, String(c.count || 0)));
        tr.appendChild(el("td", null,
            el("div", { class: "muted mono", style: { fontSize: "0.72rem" } },
                F.fmtTime(c.window_start)),
            el("div", { class: "muted mono", style: { fontSize: "0.72rem" } },
                "→ " + F.fmtTime(c.window_end))));
        tr.appendChild(el("td", null, el("span", {
            title: F.fmtTime(c.correlated_at) },
            F.fmtRelative(c.correlated_at))));
        return tr;
    }

    function rerenderTable() {
        const root = document.getElementById("corr-table");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(build());
        const count = document.getElementById("corr-count");
        if (count) count.textContent =
            `${filtered().length} of ${state.correlations.length}`;
    }

    function build() {
        const rows = filtered();
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        if (!state.correlations.length) {
            card.appendChild(F.emptyState("⌁", "No correlations yet",
                "Correlations emerge when the engine clusters related detections across events."));
            return card;
        }
        if (!rows.length) {
            card.appendChild(F.emptyState("◎", "No correlations match your filters",
                "Try clearing the search box or choosing a different pattern."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null, el("tr", null,
                el("th", null, "Correlation"),
                el("th", null, "Pattern"),
                el("th", null, "Count"),
                el("th", null, "Time window"),
                el("th", null, "Correlated"),
            )),
            el("tbody", null, rows.map(rowFor)),
        );
        card.appendChild(tbl);
        return card;
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar", id: "corr-toolbar" });
        drawToolbar(tb);
        return tb;
    }

    /** Draw/redraw toolbar — rebuilt after load so the pattern
     * dropdown offers the real pattern set. */
    function drawToolbar(tb) {
        tb.replaceChildren();
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search correlations…",
                value: state.filter,
                "aria-label": "Search correlations",
                oninput: (e) => { state.filter = e.target.value; rerenderTable(); },
            }),
        ));
        const patterns = ["all"];
        const seen = new Set();
        for (const c of state.correlations) {
            const p = c.pattern_id || "";
            if (p && !seen.has(p)) { seen.add(p); patterns.push(p); }
        }
        const sel = el("select", {
            "aria-label": "Filter by pattern",
            onchange: (e) => { state.pattern = e.target.value; rerenderTable(); } });
        for (const p of patterns) {
            sel.appendChild(el("option", { value: p },
                p === "all" ? "All patterns" : p));
        }
        sel.value = state.pattern;
        tb.appendChild(sel);
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "corr-count" },
            state.correlations.length
                ? `${filtered().length} of ${state.correlations.length} correlations`
                : ""));
    }

    async function render() {
        PSUI.mount(document.getElementById("correlations-root"), {
            title: "Correlations",
            subtitle: "Detection clusters grouped by the correlation engine. Actions happen on the parent case.",
            requireAuth: true,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "correlations-content" });
                main.appendChild(content);
                content.appendChild(renderToolbar());
                const host = el("div", { id: "corr-table" });
                content.appendChild(host);
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading correlations…");
                content.appendChild(banner);
                await load();
                banner.remove();
                const tb = document.getElementById("corr-toolbar");
                if (tb) drawToolbar(tb);
                rerenderTable();
            },
        });
    }

    global.PSCorrelations = { render };
})(window);
