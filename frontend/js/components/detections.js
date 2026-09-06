/**
 * Detections page.
 *
 * Wired to: rule.list, detection.list (recent view).
 *
 * Detections are facts, not workflow objects: they carry no severity,
 * confidence or source fields, so none are shown. Analysts identify a
 * detection by its display ID (DET-01…) plus the human rule name; the
 * technical detection_id stays reachable via the row's technical id.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = { detections: [], filter: "", category: "all",
                  ruleNames: {} };

    async function load() {
        state.detections = [];
        try {
            const rules = await PSAPI.callOrThrow("rule.list", {});
            state.ruleNames = {};
            for (const r of (rules.rules || [])) {
                state.ruleNames[r.rule_id] = r.name || r.rule_id;
            }
        } catch (e) { /* names fall back to rule_id */ }
        try {
            const d = await PSAPI.callOrThrow("detection.list", {
                limit: 200,
            });
            state.detections = d.detections || [];
        } catch (e) {
            PSFmt.toast("Failed to load detections: " + e.message, "err");
        }
        I.registerAll("DET", state.detections.map((d) => ({
            id: d.detection_id, sortKey: d.detected_at || "",
        })));
    }

    function detectionTitle(d) {
        return state.ruleNames[d.rule_id]
            || (d.rule_id ? "Rule " + d.rule_id + " v" + (d.rule_version || "?")
                          : "Detection");
    }

    function rowFor(d) {
        const tr = el("tr", null);
        tr.appendChild(el("td", null,
            el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                el("span", { class: "display-id" }, I.display("DET", d.detection_id)),
                el("span", { style: { fontWeight: "600" } }, detectionTitle(d)),
            ),
            d.reasoning
                ? el("div", { class: "muted", style: {
                    maxWidth: "420px", overflow: "hidden",
                    textOverflow: "ellipsis", whiteSpace: "nowrap" },
                    title: d.reasoning }, d.reasoning)
                : null,
        ));
        tr.appendChild(el("td", null,
            d.category ? el("span", { class: "chip" },
                F.titleCase(d.category)) : "—"));
        tr.appendChild(el("td", null,
            F.techId(d.event_id, { label: "event id" })));
        tr.appendChild(el("td", null, el("span", {
            title: F.fmtTime(d.detected_at) }, F.fmtRelative(d.detected_at))));
        return tr;
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        return state.detections.filter((d) => {
            if (state.category !== "all"
                && (d.category || "") !== state.category) return false;
            if (q) {
                const blob = [d.detection_id, I.display("DET", d.detection_id),
                    d.rule_id, state.ruleNames[d.rule_id] || "",
                    d.category, d.event_id, d.reasoning]
                    .join(" ").toLowerCase();
                if (!blob.includes(q)) return false;
            }
            return true;
        });
    }

    function rerenderTable() {
        const root = document.getElementById("det-table");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(build());
        const count = document.getElementById("det-count");
        if (count) count.textContent =
            `${filtered().length} of ${state.detections.length}`;
    }

    function build() {
        const rows = filtered();
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        if (!state.detections.length) {
            card.appendChild(F.emptyState("◎", "No detections yet",
                "Detections appear when a connected source sends telemetry that matches an active rule."));
            return card;
        }
        if (!rows.length) {
            card.appendChild(F.emptyState("◎", "No detections match your filters",
                "Try clearing the search box or choosing a different category."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null, el("tr", null,
                el("th", null, "Detection"),
                el("th", null, "Category"),
                el("th", null, "Source event"),
                el("th", null, "Detected"),
            )),
            el("tbody", null, rows.map(rowFor)),
        );
        card.appendChild(tbl);
        return card;
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar", id: "det-toolbar" });
        drawToolbar(tb);
        return tb;
    }

    /**
     * Draw (or redraw) the toolbar controls. The category dropdown is
     * rebuilt once detections have loaded so the closed set of real
     * categories is offered — the old page built it from an empty
     * list and the filter could never be used without a reload.
     */
    function drawToolbar(tb) {
        tb.replaceChildren();
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search detections…",
                value: state.filter,
                "aria-label": "Search detections",
                oninput: (e) => { state.filter = e.target.value; rerenderTable(); },
            }),
        ));
        const categories = ["all"];
        const seen = new Set();
        for (const d of state.detections) {
            const c = d.category || "";
            if (c && !seen.has(c)) { seen.add(c); categories.push(c); }
        }
        const sel = el("select", {
            "aria-label": "Filter by category",
            onchange: (e) => { state.category = e.target.value; rerenderTable(); } });
        for (const s of categories) {
            sel.appendChild(el("option", { value: s },
                s === "all" ? "All categories" : F.titleCase(s)));
        }
        sel.value = state.category;
        tb.appendChild(sel);
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "det-count" },
            state.detections.length
                ? `${filtered().length} of ${state.detections.length} detections`
                : ""));
    }

    async function render() {
        PSUI.mount(document.getElementById("detections-root"), {
            title: "Detections",
            subtitle: "Every detection produced by the rules engine, newest first.",
            requireAuth: true,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "detections-content" });
                main.appendChild(content);
                content.appendChild(renderToolbar());
                const host = el("div", { id: "det-table" });
                content.appendChild(host);
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading detections…");
                content.appendChild(banner);
                await load();
                banner.remove();
                // Rebuild the toolbar now that the real category set
                // is known, then render the table.
                const tb = document.getElementById("det-toolbar");
                if (tb) drawToolbar(tb);
                rerenderTable();
            },
        });
    }

    global.PSDetections = { render };
})(window);
