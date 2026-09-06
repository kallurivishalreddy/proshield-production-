/**
 * Incidents (cases) listing.
 *
 * Wired to: case.list
 *
 * The table renders the real Incident contract (incident_id / title /
 * summary / state / evidence / severity / confidence / created_at /
 * updated_at). The decorative columns of the old page (source, asset,
 * confidence meter, fabricated correlation_kind) read fields the
 * backend never emits and are gone. Analysts identify cases by the
 * human display ID (CASE-01…); the technical incident_id stays
 * available as secondary metadata.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = { cases: [], filter: "", severity: "all", status: "all" };

    async function loadCases() {
        try {
            const d = await PSAPI.callOrThrow("case.list", { limit: 200 });
            state.cases = d.cases || [];
        } catch (e) {
            state.cases = [];
            PSFmt.toast("Failed to load cases: " + e.message, "err");
        }
        I.registerAll("CASE", state.cases.map((c) => ({
            id: c.incident_id,
            sortKey: c.created_at || "",
        })));
    }

    function evidenceCounts(c) {
        const ev = c.evidence || {};
        return {
            events: (ev.event_ids || []).length,
            detections: (ev.detection_ids || []).length,
            correlations: (ev.correlation_ids || []).length,
        };
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        return state.cases.filter((c) => {
            if (state.severity !== "all" && c.severity !== state.severity) return false;
            if (state.status !== "all" && c.state !== state.status) return false;
            if (q) {
                const ev = c.evidence || {};
                const blob = [c.incident_id, I.display("CASE", c.incident_id),
                    c.title, c.summary, c.severity, c.state].join(" ").toLowerCase();
                if (!blob.includes(q)) return false;
            }
            return true;
        });
    }

    function rowFor(c) {
        const ev = evidenceCounts(c);
        const tr = el("tr", {
            class: "clickable",
            onclick: () => location.href = "/static/case.html?id=" +
                encodeURIComponent(c.incident_id),
            title: "Open case",
        });
        // Case: display ID + human title; technical id secondary.
        tr.appendChild(el("td", null,
            el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                el("span", { class: "display-id" }, I.display("CASE", c.incident_id)),
                el("span", { style: { fontWeight: "600" } },
                    c.title || "Untitled case"),
            ),
            c.summary
                ? el("div", { class: "muted", style: {
                    maxWidth: "420px", overflow: "hidden",
                    textOverflow: "ellipsis", whiteSpace: "nowrap" } }, c.summary)
                : null,
        ));
        tr.appendChild(el("td", null,
            F.pill(c.severity, F.severityClass(c.severity))));
        tr.appendChild(el("td", null, F.badge(c.state, F.stateClass(c.state))));
        tr.appendChild(el("td", { class: "num" },
            el("span", { title: `${ev.events} events · ${ev.detections} detections · ${ev.correlations} correlations` },
                `${ev.detections} det · ${ev.correlations} corr`)));
        tr.appendChild(el("td", null,
            el("span", { title: F.fmtTime(c.updated_at) },
                F.fmtRelative(c.updated_at))));
        tr.appendChild(el("td", null,
            el("span", { class: "muted" },
                (c.report_references || []).length
                    ? `${c.report_references.length} report${c.report_references.length === 1 ? "" : "s"}`
                    : "—")));
        return tr;
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar" });
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search cases… (title, summary, severity)",
                value: state.filter,
                "aria-label": "Search cases",
                oninput: (e) => { state.filter = e.target.value; rerenderTable(); },
            }),
        ));
        const sevSel = el("select", {
            "aria-label": "Filter by severity",
            onchange: (e) => { state.severity = e.target.value; rerenderTable(); } });
        for (const s of ["all", "critical", "high", "medium", "low", "info"]) {
            sevSel.appendChild(el("option", { value: s },
                s === "all" ? "All severities" : F.titleCase(s)));
        }
        sevSel.value = state.severity;
        const statusSel = el("select", {
            "aria-label": "Filter by status",
            onchange: (e) => { state.status = e.target.value; rerenderTable(); } });
        // Truthful lifecycle states (IncidentLifecycleState).
        for (const s of ["all", "open", "centralized_pending", "report_pending",
                         "closed"]) {
            statusSel.appendChild(el("option", { value: s },
                s === "all" ? "All statuses" : F.titleCase(s)));
        }
        statusSel.value = state.status;
        tb.appendChild(sevSel);
        tb.appendChild(statusSel);
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "cases-count" }, ""));
        return tb;
    }

    function rerenderTable() {
        const root = document.getElementById("cases-table");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(buildTable());
        const count = document.getElementById("cases-count");
        if (count) {
            const rows = filtered();
            count.textContent = `${rows.length} of ${state.cases.length} cases`;
        }
    }

    function buildTable() {
        const rows = filtered();
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        if (!state.cases.length) {
            card.appendChild(F.emptyState("▲", "No cases yet",
                "Cases are created automatically when the correlation engine clusters related detections."));
            return card;
        }
        if (!rows.length) {
            card.appendChild(F.emptyState("◎", "No cases match your filters",
                "Try clearing the search box or resetting the severity / status filters."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null,
                el("tr", null,
                    el("th", null, "Case"),
                    el("th", null, "Severity"),
                    el("th", null, "Status"),
                    el("th", null, "Evidence"),
                    el("th", null, "Updated"),
                    el("th", null, "Reports"),
                ),
            ),
            el("tbody", null, rows.map(rowFor)),
        );
        card.appendChild(tbl);
        return card;
    }

    async function render() {
        const initialQ = F.getQuery("q");
        if (initialQ) state.filter = initialQ;
        PSUI.mount(document.getElementById("cases-root"), {
            title: "Incidents",
            subtitle: "Security cases opened by the correlation engine, ranked for triage.",
            requireAuth: true,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "cases-content" });
                main.appendChild(content);
                content.appendChild(renderToolbar());
                const tableHost = el("div", { id: "cases-table" });
                content.appendChild(tableHost);
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading cases…");
                content.appendChild(banner);
                await loadCases();
                banner.remove();
                rerenderTable();
            },
        });
    }

    global.PSCases = { render };
})(window);
