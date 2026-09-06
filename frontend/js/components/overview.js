/**
 * Overview / Dashboard page.
 *
 * Wired to:
 *   - overview.summary (open_case_count, detection_count,
 *     correlation_count, scope — the complete backend contract;
 *     the old page invented "high_severity_open_cases" /
 *     "high_confidence_count" fields the backend never emits)
 *   - source.list      (source inventory + health)
 *   - rule.list        (active rules)
 *   - case.list        (priority incidents queue)
 *   - detection.list   (recent detections)
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    // Truthful load tracking for the platform panel — a row is only
    // "OK" when its data actually loaded, never a fabricated green.
    const loads = { summary: false, cases: false, detections: false,
                    rules: false, sources: false };

    async function loadSummary() {
        try { return await PSAPI.callOrThrow("overview.summary"); }
        finally { loads.summary = true; }
    }
    async function loadSources() {
        try {
            const d = await PSAPI.callOrThrow("source.list");
            return d.sources || [];
        } finally { loads.sources = true; }
    }
    async function loadRules() {
        try {
            const d = await PSAPI.callOrThrow("rule.list");
            return d.rules || [];
        } finally { loads.rules = true; }
    }
    async function loadCases() {
        try {
            const d = await PSAPI.callOrThrow("case.list", { limit: 200 });
            return d.cases || [];
        } finally { loads.cases = true; }
    }
    async function loadDetections() {
        try {
            const d = await PSAPI.callOrThrow("detection.list", { limit: 10 });
            return d.detections || [];
        } finally { loads.detections = true; }
    }

    function registerCaseIds(cases) {
        I.registerAll("CASE", cases.map((c) => ({
            id: c.incident_id,
            sortKey: c.created_at || "",
        })));
    }

    function kpiCard(label, value, delta, colorKind) {
        const card = el("div", { class: "kpi " + (colorKind || "") });
        card.appendChild(el("div", { class: "label" }, label));
        // String values (e.g. "1/1") render verbatim; numbers are
        // locale-formatted. Never "NaN"/"undefined".
        const shown = typeof value === "number" ? F.fmtNumber(value)
            : (value == null || value === "" ? "0" : String(value));
        card.appendChild(el("div", { class: "value" }, shown));
        card.appendChild(el("div", { class: "delta" }, delta));
        return card;
    }

    function renderKpis(summary, rules, sources, cases) {
        const grid = el("div", { class: "kpi-grid" });
        const open = summary ? (summary.open_case_count ?? 0) : 0;
        // Computed from the real case rows the analyst can see —
        // overview.summary has no per-severity breakdown, so we derive
        // this truthfully from the loaded open cases.
        const highOpen = cases.filter((c) =>
            c.state === "open" &&
            F.severityRank(c.severity) <= 1).length;
        const enabledRules = rules.filter((r) =>
            r.enabled && r.state === "approved").length;
        const enabledSources = sources.filter((s) => s.state === "enabled").length;
        const scope = summary ? summary.scope : null;

        grid.appendChild(kpiCard("Open Cases", open,
            "cases awaiting triage", open > 0 ? "amber" : "green"));
        grid.appendChild(kpiCard("High & Critical", highOpen,
            "open cases by severity", highOpen > 0 ? "red" : "green"));
        grid.appendChild(kpiCard("Detections", summary ? summary.detection_count : 0,
            "total produced by rules"));
        grid.appendChild(kpiCard("Correlations", summary ? summary.correlation_count : 0,
            "total clusters found"));
        grid.appendChild(kpiCard("Active Rules",
            enabledRules, "approved and enabled"));
        grid.appendChild(kpiCard("Sources Enabled",
            `${enabledSources}/${sources.length}`,
            scope ? `visibility scope: ${scope}` : "of configured sources"));
        return grid;
    }

    function renderIncidentsQueue(cases) {
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        card.appendChild(el("div", { class: "card-title",
            style: { padding: "14px 18px 0" } },
            el("h2", null, "Priority Cases"),
            el("a", { href: "/static/cases.html", class: "muted" }, "View all →"),
        ));
        const openCases = cases
            .filter((c) => c.state !== "closed")
            .sort((a, b) => {
                const d = F.severityRank(a.severity) - F.severityRank(b.severity);
                if (d !== 0) return d;
                return (b.updated_at || "").localeCompare(a.updated_at || "");
            })
            .slice(0, 8);
        if (!openCases.length) {
            card.appendChild(F.emptyState("✓", "No open cases",
                "Nothing is awaiting triage right now. New cases appear here automatically."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null,
                el("tr", null,
                    el("th", null, "Case"),
                    el("th", null, "Severity"),
                    el("th", null, "Status"),
                    el("th", null, "Updated"),
                ),
            ),
            el("tbody", null, openCases.map((c) => {
                const tr = el("tr", {
                    class: "clickable",
                    onclick: () => location.href = "/static/case.html?id=" +
                        encodeURIComponent(c.incident_id),
                });
                const caseCell = el("td", null,
                    el("div", { class: "row", style: { gap: "8px" } },
                        el("span", { class: "display-id" }, I.display("CASE", c.incident_id)),
                        el("span", null, c.title || "Untitled case"),
                    ),
                    el("div", { class: "tech-id" },
                        el("code", null, c.incident_id)));
                tr.appendChild(caseCell);
                tr.appendChild(el("td", null,
                    F.pill(c.severity, F.severityClass(c.severity))));
                tr.appendChild(el("td", null, F.badge(c.state, F.stateClass(c.state))));
                tr.appendChild(el("td", null,
                    el("span", { title: F.fmtTime(c.updated_at) },
                        F.fmtRelative(c.updated_at))));
                return tr;
            })),
        );
        card.appendChild(tbl);
        return card;
    }

    function renderRecentDetections(detections, ruleNames) {
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h2", null, "Recent Detections"),
            el("a", { href: "/static/detections.html", class: "muted" }, "View all →"),
        ));
        if (!detections.length) {
            card.appendChild(F.emptyState("◎", "No detections yet",
                "Detections appear once a connected source sends telemetry that matches an active rule."));
            return card;
        }
        I.registerAll("DET", detections.map((d) => ({
            id: d.detection_id, sortKey: d.detected_at || "",
        })));
        const list = el("div", null);
        for (const d of detections) {
            const ruleName = ruleNames[d.rule_id] || null;
            list.appendChild(el("div", {
                class: "row",
                style: { padding: "9px 0", borderBottom: "1px solid var(--line)",
                         justifyContent: "space-between", flexWrap: "nowrap" },
            },
                el("div", { style: { minWidth: "0" } },
                    el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                        el("span", { class: "display-id" }, I.display("DET", d.detection_id)),
                        el("span", { style: {
                            overflow: "hidden", textOverflow: "ellipsis",
                            whiteSpace: "nowrap" } },
                            ruleName || F.titleCase(d.category) || "Detection"),
                    ),
                    el("div", { class: "muted" },
                        (d.reasoning || "").slice(0, 90) ||
                        "Rule " + (d.rule_id || "—") + " v" + (d.rule_version || "?"))),
                el("div", { class: "row", style: { flex: "none", gap: "8px" } },
                    d.category ? el("span", { class: "chip" }, F.titleCase(d.category)) : null,
                    el("span", { class: "muted", title: F.fmtTime(d.detected_at) },
                        F.fmtRelative(d.detected_at)),
                ),
            ));
        }
        card.appendChild(list);
        return card;
    }

    function renderPlatformPanel(sources, summary) {
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h2", null, "Platform"),
        ));
        const enabled = sources.filter((s) => s.state === "enabled").length;
        const errored = sources.filter((s) =>
            s.health && s.health.status === "degraded").length;
        const rows = [
            ["API / SecureProxy", loads.summary ? "OK" : "Unavailable",
             loads.summary ? "ok" : "err"],
            ["Case Service", loads.cases ? "OK" : "Unavailable",
             loads.cases ? "ok" : "err"],
            ["Detection Engine", loads.detections ? "OK" : "Unavailable",
             loads.detections ? "ok" : "err"],
            ["Sources Connected",
             sources.length ? `${enabled}/${sources.length}` : "None registered",
             sources.length === 0 ? "warn" : (enabled === sources.length ? "ok" : "warn")],
            ["Degraded Sources", String(errored), errored > 0 ? "warn" : "ok"],
        ];
        const wrap = el("div", null);
        for (const [label, value, kind] of rows) {
            wrap.appendChild(el("div", {
                class: "row",
                style: { padding: "9px 0", borderBottom: "1px solid var(--line)",
                         justifyContent: "space-between", flexWrap: "nowrap" },
            },
                el("div", { style: { flex: "1" } }, label),
                el("div", { style: { flex: "none" } }, F.badge(value, kind)),
            ));
        }
        wrap.lastChild.style.borderBottom = "none";
        card.appendChild(wrap);
        card.appendChild(el("div", { style: { marginTop: "12px" } },
            el("a", { href: "/static/health.html", class: "muted" },
                "Open health console →")));
        return card;
    }

    async function render() {
        const main = document.querySelector("main.main")
            || document.getElementById("app");
        if (!main) {
            console.error("PSOverview: no main element found");
            return;
        }
        const wrap = el("div", null);

        const banner = el("div", { class: "loading-banner" },
            el("span", { class: "spinner" }), " Loading overview…");
        wrap.appendChild(banner);
        main.appendChild(wrap);

        const [summary, sources, rules, cases, detections] =
            await Promise.allSettled([
                loadSummary(), loadSources(), loadRules(),
                loadCases(), loadDetections(),
            ]).then((rs) => rs.map((r) =>
                r.status === "fulfilled" ? r.value :
                    (console.warn("overview load failed:", r.reason), null)));

        // Failed loads surface as truthful "Unavailable" rows — a
        // rejected call must never render a green dashboard.
        const sum = loads.summary ? summary : null;
        const src = loads.sources ? (sources || []) : [];
        const rls = loads.rules ? (rules || []) : [];
        const cs = loads.cases ? (cases || []) : [];
        const dts = loads.detections ? (detections || []) : [];

        registerCaseIds(cs);
        const ruleNames = {};
        for (const r of rls) ruleNames[r.rule_id] = r.name || r.rule_id;

        banner.remove();
        wrap.appendChild(renderKpis(sum, rls, src, cs));

        const grid = el("div", { class: "grid-2" });
        const left = el("div", null,
            renderIncidentsQueue(cs),
            renderRecentDetections(dts, ruleNames),
        );
        const right = el("div", null, renderPlatformPanel(src, sum));
        grid.appendChild(left);
        grid.appendChild(right);
        wrap.appendChild(grid);
    }

    global.PSOverview = { render };
})(window);
