/**
 * Case detail — the analyst investigation workspace.
 *
 * Wired to real ops only:
 *   case.get, case.close, case.centralized, report.generate_normal,
 *   report.export, timeline.build_for_incident,
 *   detection.list_for_incident, correlation.list_for_incident,
 *   rule.list (rule names for detection titles).
 *
 * Visual contract (see V2 FRONTEND / UI-UX UPGRADE REVALIDATION):
 *   CASE-01 + attack title + severity/state badges + analyst summary
 *   → evidence counts as compact stat cards
 *   → timeline / detections / correlations in the main column
 *   → facts, actions and technical details in the context column.
 * The internal incident_id is preserved and copyable in the
 * Technical details panel — never the visual headline.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = { caseId: null, data: null, timeline: [],
                  detections: [], correlations: [], report: null,
                  ruleNames: {} };

    async function loadCase() {
        const d = await PSAPI.callOrThrow("case.get", {
            incident_id: state.caseId,
        });
        state.data = d.case;
        state.report = null;
        I.registerAll("CASE", [{ id: state.data.incident_id,
                                 sortKey: state.data.created_at || "" }]);
    }

    async function loadTimeline() {
        try {
            const d = await PSAPI.callOrThrow("timeline.build_for_incident", {
                incident_id: state.caseId,
            });
            // The wire contract returns {items: [...]} at the top of
            // the payload (V2-18).
            state.timeline = (d && Array.isArray(d.items)) ? d.items : [];
        } catch (e) { state.timeline = []; }
    }

    async function loadDetections() {
        try {
            // Incident-scoped op (V2-03 fix retained).
            const d = await PSAPI.callOrThrow(
                "detection.list_for_incident",
                { incident_id: state.caseId },
            );
            state.detections = d.detections || [];
        } catch (e) { state.detections = []; }
        I.registerAll("DET", state.detections.map((d) => ({
            id: d.detection_id, sortKey: d.detected_at || "",
        })));
    }

    async function loadCorrelations() {
        try {
            // Incident-scoped op (V2-03 fix retained).
            const d = await PSAPI.callOrThrow(
                "correlation.list_for_incident",
                { incident_id: state.caseId },
            );
            state.correlations = d.correlations || [];
        } catch (e) { state.correlations = []; }
        I.registerAll("CORR", state.correlations.map((c) => ({
            id: c.correlation_id, sortKey: c.correlated_at || "",
        })));
    }

    async function loadRuleNames() {
        try {
            const d = await PSAPI.callOrThrow("rule.list", {});
            for (const r of (d.rules || [])) {
                state.ruleNames[r.rule_id] = r.name || r.rule_id;
            }
        } catch (e) { /* names stay fallback rule_id */ }
    }

    function evidenceCounts() {
        const ev = (state.data && state.data.evidence) || {};
        return {
            events: (ev.event_ids || []).length,
            detections: (ev.detection_ids || []).length,
            correlations: (ev.correlation_ids || []).length,
            reports: (state.data && state.data.report_references || []).length,
        };
    }

    function renderHeader() {
        const c = state.data;
        const ev = evidenceCounts();
        const head = el("div", { class: "case-head" });

        head.appendChild(el("div", { class: "case-head-top" },
            el("span", { class: "display-id" }, I.display("CASE", c.incident_id)),
            F.pill(c.severity, F.severityClass(c.severity)),
            F.badge(c.state, F.stateClass(c.state)),
            ev.correlations > 0
                ? F.badge("correlated", "ok")
                : F.badge("no correlation", "warn"),
        ));

        const titleBlock = el("div", { class: "case-title-block" },
            el("h1", null, c.title || "Untitled case"));
        head.appendChild(titleBlock);

        head.appendChild(el("p", { class: "case-summary" },
            c.summary || "No analyst summary has been recorded for this case yet."));

        head.appendChild(el("div", { class: "stat-grid", style: { marginTop: "14px" } },
            F.statCard(ev.events, "Events", "info",
                "Raw security events in the evidence bundle"),
            F.statCard(ev.detections, "Detections", "",
                "Rule matches in the evidence bundle"),
            F.statCard(ev.correlations, "Correlations", "ok",
                "Correlation clusters in the evidence bundle"),
            F.statCard(ev.reports, "Reports", "",
                "Reports generated from this case"),
        ));

        head.appendChild(el("div", { class: "case-meta" },
            el("span", null, "Created ", el("b", null,
                F.fmtTime(c.created_at) || "—")),
            el("span", null, "Updated ", el("b", null,
                F.fmtTime(c.updated_at) || "—")),
            el("span", null, "Opened by ", el("b", null,
                c.created_by || "—")),
            el("span", null, "Confidence ", el("b", null,
                c.confidence ? F.titleCase(c.confidence) : "—")),
        ));
        return head;
    }

    function renderFacts() {
        const c = state.data;
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h3", null, "Case facts")));
        const dl = el("dl", { class: "kv" });
        const add = (k, v) => {
            if (v == null || v === "") return;
            dl.appendChild(el("dt", null, k));
            dl.appendChild(el("dd", null, v));
        };
        add("Display ID", el("span", { class: "display-id" },
            I.display("CASE", c.incident_id)));
        add("Status", F.badge(c.state, F.stateClass(c.state)));
        add("Severity", F.pill(c.severity, F.severityClass(c.severity)));
        add("Confidence", c.confidence ? F.titleCase(c.confidence) : null);
        add("Created", F.fmtTime(c.created_at));
        add("Updated", F.fmtTime(c.updated_at));
        add("Opened by", c.created_by);
        card.appendChild(dl);
        return card;
    }

    function renderActions() {
        const c = state.data;
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h3", null, "Actions")));

        const stack = el("div", { class: "action-stack" });
        if (c.state !== "closed") {
            stack.appendChild(el("button", {
                class: "btn btn-primary",
                onclick: runCentralized,
                title: "Re-run correlation across the full case evidence bundle",
            }, "▶ Run centralized analysis"));
            stack.appendChild(el("button", {
                class: "btn",
                onclick: generateReport,
            }, "⇩ Generate report"));
            if (state.report) {
                stack.appendChild(el("button", {
                    class: "btn",
                    onclick: exportReport,
                }, "⬒ Export report (JSON)"));
            }
            stack.appendChild(el("div", { class: "danger-zone" },
                el("div", { class: "danger-zone-label" }, "Danger zone"),
                el("button", {
                    class: "btn btn-danger",
                    onclick: openClose,
                    title: "Close this case with a reason and resolution",
                }, "✕ Close case"),
            ));
        } else {
            stack.appendChild(el("div", { class: "muted" },
                "This case is closed. No further actions are available."));
        }
        card.appendChild(stack);

        if (state.report) {
            card.appendChild(el("details", { class: "tech-panel",
                style: { marginTop: "12px" } },
                el("summary", null,
                    "Report · " + (state.report.report_id || "")),
                el("div", { class: "tech-body" },
                    el("pre", { class: "code-block" },
                        JSON.stringify(state.report, null, 2).slice(0, 1600))),
            ));
        }
        return card;
    }

    function renderTechnical() {
        const c = state.data;
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h3", null, "Technical details")));
        card.appendChild(el("div", { class: "muted",
            style: { marginBottom: "8px" } },
            "Internal identifiers for cross-referencing with tooling and logs."));
        const dl = el("dl", { class: "kv" });
        dl.appendChild(el("dt", null, "Incident ID"));
        dl.appendChild(el("dd", null, F.techId(c.incident_id, { label: "incident id" })));
        if (c.centralized_correlation_ids && c.centralized_correlation_ids.length) {
            dl.appendChild(el("dt", null, "Centralized correlations"));
            dl.appendChild(el("dd", null,
                el("div", { class: "status-row" },
                    c.centralized_correlation_ids.map((id) =>
                        F.techId(id, { label: "correlation id" })))));
        }
        if (c.centralized_failed) {
            dl.appendChild(el("dt", null, "Centralized failure"));
            dl.appendChild(el("dd", null,
                el("div", { class: "error-banner" },
                    c.centralized_failure_reason || "unknown failure")));
        }
        card.appendChild(dl);
        return card;
    }

    async function runCentralized() {
        try {
            const r = await PSAPI.callOrThrow("case.centralized", {
                incident_id: state.caseId,
                reason: "Analyst-initiated centralized analysis",
            });
            const n = (r.new_correlation_ids || []).length;
            PSFmt.toast(
                r.failed
                    ? "Centralized analysis incomplete: " + (r.failure_reason || "?")
                    : "Centralized analysis complete (" + n + " new correlation" +
                      (n === 1 ? "" : "s") + ").",
                r.failed ? "err" : "ok",
            );
            await Promise.all([loadCase(), loadCorrelations(), loadTimeline()]);
            rerender();
        } catch (e) {
            PSFmt.toast("Centralized analysis failed: " + e.message, "err");
        }
    }

    async function generateReport() {
        try {
            const r = await PSAPI.callOrThrow("report.generate_normal", {
                incident_id: state.caseId,
                title: "Incident report — " + I.display("CASE", state.caseId),
            });
            state.report = r.report;
            PSFmt.toast("Report generated: " + (r.report.report_id || ""), "ok");
            rerender();
        } catch (e) {
            PSFmt.toast("Report generation failed: " + e.message, "err");
        }
    }

    async function exportReport() {
        try {
            if (!state.report) return;
            const r = await PSAPI.callOrThrow("report.export", {
                report_id: state.report.report_id,
                format: "json",
            });
            const blob = new Blob([JSON.stringify(r.payload, null, 2)],
                { type: "application/json" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = (r.report_id || "report") + ".json";
            document.body.appendChild(a);
            a.click();
            setTimeout(() => URL.revokeObjectURL(a.href), 2000);
            PSFmt.toast("Exported report JSON.", "ok");
        } catch (e) {
            PSFmt.toast("Export failed: " + e.message, "err");
        }
    }

    function openClose() {
        // Rich close dialog: reason + resolution, both preserved from
        // the original workflow.
        const root = document.createElement("div");
        root.innerHTML = `
            <div class="confirm-overlay">
                <div class="confirm-modal" style="max-width:520px;">
                    <h3>Close case</h3>
                    <p class="muted">Closing is terminal for the investigation workflow.
                    Provide the reason for the audit trail.</p>
                    <form id="close-form" class="col">
                        <div><label for="close-reason">Reason (required)</label>
                            <textarea id="close-reason" rows="3" required></textarea></div>
                        <div><label for="close-resolution">Resolution</label>
                            <select id="close-resolution">
                                <option value="remediated">Remediated</option>
                                <option value="false_positive">False positive</option>
                                <option value="risk_accepted">Risk accepted</option>
                                <option value="suppressed">Suppressed</option>
                            </select></div>
                        <div class="row" style="justify-content:flex-end;">
                            <button type="button" class="btn" data-act="cancel">Cancel</button>
                            <button type="submit" class="btn btn-danger" data-act="ok">Close case</button>
                        </div>
                    </form>
                </div>
            </div>`;
        document.body.appendChild(root);
        const close = () => root.remove();
        root.querySelector('[data-act="cancel"]').onclick = close;
        root.querySelector("#close-form").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            try {
                const r = await PSAPI.callOrThrow("case.close", {
                    incident_id: state.caseId,
                    reason: root.querySelector("#close-reason").value.trim(),
                    resolution: root.querySelector("#close-resolution").value,
                });
                state.data = r.case || state.data;
                PSFmt.toast("Case closed.", "ok");
                close();
                await loadTimeline();
                rerender();
            } catch (e) { PSFmt.toast("Close failed: " + e.message, "err"); }
        });
    }

    function renderTimeline() {
        const card = el("div", { class: "card" });
        card.appendChild(el("div", { class: "card-title" },
            el("h2", null, "Investigation timeline"),
            el("span", { class: "muted" },
                state.timeline.length + (state.timeline.length === 1 ? " entry" : " entries")),
        ));
        if (!state.timeline.length) {
            card.appendChild(F.emptyState("◷", "No timeline entries yet",
                "Timeline entries are derived from the evidence bundle (events, detections and correlations)."));
            return card;
        }
        const tl = el("div", { class: "timeline" });
        for (const item of state.timeline) {
            const kind = item.kind || "observed";
            // Human title: description's first line, or the mapped
            // object label for detection/correlation items.
            let objectLabel = null;
            if (item.source_id && item.source_id.startsWith("det-")) {
                objectLabel = I.display("DET", item.source_id);
            } else if (item.source_id && item.source_id.startsWith("corr-")) {
                objectLabel = I.display("CORR", item.source_id);
            }
            const desc = item.description || "";
            const title = desc ? desc.split("\n")[0].slice(0, 140)
                               : (objectLabel || F.titleCase(kind));
            const cardEl = el("div", { class: "timeline-card" },
                el("div", { class: "status-row" },
                    F.badge(kind, F.stateClass(kind)),
                    el("span", { class: "tl-title" }, title),
                ),
                objectLabel
                    ? el("div", { class: "meta" }, "Object: " + objectLabel)
                    : null,
                item.reasoning
                    ? el("div", { class: "meta" }, item.reasoning)
                    : null,
            );
            tl.appendChild(el("div", { class: "timeline-item " + kind },
                el("div", { class: "time" }, F.fmtTime(item.occurred_at)),
                cardEl,
            ));
        }
        card.appendChild(tl);
        return card;
    }

    function renderDetections() {
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        card.appendChild(el("div", { class: "card-title",
            style: { padding: "14px 18px 0" } },
            el("h2", null, "Detections"),
            el("span", { class: "muted" }, String(state.detections.length)),
        ));
        if (!state.detections.length) {
            card.appendChild(F.emptyState("◎", "No detections in this case",
                "Detections linked to this case's correlation clusters appear here."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null, el("tr", null,
                el("th", null, "Detection"),
                el("th", null, "Category"),
                el("th", null, "Source event"),
                el("th", null, "Detected at"),
            )),
            el("tbody", null, state.detections.map((d) => {
                const ruleName = state.ruleNames[d.rule_id] || null;
                const tr = el("tr", null);
                tr.appendChild(el("td", null,
                    el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                        el("span", { class: "display-id" }, I.display("DET", d.detection_id)),
                        el("span", null, ruleName ||
                            "Rule " + (d.rule_id || "—") + " v" + (d.rule_version || "?")),
                    ),
                    d.reasoning
                        ? el("div", { class: "muted", style: {
                            maxWidth: "360px", overflow: "hidden",
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
                    title: F.fmtTime(d.detected_at) },
                    F.fmtRelative(d.detected_at))));
                return tr;
            })),
        );
        card.appendChild(tbl);
        return card;
    }

    function renderCorrelations() {
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        card.appendChild(el("div", { class: "card-title",
            style: { padding: "14px 18px 0" } },
            el("h2", null, "Correlations"),
            el("span", { class: "muted" }, String(state.correlations.length)),
        ));
        if (!state.correlations.length) {
            card.appendChild(F.emptyState("⌁", "No correlations",
                "This case has no correlation clusters attached yet. Run centralized analysis to search for more."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null, el("tr", null,
                el("th", null, "Correlation"),
                el("th", null, "Pattern"),
                el("th", null, "Trigger"),
                el("th", null, "Count"),
                el("th", null, "Window"),
            )),
            el("tbody", null, state.correlations.map((c) => {
                const tr = el("tr", null);
                tr.appendChild(el("td", null,
                    el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                        el("span", { class: "display-id" }, I.display("CORR", c.correlation_id)),
                        el("span", null, F.titleCase(c.trigger) || "Cluster"),
                    ),
                ));
                tr.appendChild(el("td", null,
                    el("span", { class: "mono" },
                        (c.pattern_id || "—") + " v" + (c.pattern_version || "?"))));
                tr.appendChild(el("td", null,
                    el("span", { class: "muted" },
                        (c.detection_ids || []).length + " detections · " +
                        (c.event_ids || []).length + " events")));
                tr.appendChild(el("td", { class: "num" }, String(c.count || 0)));
                tr.appendChild(el("td", null,
                    el("span", { class: "muted mono", style: { fontSize: "0.72rem" } },
                        F.fmtTime(c.window_start) + " → " + F.fmtTime(c.window_end))));
                return tr;
            })),
        );
        card.appendChild(tbl);
        return card;
    }

    function rerender() {
        const content = document.getElementById("case-content");
        if (!content) return;
        content.replaceChildren();
        content.appendChild(renderHeader());
        const grid = el("div", { class: "grid-2" });
        const left = el("div", null,
            renderTimeline(),
            renderDetections(),
            renderCorrelations(),
        );
        const right = el("div", null,
            renderFacts(),
            renderActions(),
            renderTechnical(),
        );
        grid.appendChild(left);
        grid.appendChild(right);
        content.appendChild(grid);
    }

    async function render() {
        state.caseId = F.getQuery("id");
        PSUI.mount(document.getElementById("case-root"), {
            title: "Case investigation",
            subtitle: state.caseId
                ? "Technical ID: " + state.caseId
                : "Full evidence, timeline and actions for one case.",
            requireAuth: true,
            actions: el("a", { href: "/static/cases.html",
                class: "btn btn-sm" }, "← All cases"),
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "case-content" });
                main.appendChild(content);
                if (!state.caseId) {
                    content.appendChild(el("div", { class: "card" },
                        el("h2", null, "No case selected"),
                        F.emptyState("▲", "Open a case from the Incidents list",
                            "This page needs a case id. Pick a case from the Incidents page."),
                    ));
                    return;
                }
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading case…");
                content.appendChild(banner);
                try {
                    await Promise.all([loadCase(), loadRuleNames()]);
                    banner.remove();
                    rerender();
                    // Secondary evidence loads after first paint.
                    await Promise.all([loadTimeline(), loadDetections(),
                                       loadCorrelations()]);
                    rerender();
                } catch (e) {
                    banner.remove();
                    content.appendChild(el("div", { class: "card" },
                        el("h2", null, "Failed to load case"),
                        el("div", { class: "error-banner" }, e.message)));
                    PSFmt.toast("Failed to load case: " + e.message, "err");
                }
            },
        });
    }

    global.PSCase = { render };
})(window);
