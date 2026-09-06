/**
 * Global investigation timeline.
 *
 * Wired to: case.list + timeline.build_for_incident (the documented
 * per-incident surface; the global page merges case timelines).
 *
 * CONTRACT FIX: timeline.build_for_incident returns ``{items: [...]}``
 * at the TOP LEVEL of the payload with TimelineItem fields
 * (timeline_item_id / kind / source_id / occurred_at / description /
 * reasoning). The old page read a nested ``timeline`` wrapper plus
 * ``events``/``timestamp``/``title``/``event_id`` fields the backend
 * never emits — so this page silently rendered empty. De-duplication
 * now keys on timeline_item_id (event_id does not exist on items).
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = { events: [], filter: "", kind: "all", cases: {} };

    async function load() {
        state.events = [];
        state.cases = {};
        try {
            const cl = await PSAPI.callOrThrow("case.list", { limit: 50 });
            const cases = cl.cases || [];
            I.registerAll("CASE", cases.map((c) => ({
                id: c.incident_id, sortKey: c.created_at || "",
            })));
            for (const c of cases) state.cases[c.incident_id] = c;
            const all = [];
            for (const c of cases) {
                try {
                    const d = await PSAPI.callOrThrow(
                        "timeline.build_for_incident", {
                            incident_id: c.incident_id, limit: 100,
                        });
                    const items = (d && Array.isArray(d.items)) ? d.items : [];
                    for (const it of items) {
                        all.push(Object.assign({}, it, {
                            incident_id: c.incident_id,
                        }));
                    }
                } catch (e) { /* per-case failures are tolerated */ }
            }
            // de-dupe by the real item identity
            const seen = new Set();
            state.events = all.filter((e) => {
                const key = e.timeline_item_id ||
                    (e.incident_id + "|" + e.source_id + "|" + e.occurred_at);
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
            // newest first
            state.events.sort((a, b) =>
                (b.occurred_at || "").localeCompare(a.occurred_at || ""));
        } catch (e) {
            PSFmt.toast("Failed to load timeline: " + e.message, "err");
        }
    }

    function objectLabelFor(ev) {
        if (ev.source_id && ev.source_id.startsWith("det-")) {
            return { label: I.display("DET", ev.source_id), kind: "DET" };
        }
        if (ev.source_id && ev.source_id.startsWith("corr-")) {
            return { label: I.display("CORR", ev.source_id), kind: "CORR" };
        }
        return null;
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        return state.events.filter((ev) => {
            if (state.kind !== "all" && ev.kind !== state.kind) return false;
            if (q) {
                const lbl = objectLabelFor(ev);
                const blob = [ev.timeline_item_id, ev.description,
                    ev.reasoning, ev.kind, ev.source_id,
                    lbl ? lbl.label : "",
                    I.display("CASE", ev.incident_id)]
                    .filter(Boolean).join(" ").toLowerCase();
                if (!blob.includes(q)) return false;
            }
            return true;
        });
    }

    function rerender() {
        const root = document.getElementById("tl-content");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(buildRail());
        const count = document.getElementById("tl-count");
        if (count) count.textContent =
            `${filtered().length} of ${state.events.length} entries`;
    }

    function buildRail() {
        const events = filtered();
        if (!state.events.length) {
            return F.emptyState("◷", "No timeline entries",
                "Timeline entries are derived from case evidence. They appear once events flow through a connected source.");
        }
        if (!events.length) {
            return F.emptyState("◎", "No entries match your filters",
                "Try clearing the search box or choosing a different kind.");
        }
        const rail = el("div", { class: "timeline" });
        for (const ev of events) {
            const kind = ev.kind || "observed";
            const obj = objectLabelFor(ev);
            const desc = ev.description || "";
            const title = desc ? desc.split("\n")[0].slice(0, 160)
                               : (obj ? obj.label : F.titleCase(kind));
            rail.appendChild(el("div", { class: "timeline-item " + kind },
                el("div", { class: "time" }, F.fmtTime(ev.occurred_at)),
                el("div", { class: "timeline-card" },
                    el("div", { class: "status-row" },
                        F.badge(kind, F.stateClass(kind)),
                        el("span", { class: "tl-title" }, title),
                    ),
                    obj
                        ? el("div", { class: "meta" },
                            "Object: " + obj.label + " · " + F.titleCase(kind))
                        : null,
                    ev.reasoning
                        ? el("div", { class: "meta" }, ev.reasoning)
                        : null,
                    el("div", { class: "meta" },
                        "Case: ",
                        el("span", { class: "display-id" },
                            I.display("CASE", ev.incident_id)),
                        ev.incident_id
                            ? el("a", { href: "/static/case.html?id=" +
                                encodeURIComponent(ev.incident_id),
                                style: { marginLeft: "8px" } },
                                "Open case →")
                            : null,
                    ),
                ),
            ));
        }
        return rail;
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar" });
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search timeline…",
                value: state.filter,
                "aria-label": "Search timeline",
                oninput: (e) => { state.filter = e.target.value; rerender(); },
            }),
        ));
        const sel = el("select", {
            "aria-label": "Filter by kind",
            onchange: (e) => { state.kind = e.target.value; rerender(); } });
        for (const k of ["all", "observed", "detection", "correlation",
                         "derived", "recommendation"]) {
            sel.appendChild(el("option", { value: k },
                k === "all" ? "All kinds" : F.titleCase(k)));
        }
        sel.value = state.kind;
        tb.appendChild(sel);
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "tl-count" }, ""));
        return tb;
    }

    async function render() {
        PSUI.mount(document.getElementById("timeline-root"), {
            title: "Timeline",
            subtitle: "Chronological investigation stream derived from case evidence.",
            requireAuth: true,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "tl-content" });
                const card = el("div", { class: "card" },
                    el("div", { class: "card-title" },
                        el("h2", null, "Recent activity"),
                        el("span", { class: "muted" }, "")),
                    content,
                );
                main.appendChild(el("div", null, renderToolbar(), card));
                const loading = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading timeline…");
                content.appendChild(loading);
                await load();
                loading.remove();
                rerender();
            },
        });
    }

    global.PSTimeline = { render };
})(window);
