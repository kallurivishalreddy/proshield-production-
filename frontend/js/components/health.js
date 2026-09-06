/**
 * Health — operational health console.
 *
 * Wired to: real /health endpoint + live SecureProxy probes of every
 * operational operation (overview.summary, source.*, rule.*, case.*,
 * detection.*, correlation.*, event.list, timeline.build_for_incident
 * against the most recent case).
 *
 * Every probe row shows a friendly component name with the technical
 * operation code as secondary metadata, a Healthy/Failed pill and the
 * latency. No phantom operations, no fabricated green: a failed probe
 * renders its error verbatim.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;

    // friendly component name → technical operation
    const COMPONENTS = {
        "health":                    "Backend API",
        "overview.summary":          "Dashboard summary",
        "source.list":               "Source inventory",
        "source.list_types":         "Source type catalogue",
        "rule.list":                 "Rule library",
        "case.list":                 "Case service",
        "detection.list":            "Detection engine",
        "correlation.list":          "Correlation engine",
        "event.list":                "Event store",
        "timeline.build_for_incident": "Timeline engine",
    };

    async function probe() {
        const probes = [];
        async function add(name, fn) {
            const t0 = performance.now();
            try {
                const r = await fn();
                const ms = (performance.now() - t0).toFixed(0);
                probes.push({ name, ok: true, ms, detail: r });
            } catch (e) {
                const ms = (performance.now() - t0).toFixed(0);
                probes.push({ name, ok: false, ms, error: e.message });
            }
        }
        await add("health", () => PSAPI.health().then((r) => {
            if (!r || r.ok === false) throw new Error("backend unreachable");
            return r.body || r;
        }));
        // ``/api/meta`` is a real unauthenticated HTTP GET handled by
        // the HTTP server itself, not a proxy op — no probe emitted.
        await add("overview.summary", () => PSAPI.callOrThrow("overview.summary"));
        await add("source.list", () => PSAPI.callOrThrow("source.list"));
        await add("source.list_types", () => PSAPI.callOrThrow("source.list_types"));
        await add("rule.list", () => PSAPI.callOrThrow("rule.list"));
        await add("case.list", () => PSAPI.callOrThrow("case.list", { limit: 1 }));
        await add("detection.list", () => PSAPI.callOrThrow("detection.list", { limit: 1 }));
        await add("correlation.list", () => PSAPI.callOrThrow("correlation.list", { limit: 1 }));
        await add("event.list", () => PSAPI.callOrThrow("event.list", { limit: 1 }));
        // The timeline surface is probed with its real operation
        // (``timeline.build_for_incident``) against the most recent
        // case when one exists (V2-14/V2-17 fix retained).
        let firstCaseId = null;
        try {
            const cl = await PSAPI.callOrThrow("case.list", { limit: 1 });
            const rows = (cl && cl.cases) || [];
            if (rows.length && rows[0] && rows[0].incident_id) {
                firstCaseId = rows[0].incident_id;
            }
        } catch (e) { /* no cases (or none readable): skip below */ }
        if (firstCaseId) {
            await add("timeline.build_for_incident", () =>
                PSAPI.callOrThrow("timeline.build_for_incident", {
                    incident_id: firstCaseId,
                }));
        }
        return probes;
    }

    function renderProbe(p) {
        const name = COMPONENTS[p.name] || p.name;
        const tr = el("tr", null);
        tr.appendChild(el("td", null,
            el("div", { style: { fontWeight: "600" } }, name),
            el("div", { class: "tech-id" }, el("code", null, p.name)),
        ));
        tr.appendChild(el("td", null, p.ok
            ? F.badge("healthy", "ok")
            : F.badge("failed", "err")));
        tr.appendChild(el("td", { class: "num" }, p.ms + " ms"));
        tr.appendChild(el("td", null, p.ok
            ? el("span", { class: "muted" }, "responded")
            : el("div", { class: "error-banner" }, p.error || "unknown error")));
        return tr;
    }

    async function render() {
        const meta = await PSAPI.loadMeta();
        PSUI.mount(document.getElementById("health-root"), {
            title: "Health",
            subtitle: "Live probe of every operational component, executed on demand.",
            requireAuth: true,
            actions: el("button", {
                class: "btn",
                onclick: () => location.reload(),
            }, "↻ Re-probe"),
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", null);

                // Overall status is rendered AFTER the probes complete;
                // until then we show an honest loading state instead
                // of a premature green banner.
                const bannerSlot = el("div", null,
                    el("div", { class: "loading-banner" },
                        el("span", { class: "spinner" }),
                        " Probing components…"));
                content.appendChild(bannerSlot);

                const m = meta || {};
                const metaCard = el("div", { class: "card" },
                    el("div", { class: "card-title" },
                        el("h3", null, "Backend"),
                        el("span", { class: "muted" },
                            "runtime metadata (GET /api/meta)"),
                    ),
                );
                const dl = el("dl", { class: "kv" });
                for (const [k, v] of Object.entries(m)) {
                    if (v == null) continue;
                    dl.appendChild(el("dt", null, F.titleCase(k)));
                    dl.appendChild(el("dd", null, typeof v === "object"
                        ? JSON.stringify(v) : String(v)));
                }
                metaCard.appendChild(dl);
                content.appendChild(metaCard);

                const probeCard = el("div", { class: "card",
                    style: { padding: "0", overflow: "hidden" } },
                    el("div", { class: "card-title",
                        style: { padding: "14px 18px 0" } },
                        el("h2", null, "Components"),
                        el("span", { class: "muted" },
                            "each row is one live call"),
                    ),
                );
                const tbl = el("table", null,
                    el("thead", null, el("tr", null,
                        el("th", null, "Component"),
                        el("th", null, "Status"),
                        el("th", null, "Latency"),
                        el("th", null, "Detail"),
                    )),
                    el("tbody", { id: "probes-body" }),
                );
                probeCard.appendChild(tbl);
                content.appendChild(probeCard);

                main.appendChild(content);
                const body = document.getElementById("probes-body");
                const probes = await probe();
                for (const p of probes) body.appendChild(renderProbe(p));

                const failed = probes.filter((p) => !p.ok);
                bannerSlot.replaceChildren(el("div", {
                    class: "health-banner" +
                        (failed.length === 0 ? "" :
                         failed.length === probes.length ? " down" : " degraded"),
                },
                    el("span", { class: "hb-icon", "aria-hidden": "true" },
                        failed.length === 0 ? "✓" :
                        failed.length === probes.length ? "✕" : "!"),
                    failed.length === 0
                        ? "All systems operational (" + probes.length + " components)"
                        : failed.length === probes.length
                            ? "All components failing — backend unreachable?"
                            : failed.length + " of " + probes.length +
                              " components failing: " +
                              failed.map((p) =>
                                  COMPONENTS[p.name] || p.name).join(", "),
                ));
            },
        });
    }

    global.PSHealth = { render };
})(window);
