/**
 * Rules page — security-control lifecycle management.
 *
 * Wired to:
 *   - rule.list, rule.get
 *   - rule.enable, rule.disable, rule.retire  (real wire ops)
 *
 * CONTRACT FIXES:
 *   - ManagedRuleDefinition has ``name`` (not ``title``) and NO
 *     ``provider`` field; the old table always fell back to the raw
 *     rule_id and showed a permanently empty provider column.
 *   - rule.approve / rule.revoke / rule.candidates / rule.history are
 *     NOT in ALLOWED_OPERATIONS — the old detail panel offered
 *     lifecycle buttons that only ever produced 400s. Only the real
 *     Enable / Disable / Retire actions are rendered.
 *
 * Rules display as security-control objects: human name + display ID
 * (RULE-01…), severity, lifecycle state, scope; the semantic rule_id
 * (e.g. NGINX-AUTH-BRUTEFORCE-001) is a stable secondary identifier.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = {
        rules: [],
        selectedId: null,
        details: null,
        filter: "",
    };

    async function loadRules() {
        try {
            const d = await PSAPI.callOrThrow("rule.list");
            state.rules = d.rules || [];
        } catch (e) {
            state.rules = [];
            PSFmt.toast("Failed to load rules: " + e.message, "err");
        }
        I.registerAll("RULE", state.rules.map((r) => ({
            id: r.rule_id, sortKey: r.rule_id,
        })));
    }

    async function selectRule(ruleId) {
        state.selectedId = ruleId;
        state.details = null;
        rerenderDetail();
        rerenderTable();
        try {
            const d = await PSAPI.callOrThrow("rule.get", { rule_id: ruleId });
            state.details = d.rule;
        } catch (e) {
            state.details = { rule_id: ruleId, _error: e.message };
        }
        // NOTE: there is no shipped history-READ wire op. ``rule.version``
        // CREATES a new version (a mutation) and ``rule.history`` is not
        // in ALLOWED_OPERATIONS — the version-history panel is therefore
        // never rendered rather than firing a 400.
        rerenderDetail();
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        if (!q) return state.rules;
        return state.rules.filter((r) => {
            const blob = [r.rule_id, I.display("RULE", r.rule_id), r.name,
                r.category, r.type, r.state, r.severity,
                (r.tags || []).join(" "), (r.sources || []).join(" ")]
                .join(" ").toLowerCase();
            return blob.includes(q);
        });
    }

    function rowFor(r) {
        const selected = r.rule_id === state.selectedId;
        const tr = el("tr", {
            class: "clickable" + (selected ? " selected" : ""),
            onclick: () => selectRule(r.rule_id),
            title: "Show rule details",
        });
        tr.appendChild(el("td", null,
            el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                el("span", { class: "display-id" }, I.display("RULE", r.rule_id)),
                el("span", { style: { fontWeight: "600" } },
                    r.name || r.rule_id),
            ),
            el("div", { class: "tech-id" }, el("code", null, r.rule_id)),
        ));
        tr.appendChild(el("td", null,
            el("span", { class: "chip" }, F.titleCase(r.category) || "—")));
        tr.appendChild(el("td", null,
            F.pill(r.severity, F.severityClass(r.severity))));
        tr.appendChild(el("td", null, F.badge(r.state, F.stateClass(r.state))));
        tr.appendChild(el("td", null, r.enabled
            ? F.badge("enabled", "ok")
            : F.badge("disabled", "warn")));
        return tr;
    }

    function rerenderTable() {
        const root = document.getElementById("rules-table");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(buildTable());
    }

    function buildTable() {
        const rows = filtered();
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        if (!state.rules.length) {
            card.appendChild(F.emptyState("✦", "No rules registered",
                "Detection rules drive the rules engine. Register rules to start producing detections."));
            return card;
        }
        if (!rows.length) {
            card.appendChild(F.emptyState("◎", "No rules match your filter",
                "Try a different search term."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null,
                el("tr", null,
                    el("th", null, "Rule"),
                    el("th", null, "Category"),
                    el("th", null, "Severity"),
                    el("th", null, "Lifecycle"),
                    el("th", null, "Engine"),
                ),
            ),
            el("tbody", null, rows.map(rowFor)),
        );
        card.appendChild(tbl);
        return card;
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar" });
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search rules…",
                value: state.filter,
                "aria-label": "Search rules",
                oninput: (e) => { state.filter = e.target.value; rerenderTable(); },
            }),
        ));
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "rules-count" },
            state.rules.length
                ? `${filtered().length} of ${state.rules.length} rules`
                : ""));
        tb.appendChild(el("a", { href: "/static/detections.html",
            class: "btn btn-sm" },
            "View detections"));
        return tb;
    }

    function buildDetail() {
        const card = el("div", { class: "card" });
        const r = state.details;
        if (!r) {
            card.appendChild(F.emptyState("✦", "Select a rule",
                "Pick a rule from the list to inspect its definition and lifecycle."));
            return card;
        }
        if (r._error) {
            card.appendChild(el("div", { class: "error-banner" },
                "Failed to load rule: " + r._error));
            return card;
        }

        card.appendChild(el("div", { class: "card-title" },
            el("div", null,
                el("div", { class: "row", style: { gap: "8px" } },
                    el("span", { class: "display-id" }, I.display("RULE", r.rule_id)),
                    F.pill(r.severity, F.severityClass(r.severity)),
                    F.badge(r.state, F.stateClass(r.state)),
                ),
                el("h2", { style: { margin: "4px 0 0" } }, r.name || r.rule_id),
                el("div", { class: "muted mono" }, r.rule_id + " · v" + r.version),
            ),
        ));

        if (r.description) {
            card.appendChild(el("p", null, r.description));
        }

        const dl = el("dl", { class: "kv" });
        const add = (k, v) => {
            if (v == null || v === "" ||
                (Array.isArray(v) && v.length === 0)) return;
            dl.appendChild(el("dt", null, k));
            dl.appendChild(el("dd", null, v));
        };
        add("Category", r.category ? el("span", { class: "chip" },
            F.titleCase(r.category)) : null);
        add("Rule type", r.type ? F.titleCase(r.type) : null);
        add("Severity", F.pill(r.severity, F.severityClass(r.severity)));
        add("Lifecycle", F.badge(r.state, F.stateClass(r.state)));
        add("Engine state", r.enabled
            ? F.badge("enabled", "ok")
            : F.badge("disabled", "warn"));
        if (r.sources && r.sources.length) {
            add("Source scope",
                el("div", { class: "status-row" },
                    r.sources.map((s) => el("span", { class: "chip" }, s))));
        }
        if (r.event_types && r.event_types.length) {
            add("Event types",
                el("div", { class: "status-row" },
                    r.event_types.map((s) => el("span", { class: "chip" }, s))));
        }
        if (r.tags && r.tags.length) {
            add("Tags",
                el("div", { class: "status-row" },
                    r.tags.map((s) => el("span", { class: "chip" }, s))));
        }
        if (r.window_seconds != null) {
            add("Window", r.window_seconds + "s");
        }
        if (r.actions && r.actions.length) {
            add("Actions", r.actions.join(", "));
        }
        card.appendChild(dl);

        // Lifecycle actions — only the real wire ops.
        const stack = el("div", { class: "action-stack",
            style: { marginTop: "14px" } });
        if (r.enabled) {
            stack.appendChild(el("button", { class: "btn",
                onclick: () => invoke("rule.disable",
                    { rule_id: r.rule_id, version: r.version }) },
                "⏸ Disable rule"));
        } else if (r.state === "approved" || r.state === "candidate") {
            stack.appendChild(el("button", { class: "btn btn-primary",
                onclick: () => invoke("rule.enable",
                    { rule_id: r.rule_id, version: r.version }) },
                "▶ Enable rule"));
        }
        if (r.state !== "retired") {
            stack.appendChild(el("div", { class: "danger-zone" },
                el("div", { class: "danger-zone-label" }, "Danger zone"),
                el("button", { class: "btn btn-danger",
                    onclick: () => retire(r) },
                    "✕ Retire rule"),
            ));
        }
        if (stack.childNodes.length) {
            card.appendChild(stack);
        }

        // Definition — the technical control definition, secondary.
        const defBlob = {};
        for (const k of ["combinator", "conditions", "scope",
                         "evidence_requirements", "thresholds",
                         "window_seconds", "actions", "references"]) {
            if (r[k] != null &&
                !(Array.isArray(r[k]) && r[k].length === 0)) {
                defBlob[k] = r[k];
            }
        }
        if (Object.keys(defBlob).length) {
            card.appendChild(el("details", { class: "tech-panel" },
                el("summary", null, "Definition (technical)"),
                el("div", { class: "tech-body" },
                    el("pre", { class: "code-block" },
                        JSON.stringify(defBlob, null, 2))),
            ));
        }
        return card;
    }

    function rerenderDetail() {
        const root = document.getElementById("rules-detail");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(buildDetail());
    }

    async function invoke(op, body) {
        try {
            await PSAPI.callOrThrow(op, body);
            PSFmt.toast("Rule " + op.replace("rule.", "") + " — done.", "ok");
            await loadRules();
            rerenderTable();
            if (state.selectedId) {
                try {
                    const d = await PSAPI.callOrThrow("rule.get",
                        { rule_id: state.selectedId });
                    state.details = d.rule;
                } catch (e) {
                    state.details = { rule_id: state.selectedId,
                                      _error: e.message };
                }
            }
            rerenderDetail();
        } catch (e) {
            PSFmt.toast("Failed: " + e.message, "err");
        }
    }

    async function retire(r) {
        const ok = await F.confirmDialog(
            "Retire rule '" + (r.name || r.rule_id) + "'? Retirement is " +
            "the terminal lifecycle state.",
            { title: "Retire rule", okLabel: "Retire" });
        if (!ok) return;
        await invoke("rule.retire", { rule_id: r.rule_id, version: r.version });
    }

    async function render() {
        PSUI.mount(document.getElementById("rules-root"), {
            title: "Rules",
            subtitle: "The detection-rule library and its lifecycle. Enabled rules drive the live detection engine.",
            requireAuth: true,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "rules-content" });
                main.appendChild(content);
                content.appendChild(renderToolbar());
                const grid = el("div", { class: "grid-2" });
                const left = el("div", { id: "rules-table" });
                const right = el("div", { id: "rules-detail" });
                grid.appendChild(left);
                grid.appendChild(right);
                content.appendChild(grid);
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading rules…");
                content.appendChild(banner);
                await loadRules();
                banner.remove();
                const count = document.getElementById("rules-count");
                if (count) count.textContent = state.rules.length
                    ? `${filtered().length} of ${state.rules.length} rules`
                    : "";
                rerenderTable();
                rerenderDetail();
            },
        });
    }

    global.PSRules = { render, selectRule };
})(window);
