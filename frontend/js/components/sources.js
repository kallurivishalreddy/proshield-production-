/**
 * Sources page — source-instance management.
 *
 * Wired to:
 *   - source.list, source.get, source.list_types
 *   - source.register, source.configure, source.validate
 *   - source.enable, source.disable, source.retire
 *   - source.issue_token
 *
 * CONTRACT FIX: the SourceInstanceView carries ``health`` (status:
 * ok|degraded|unknown|disabled|retired, plus last_received_at /
 * last_error). The old page rendered ``s.last_event_at`` and
 * ``s.connector_type`` — fields the backend never emits — so the Last
 * Event column was always blank. Health now comes from the real
 * health sub-object.
 *
 * The source-instance workflow is preserved: an operator creates a
 * new SOURCE (an instance of an existing connector capability), then
 * configures → validates → enables it.
 */
(function (global) {
    "use strict";

    const el = PSUI.el;
    const F = PSFmt;
    const I = PSIds;

    let state = {
        sources: [],
        types: [],
        filter: "",
        typeFilter: "all",
        stateFilter: "all",
        // Resolved role of the current user, set in render().
        // Source management is admin-only (Phase 4.9 RBAC:
        // Permission.SOURCE_WRITE). ``analyst`` and ``collector`` see
        // the inventory but never the management controls.
        userRole: null,
        isAdmin: false,
    };

    async function loadSources() {
        try {
            const d = await PSAPI.callOrThrow("source.list");
            state.sources = d.sources || [];
            // The list response already includes the supported
            // connector types so we can avoid a second round-trip
            // to source.list_types on every page load.
            if (Array.isArray(d.supported_connector_types)) {
                state.types = d.supported_connector_types;
            }
        } catch (e) {
            state.sources = [];
            PSFmt.toast("Failed to load sources: " + e.message, "err");
        }
        I.registerAll("SRC", state.sources.map((s) => ({
            id: s.source_instance_id, sortKey: s.created_at || "",
        })));
    }

    async function loadTypes() {
        // Fallback only — used if loadSources() never populated the
        // type catalogue. loadSources() runs first in refreshAll(),
        // so this is normally a no-op.
        if (state.types && state.types.length) return;
        try {
            const d = await PSAPI.callOrThrow("source.list_types");
            state.types = d.supported_connector_types || [];
        } catch (e) {
            state.types = [];
        }
    }

    async function refreshAll() {
        // Sequential: loadSources() may populate state.types as a
        // side-effect (the list response already returns the
        // supported connector types). Running them in parallel
        // caused a redundant source.list_types round-trip.
        await loadSources();
        await loadTypes();
    }

    function filtered() {
        const q = (state.filter || "").toLowerCase();
        return state.sources.filter((s) => {
            if (state.typeFilter !== "all" && s.source_type !== state.typeFilter) return false;
            if (state.stateFilter !== "all" && s.state !== state.stateFilter) return false;
            if (q) {
                const blob = [
                    s.source_instance_id,
                    I.display("SRC", s.source_instance_id),
                    s.display_name,
                    s.source_type,
                    s.description || "",
                    (s.tags || []).join(" "),
                ].join(" ").toLowerCase();
                if (!blob.includes(q)) return false;
            }
            return true;
        });
    }

    function rerender() {
        // Only the dynamic body (toolbar + table) is replaced. The
        // read-only banner lives in a sibling slot so it survives
        // every re-render.
        const root = document.getElementById("sources-body");
        if (!root) return;
        root.replaceChildren();
        root.appendChild(renderToolbar());
        root.appendChild(renderTable());
    }

    function healthBadge(s) {
        const h = s.health || {};
        const status = h.status || s.state;
        // Truthful mapping of the documented status closed set
        // (ok|degraded|unknown|disabled|retired).
        const kind = F.stateClass(status) ||
            (s.state === "enabled" ? "ok" : "");
        return F.badge(status, kind);
    }

    function renderToolbar() {
        const tb = el("div", { class: "toolbar" });
        tb.appendChild(el("div", { class: "search-row" },
            el("input", {
                type: "search",
                placeholder: "Search sources…",
                value: state.filter,
                "aria-label": "Search sources",
                oninput: (e) => { state.filter = e.target.value; rerender(); },
            }),
        ));
        tb.appendChild((() => {
            const sel = el("select", {
                "aria-label": "Filter by type",
                onchange: (e) => { state.typeFilter = e.target.value; rerender(); },
            });
            sel.appendChild(el("option", { value: "all" }, "All types"));
            for (const t of state.types) {
                sel.appendChild(el("option", { value: t }, t));
            }
            sel.value = state.typeFilter;
            return sel;
        })());
        tb.appendChild((() => {
            const sel = el("select", {
                "aria-label": "Filter by state",
                onchange: (e) => { state.stateFilter = e.target.value; rerender(); },
            });
            for (const s of ["all", "registered", "configured", "validated",
                             "enabled", "disabled", "retired"]) {
                sel.appendChild(el("option", { value: s },
                    s === "all" ? "All states" : F.titleCase(s)));
            }
            sel.value = state.stateFilter;
            return sel;
        })());
        tb.appendChild(el("div", { class: "toolbar-spacer" }));
        tb.appendChild(el("span", { class: "muted", id: "src-count" },
            state.sources.length
                ? `${filtered().length} of ${state.sources.length} sources`
                : ""));
        // "Create New Source" lives in the page header only (the
        // toolbar previously duplicated it).
        return tb;
    }

    function rowFor(s) {
        const tr = el("tr", { class: "clickable" });
        const h = s.health || {};
        tr.appendChild(el("td", null,
            el("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } },
                el("span", { class: "display-id" },
                    I.display("SRC", s.source_instance_id)),
                el("span", { style: { fontWeight: "600" } },
                    s.display_name || "Unnamed source"),
            ),
            el("div", { class: "tech-id" },
                el("code", null, s.source_instance_id)),
        ));
        tr.appendChild(el("td", null,
            el("span", { class: "chip" }, s.source_type || "—"),
            (s.tags && s.tags.length)
                ? el("div", { class: "row", style: { gap: "4px", marginTop: "4px" } },
                    s.tags.slice(0, 3).map((t) =>
                        el("span", { class: "muted mono", style: { fontSize: "0.68rem" } }, t)))
                : null,
        ));
        tr.appendChild(el("td", null, F.badge(s.state, F.stateClass(s.state))));
        tr.appendChild(el("td", null,
            healthBadge(s),
            h.last_error
                ? el("div", { class: "muted", style: {
                    color: "var(--err)", maxWidth: "220px",
                    overflow: "hidden", textOverflow: "ellipsis",
                    whiteSpace: "nowrap" }, title: h.last_error },
                    h.last_error)
                : null,
        ));
        tr.appendChild(el("td", null,
            h.last_received_at
                ? el("span", { title: F.fmtTime(h.last_received_at) },
                    F.fmtRelative(h.last_received_at))
                : el("span", { class: "muted" }, "never")));
        // The Actions column is admin-only. Analyst / collector users
        // see the inventory state but never the management buttons
        // (Phase 4.9 RBAC: source:write). The backend would 403 a
        // mis-fired call anyway; hiding the controls avoids the wasted
        // round-trip and the read-only banner explains why.
        if (!state.isAdmin) {
            tr.appendChild(el("td", { class: "muted" }, "read-only"));
            return tr;
        }
        tr.appendChild(el("td", null,
            el("div", { class: "status-row" },
                el("button", { class: "btn btn-sm",
                    onclick: () => invokeAction("validate", s) },
                    "Validate"),
                el("button", { class: "btn btn-sm",
                    onclick: () => invokeAction("configure", s) },
                    "Edit"),
                el("button", { class: "btn btn-sm",
                    onclick: () => invokeAction("issue_token", s),
                    title: "Issue a source-identity token for this instance" },
                    "Token"),
                enableDisableBtnFor(s),
                retireBtnFor(s),
            ),
        ));
        return tr;
    }

    function enableDisableBtnFor(s) {
        if (s.state === "enabled") {
            return el("button", { class: "btn btn-sm",
                onclick: () => invokeAction("disable", s) },
                "Disable");
        }
        if (s.state === "validated" || s.state === "disabled") {
            return el("button", { class: "btn btn-sm btn-primary",
                onclick: () => invokeAction("enable", s) },
                "Enable");
        }
        return null;
    }

    function retireBtnFor(s) {
        if (s.state === "retired") return null;
        return el("button", { class: "btn btn-sm btn-danger",
            onclick: () => invokeAction("retire", s) },
            "Retire");
    }

    async function invokeAction(action, s) {
        try {
            if (action === "configure") {
                openConfigureDialog(s);
                return;
            }
            if (action === "issue_token") {
                openTokenDialog(s);
                return;
            }
            let op = action;
            if (op === "validate") op = "source.validate";
            else if (op === "enable") op = "source.enable";
            else if (op === "disable") op = "source.disable";
            else if (op === "retire") op = "source.retire";
            const body = { source_instance_id: s.source_instance_id };
            if (op === "source.retire") {
                const ok = await F.confirmDialog(
                    "Retire source '" + (s.display_name ||
                        I.display("SRC", s.source_instance_id)) +
                    "'? This is the terminal state.",
                    { title: "Retire source", okLabel: "Retire" });
                if (!ok) return;
            }
            const r = await PSAPI.callOrThrow(op, body);
            const nextState = r && r.source && r.source.state;
            PSFmt.toast("Source " + action + ": " +
                (nextState ? F.titleCase(nextState) : "ok"), "ok");
            await loadSources();
            rerender();
        } catch (e) {
            // V2-22 fix retained: the backend's 409 source-state guard
            // is truthful but was unguided — surface the documented
            // recovery path directly.
            if (e.status === 409) {
                PSFmt.toast(
                    "This source is currently enabled, so it is locked for " +
                    "changes. To change it: Disable → Edit → Validate → " +
                    "Enable. (" + e.message + ")",
                    "warn",
                );
            } else {
                PSFmt.toast("Action failed: " + e.message, "err");
            }
        }
    }

    function openRegisterDialog() {
        const root = document.createElement("div");
        // The closed-set of supported types comes back from the
        // backend sorted alphabetically. A disabled placeholder option
        // prevents the browser silently pre-selecting the first type
        // (a real incident from manual E2E), plus a client-side guard
        // so the form can never submit with the placeholder.
        const supported = state.types || [];
        const optionsHtml = [
            '<option value="" disabled selected>',
            "— select a source type —",
            "</option>",
        ].join("").concat(
            supported.map((t) =>
                `<option value="${F.escapeHtml(t)}">${F.escapeHtml(t)}</option>`
            ).join(""),
        );
        root.innerHTML = `
            <div class="confirm-overlay">
                <div class="confirm-modal" style="max-width:540px;">
                    <h3>Create New Source</h3>
                    <p class="muted">You are creating a new source <strong>instance</strong>
                    of an existing connector capability — not a new connector.
                    Many source instances can share one connector implementation.
                    After creating it, configure, validate and enable the source.</p>
                    <form id="register-form" class="col">
                        <div>
                            <label for="src-type">Connector capability / source type</label>
                            <select id="src-type" required>
                                ${optionsHtml}
                            </select>
                        </div>
                        <div>
                            <label for="src-name">Source name</label>
                            <input id="src-name" placeholder="e.g. Production NGINX Gateway" required />
                        </div>
                        <div>
                            <label for="src-desc">Description</label>
                            <input id="src-desc" placeholder="optional" />
                        </div>
                        <div>
                            <label for="src-tags">Tags (comma-separated, UPPERCASE)</label>
                            <input id="src-tags" placeholder="e.g. PROD, WEB" value="PROD" />
                        </div>
                        <div>
                            <label for="src-assets">Asset tags (comma-separated, lowercase)</label>
                            <input id="src-assets" placeholder="e.g. web, api" value="web" />
                        </div>
                        <div class="row" style="justify-content:flex-end;">
                            <button type="button" class="btn" data-act="cancel">Cancel</button>
                            <button type="submit" class="btn btn-primary" data-act="ok">Create source</button>
                        </div>
                    </form>
                </div>
            </div>`;
        document.body.appendChild(root);
        const close = () => root.remove();
        root.querySelector('[data-act="cancel"]').onclick = close;
        root.querySelector("#register-form").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const sel = root.querySelector("#src-type");
            const sourceType = sel ? sel.value : "";
            if (!sourceType) {
                PSFmt.toast("Pick a connector capability before creating the source.", "err");
                if (sel) sel.focus();
                return;
            }
            // Defence in depth: refuse to ship a source_type
            // that the backend's closed set doesn't accept.
            if (supported.length && !supported.includes(sourceType)) {
                PSFmt.toast("Unsupported connector capability: " + sourceType, "err");
                return;
            }
            try {
                const r = await PSAPI.callOrThrow("source.register", {
                    source_type: sourceType,
                    display_name: root.querySelector("#src-name").value.trim(),
                    description: root.querySelector("#src-desc").value.trim(),
                    tags: root.querySelector("#src-tags").value
                        .split(",").map((t) => t.trim()).filter(Boolean),
                    asset_tags: root.querySelector("#src-assets").value
                        .split(",").map((t) => t.trim()).filter(Boolean),
                });
                PSFmt.toast("Source created. Next: configure and validate.", "ok");
                close();
                await loadSources();
                rerender();
                if (r && r.source) openConfigureDialog(r.source);
            } catch (e) {
                PSFmt.toast("Create failed: " + e.message, "err");
            }
        });
    }

    function openConfigureDialog(s) {
        const cfg = s.configuration || {};
        const root = document.createElement("div");
        root.innerHTML = `
            <div class="confirm-overlay">
                <div class="confirm-modal" style="max-width:540px;">
                    <h3>Configure source · ${F.escapeHtml(
                        I.display("SRC", s.source_instance_id))}</h3>
                    <p class="muted">Connection settings for this source instance.
                    Technical ID: <code>${F.escapeHtml(s.source_instance_id)}</code></p>
                    <form id="cfg-form" class="col">
                        <div>
                            <label for="cfg-conn">Connection type</label>
                            <select id="cfg-conn">
                                <option value="push">push</option>
                                <option value="pull">pull</option>
                            </select>
                        </div>
                        <div>
                            <label for="cfg-endpoint">External endpoint</label>
                            <input id="cfg-endpoint" value="${F.escapeHtml(cfg.endpoint || "/ingress/" + (s.display_name || "source"))}" />
                        </div>
                        <div>
                            <label for="cfg-dest">Destination (optional)</label>
                            <input id="cfg-dest" value="${F.escapeHtml(cfg.destination || "")}" placeholder="routing destination key" />
                        </div>
                        <div>
                            <label for="cfg-assets">Asset tags (comma-separated, lowercase)</label>
                            <input id="cfg-assets" value="${F.escapeHtml((cfg.asset_tags || s.asset_tags || ["web"]).join(", "))}" />
                        </div>
                        <div>
                            <label for="cfg-secret">Authentication — secret reference (optional)</label>
                            <input id="cfg-secret" placeholder="vault://path/to/secret (only when secret store is configured)" />
                        </div>
                        <div class="row" style="justify-content:flex-end;">
                            <button type="button" class="btn" data-act="cancel">Cancel</button>
                            <button type="submit" class="btn btn-primary" data-act="ok">Save configuration</button>
                        </div>
                    </form>
                </div>
            </div>`;
        document.body.appendChild(root);
        const close = () => root.remove();
        root.querySelector('[data-act="cancel"]').onclick = close;
        root.querySelector("#cfg-conn").value = cfg.connection_type || "push";
        root.querySelector("#cfg-form").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const configuration = {
                connection_type: root.querySelector("#cfg-conn").value,
                endpoint: root.querySelector("#cfg-endpoint").value.trim(),
                asset_tags: root.querySelector("#cfg-assets").value
                    .split(",").map((t) => t.trim()).filter(Boolean),
            };
            const destination = root.querySelector("#cfg-dest").value.trim();
            if (destination) configuration.destination = destination;
            const secretRef = root.querySelector("#cfg-secret").value.trim();
            if (secretRef) configuration.secret_ref = secretRef;
            try {
                await PSAPI.callOrThrow("source.configure", {
                    source_instance_id: s.source_instance_id,
                    configuration,
                });
                PSFmt.toast("Configuration saved. Next: validate.", "ok");
                close();
                await loadSources();
                rerender();
            } catch (e) {
                PSFmt.toast("Configure failed: " + e.message, "err");
            }
        });
    }

    function openTokenDialog(s) {
        const root = document.createElement("div");
        root.innerHTML = `
            <div class="confirm-overlay">
                <div class="confirm-modal">
                    <h3>Issue source-identity token</h3>
                    <p class="muted">The token authenticates this source instance to the
                    ingress boundary. It is bound to
                    <code>${F.escapeHtml(s.source_instance_id)}</code>
                    (${F.escapeHtml(I.display("SRC", s.source_instance_id))}).</p>
                    <form id="tok-form" class="col">
                        <div>
                            <label for="tok-ttl">Lifetime (seconds)</label>
                            <input id="tok-ttl" type="number" min="60" max="3600" value="600" />
                        </div>
                        <div class="row" style="justify-content:flex-end;">
                            <button type="button" class="btn" data-act="cancel">Cancel</button>
                            <button type="submit" class="btn btn-primary" data-act="ok">Issue token</button>
                        </div>
                    </form>
                </div>
            </div>`;
        document.body.appendChild(root);
        const close = () => root.remove();
        root.querySelector('[data-act="cancel"]').onclick = close;
        root.querySelector("#tok-form").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const lifetime = parseInt(root.querySelector("#tok-ttl").value, 10);
            try {
                const r = await PSAPI.callOrThrow("source.issue_token", {
                    source_instance_id: s.source_instance_id,
                    lifetime_seconds: lifetime,
                });
                root.innerHTML = `
                    <div class="confirm-overlay">
                        <div class="confirm-modal">
                            <h3>Source-identity token issued</h3>
                            <p class="muted">Expires ${F.escapeHtml(F.fmtTime(r.expires_at))}.
                            Store it now — it is shown only once.</p>
                            <div class="code-block">${F.escapeHtml(r.source_token)}</div>
                            <div class="row" style="justify-content:flex-end;margin-top:12px;">
                                <button type="button" class="btn btn-primary" data-act="ok">Close</button>
                            </div>
                        </div>
                    </div>`;
                root.querySelector('[data-act="ok"]').onclick = close;
            } catch (e) {
                PSFmt.toast("Issue failed: " + e.message, "err");
            }
        });
    }

    function renderTable() {
        const rows = filtered();
        const card = el("div", { class: "card", style: { padding: "0", overflow: "hidden" } });
        if (!state.sources.length) {
            card.appendChild(F.emptyState("⇄", "No sources yet",
                state.isAdmin
                    ? "Create your first source to start receiving telemetry."
                    : "No sources are registered yet. Ask a security admin to create one."));
            return card;
        }
        if (!rows.length) {
            card.appendChild(F.emptyState("◎", "No sources match your filters",
                "Try clearing the search box or resetting the type / state filters."));
            return card;
        }
        const tbl = el("table", null,
            el("thead", null,
                el("tr", null,
                    el("th", null, "Source"),
                    el("th", null, "Type / Tags"),
                    el("th", null, "State"),
                    el("th", null, "Health"),
                    el("th", null, "Last received"),
                    el("th", null, state.isAdmin ? "Actions" : "Actions (read-only)"),
                ),
            ),
            el("tbody", null, rows.map(rowFor)),
        );
        card.appendChild(tbl);
        return card;
    }

    async function render(root) {
        await PSAPI.loadMeta();
        const user = PSAPI.getUser();
        // Phase 4.9 RBAC: source management is ``source:write`` and is
        // admin-only. Analyst and collector tokens have ``source:read``
        // at most — every write op returns 403. The UI hides the
        // controls before the user clicks and explains why.
        const userRole = (user && user.role) || null;
        const isAdmin = userRole === "admin";
        state.userRole = userRole;
        state.isAdmin = isAdmin;
        const actions = isAdmin
            ? el("button", { class: "btn btn-primary",
                onclick: openRegisterDialog },
                "+ Create New Source")
            : null;

        const subtitle = isAdmin
            ? "Manage the source instances feeding telemetry into ProShield."
            : "Connected source instances (read-only). Creating and lifecycle changes are admin-only operations.";

        PSUI.mount(root || document.getElementById("sources-root"), {
            title: "Sources",
            subtitle,
            requireAuth: true,
            actions,
            afterRender: async () => {
                const main = document.querySelector("main.main");
                if (!main) return;
                const content = el("div", { id: "sources-content" });
                // The role banner sits above the toolbar in a persistent
                // slot so the reason for the missing controls is obvious
                // before the user goes hunting for them — and it is NOT
                // wiped when the toolbar/table re-render.
                if (!isAdmin) {
                    content.appendChild(el("div", {
                        class: "card",
                        style: {
                            padding: "12px 16px",
                            borderLeft: "3px solid var(--brand)",
                        },
                    },
                        el("strong", null, "Read-only view."),
                        " Your role (",
                        el("span", { class: "mono" }, userRole || "unknown"),
                        ") can inspect the source inventory but cannot " +
                        "create, configure, validate, enable, disable, " +
                        "retire sources or issue tokens. Contact a " +
                        "security admin if a change is required.",
                    ));
                }
                const body = el("div", { id: "sources-body" });
                content.appendChild(body);
                main.appendChild(content);
                const banner = el("div", { class: "loading-banner" },
                    el("span", { class: "spinner" }), " Loading sources…");
                body.appendChild(banner);
                await refreshAll();
                rerender();
            },
        });
    }

    global.PSSources = { render };
})(window);
