/**
 * ProShield application shell — top bar, sidebar, page header.
 * Rendered on every page so navigation state is shared.
 *
 * The navigation is grouped the way an analyst thinks:
 *   Operations (Overview, Incidents, Detections, Correlations, Timeline)
 *   Configuration (Sources, Rules)
 *   System (Health)
 * with one persistent active state, a backend health indicator and
 * the signed-in identity always visible in the top bar.
 */
(function (global) {
    "use strict";

    const NAV_GROUPS = [
        {
            label: "Operations",
            items: [
                { id: "overview",      href: "/static/index.html",        label: "Overview",     icon: "▦" },
                { id: "incidents",     href: "/static/cases.html",        label: "Incidents",    icon: "▲" },
                { id: "detections",    href: "/static/detections.html",   label: "Detections",   icon: "◎" },
                { id: "correlations",  href: "/static/correlations.html", label: "Correlations", icon: "⌁" },
                { id: "timeline",      href: "/static/timeline.html",     label: "Timeline",     icon: "◷" },
            ],
        },
        {
            label: "Configuration",
            items: [
                { id: "sources",       href: "/static/sources.html",      label: "Sources",      icon: "⇄" },
                { id: "rules",         href: "/static/rules.html",        label: "Rules",        icon: "✦" },
            ],
        },
        {
            label: "System",
            items: [
                { id: "health",        href: "/static/health.html",       label: "Health",       icon: "♥" },
            ],
        },
    ];

    // Flat list preserved for backwards compatibility (PSUI.NAV).
    const NAV = NAV_GROUPS.flatMap((g) => g.items);

    function getActiveId() {
        const path = window.location.pathname.replace(/^\/static\//, "");
        const file = path.split("/").pop() || "index.html";
        const map = {
            "index.html": "overview",
            "cases.html": "incidents",
            "detections.html": "detections",
            "correlations.html": "correlations",
            "timeline.html": "timeline",
            "sources.html": "sources",
            "rules.html": "rules",
            "health.html": "health",
            "case.html": "incidents",
        };
        return map[file] || "overview";
    }

    function el(tag, attrs, ...children) {
        const e = document.createElement(tag);
        if (attrs) {
            for (const [k, v] of Object.entries(attrs)) {
                if (k === "class") e.className = v;
                else if (k === "style" && typeof v === "object") Object.assign(e.style, v);
                else if (k.startsWith("on") && typeof v === "function")
                    e.addEventListener(k.slice(2).toLowerCase(), v);
                else if (v === true) e.setAttribute(k, "");
                else if (v === false || v == null) { /* skip */ }
                else e.setAttribute(k, v);
            }
        }
        // Flatten nested arrays of children recursively and append
        // element nodes natively. Scalars become text nodes — which is
        // why PSFmt.badge/pill return real elements (raw-markup fix).
        const append = (c) => {
            if (c == null || c === false || c === true) return;
            if (Array.isArray(c)) {
                for (const x of c) append(x);
                return;
            }
            e.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
        };
        for (const c of children) append(c);
        return e;
    }

    function buildSidebar(active) {
        const sidebar = el("aside", { class: "sidebar" });
        sidebar.appendChild(el("div", { class: "side-brand" },
            el("span", { class: "logo", "aria-hidden": "true" }, "P"),
            el("span", { class: "side-brand-name" }, "ProShield"),
        ));
        for (const group of NAV_GROUPS) {
            sidebar.appendChild(el("div", { class: "nav-group" },
                el("div", { class: "nav-label" }, group.label),
                el("nav", { class: "nav-items", "aria-label": group.label },
                    group.items.map((item) => {
                        const a = el("a", {
                            href: item.href,
                            class: "nav-item" + (item.id === active ? " active" : ""),
                            "aria-current": item.id === active ? "page" : null,
                            title: item.label,
                        },
                            el("span", { class: "nav-icon", "aria-hidden": "true" }, item.icon),
                            el("span", { class: "nav-text" }, item.label),
                        );
                        return a;
                    }),
                ),
            ));
        }
        sidebar.appendChild(el("div", { class: "side-foot" },
            el("div", { class: "side-foot-line" }),
            el("div", { class: "side-foot-note" }, "Rule-based MVP"),
        ));
        return sidebar;
    }

    function shell(contentEl, opts) {
        opts = opts || {};
        document.title = opts.title ? `${opts.title} · ProShield` : "ProShield";

        const user = PSAPI.getUser();
        const active = getActiveId();

        const root = el("div", { class: "app-shell" });

        const topbar = el("header", { class: "topbar" },
            el("div", { class: "topbar-left" },
                el("div", { class: "brand" },
                    el("span", { class: "logo", "aria-hidden": "true" }, "P"),
                    el("span", null, "ProShield"),
                ),
                el("span", { class: "topbar-env" }, "SOC Console"),
            ),
            el("div", { class: "topbar-right" },
                el("div", { class: "search" },
                    el("input", {
                        id: "global-search",
                        type: "search",
                        placeholder: "Search cases…  ( / )",
                        "aria-label": "Search cases",
                    }),
                ),
                el("div", { class: "health-chip", id: "health-chip" },
                    el("span", { class: "health-dot", id: "health-dot" }),
                    el("span", { id: "health-label" }, "…"),
                ),
                el("div", { class: "user-chip", title: user ? user.subject_id : "" },
                    el("span", { class: "user-avatar", "aria-hidden": "true" },
                        user && user.subject_id ? user.subject_id.charAt(0).toUpperCase() : "?"),
                    el("span", { class: "user-name" },
                        user && user.subject_id ? user.subject_id : "signed out"),
                    user && user.role
                        ? el("span", { class: "user-role" }, user.role)
                        : null,
                ),
                el("button", {
                    class: "btn btn-ghost btn-sm",
                    onclick: () => { PSAPI.logout(); window.location.href = "/static/login.html"; },
                    "aria-label": "Sign out",
                }, "Sign out"),
            ),
        );

        const sidebar = buildSidebar(active);

        const main = el("main", { class: "main" });
        if (opts.title || opts.subtitle || opts.actions) {
            const header = el("div", { class: "page-header" },
                el("div", { class: "page-header-text" },
                    opts.eyebrow ? el("div", { class: "eyebrow" }, opts.eyebrow) : null,
                    el("h1", null, opts.title || ""),
                    opts.subtitle ? el("div", { class: "subtitle" }, opts.subtitle) : null,
                ),
                opts.actions ? el("div", { class: "actions" }, opts.actions) : null,
            );
            main.appendChild(header);
        }
        if (contentEl) main.appendChild(contentEl);

        root.appendChild(topbar);
        root.appendChild(sidebar);
        root.appendChild(main);
        const host = document.getElementById("app");
        if (host) host.replaceWith(root);
        else document.body.appendChild(root);

        const dot = document.getElementById("health-dot");
        const label = document.getElementById("health-label");
        async function poll() {
            const r = await PSAPI.health();
            if (!r.ok) {
                dot.classList.remove("warn");
                dot.classList.add("err");
                if (label) label.textContent = "Backend unreachable";
                dot.title = "Backend unreachable";
            } else {
                dot.classList.remove("err", "warn");
                if (label) label.textContent = "Operational";
                dot.title = "Backend healthy (" + (r.body.backend_kind || "?") + ")";
            }
        }
        poll();
        setInterval(poll, 30000);

        const searchInput = document.getElementById("global-search");
        if (searchInput) {
            searchInput.addEventListener("keydown", (ev) => {
                if (ev.key === "Enter" && searchInput.value.trim()) {
                    const q = encodeURIComponent(searchInput.value.trim());
                    window.location.href = `/static/cases.html?q=${q}`;
                }
            });
            // "/" focuses the global search from anywhere.
            document.addEventListener("keydown", (ev) => {
                if (ev.key === "/" && document.activeElement !== searchInput &&
                    !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
                    ev.preventDefault();
                    searchInput.focus();
                }
            });
        }
    }

    function mount(contentEl, opts) {
        // Run immediately if the DOM is already interactive (pages
        // whose render() awaits before mounting would otherwise miss
        // the DOMContentLoaded event entirely).
        const run = () => {
            if (opts && opts.requireAuth && !PSAPI.getSession()) {
                window.location.href = "/static/login.html?next=" +
                    encodeURIComponent(window.location.pathname);
                return;
            }
            shell(contentEl, opts);
            if (opts && opts.afterRender) {
                const r = opts.afterRender();
                if (r && typeof r.then === "function") r.catch((e) => {
                    console.error("afterRender error", e);
                });
            }
        };
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", run, { once: true });
        } else {
            run();
        }
    }

    global.PSUI = {
        mount,
        el,
        shell,
        getActiveId,
        NAV,
        NAV_GROUPS,
    };
})(window);
