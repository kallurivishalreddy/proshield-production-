/**
 * Shared formatting + rendering helpers used across pages.
 *
 * RAW-MARKUP ROOT-CAUSE FIX (V2 UI-UX pass):
 * ``badge()`` / ``pill()`` used to return HTML *strings*. The shared
 * ``PSUI.el()`` builder renders string children with
 * ``document.createTextNode`` (deliberately, for XSS safety), so every
 * badge passed as an el() child was displayed as literal markup —
 * analysts saw ``<span class="pill medium">medium</span>`` printed on
 * screen. The fix lives here, at the shared helper layer: badge/pill
 * now build real DOM elements, which ``el()`` appends natively. All
 * call sites are fixed at once; none of them needed page-specific
 * workarounds.
 */
(function (global) {
    "use strict";

    function escapeHtml(s) {
        if (s == null) return "";
        return String(s).replace(/[&<>"']/g, (c) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
        })[c]);
    }

    /** "brute_force" → "Brute Force"; "open" → "Open". */
    function titleCase(s) {
        if (s == null || s === "") return "";
        return String(s)
            .replace(/[_-]+/g, " ")
            .trim()
            .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    function severityClass(sev) {
        const s = (sev || "").toLowerCase();
        if (s === "critical" || s === "crit") return "crit";
        if (s === "high") return "high";
        if (s === "medium" || s === "med") return "med";
        if (s === "low") return "low";
        if (s === "info" || s === "informational") return "info";
        return "";
    }

    /** Sort rank for severity (lower = more severe). Unknown = last. */
    function severityRank(sev) {
        const s = (sev || "").toLowerCase();
        if (s === "critical" || s === "crit") return 0;
        if (s === "high") return 1;
        if (s === "medium" || s === "med") return 2;
        if (s === "low") return 3;
        if (s === "info" || s === "informational") return 4;
        return 5;
    }

    /**
     * Detections carry no severity field of their own; the analyst
     * surface therefore shows the rule CATEGORY as a neutral chip —
     * never a fabricated severity.
     */
    function severityClassForCategory(cat) {
        const c = (cat || "").toLowerCase();
        if (c.includes("brute") || c.includes("auth")) return "crit";
        if (c.includes("rate")) return "high";
        if (c.includes("block")) return "med";
        if (c.includes("anomal")) return "low";
        if (c.includes("info")) return "info";
        return "";
    }

    function stateClass(state) {
        const s = (state || "").toLowerCase();
        if (s === "enabled" || s === "ok" || s === "closed" ||
            s === "approved" || s === "healthy") return "ok";
        if (s === "configured" || s === "validated" ||
            s === "investigating" || s === "centralized_pending" ||
            s === "report_pending") return "info";
        if (s === "registered" || s === "candidate" ||
            s === "acknowledged" || s === "degraded" ||
            s === "disabled" || s === "unknown") return "warn";
        if (s === "retired" || s === "err" || s === "error" ||
            s === "unhealthy" || s === "centralized_failed") return "err";
        if (s === "open") return "open";
        return "";
    }

    function fmtTime(iso) {
        if (!iso) return "";
        try {
            const d = new Date(iso);
            if (isNaN(d)) return String(iso);
            return d.toISOString().replace("T", " ").replace(/\..*$/, "Z");
        } catch (e) { return String(iso); }
    }

    function fmtRelative(iso) {
        if (!iso) return "";
        try {
            const d = new Date(iso);
            if (isNaN(d)) return String(iso);
            const diffMs = Date.now() - d.getTime();
            const sec = Math.round(diffMs / 1000);
            if (sec < 60) return sec + "s ago";
            const min = Math.round(sec / 60);
            if (min < 60) return min + "m ago";
            const hr = Math.round(min / 60);
            if (hr < 24) return hr + "h ago";
            const day = Math.round(hr / 24);
            if (day < 30) return day + "d ago";
            return d.toISOString().slice(0, 10);
        } catch (e) { return String(iso); }
    }

    function fmtNumber(n) {
        if (n == null || isNaN(Number(n))) return "0";
        return Number(n).toLocaleString();
    }

    function fmtBytes(n) {
        if (!n) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        let i = 0;
        let v = n;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        return v.toFixed(1) + " " + units[i];
    }

    /** Truthful dash for absent values — never "undefined"/"null". */
    function orDash(v) {
        if (v == null || v === "") return "—";
        return String(v);
    }

    /** Severity pill. Empty/unknown severity renders a truthful "—". */
    function pill(text, kind) {
        const span = document.createElement("span");
        const label = (text == null || text === "") ? "—" : String(text);
        span.className = "pill " + (kind || "");
        span.textContent = titleCase(label);
        return span;
    }

    /** Status badge (open/closed/enabled/…). Title-cased label. */
    function badge(text, kind) {
        const span = document.createElement("span");
        const label = (text == null || text === "") ? "—" : String(text);
        span.className = "badge " + (kind || "");
        span.textContent = titleCase(label);
        return span;
    }

    /** Monospace technical id with copy affordance. */
    function techId(id, opts) {
        opts = opts || {};
        const wrap = document.createElement("span");
        wrap.className = "tech-id";
        if (opts.title) wrap.title = opts.title;
        const code = document.createElement("code");
        code.textContent = id || "—";
        wrap.appendChild(code);
        if (id && opts.copyable !== false) {
            wrap.appendChild(copyButton(id));
        }
        return wrap;
    }

    /** Small copy-to-clipboard icon button with toast feedback. */
    function copyButton(text, label) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "copy-btn";
        btn.title = "Copy " + (label || "value") + " to clipboard";
        btn.setAttribute("aria-label", btn.title);
        btn.textContent = "⧉";
        btn.addEventListener("click", async (ev) => {
            ev.stopPropagation();
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(text);
                } else {
                    const ta = document.createElement("textarea");
                    ta.value = text;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand("copy");
                    ta.remove();
                }
                toast("Copied " + (label || "value") + " to clipboard.", "ok");
            } catch (e) {
                toast("Copy failed: " + (e && e.message || e), "err");
            }
        });
        return btn;
    }

    /** Polished empty state: icon + title + optional hint. */
    function emptyState(icon, title, hint) {
        const box = document.createElement("div");
        box.className = "empty";
        const ic = document.createElement("div");
        ic.className = "icon";
        ic.setAttribute("aria-hidden", "true");
        ic.textContent = icon || "◎";
        box.appendChild(ic);
        const t = document.createElement("div");
        t.className = "empty-title";
        t.textContent = title || "Nothing here yet";
        box.appendChild(t);
        if (hint) {
            const h = document.createElement("div");
            h.className = "empty-hint";
            h.textContent = hint;
            box.appendChild(h);
        }
        return box;
    }

    /** Compact stat card (evidence counts, KPI tiles). */
    function statCard(value, label, kind, title) {
        const card = document.createElement("div");
        card.className = "stat" + (kind ? " " + kind : "");
        if (title) card.title = title;
        const v = document.createElement("div");
        v.className = "stat-value";
        v.textContent = (value == null || value === "") ? "0" : String(value);
        card.appendChild(v);
        const l = document.createElement("div");
        l.className = "stat-label";
        l.textContent = label || "";
        card.appendChild(l);
        return card;
    }

    function confirmDialog(message, opts) {
        opts = opts || {};
        return new Promise((resolve) => {
            const overlay = document.createElement("div");
            overlay.className = "confirm-overlay";
            overlay.addEventListener("mousedown", (ev) => {
                if (ev.target === overlay) { overlay.remove(); resolve(false); }
            });
            const modal = document.createElement("div");
            modal.className = "confirm-modal";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");
            const h = document.createElement("h3");
            h.textContent = opts.title || "Confirm";
            modal.appendChild(h);
            const p = document.createElement("p");
            p.textContent = message;
            modal.appendChild(p);
            const row = document.createElement("div");
            row.className = "row";
            row.style.justifyContent = "flex-end";
            row.style.marginTop = "12px";
            const cancel = document.createElement("button");
            cancel.type = "button";
            cancel.className = "btn";
            cancel.textContent = "Cancel";
            const ok = document.createElement("button");
            ok.type = "button";
            ok.className = "btn btn-primary";
            ok.textContent = opts.okLabel || "Confirm";
            row.appendChild(cancel);
            row.appendChild(ok);
            modal.appendChild(row);
            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            cancel.onclick = () => { overlay.remove(); resolve(false); };
            ok.onclick = () => { overlay.remove(); resolve(true); };
            ok.focus();
        });
    }

    function toast(msg, kind) {
        const region = getToastRegion();
        const el = document.createElement("div");
        el.className = "toast" + (kind ? " toast-" + kind : "");
        el.setAttribute("role", "status");
        el.textContent = msg;
        region.appendChild(el);
        requestAnimationFrame(() => el.classList.add("show"));
        setTimeout(() => {
            el.classList.remove("show");
            setTimeout(() => el.remove(), 300);
        }, 4500);
    }

    function getToastRegion() {
        let region = document.querySelector(".toast-region");
        if (!region) {
            region = document.createElement("div");
            region.className = "toast-region";
            region.setAttribute("aria-live", "polite");
            document.body.appendChild(region);
        }
        return region;
    }

    function getQuery(name) {
        const u = new URL(window.location.href);
        return u.searchParams.get(name);
    }

    global.PSFmt = {
        escapeHtml,
        titleCase,
        humanize: titleCase,
        severityClass,
        severityRank,
        severityClassForCategory,
        stateClass,
        fmtTime,
        fmtRelative,
        fmtNumber,
        fmtBytes,
        orDash,
        badge,
        pill,
        techId,
        copyButton,
        emptyState,
        statCard,
        confirmDialog,
        toast,
        getQuery,
    };
})(window);
