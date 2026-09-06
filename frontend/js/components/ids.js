/**
 * ProShield human-readable display identifiers.
 *
 * Analysts triage with "CASE-01", "DET-01", "CORR-01" — never with a
 * raw UUID. This module owns the mapping between internal backend
 * identifiers (incident_id, detection_id, correlation_id,
 * source_instance_id, rule_id) and the stable, human-friendly label
 * shown in the UI.
 *
 * Design constraints (see PROSHIELD-DEEPTEST-ISSUES-V2.md,
 * "V2 FRONTEND / UI-UX UPGRADE REVALIDATION"):
 *
 * 1. PURE PRESENTATION. The canonical backend identity is never
 *    replaced, mutated or hidden — every surface that shows a display
 *    ID also keeps the technical ID reachable (secondary line, tooltip
 *    or the Technical details panel with a copy action).
 * 2. STABLE. Assignments are persisted in localStorage, so the same
 *    backend object keeps the same display ID across reloads and
 *    pages. No random numbering, no per-render renumbering.
 * 3. DETERMINISTIC. When a batch of objects is registered, unknown
 *    objects receive their sequence number in (sortKey, backendId)
 *    order — i.e. oldest objects get the lowest numbers.
 * 4. PER-PREFIX SEQUENCE. CASE-, DET-, CORR-, SRC- and RULE- each
 *    have their own monotonic counter, zero-padded to two digits.
 */
(function (global) {
    "use strict";

    const STORE_KEY = "proshield.display-ids.v1";

    function loadStore() {
        try {
            const raw = global.localStorage.getItem(STORE_KEY);
            if (!raw) return {};
            const parsed = JSON.parse(raw);
            return (parsed && typeof parsed === "object") ? parsed : {};
        } catch (e) { return {}; }
    }

    function saveStore(store) {
        try {
            global.localStorage.setItem(STORE_KEY, JSON.stringify(store));
        } catch (e) { /* storage unavailable: in-session only */ }
    }

    let store = loadStore();

    function nextNumber(prefix) {
        const bucket = store[prefix] || {};
        let max = 0;
        for (const k of Object.keys(bucket)) {
            const n = Number(bucket[k]);
            if (Number.isFinite(n) && n > max) max = n;
        }
        return max + 1;
    }

    function format(prefix, n) {
        const digits = Math.max(2, String(n).length);
        return prefix + "-" + String(n).padStart(digits, "0");
    }

    /**
     * Register a batch of backend ids for a prefix. ``items`` is an
     * array of ``{ id, sortKey }`` (sortKey typically created_at /
     * detected_at). Unknown ids get numbered in (sortKey, id) order so
     * the assignment is deterministic for the same dataset. Already
     * known ids keep their existing number — assignment is never
     * renumbered.
     *
     * @param {string} prefix  e.g. "CASE"
     * @param {Array<{id: string, sortKey?: string}>} items
     */
    function registerAll(prefix, items) {
        if (!prefix || !Array.isArray(items)) return;
        let dirty = false;
        const bucket = store[prefix] || {};
        const known = new Set(Object.keys(bucket));
        const pending = [];
        for (const it of items) {
            const id = it && it.id;
            if (!id || typeof id !== "string" || known.has(id)) continue;
            pending.push({
                id,
                sortKey: typeof it.sortKey === "string" ? it.sortKey : "",
            });
        }
        // Deterministic: oldest first, tie-break on the backend id.
        pending.sort((a, b) =>
            a.sortKey < b.sortKey ? -1 :
            a.sortKey > b.sortKey ? 1 :
            a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
        let counter = nextNumber(prefix);
        for (const p of pending) {
            bucket[p.id] = counter++;
        }
        if (pending.length) {
            store[prefix] = bucket;
            dirty = true;
        }
        if (dirty) saveStore(store);
    }

    /**
     * The human-readable display label, e.g. ``PSIds.display("CASE",
     * "case-04861cab-…")`` → ``"CASE-01"``. Registers on first sight
     * (append-only fallback when a caller forgot registerAll).
     */
    function display(prefix, backendId) {
        if (!backendId) return "";
        const bucket = store[prefix] || {};
        let n = bucket[backendId];
        if (!Number.isFinite(n)) {
            registerAll(prefix, [{ id: backendId }]);
            n = (store[prefix] || {})[backendId];
        }
        return format(prefix, n);
    }

    /** True when the string looks like one of our display labels. */
    function isDisplayLabel(s) {
        return typeof s === "string" &&
            /^(CASE|DET|CORR|SRC|RULE|REPORT)-\d+$/.test(s);
    }

    /** Test/diagnostic helper: drop the whole registry. */
    function resetForTests() {
        store = {};
        try { global.localStorage.removeItem(STORE_KEY); } catch (e) { /* noop */ }
    }

    global.PSIds = { registerAll, display, isDisplayLabel, resetForTests };
})(window);
