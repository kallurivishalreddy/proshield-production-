/**
 * ProShield API client.
 *
 * Wraps every call to /api/proxy so pages never have to think
 * about session tokens, error envelopes or pagination. This is the
 * single integration boundary between the frontend and the
 * production ``SecureProxy.handle(ProxyRequest)`` server.
 */
(function (global) {
    "use strict";

    const SESSION_KEY = "proshield.session";
    const USER_KEY = "proshield.user";
    const META_KEY = "proshield.meta";

    function getMeta() {
        try { return JSON.parse(localStorage.getItem(META_KEY) || "{}"); }
        catch (e) { return {}; }
    }
    function setMeta(meta) {
        localStorage.setItem(META_KEY, JSON.stringify(meta || {}));
    }

    function getSession() {
        return localStorage.getItem(SESSION_KEY) || "";
    }
    function setSession(token, user) {
        if (token) localStorage.setItem(SESSION_KEY, token);
        else localStorage.removeItem(SESSION_KEY);
        if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
        else localStorage.removeItem(USER_KEY);
    }
    function getUser() {
        try { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); }
        catch (e) { return null; }
    }

    /**
     * Call the backend via the SecureProxy wrapper.
     *
     * @param {string} operation  Proxy operation name (e.g. "case.list")
     * @param {object} [body]     Request body fields
     * @param {object} [opts]
     * @param {boolean} [opts.authenticated=true]
     * @param {boolean} [opts.allowAnonymous=false]
     * @returns {Promise<{ok: boolean, status: number, data: any, error: any}>}
     */
    async function call(operation, body, opts) {
        opts = opts || {};
        const headers = { "Content-Type": "application/json" };
        const useSession =
            opts.authenticated !== false && opts.allowAnonymous !== true;
        if (useSession) {
            const tok = getSession();
            if (tok) headers["X-ProShield-Session"] = tok;
        }
        const payload = Object.assign({ operation }, body || {});
        try {
            const resp = await fetch("/api/proxy", {
                method: "POST",
                headers,
                body: JSON.stringify(payload),
            });
            let parsed = null;
            try { parsed = await resp.json(); } catch (e) { parsed = null; }
            // V2-16 fix: an HTTP error status is an error, period.
            // The previous rule (``parsed.ok !== false``) treated every
            // SecureProxy error envelope — ``{"error": {...}}`` with no
            // ``ok`` field, on 400/401/403/404/409/429/500 — as a
            // success, so ``callOrThrow`` never threw and pages
            // rendered silent or false-success states for every
            // backend failure. Success now requires: HTTP 2xx AND a
            // parsed body that does not carry an error envelope.
            const httpOk = resp.ok;
            const envelopeOk = !!parsed && parsed.ok !== false && !parsed.error;
            return {
                ok: httpOk && envelopeOk,
                status: resp.status,
                data: parsed && parsed.data,
                error: parsed && parsed.error,
            };
        } catch (e) {
            return {
                ok: false,
                status: 0,
                data: null,
                error: {
                    code: "network_error",
                    message: e.message || "network failure",
                },
            };
        }
    }

    async function authIssue(subjectId, credential) {
        const r = await call(
            "auth.issue",
            { subject_id: subjectId, credential },
            { authenticated: false },
        );
        if (r.ok && r.data && r.data.token) {
            setSession(r.data.token, {
                subject_id: r.data.subject_id,
                role: r.data.role,
                expires_at: r.data.expires_at,
            });
            return r;
        }
        return r;
    }

    async function health() {
        try {
            const r = await fetch("/health");
            if (!r.ok) return { ok: false };
            const body = await r.json();
            return { ok: true, body };
        } catch (e) {
            return { ok: false };
        }
    }

    async function loadMeta() {
        try {
            const r = await fetch("/api/meta");
            if (!r.ok) return null;
            const body = await r.json();
            setMeta(body);
            return body;
        } catch (e) {
            return null;
        }
    }

    /**
     * Convenience wrapper that throws on error envelopes so page
     * code can use plain ``await api.call(...).data``.
     *
     * @param {string} operation
     * @param {object} [body]
     * @param {object} [opts]
     */
    async function callOrThrow(operation, body, opts) {
        const r = await call(operation, body, opts);
        if (!r.ok) {
            const code = (r.error && r.error.code) || "unknown_error";
            const msg =
                (r.error && r.error.message) || "Backend error";
            const err = new Error(msg);
            err.code = code;
            err.status = r.status;
            err.detail = r.error;
            throw err;
        }
        return r.data;
    }

    function logout() {
        setSession(null, null);
    }

    global.PSAPI = {
        call,
        callOrThrow,
        authIssue,
        health,
        loadMeta,
        getSession,
        getUser,
        getMeta,
        logout,
    };
})(window);