# ProShield Frontend Implementation (Phase 4.10)

**Status:** Complete. All 8 pages + login render, every page exercises
only the proxy ops that the **Phase 4.8 backend contract** documents.
The frontend contains no fake data and no fabricated responses —
when the proxy returns an error, the UI surfaces the error.

## Scope

The backend already exposes 21 wire ops through `SecureProxy.handle()`.
We ship a single-page-style web UI (vanilla HTML + CSS + JS, no build
step) that exercises every read op an analyst needs, plus the analyst
write ops (`source.register / configure / validate / enable / disable
/ retire`, `case.close`, `case.centralized`).

Backend is **read-only**; the only "new backend code" is
`scripts/proxy_server.py`, a thin FastAPI listener that wraps
`SecureProxy.handle(ProxyRequest)` — exactly the boundary the
`PHASE_4_BACKEND_PROXY_CONTRACT.md` requires every deployment listener
to sit on.

## File map

```
frontend/
├── login.html
├── index.html         ← Overview / KPIs
├── cases.html         ← Case list
├── case.html?id=...   ← Case detail
├── rules.html         ← Rule catalog
├── sources.html       ← Source lifecycle
├── detections.html    ← Detections
├── correlations.html  ← Correlations
├── timeline.html      ← Timeline
├── health.html        ← System health
├── css/app.css        ← Design tokens + dark UI
└── js/
    ├── services/api.js     ← PSAPI client
    └── components/
        ├── layout.js
        ├── format.js
        ├── overview.js
        ├── cases.js
        ├── case.js
        ├── rules.js
        ├── sources.js
        ├── detections.js
        ├── correlations.js
        ├── timeline.js
        └── health.js
```

## Wire ops per page

| Page | Wire ops called | Notes |
|------|-----------------|-------|
| `login.html` | `auth.issue` | Response field is `token`, **not** `session_token`. |
| `index.html` (Overview) | `overview.summary` | Returns `{ok, data: {open_case_count, detection_count, correlation_count, scope, produced_at}}`. The `summary` string is **not** in the documented response; we render the four numbers directly. |
| `cases.html` | `case.list`, `case.centralized` (button) | `case.create` is documented as 400-by-design (creation only happens through correlation side-effect), so the UI does not call it. |
| `case.html` | `case.get`, `case.close`, `timeline.list`, `correlation.list`, `detection.list_for_incident` | The `case.acknowledge` / `case.assign` / `case.add_note` / `case.add_recommendation` ops are **not** in the Phase 4.8 wire surface; the UI exposes an "Acknowledge / assign (planned)" button that fires a toast. If no `?id=…` is in the URL, the page renders a hint instead of firing 4 × 400. |
| `rules.html` | `rule.list` | Returns the 5 NGINX rules seeded by `scripts/proxy_server.py`. |
| `sources.html` | `source.list` (initial load) + on-demand `source.register`, `source.configure`, `source.validate`, `source.enable`, `source.disable`, `source.retire`, `source.issue_token`. `source.list_types` is **no longer** called separately — the supported connector types come back inside the `source.list` response. | Full lifecycle surface. The list request and the per-rule metadata call are sequenced (`refreshAll()`) to avoid a redundant round-trip. |
| `detections.html` | `detection.list` (per `rule_id`) and `rule.list` (to discover the `rule_id`s). | `detection.list` returns `[]` when no `rule_id`/`event_id` filter is supplied, so the page iterates the rule list and merges per-rule results, then de-dupes by `detection_id`. |
| `correlations.html` | `correlation.list` (per `rule_id`) and `rule.list`. | Same pattern as detections. `correlation.confirm` / `correlation.dismiss` are **not** in the wire surface; the buttons surface a toast. |
| `timeline.html` | `case.list` (to discover the cases), then `timeline.list` per `incident_id`. | The wire op is per-incident (`timeline.build_for_incident` is the documented surface). Events from every case are merged and de-duped. |
| `health.html` | `overview.summary` + a small static status panel | Backend has no `health.*` op; we render the auth token expiry chip and the overview-produced_at as a coarse "last refresh" indicator. |

## Design choices

- **Vanilla JS, no framework.** Matches the rest of the ProShield repo
  (which has no build step). Total JS is ~1.2k LoC across 11 files.
- **Single CSS file.** `css/app.css` defines design tokens (colour ramp,
  shadows, font) and component styles. Dark theme is the default.
- **No router, query string only.** `case.html?id=<incident_id>` and
  `timeline.html?case=<incident_id>` are the only deep links. Every
  page is a stand-alone HTML file; navigation is plain anchor tags.
- **Session token in `localStorage`.** Cleared on logout or on 401. The
  `PSAPI` client adds `Authorization: Bearer <token>` automatically.
- **No offline / no cache.** Every page fetches live data on load.
- **No mocked data.** When the backend returns an error, the page shows
  the error and the affected table is empty.

## Auth assumption

- The Phase 4.8 contract documents `auth.issue` (POST credentials) and
  `auth.whoami`. We do **not** use a cookie; we use a bearer token in
  `localStorage`. The contract does not forbid this and the proxy
  happily accepts the token via `Authorization: Bearer ...`.
- The two seeded identities are `admin / admin` and `analyst / analyst`.
- Token expiry is read from the token payload; expired tokens trigger a
  redirect to `login.html`.

## Backend blockers (intentional)

These ops are documented as "frontend-required" in the contract but
are **not yet promoted to wire ops**. The UI shows them as disabled
or planned:

| Op | UI treatment |
|----|--------------|
| `case.acknowledge` | Toast: "planned" |
| `case.assign` | Toast: "planned" |
| `case.add_note` | Toast: "planned" |
| `case.add_recommendation` | Toast: "planned" |
| `case.create` | Not called (creation is correlation-driven by design) |
| `health.*` | Page renders overview timestamps as a coarse health signal |

## Running it

```bash
# Terminal 1 — backend listener
python -m scripts.proxy_server --backend memory --port 8000

# then open http://localhost:8000/static/login.html
```

The FastAPI listener in `scripts/proxy_server.py` mounts the `frontend/`
directory at `/static/` and exposes the wire boundary at `/api/proxy`.

## Verification

- `scripts/smoke_test.py` — 21 backend smoke checks.
- `scripts/e2e_test.py` — 56 full-stack HTTP checks.
- `scripts/demo_security_workflow.py` — runs the real pipeline and
  prints every step.
- `scripts/check_wiring.py` — static inspection of every page +
  every component; confirms each page is wired to the right ops,
  each component targets `<main class="main">`, the layout uses
  the `readyState` DOMContentLoaded fix, the sources page uses
  `refreshAll()`, the case page has a no-id guard, and the
  overview page doesn't depend on `#app` (which the shell
  replaces).
- `scripts/verify_sources_fix.py` — focused end-to-end check
  for the original bug: the sources page must fire
  `source.list` (status 200) and render the toolbar + content
  root, with no console errors and no redundant
  `source.list_types` round-trip.

## Initialization race fix (the "page only fires /api/meta" bug)

The previous implementation of `PSUI.mount` always wrapped its
work in a `DOMContentLoaded` listener:

```js
function mount(contentEl, opts) {
    document.addEventListener("DOMContentLoaded", () => {
        shell(contentEl, opts);
        if (opts && opts.afterRender) opts.afterRender();
    });
}
```

For the Overview and every per-page component whose
`render()` did an `await` *before* calling `PSUI.mount(...)`,
this silently failed. The reason is timing:

1. The script is inline at the end of `<body>`, so the HTML
   parser is still running.
2. The component's `render()` is `async`; `await PSAPI.loadMeta()`
   starts the `/api/meta` fetch and suspends the function.
3. The HTML parser finishes, `DOMContentLoaded` fires.
4. The component's `render()` resumes, **then** calls
   `PSUI.mount(...)`, which now tries to register a listener for
   an event that has already fired.
5. The shell renders the topbar/sidebar scaffold, but the
   `afterRender` callback — the one that actually calls
   `source.list` / `case.list` / `detection.list` — **never
   runs**.

What the user saw in DevTools: the page renders the shell
chrome, fires `GET /api/meta`, and nothing else. The fix is to
register the listener only when the event is still pending,
and run synchronously otherwise:

```js
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
} else {
    run();
}
```

This is the **single line of defense** for every page. The
secondary defence is to target the actual `<main class="main">`
element that `shell()` creates, rather than a hypothetical
`#sources-root` / `#cases-root` etc. anchor that does not exist
in the HTML.


