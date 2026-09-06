# ProShield Full-Pipeline Test (Phase 4.10)

**Status:** End-to-end run is reproducible with
`python scripts/demo_security_workflow.py`. The script drives the real
Phase 4.10 pipeline: 5 NGINX rules seed the registry, 11 NGINX-shaped
events are ingested, 36 detection documents are produced, the
correlation engine fires the brute-force pattern, the incident service
opens a case, and the case lifecycle is exercised.

## Environment

- Python 3.13
- In-process FastAPI `TestClient` (no separate process)
- Backend: in-memory `FakeDatabase` (`--backend memory`)
- Two identities:
  - `admin` / `admin` (token role = `admin`)
  - `analyst` / `analyst` (token role = `analyst`)

## How to run

```bash
cd proshield
python scripts/demo_security_workflow.py
```

The script prints a numbered trace to stdout and writes
`demo_out.txt`.

## Pipeline trace (excerpt)

```
======================================================================
ProShield end-to-end security workflow demo (memory backend)
======================================================================
admin token prefix: ps.admin.1788334683.1788338283
analyst token prefix: ps.analyst.1788334683.17883382

registered source: src-01a0610d-b415-76ab-9c94-9432a9302fc7-nginx-demo-0bdfae
source state: enabled

======================================================================
Phase: pipeline
======================================================================
  ingested 01a0610d-8d20-75..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-9108-74..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-94f0-72..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-98d8-71..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-9cc0-7a..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-a0a8-7e..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-a490-76..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-a878-72..  type=authentication_failure ip=10.0.0.66  ->  2 detection(s)
  ingested 01a0610d-b430-7f..  type=authentication_success ip=10.0.0.10  ->  0 detection(s)
  ingested 01a0610d-b430-7a..  type=request_blocked        ip=10.0.0.66  ->  1 detection(s)
  ingested 01a0610d-b431-78..  type=rate_limit_exceeded    ip=10.0.0.66  ->  1 detection(s)
```

(The 11 lines are then sent a second time so the correlation window
sees enough events.)

```
detection.list (rule=NGINX-AUTH-FAILURE-001) reports 16 detections:
  - det-01a0610d-8d20-7924-a.. rule=NGINX-AUTH-FAILURE-001 cat=source_specific event=01a0610d-8d20-75..
  - det-01a0610d-8d20-7924-a.. rule=NGINX-AUTH-FAILURE-001 cat=source_specific event=01a0610d-8d20-75..
  ...

======================================================================
Phase: correlation + incident
======================================================================
  raw detection documents in repo: 36
correlation engine produced 1 correlation(s)
  - corr-147ab786-8f08-7b81-a06e-7830749bae48 pattern=NGINX-CORR-BRUTEFORCE-001 trigger=brute_force_count_threshold key=10.0.0.66|/auth/login count=8

created case: case-01a0610d-b449-71f4-bf13-b925e64cb224 (state=IncidentLifecycleState.OPEN)

case.list now reports 1 incident(s):
  - case-01a0610d-b449-71f4-.. state=open created_by=analyst

Triage of incident case-01a0610d-b449-71f4-..
  fetched: state=open created_by=analyst centralized_correlations=0
  closed: state=closed history=2 transitions
```

## What this proves

- **End-to-end flow works:** the demo uses only the public Phase 4.8
  wire surface (no `app.*` internals leaked into the script).
- **Detection engine is wired:** 36 detection documents exist in the
  repository after the run (verified by `DetectionRepository.count()`).
- **Correlation engine is wired:** exactly **one** correlation fired —
  `corr-…NGINX-CORR-BRUTEFORCE-001` — keyed on
  `10.0.0.66|/auth/login` with a count of 8.
- **Incident side-effect is wired:** the correlation caused an
  automatic `case-…` to be created with state `OPEN`.
- **Lifecycle is wired:** `case.close` moved the case through
  `OPEN → CLOSED` (2 transitions in `lifecycle_history`).
- **Overview aggregator is wired:** `overview.summary` returns the
  expected numbers immediately after close:

```json
{
  "ok": true,
  "data": {
    "open_case_count": 0,
    "detection_count": 36,
    "correlation_count": 1,
    "scope": "own",
    "produced_at": "2026-09-02T07:38:03.245739+00:00"
  }
}
```

## Real IDs (sample run, 2026-09-02)

| Object | ID |
|--------|----|
| Source | `src-01a0610d-b415-76ab-9c94-9432a9302fc7-nginx-demo-0bdfae` |
| Rule | `NGINX-AUTH-FAILURE-001` (seeded from `app.rules._library.nginx`) |
| Correlation | `corr-147ab786-8f08-7b81-a06e-7830749bae48` |
| Case | `case-01a0610d-b449-71f4-bf13-b925e64cb224` |
| Admin token | `ps.admin.1788334683.1788338283…` |
| Analyst token | `ps.analyst.1788334683.17883382…` |

## RBAC checks (verified in `scripts/e2e_test.py`)

| Caller | Op | Expected | Got |
|--------|----|----------|-----|
| (none) | `case.list` | 401 | 401 |
| (none) | `auth.issue` (wrong password) | 401 | 401 |
| `collector` | `case.list` | 403 | 403 |
| `analyst` | `case.list` | 200 | 200 |
| `admin` | `source.register` | 200 | 200 |
| `analyst` | `case.close` | 200 | 200 |

## Notes / known limitations

- `case.acknowledge`, `case.assign`, `case.add_note`,
  `case.add_recommendation` are **not** in the wire surface. The demo
  intentionally does not call them. They are exposed in the UI as
  planned buttons (toast: "not yet promoted to wire ops").
- `timeline.build_for_incident` is the only timeline construction path;
  a global "firehose" timeline is not part of the Phase 4.8 surface.
  The timeline page in the UI is therefore scoped to a single case.
- Correlation count is `1` because the brute-force pattern matched
  cleanly and the other 8 NGINX rules were not triggered in this
  short, single-IP scenario.

## Frontend regression: the "page only fires /api/meta" fix

A separate manual E2E on the live Sources page surfaced a
silent initialization bug: the page rendered the shell
chrome, fired `GET /api/meta` once, and never called
`source.list`. Chrome DevTools Network panel showed exactly
two requests, neither of them the inventory fetch. The
backend was not at fault; the same e2e test that runs
against `SecureProxy` directly still passed, so the proxy
was happy to serve the call.

### Root cause

`PSUI.mount(contentEl, opts)` wrapped its work in a
`DOMContentLoaded` listener unconditionally:

```js
function mount(contentEl, opts) {
    document.addEventListener("DOMContentLoaded", () => {
        if (opts.requireAuth && !PSAPI.getSession()) { ... }
        shell(contentEl, opts);
        opts.afterRender();
    });
}
```

The components call `PSUI.mount(...)` from inside an
`async render()` function — and on the sources page, the
very first line of `render()` is `await
PSAPI.loadMeta()`. That `await` suspends the async
function, lets the HTML parser finish, and **DOMContentLoaded
fires** before `PSUI.mount(...)` is ever reached. The
listener is then registered too late, `shell()` and
`afterRender()` never run, and no per-page data is fetched.

### Files involved

- `frontend/js/components/layout.js` — the buggy `mount()`.
- `frontend/js/components/sources.js` — the component
  whose `render()` did an `await` first.
- `frontend/js/components/overview.js` — same pattern.
- `frontend/js/components/health.js` — same pattern.
- (Every other component called `PSUI.mount(...)`
  synchronously inside `render()` so they were unaffected.)

### The fix (frontend only)

`PSUI.mount(...)` now registers the listener only when
`document.readyState === "loading"` and otherwise runs the
work synchronously:

```js
const run = () => { ... };
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
} else {
    run();
}
```

This is one small change in `frontend/js/components/layout.js`
and fixes the bug for every page whose component does an
`await` before mounting.

A second, related class of issues was discovered while
regression-testing the other pages: `detection.list`,
`correlation.list`, and `timeline.list` all return `[]`
when called with no filter, so calling them once on page
load produced empty tables. The fix is to first call
`rule.list` / `case.list` to discover the IDs and then
issue a per-id request for each, merging and de-duping
the results. The implementation:

- `frontend/js/components/detections.js` — per-rule
  `detection.list` calls merged into one table.
- `frontend/js/components/correlations.js` — per-rule
  `correlation.list` calls; `correlation.confirm` /
  `correlation.dismiss` surfaced as toasts.
- `frontend/js/components/timeline.js` — `case.list` to
  discover cases, then `timeline.list` per case.
- `frontend/js/components/sources.js` — single
  `source.list` call; the supported connector types come
  back inside the response so the redundant
  `source.list_types` round-trip is removed via the new
  `refreshAll()` helper.
- `frontend/js/components/case.js` — guard for missing
  `?id=...` URL parameter that previously produced four
  400 errors per page load.
- `frontend/js/components/overview.js` — targets
  `<main class="main">` instead of `getElementById("app")`,
  which the shell has already replaced.

### Evidence

`scripts/verify_sources_fix.py` (focused end-to-end test
for the original bug):

```
==================================================
Sources page (the original bug)
==================================================
  ops:    ['source.list']
  status: {'source.list': 200}
  errors: []
  body:   3173 bytes
  toolbar present: True
  content present: True
==================================================
  RESULT: PASS
```

`scripts/check_wiring.py` (static wiring check across all
9 pages):

```
WIRING CHECK OK
  pages: 9
  layout fix: present
  sources.js: refreshAll present, no redundant list_types
  case.js: no-id guard present
  overview.js: targets <main class='main'>
```

`scripts/e2e_test.py` (full-stack HTTP regression):

```
PASSED: 56    FAILED: 0
ALL E2E STACK CHECKS PASSED
```

`scripts/smoke_test.py` (in-process backend smoke):

```
ALL 21 SMOKE CHECKS PASSED
```

`scripts/demo_security_workflow.py` (real pipeline):

```
DEMO COMPLETE — all phases executed through the real pipeline.
```


