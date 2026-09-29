# ProShield — Gemini Frontend Integration Review Report

**Phase:** Gemini frontend integration + real API wiring + backend gap discovery
**Repository:** authoritative main ProShield repo (`main`)
**Date:** 2026-09-06
**Final verdict:** see §21.

---

## 1. Repository baseline

- Backend: Python 3.13, `SecureProxy.handle(ProxyRequest)` wire boundary
  (`app/proxy/proxy.py`), 40 declared operations, MongoDB 8.0.13 persistence.
- Deployment listener: `python -m scripts.proxy_server --host 127.0.0.1
  --port 8088 --backend mongo --seed-credentials` (analyst plane;
  `/api/proxy` + `/static/**`).
- Legacy frontend: `frontend/*.html` + `frontend/js/services/api.js`
  (single `PSAPI` client over `POST /api/proxy`, session header
  `X-ProShield-Session`, localStorage keys `proshield.session` / `proshield.user`).
- Authoritative wire contract:
  `docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md` (frozen).
- Git: work performed on `main`; backend code untouched.

## 2. Gemini frontend structure

`frontend/src_upgraded_gemini/` — React 19 + Vite 7 + Tailwind 4
(`vite-plugin-singlefile`), 9 pages + shell (Sidebar/TopBar), global context
(`SocContext`), mock-data layer (`src/data/mockData.ts`), 6 action modals,
payload drawer, omni-search, design-spec deliverable, error sandbox.

## 3. Old frontend structure

Static multi-page app (`index/cases/case/detections/correlations/timeline/
sources/rules/health/login.html`) served from `/static/**`; pages consume
`PSAPI` (`frontend/js/services/api.js`).

## 4–5. Files integrated / retained / removed

**Integrated (new or rewritten, all under `frontend/src_upgraded_gemini/`):**

| File | Change |
|---|---|
| `src/services/api.ts` | NEW — TypeScript port of the existing `api.js` wire semantics (same endpoint, header, localStorage keys, error-envelope rules). |
| `src/services/backend.ts` | NEW — raw backend response types + typed wrappers for existing wire ops only. |
| `src/services/adapters.ts` | NEW — backend → view-model mapping; human-id derivation; explicit nulls where the backend supplies no data. |
| `src/context/SocContext.tsx` | REWRITTEN — API-backed state: auth/boot gate, real data load, real action wiring, truthful error toasts. |
| `src/types/soc.ts` | UPDATED — `severity`/`confidenceScore`/per-source metrics made nullable to match the wire truth. |
| `src/App.tsx`, `src/components/LoginGate.tsx` | NEW/REWRITTEN — real `auth.issue` login gate + boot states (loading/anon/ready/error). |
| `src/components/modals/{AddSourceModal,AddRuleModal}.tsx` | REWRITTEN/PATCHED — real source lifecycle wizard; truthful rule-authoring (no Sigma/YARA-L/CEL claim; CANDIDATE creation). |
| `src/components/investigation/{CentralizedAnalysisModal,ReportGeneratorModal}.tsx` | REWRITTEN — real `case.centralized` / `report.generate_*` / `report.export`; no fake timers, no fabricated findings. |
| `src/components/investigation/AttackGraphTopology.tsx` | PATCHED — removed fabricated ASN/host/reputation/threshold data; node inspector now renders only real evidence or explicit "not available from backend". |
| Pages (Overview/Incidents/CaseDetail/Detections/Correlations/Timeline/Sources/Rules/Health) + Shell/Sidebar/TopBar | PATCHED — removed every hardcoded demo metric (fake eps, fake analyst, fake backlog, fake uptime, fake trend); real timestamps; null-safe severity/confidence/source; render cap for large lists; real per-case timeline loader + case selector. |
| `src/utils/format.ts`, `src/types/lucide-react.d.ts` | NEW — ISO-UTC formatting; lucide-react type shim. |
| `vite.config.ts`, `package.json`, `index.html` | UPDATED — dev proxy to the real backend (`:8088`), production build to `frontend/soc/` (same-origin with `/api/proxy`), `typecheck` script, favicon. |

**Retained (untouched):** the entire legacy frontend (`frontend/*.html`,
`frontend/js/**`, `frontend/css/**`) — still served at `/static/*.html` and
still the reference consumer of `api.js`. Not removed: no dependency analysis
in this phase proved all legacy files obsolete, and the proxy server's
`/` route serves `frontend/index.html`.

**Removed:** nothing.

**Built artifact:** `frontend/soc/index.html` (single-file Vite build),
served by the existing StaticFiles mount at
`http://127.0.0.1:8088/static/soc/index.html` — same origin as `/api/proxy`,
no CORS, no runtime wiring changes.

## 6–7. API client reuse + operations used

The Gemini frontend now uses ONE client (`src/services/api.ts`) that mirrors
the legacy `api.js` exactly: `POST /api/proxy` with `{operation, …}`,
`X-ProShield-Session` header, localStorage session persistence, and the
V2-16 success rule (HTTP 2xx AND no error envelope). No second API layer.

Wire operations exercised by the integrated frontend (all pre-existing):

`auth.issue`, `health`, `overview.summary`, `case.list`, `case.get`,
`case.close`, `case.centralized`, `report.list` (per-incident),
`report.generate_normal`, `report.generate_centralized`, `report.export`,
`source.list`, `source.list_types`, `source.register`, `source.configure`,
`source.validate`, `source.enable`, `source.disable`, `source.retire`,
`source.issue_token`, `detection.list`, `correlation.list` (per-pattern),
`correlation.list_for_incident`, `timeline.build_for_incident`,
`rule.list`, `rule.create`, `rule.enable`, `rule.disable`, `rule.retire`.

## 8. Mock/demo data disposition

- `src/data/mockData.ts` **removed from all production data paths.**
  No page imports `INITIAL_*`; all lists render backend data.
- Capabilities: derived ONLY from `source.list_types` (the fabricated
  Okta/AWS/CrowdStrike catalog is gone).
- `mockData.ts` remains on disk solely for the `design-spec` preview page
  (pure design-preview classification; it renders no operational data).
- Demo artifacts deleted from production UI: fake "8,420 eps" stream
  indicator, fake analyst "Sarah Chen", fake subsystem backlog
  ("SRC-05 … 88%"), fake 99.98% uptime, fake hourly trend, fake ingest
  tokens, fake validation timers, fake report content, fake ASN/reputation
  node intel, fake notifications.

## 9–12. Real workflows verified (live browser, real backend)

Verified via Playwright MCP against the REAL mongo-backed server:

| Flow | Result | Evidence |
|---|---|---|
| Login (wrong credential) | truthful 401 alert "credential rejected"; no entry | UI alert + HTTP 401 |
| Login (analyst) | session issued; data loaded | `auth.issue` 200 |
| Session restore across reload | token verified by restarted server | boot → ready |
| Logout → login (admin) | works; role shown in TopBar | UI |
| Overview | CASE-01 hero, real counts (9e/17d/1c), real attacker 10.0.0.66 derived from correlation key, real health (probe latency 5–11 ms), real hourly buckets (17 signals @ 16:00 UTC) | UI |
| Incidents queue | real case rows, severity/state/evidence counts from backend, "—" for unattributed fields | UI |
| Acknowledge attempt | truthful refusal toast: "…state was NOT changed" (no backend op) | UI toast |
| Case Detail | real evidence counts, real topology (rules ×N, correlation key, member detections), lifecycle rail | UI |
| Centralized analysis | REAL: "CENTRALIZED ANALYSIS COMPLETE (backend-verified) — 0 new correlation(s)… bound to CASE-04" (backend dedup truth) | UI + `case.centralized` |
| Report generation | REAL: `rpt-01a077b3-…` persisted; preview renders backend-built sections (`what_was_detected` with real event refs/timestamps) | UI + `report.generate_centralized` |
| Case closure | REAL: modal reason → `case.close` → backend `state=closed` verified on the wire; open-case badge 3→2 | UI + `case.list` |
| Source enable/disable (analyst) | truthful 403 "operation forbidden" toast — RBAC rejection surfaced | UI + HTTP 403 |
| Source enable/disable (admin) | REAL: "SRC-04 disabled/enabled on the backend", list refreshed from backend | UI + `source.disable/enable` |
| Detections | 200 real detections, real rule ids/reasoning/timestamps, "UNRATED" badges (no severity on wire), case links | UI |
| Correlations | 39 real clusters (pattern, key, window, member detections), "Confidence: —" | UI |
| Timeline | 26 real timeline items (9 events + 17 detections) from `timeline.build_for_incident`; truthful empty-state text for evidence-less cases | UI |
| Sources | 4 real instances (2 retired, 2 enabled), real endpoints/tags, "—" metrics with tooltip | UI |
| Rules | 5 real registry rules, real descriptions/scope/affected-detection counts, "STRUCTURED (backend engine)" label | UI |
| Health | real liveness probe + real per-source health rows; "—" where backend has no data | UI |

## 13–15. Console / network / accessibility findings

**Console:** 0 unexpected errors in the final bundle session. Historical
session entries were the deliberate error-path probes (401 bad credential,
400 pre-fix `report.list`, 2× 403 RBAC) and a favicon 404 (fixed by inlining
a favicon in the build). No React errors, no unhandled rejections, no
hydration/runtime exceptions.

**Network:** every request is a purposeful `POST /api/proxy` with a valid
operation; no requests to nonexistent endpoints (favicon fixed); no runaway
polling; no duplicate request storms; correct HTTP methods; auth header on
all authenticated calls. Non-2xx responses occurred only in the deliberate
probes. Owner classification: 401 = expected auth rejection; 403 = expected
business rejection (RBAC, working as designed); 400 `report.list` was an
API-client bug (fixed) — the wire requires `incident_id` although the frozen
contract documents it as optional (contract doc discrepancy recorded in the
backend-gaps document).

**Accessibility (spot checks):** semantic landmarks (`main`, `header`,
`aside`), labeled form controls (login inputs, filter comboboxes with
aria-labels, case selector), `role="alert"` on error banners, Escape-closable
modals and keyboard-focusable controls are provided by the design system;
severity uses text labels in addition to color (badges carry the word).
A full audit pass is future work; no claims beyond the tested behaviors.

## 16. Responsive findings

1440 / 768 / 390 px verified live: no horizontal overflow at any width
(`scrollWidth === innerWidth`), sidebar navigation remains present and all
six primary nav targets reachable at 390 px, content reflows. 1024/1280 not
individually screenshot-verified (same fluid layout between checked widths).

## 17. Performance findings

- Data load: one parallel batch (cases, detections, correlations,
  sources, rules, overview) + bounded per-case enrichment loops (≤20 cases),
  no N+1 storms.
- Detection cards render-capped at 60 with an analyst-visible notice
  (the wire op is capped at 200; rendering all 200 cards was a measured
  DOM hazard — the pre-cap snapshot alone was ~252k characters).
- Single-file bundle ≈ 1.14 MB (≈286 kB gzip) — acceptable for the
  single-file deployment model; route-level lazy-loading is a future
  optimization (all 9 pages are small relative to the icon library).
- No polling loops exist; all data refreshes are explicit (action results,
  re-probe, reload).

## 18. Test results

| Suite | Result |
|---|---|
| `tsc --noEmit` (frontend typecheck) | PASS (0 errors) |
| `vite build` (production) | PASS |
| `python -m pytest -q` (FULL backend suite, real MongoDB) | **1313 passed, 1 warning** — run 1: 26.22 s; final re-run after all integration work: 30.12 s. No backend source files were modified in this phase (`scripts/seed_mongo_demo.py` is additive test support), and the suite is green both before and after. |
| Live browser smoke (Playwright MCP, real backend) | all flows in §9–12 |

Bugs found by live validation and fixed during the phase:

1. `report.list` called without `incident_id` → 400 broke `refreshAll`
   (fixed: per-case report fetch; contract discrepancy documented).
2. Timeline response shape mismatch (`data.items` vs assumed
   `data.timeline.items`) → empty timeline (fixed).
3. Centralized-analysis modal had no run trigger in its initial state
   (fixed).
4. lucide-react vendored tarball missing its ESM entry → build failure
   (fixed: Vite alias to the intact CJS bundle; TS shim added).

## 19. Browser results

Chromium via Playwright MCP against
`http://127.0.0.1:8088/static/soc/index.html` (mongo backend, seeded via
`scripts/seed_mongo_demo.py` through the real pipeline: 2 source instances,
9→17 detections, correlation, case). All page renders and interactions
listed in §9–12 executed in the real browser.

## 20. Backend gaps (summary)

Full detail: `docs/PHASE 4/backend-missing-features.md` (15 documented gaps,
all `Implementation deferred: YES`). Highest-severity items:

- **P1** case acknowledge/investigate transitions (no wire op)
- **P1** case attacker/target/source attribution (not on the wire)
- **P1** deep health/subsystem observability (liveness only)
- **P2** human-readable IDs (client-side derivation), case notes,
  detection severity/source, correlation confidence, correlation pattern
  catalogue op, per-source ingest telemetry, Sigma/YARA-L/CEL authoring,
  global timeline, contract doc discrepancy (`report.list` `incident_id`
  optional on paper, required on the wire)
- **P3** notification feed, report export formats, overview time-series

## 21. Final verdict

**INTEGRATION PASS WITH DOCUMENTED BACKEND GAPS.**

The Gemini frontend now operates truthfully on the CURRENT ProShield
backend through the existing API architecture: every rendered metric,
record, relationship and lifecycle state is real backend data or an
explicit, labeled "not available"; every action is a real wire operation
whose success AND failure are surfaced faithfully; the full backend test
suite passes untouched. The approved UX cannot be made fully real without
the backend capabilities documented in `backend-missing-features.md` —
per the phase boundary, implementing those is explicitly deferred.
