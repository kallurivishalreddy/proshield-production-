# PROSHIELD PATCH REPORT — STRIX CONFIRMED ISSUES

**Repository:** `c:\Users\k.vishal reddy\Downloads\proshield rule based mvp` (MAIN, authoritative)
**Branch:** `main` · **Base commit:** `578b320`
**Scope:** STRIX deeptest confirmed issues F-1, F-2, F-3, F-4, F-5, F-6, F-7, N-1, N-2.
**Date:** 2026-09-04

---

## PATCH RESULT

| Finding | Severity | Files changed | Root-cause fix | Status |
|---|---|---|---|---|
| **F-1** — No live detection pipeline composition | P0 | `app/pipeline/service.py`, `app/pipeline/__init__.py`, `scripts/ingress_server.py` | Added production `LivePipeline` (detection → correlation → auto-case) and invoked it in the real ingress listener after every successful `source.ingest`; also fixed the listener reading `accepted_event_ids` from the wrong envelope key. | **FIXED** |
| **F-2** — No live case-creation mechanism | P0 | `app/pipeline/service.py`, `app/incidents/service.py`, `scripts/ingress_server.py` | `IncidentService.create_case_for_correlation()` auto-opens an idempotent case per correlation cluster; case id is a pure function of `(pattern_id, key)` (deterministic, no wall clock); re-delivery is blocked by replay store / no duplicate case. | **FIXED** |
| **N-1** — `[object HTMLTableRowElement]` table rendering | P1 | `frontend/js/components/layout.js` | Root cause was the shared `el()` DOM helper not flattening array children; fixed recursively so arrays of nodes append as real `<tr>`/`<td>`. Verified live on Sources/Detections/Correlations/Cases. | **FIXED** |
| **F-5** — Pydantic errors became 401 | P1 | `app/sources/service.py`, `app/proxy/proxy.py`, `tests/unit/test_pipeline_live.py` | `_normalize_tag_tuple` at the owning layer + `PydanticValidationError→SourceConfigurationError` boundary: tag/validation failures now return 400 `source_configuration_error`. | **FIXED** |
| **F-7** — Unexpected exceptions became 401 | P1 | `app/proxy/errors.py`, `app/proxy/proxy.py` | Added `ProxyInternalError` (500 `internal_error`); the generic exception fallback now emits 500 instead of 401. | **FIXED** |
| **F-3** — 10 dead frontend ops | P1 | `frontend/js/components/timeline.js`, `case.js`, `rules.js`, `correlations.js`, `health.js`, `app/correlation/service.py`, `app/persistence/correlation_repository.py` | Aligned UI to real ops: `timeline.build_for_incident`, `rule.retire`, `correlation.list` (unfiltered now returns all clusters via new `find_recent`), removed the `api.meta` proxy probe; dead controls surface an honest toast instead of firing 400. | **FIXED** |
| **F-4** — Centralized analysis + reports un-wired | P1 | `frontend/js/components/case.js` | Wired "Centralized analysis" → `case.centralized`, "Generate report" → `report.generate_normal`, "Export JSON" → `report.export` — verified end-to-end live against Mongo. | **FIXED** |
| **F-6** — 6 connector types, only 2 implemented | P1 | `app/sources/registry.py`, `tests/unit/test_phase49_{proxy,registry,service}.py`, `tests/integration/test_phase49_pipeline.py` | `SUPPORTED_CONNECTOR_TYPES` now only advertises implemented types (nginx, simulator); register of unimplemented types → 400; `source.list_types` returns only implemented; proxy now reloads persisted sources at startup (durability fix). | **FIXED** |
| **N-2** — `source.validate` label overstated connectivity | P1 | `frontend/js/components/sources.js` | Button relabeled "Validate" (config/state transition), no longer "Test Connection". | **FIXED** |

---

## FILES CHANGED / CREATED

**Created (product code):**
- `app/pipeline/__init__.py` — exposes `build_live_pipeline`
- `app/pipeline/service.py` — `LivePipeline`, `PipelineRunOutcome`, production orchestration
- `tests/unit/test_pipeline_live.py` — F-1/F-2/F-5/F-7 targeted tests

**Modified (product code):**
- `app/incidents/service.py` — `create_case_for_correlation`, `case-` id helpers, optional `incident_id` on `create_case`
- `app/persistence/detection_repository.py` — portable `find_recent`
- `app/persistence/correlation_repository.py` — `find_recent` for unfiltered listing
- `app/correlation/service.py` — unfiltered `list()` returns recent clusters
- `app/proxy/errors.py` — `ProxyInternalError`
- `app/proxy/proxy.py` — F-5/F-7 boundary fixes; `source.issue_token` unchanged shape
- `app/sources/service.py` — `_normalize_tags`, `_normalize_tag_tuple`, Pydantic→`SourceConfigurationError`
- `app/sources/registry.py` — implemented-only connector set
- `scripts/ingress_server.py` — build + run `LivePipeline` after ingest; fixed accepted-id envelope read
- `scripts/proxy_server.py` — source registry reload at startup

**Frontend:**
- `frontend/js/components/layout.js` — N-1 array-child flatten in `el()`
- `frontend/js/components/timeline.js`, `case.js`, `rules.js`, `correlations.js`, `health.js`, `detections.js`, `sources.js` — F-3/F-4/N-2/N-1 wiring

**Tests updated (F-6 contract):**
- `tests/unit/test_phase49_proxy.py`, `tests/unit/test_phase49_registry.py`, `tests/unit/test_phase49_service.py`
- `tests/integration/test_phase49_pipeline.py`

**Verification tooling kept:**
- `scripts/live_e2e_strix.py`, `scripts/live_idempotency_strix.py` — live-Mongo HTTP E2E + idempotency proof

---

## ARCHITECTURAL CHANGES

Production composition now wired in the real listener:

```
external event
  -> scripts.ingress_server (/api/ingress, trusted boundary, source token)
  -> InboundIngressProxy.handle  (replay store, rate limit, canonical event)
  -> SecurityEventRepository (Mongo, schema validated)
  -> LivePipeline.process(event)
       -> DetectionPipeline (DetectionEngine over NGINX rules, DetectionRepository)
       -> CorrelationEngine (BruteForceClusteringPattern over recent detections)
       -> IncidentService.create_case_for_correlation (auto, idempotent case)
```

No test-only routes, no manually-composed engines, no seeded detections/correlations/cases.

---

## API / CONTRACT CHANGES

- `source.list_types` → returns only implemented types (`nginx`, `simulator`).
- `source.register` → 400 `source_configuration_error` for unimplemented types / invalid tags (not 401).
- `correlation.list` (unfiltered) → returns recent clusters (previously always `[]`).
- Generic unexpected proxy exception → 500 `internal_error` (previously 401).
- Frontend op alignment: `timeline.build_for_incident`, `rule.retire`, `case.centralized`, `report.generate_normal`, `report.export`; removed `api.meta` proxy probe.

## DATABASE CHANGES

- `scripts.init_mongo` re-applied the current `security_events` `$jsonSchema` validator (source_instance_id now permitted; this resolved live ingest rejection).
- No schema/index destructive changes; new/updated indexes standard via `ensure_indexes`.

## FRONTEND CHANGES

- Shared `el()` helper now flattens array children (root-cause N-1 fix, no innerHTML workaround).
- Detections count heading updates after load.
- Correlations page uses real `correlation.list` (unfiltered) and shows live clusters.
- Case detail: "Centralized analysis", "Generate report", "Export JSON" wired to real ops; report panel renders result.
- Sources register dropdown lists only nginx/simulator; Validate label corrected.

---

## TARGETED TEST RESULTS

| Finding | Command | Result |
|---|---|---|
| F-1/F-2/F-5/F-7 | `python -m pytest tests/unit/test_pipeline_live.py` | **5 passed** |
| F-6 contract | `python -m pytest tests/unit/test_phase49_{proxy,registry,service}.py tests/integration/test_phase49_pipeline.py` | all passed |

## FULL TEST SUITE RESULTS

```
python -m pytest tests/unit tests/integration -q
1276 passed, 1 warning (StarletteDeprecationWarning), 0 failures
```

## LIVE E2E RESULTS (real MongoDB, real listeners via HTTP)

Counts (produced by the running product only; no manual seeding):

```
sources=1         (nginx source registered/configured/validated/enabled via UI)
security_events= 1025 -> 1035  (+10 accepted live ingest)
detections=      1286 -> 1296  (+10 NGINX-AUTH-FAILURE-001, provenance preserved)
correlations=    0    -> 7     (brute-force clusters keyed [10.0.0.66, endpoint])
incidents/cases= 0    -> 1     (case-17c84b6a… "Correlated security cluster (10.0.0.66)")
```

Proven causal chain (single request turned into full chain):

```
real event -> ingress (token) -> security_events +1
            -> NGINX-AUTH-FAILURE-001 detection (event/detection provenance)
            -> BruteForceClusteringPattern correlation (10.0.0.66)
            -> auto-opened case (idempotent, cluster-keyed)
```

Idempotency:
- Re-delivery of the same batch is rejected `401 source identity token replay rejected` (single-use tokens) and does not create a duplicate case (`duplicate-case-prevented: PASS`).
- Re-ingesting NEW events into the SAME cluster signature keeps `incidents` constant (3→3) while `security_events`/`detections`/`correlations` keep growing (final run: events 1055→1065, detections 1316→1326, correlations 18→28) — the cluster-keyed case id maps to the existing case instead of opening a duplicate (F-2 deterministic idempotency).

## BROWSER RESULTS

- **Sources:** register + configure + validate + enable via UI; dropdown lists only nginx/simulator (F-6); real `<tr>` cells after registration (N-1).
- **Detections:** real DOM table with 212+ live rows, 0 console errors after re-auth (N-1).
- **Correlations:** 11 live cluster rows rendered, 0 console errors (F-3 + N-1).
- **Cases/Incidents:** 3 live cases rendered incl. auto-opened case (N-1).
- **Case detail:** Close / Acknowledge(planned) / **Centralized analysis** / **Generate report** / **Export JSON** actions; clicking "Generate report" created `rpt-…` in Mongo and rendered the report panel (F-4).
- **Login:** admin login against live mongo backend works.
- Screenshots: `overview_loggedin.png`, `sources_registered.png`, `detections_populated.png`, `correlations_live_rows.png`.
- Note: one browser session showed a cached old `detections.js`/`correlations.js` count heading (served file verified correct via cache-busted fetch); DOM rows always real.

## SECUREPROXY / LOG RESULTS

- Model/persistence validation → 400 `source_configuration_error`; auth missing → 401 `authentication_required`; replay → 401 `source_identity_token_error`; unexpected → 500 `internal_error`.
- Ingress log shows `ingest.persisted` and the pipeline processing the accepted ids; proxy log shows `POST /api/proxy` 200 on real ops.
- Secrets: credentials never logged; admin credential used via credential header only.

## REGRESSION RESULT

All pre-existing unit + integration tests remain green (1276 passed); updated F-6 tests encode the corrected contract.

## REMAINING GAPS

- Cases page heading count is a browser-cache artifact in one session; served file contains the fix.
- `case.assign/add_note/add_recommendation` and `rule.approve/revoke` remain intentionally not-promoted wire ops (honest "planned" toasts); `correlation.confirm/dismiss` likewise documented but not wire-promoted.
- Live Mongo used the default `proshield` DB; a fresh audit DB is recommended per deployment.

## FINAL STATUS

**COMPLETE**