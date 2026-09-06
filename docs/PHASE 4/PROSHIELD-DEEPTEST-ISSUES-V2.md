# PROSHIELD — STRIX DEEP FORENSIC REVIEW V2
## CODE / ARCHITECTURE / BACKEND / FRONTEND WIRING / API / PERSISTENCE / RUNTIME COMPOSITION

**REPORT FILE:** `docs/PHASE 4/PROSHIELD-DEEPTEST-ISSUES-V2.md`
**DATE:** 2026-09-05
**PASS:** V2 (code/architecture causal audit — Prompt 1)
**MODEL ROLE:** Principal Security Architect / Backend Architect / Distributed Systems / Platform Engineer / Adversarial QA

This pass is a **review**, not a patch. No product code was modified.

---

## EXECUTIVE VERDICT

> **NOT READY — IMPORTANT GAPS** (an upgrade from the V1 verdict `ARCHITECTURALLY INCOMPLETE — NOT READY`).

**What changed since V1:** the central architectural defect of V1 — *live composition missing* (V1 F-1/F-2) — is **genuinely fixed**. Proof in the current MAIN repository plus the live MongoDB the product actually used:

```
external event -> ingress (HMAC token, single-use replay, source-state check)
  -> SecurityEvent persisted (source_instance_id provenance)
  -> LivePipeline.process (DetectionPipeline -> CorrelationEngine -> create_case_for_correlation)
  -> detections / correlations / auto-case rows in Mongo
```

DB state on this machine (`proshield` db, Mongo 8.0.13): `security_events=1075`, `detections=1336`, `correlations=38`, `incidents=3`, `reports=4`, `managed_rules=5`, `source_instances=1` — rows that a real external sender produced through the live listeners, not test seeding. The `app/pipeline/` package + the ingress listener hook are real product code, and the unit+integration suites are green (**1190 unit + 86 integration passed** on this run).

**What still makes it NOT READY — IMPORTANT GAPS:**

1. **Persistence contract incomplete at runtime (V2-P0).** The accidental live Ops never apply the documented `$jsonSchema` validators + unique indexes to `incidents`, `reports`, `managed_rules`, `source_instances` (live DB evidence: those collections have ONLY `_id_` and `validator=NO`). The F-2 idempotency guarantee is therefore **not actually enforced at the database boundary** under concurrency; `IncidentRepository.create` relies entirely on the unique index that does not exist in the live DB. The same gap silently disables schema defence-in-depth and duplicate-report / duplicate-rule / duplicate-source-instance protection.
2. **Rule lifecycle governance is disconnected from the live detection engine (V2-P1).** `rule.create / enable / disable / retire` mutate the analyst-plane in-memory registry + the `managed_rules` collection, but the ingress-plane `LivePipeline` builds its OWN registry from `app.rules._library.nginx` at startup and never reloads managed rules. A rule the operator disables/retires in the UI **keeps firing** in the live pipeline; operator-created rules **never fire**.
3. **Case evidence is frozen at first open (V2-P1).** A growing brute-force cluster produces new detections + new correlations, but `create_case_for_correlation` returns the existing case unchanged; `case.evidence` never accumulates. The case detail page therefore shows only the first triggering event.
4. **Analyst-plane wire mismatches remain (V2-P1).** The case detail page calls `detection.list {incident_id}` (ignored → always `[]`) and `correlation.list {incident_id}` (ignored → global recent rows), and the whole analyst UI renders fields the backend never emits (`severity`, `confidence`, `source_id`, `correlation_kind`, `kind`, `strategy`, `score`, `primary_incident_id`, `related_incident_ids`, …). Most tables are decorative.
5. **Centralized analysis from the UI is a no-op (V2-P1).** `case.js` invokes `case.centralized` with only `incident_id`; the handler derives `detections=[]`, `events=[]`, so the correlation engine runs over zero inputs and reports "0 new correlations"; the lifecycle flips PENDING→OPEN.
6. **Unmatched (valid, trusted, persisted, no-rule) events have zero analyst visibility (V2-P2).** There is no event browser/op in the product; the docs require "make the event available for human review."

**Bottom line:** individual engines are sound and now composed in the live path; what is missing today is the *governance/persistence-analyst wiring that makes the output trustworthy, complete, and idempotent in a running deployment* — plus a large set of frontend claim-vs-contract mismatches that make the shipped analyst UI show placeholder data and wrong-scope data.

---

## AUDIT SCOPE

- **In scope:** code, architecture, backend composition, frontend wiring, API contract, persistence, runtime composition, end-to-end causal paths, security boundaries.
- **Out of scope (Prompt 2):** dedicated visual / human-operator / browser walkthrough.
- **Method:** document → code → runtime evidence (live MongoDB state, live counts). No product code changed. Browser not used for visual proof; runtime DB state is used as evidence where available.
- **Tests run on this pass:**
  - `python -m pytest tests/unit -q` → **1190 passed** (12.33s)
  - `python -m pytest tests/integration -q` → **86 passed** (14.52s, real MongoDB) — matches the patch report's `1276 passed` combined figure.
  - `python scripts/check_wiring.py` → **FAILED** (`correlations.js: expected op 'rule.list' not present`) — the repository's own static wiring check is stale/red on current MAIN.

## CURRENT MAIN REPOSITORY

- Path: `C:\Users\k.vishal reddy\Downloads\proshield rule based mvp` (MAIN, authoritative).
- Git: `main` @ `578b320` plus STRIX-patched working tree (`app/pipeline/`, `app/sources/replay_store.py`, `frontend/`, `scripts/proxy_server.py`, `scripts/ingress_server.py`, docs, tests — all uncommitted as of this pass).
- Serena project config `.serena/project.yml` → project_name `proshield rule based mvp`; memory `mem:proshield/workspace` confirms the MAIN path is authoritative and testing copies are NOT to be used. **Serena points at MAIN.**
- Spec kit `.specify/` exists (workflows/templates) but contains no product spec; the product specifications live in `docs/`.

---

## PATCH RECHECK

Legend: ✅ PATCH CORRECT · 🟡 PATCH PARTIAL · ❌ PATCH INCORRECT · 🔴 PATCH INTRODUCED NEW RISK · ⚪ NOT RELEVANT

| ID | Claimed fix | Recheck result | Notes |
|---|---|---|---|
| F-1 | Live detection pipeline composition in the real listener | 🟡 **PARTIAL** | The composition NOW exists and provably works (`app/pipeline/service.py` + `scripts/ingress_server.py::_run_live_pipeline_after_ingest`). However the fix is synchronous in-request, pipeline failures are log-only, the pipeline's rule registry is disconnected from rule management (V2-P1), and `find_recent` does a full-collection scan per detection (V2-08). |
| F-2 | Auto case creation, deterministic idempotent | 🟡 **PARTIAL** | `_case_id_for_correlation` is a correct pure function of `(pattern_id, key)`. But the DB safety net (unique `inc_incident_id_unique` index) is **absent in the live DB** (V2-P0), so the check-then-act `get_by_id`+`create` race is unguarded; and case evidence never accumulates (V2-03). |
| F-3 | 10 dead frontend ops aligned | 🟡 **PARTIAL** | `timeline.build_for_incident`, `rule.retire`, unfiltered `correlation.list`, and removal of the `api.meta` proxy probe are real. **But** `case.js` still calls `detection.list {incident_id}` (always `[]`) and `correlation.list {incident_id}` (global scope → wrong data + cross-scope leak to the case page); `health.js` still probes the non-existent `timeline.list`; `check_wiring.py` itself now fails. |
| F-4 | Centralized analysis + reports wired | 🟡 **PARTIAL** | `report.generate_normal` / `report.export` genuinely work (4 report docs in live DB). "Centralized analysis" is wired to `case.centralized` **but with an empty evidence payload** → no-op analysis (V2-06). |
| F-5 | Pydantic errors became 401 | ✅ **PATCH CORRECT** | `_normalize_tag_tuple` at the owning layer + `PydanticValidationError → SourceConfigurationError` boundary; live tests cover tag/validate → 400 `source_configuration_error`. |
| F-6 | 6 connector types → only implemented advertised | 🟡 **PARTIAL** | `SUPPORTED_CONNECTOR_TYPES = {nginx, simulator}`; registering `waf/iam/...` → 400. **But** `simulator` fails the fix's own stated criterion ("implementation AND rule library"): there is no simulator rule library, so simulator ingests produce zero detections in the live pipeline (V2-12). |
| F-7 | Unexpected exceptions became 401 | ✅ **PATCH CORRECT** | `ProxyInternalError` (500 `internal_error`); generic fallback in `SecureProxy.handle` now emits 500; `app/proxy/errors.py`. |
| N-1 | `[object HTMLTableRowElement]` table rendering | ✅ **PATCH CORRECT** | `layout.js::el()` recursively flattens array children — genuine root-cause fix. |
| N-2 | `source.validate` label overstated connectivity | ✅ **PATCH CORRECT** | Relabelled "Validate". |

**Recheck cross-cutting observation:** the patch fixed *operation-name* wiring but not *payload-shape / response-contract* wiring, which is where the remaining analyst-UI breakage lives.

---
## ARCHITECTURE RECONSTRUCTION

### Component → runtime owner matrix (current MAIN)

| Component | File(s) | Runtime owner | Live-composed? |
|---|---|---|---|
| Canonical SecurityEvent | `app/domain/security_event.py` | both planes via repos | yes |
| InboundIngressProxy (trust+replay+ingest) | `app/sources/ingress.py` | `scripts/ingress_server.py` process | yes |
| Source identity token issuer/verifier | `app/sources/trust.py` | proxy (issue) / ingress (verify) | yes |
| Replay store | `app/sources/replay_store.py` (`MongoReplayStore`) | ingress server (`--backend mongo`) | yes |
| Source registry + repository | `app/sources/registry.py`, `app/sources/repository.py` | proxy (admin) / ingress (authoritative resolver) | yes; ingress uses Mongo resolver |
| Rule registry / loader | `app/rules/registry.py`, `app/rules/loader.py` | two independent in-memory registries (one per process) | yes — but **disconnected from each other** (V2-02) |
| Rule management | `app/rules/management/service.py` | proxy process only | **NOT in live detection path** |
| DetectionEngine | `app/detection/engine.py` | ingress pipeline | yes |
| DetectionPipeline | `app/detection/pipeline.py` | ingress pipeline | yes |
| CorrelationEngine | `app/correlation/engine.py` | ingress pipeline + centralized | yes |
| **LivePipeline** | `app/pipeline/service.py` | ingress server after each accepted ingest | yes (NEW in patch) |
| IncidentService / create_case_for_correlation | `app/incidents/service.py` | proxy + ingress pipeline | yes |
| Timeline engine/service | `app/timeline/` | proxy read op | yes |
| RoutingEngine | `app/routing/` | proxy `routing.compute` | recommendation-only |
| ReportService | `app/reports/service.py` | proxy | yes |
| OverviewReadService | `app/overview/service.py` | proxy | yes |
| SecureProxy | `app/proxy/proxy.py` | proxy server | yes |
| SeverityEngine / ConfidenceEngine | `app/severity/engine.py` (+ models) | **nobody** | **NOT composed anywhere in the live chain** (V2-10) |
| Connector classes (`NginxConnector`, `SimulatedConnector`) | `app/connectors/` | **nobody in the live path** — ingress builds events directly | **NOT composed** (V2-12) |
| Startup composition | — | **only manual two-process startup** (`scripts/proxy_server.py`, `scripts/ingress_server.py`) | no single `app/` main, no migration step |

### Live causal path (verified)

```
POST /api/ingress  (X-ProShield-Source-Token)
  → _extract_token → SourceIdentityTokenVerifier.verify
      → HMAC + expiry + not_before + source_resolver(Mongo) + replay claim (atomic Mongo insert)
  → authoritative source state check (ENABLED, not RETIRED, type/source match)
  → per-request + per-event rate limit
  → _build_security_event(raw) → SecurityEvent (source_instance_id provenance, ST-04 untrusted-field reconciliation)
  → SecurityEventIngestionService.ingest → SecurityEventRepository.create (idempotent on event_id)
  → _run_live_pipeline_after_ingest:
      LivePipeline.process(event):
        DetectionPipeline.run(event) → DetectionEngine(rule_registry.applies_to) → DetectionRepository.create
        _run_correlation → DetectionRepository.find_recent(5 min) → CorrelationEngine(brute-force pattern)
                             → CorrelationRepository.create (idempotent on correlation_id)
        _open_case_for_correlation → IncidentService.create_case_for_correlation
                             → case id = sha256(pattern_id + key_parts) → IncidentRepository.create
```

Runtime counts in the live `proshield` DB (this machine) prove the chain ran end-to-end from real HTTP: 1075 events, 1336 detections, 38 correlations, 3 cases.
## CONNECTOR / SOURCE / SOURCE INSTANCE MODEL

**What "Add Source" actually is (current implementation):** it registers a **SourceInstance** — a persisted Mongo document `{source_instance_id, source_type, source, display_name, configuration, state, tags, ...}` — of a **SourceType**. There is no connector-family/connector-implementation/sub-connector object in the runtime. The `app/connectors/` package (connector interface, `NginxConnector`, `SimulatedConnector`, nginx parser/mapping) is **not called by the live ingress path**: `InboundIngressProxy._build_security_event` assembles the `SecurityEvent` directly from the wire payload JSON + the registered SourceInstance (source string, endpoint/asset reconciliation, provenance collector=source_type). Connectors appear only in test/demo scripts and `DetectionPipeline.run_from_connector`. Summary: the runtime model is **MODEL A (Connector → Source Instance) with no live connector consumer**.

**Model comparison (Model A vs Model B "sub-connector"):** no capability in the specification requires a sub-connector layer. Per-source configurability, per-source tokens, per-source state, per-source provenance and per-source rules (via rule `sources` metadata) all exist without it. A sub-connector layer would be **unnecessary complexity**. Recommendation: keep Model A.

**Multiple connector / multiple source support (verified):**
- Multiple SourceInstances can be registered (DB `source_instances` collection; token per instance).
- Provenance: `SecurityEvent.provenance.source_instance_id` is stamped (index `ev_provenance_source_instance_id` sparse — present in live DB).
- Rule applicability is by `event.source` (== source_type), NOT by source_instance_id → all nginx instances share the nginx rule set (appropriate: "one connector → shared rule model → multiple source instances").
- **Cross-source-instance correlation mixing (design note):** `BruteForceClusteringPattern` groups by `(source_ip, endpoint)` only; the `Correlation.key` and auto-case id do **not** include `source_instance_id`. Two nginx instances observing the same attacker IP/endpoint merge into one correlation and one case. Not a spec violation, but an explicit source-isolation decision the docs do not make.

## RULE OWNERSHIP

Rule *evaluation* state lives in **two independent in-memory `RuleRegistry` instances**:

1. **Analyst plane** (`scripts/proxy_server.py::_build_mongo_backend` + `_attach_services`): registry seeded from `app.rules._library.nginx`; `RuleManagementService` persists the same 5 rules into `managed_rules` (Mongo) and reconciles them into the registry; `rule.create/update/version/enable/disable/retire` mutate registry + Mongo.
2. **Ingress plane** (`scripts/ingress_server.py::_build_ingress_pipeline`): a **fresh `RuleRegistry`** loaded ONLY from `app.rules._library.nginx`. `RuleManagementService.reload_from_repository()` is **never called** here; no runtime refresh exists.

Consequences (V2-02): `rule.disable`/`rule.retire` executed by an admin have **no effect** on live detections; operator-authored rules never evaluate; the documented invariant "the registry is the single source of truth for which rules are live" (registry doc §88) is **untrue across planes**.

Correct ownership model: built-in library rules are owned by the code library; *managed* (operator) rules are owned by the `managed_rules` collection; but the live pipeline must run the same reconcile step (`reload_from_repository`) so lifecycle decisions apply. Currently only the library subset is live.

## LIVE PIPELINE COMPOSITION

Verified wiring (real code, real run): event → trust → replay → canonical event → persistence → detection → correlation → case. This closes V1 F-1/F-2 at the composition level.

**Still missing or weak in the live chain:**
- Severity/confidence engines are not invoked anywhere — no `severity`/`confidence` on `Detection`, `Correlation`, `Incident`. `SeverityEngine` (`app/severity/engine.py`) is referenced only by its own package; routing substitutes a heuristic (V2-10).
- Rule registry governance disconnect (V2-02).
- Synchronous in-request processing: the HTTP 200 to the source is delayed until the whole chain (incl. correlation full-scan) completes; pipeline exceptions only log (no dead-letter, no retry, no compensation) (V2-11).
- No worker/queue/consumer infrastructure (not documented for MVP — acceptable), but "no silent event loss" (`app/pipeline/service.py` docstring) is only true while the ingress process stays up and Mongo stays healthy.
- Detections/correlation/case replay-dedup depends on the unique indexes, which are NOT all present in the live DB (V2-P0).

---
## UNKNOWN / UNMATCHED EVENT MODEL

**Documented semantics:** `docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md` (Phase 4.4 report): "the engine does not classify anything; an event that no rule fires on is a `DetectionResult` with `detections=()`". `docs/PHASE 1/ARCHITECTURE.md` (§545): "An event may remain useful as evidence even when no rule is triggered." `docs/PHASE 0/INITIAL_SECURITY_EVENTS.md` (§488-491): "optionally classify the activity as unclassified/suspicious according to the defined MVP behavior; make the event available for human review".

**Actual behavior (traced):**
- VALID + TRUSTED + PERSISTED + SECURITY-RELEVANT + NO MATCHING ENABLED RULE → event persisted in `security_events`; `LivePipeline.process` returns `detections=()`, `correlations=()`, `case=None`. No classification, no severity, no escalation, no analyst row.
- **Analyst visibility: effectively zero.** The frontend has no events page and there is no `event.*` wire op; the case-detail timeline shows events only through case evidence; unmatched events are invisible to operators.

**Requirement check (V2-07):** the docs do NOT require automated escalation of unmatched events, so the absence of escalation is **not a defect per se**. But the documented obligation "make the event available for human review" **is unfulfilled** — there is no read path for raw events. Genuine gap (P2), plus a security-improvement recommendation (read-only, source-instance-scoped event browser).

## SECUREPROXY / API CONTRACT

**Traced:** `SecureProxy.handle` → `_validate_request_shape` → `_dispatch` → per-op handler → service → repository → `_shape`/`_shape_ok`.

- 400 validation; 401 (`ProxyUnauthorizedError`/`AuthenticationRequiredError`); 403 (`AuthorizationError`); 404 (`NotFoundError`, and **IDOR defence**: `CaseAccessDeniedError` → `404 case_not_found` at the wire); 409 conflict; 429 rate limit (per-subject + separate centralized budget); 500 `internal_error` for unexpected (F-7 verified); 503 replay-store unavailable fail-closed. No secret leakage in safe envelopes; `internal_detail` is server-side only.
- **Residual contract issues:** (a) `case.centralized` with an empty evidence payload succeeds trivially (no-op) instead of rejecting or pulling case evidence (V2-06); (b) `case.create` is in `ALLOWED_OPERATIONS` but always 400s by design (honest docstring — cosmetic API surface); (c) `detection.list`/`correlation.list` silently ignore unknown body keys such as `incident_id` — exactly how the frontend mis-uses them (V2-04); (d) `timeline.list` does not exist but `health.js` probes it.
- Every `ALLOWED_OPERATIONS` entry has a real handler; no swallowed dispatch found.

## DETECTION

Traced `SecurityEvent → DetectionEngine.run → DetectionRepository.create`:
- Eligibility: `registry.applies_to(event)` (source + event_type) and only `APPROVED + enabled` rules.
- `detection_id` deterministic from `(rule_id, version, event_id, detected_at=event_time)`; `evidence_refs=(event_id,)`; `rule_version` preserved. Replay dedup relies on unique `det_detection_id_unique` (present in this DB; must exist in every deployment — V2-P0).
- Rule-evaluation failures are quarantined into `DetectionResult.errors`. `DetectionPipeline.run` treats a duplicate as kept, but **other** persistence failures are logged and the detection is dropped from `persisted_detections` with **no retry/compensation** (part of V2-11).
- No-rule events → `detections=()`. Severity/confidence not set on detections (by design), and nothing downstream computes them either (V2-10).

---
## CORRELATION

- Single pattern `BruteForceClusteringPattern` (threshold 5, window 5 min, key `(source_ip, endpoint)`); deterministic, fail-closed per pattern.
- Live trigger: `LivePipeline._run_correlation` reads `DetectionRepository.find_recent(now-5min)` **per detection-bearing event** → full-collection `find({})` + Python filter/sort (V2-08). Dedup on `corr_correlation_id_unique` (present in this DB; V2-P0 applies).
- **Correlation proliferation (V2-09):** `_build_correlation_id` includes `window_start`, `window_end`, and the exact `detection_ids` set → a growing cluster produces a **new correlation_id per distinct detection-set** observed. Re-running the window after each new event creates many correlation rows for one logical cluster (38 rows / 3 cases in the live DB is consistent). Case opening stays single because the case id is key-stable, but `correlation.list` is noisy and the case evidence keeps only the first correlation (V2-03).
- Window is all-sources (see CONNECTOR section).

## CASE

- Opening policy: automatic per correlation (F-2); case id = `sha256(pattern_id + "|" + key_parts)` formatted UUIDv7 (`_case_id_for_correlation`, `app/incidents/service.py:607-641`) — deterministic, no wall-clock.
- Idempotency: `get_by_id(case_id)` short-circuit then `IncidentRepository.create` (duplicate tolerant). **In the live DB the unique `inc_incident_id_unique` index does NOT exist** → the DB safety net is gone; the check-then-act is the only guard (V2-P0 race).
- Evidence: `IncidentEvidence(event_ids, detection_ids, correlation_ids, rule_references)` — references-only (good), but **frozen at first open**; subsequent cluster events never update the case (V2-03).
- Lifecycle: `open → centralized_pending → centralized_failed → open`; `open → closed`. No `acknowledged`/`investigating` states even though the cases UI filter offers them (V2-05).
- Authorization: `case.read`/`case.read:any`; IDOR → 404 at wire.

## TIMELINE / EVIDENCE / PROVENANCE

- `timeline.build_for_incident` resolves `case.evidence` (events via repo, detections via `list_for_incident`, correlations via ids) into `TimelineEngine`. Because case evidence is frozen, timelines are limited to first-trigger evidence (V2-03).
- Provenance: event→detection (`evidence_refs`), detection→correlation (`detection_ids`/`event_ids`), correlation→case (`correlation_ids`). No evidence mutation found; missing ids are skipped silently (documented forward-compat).

## ROUTING

`routing.compute` is **recommendation-only**: deterministic heuristic → `(level, team, queue)` + reasons; no dispatch/send transport, no SIEM feed, no queue push anywhere in the repo. Matches the documented MVP boundary (`docs/PHASE 0/ROUTING_MATRIX.md` §20). The analyst UI does not surface routing. Classification: recommendation-only per documented requirements — **not a bug**, but un-wired frontend.

## CENTRALIZED ANALYSIS

- Contract (`case.centralized`): analyst supplies `detections` + `events` (payload-shaped); service runs `CorrelationEngine.run` over exactly those, persists new correlations, merges ids into the case, transitions `open→centralized_pending→open`.
- **UI is a no-op (V2-06):** `case.js::runCentralized` sends only `{incident_id, reason}` → `detections=[]`, `events=[]` → engine runs over zero inputs → "0 new correlations" → success toast. No case-evidence retrieval, no cross-source fetch; the "cross-source retrieval" capability implied by the docs is **not** provided by the wire op (evidence must be assembled client-side) and the UI never does it.
- Authorization, rate limit, and centralized-failed lifecycle paths are correct.

## REPORTING

- `report.generate_normal` / `report.get` / `report.list` / `report.export` (JSON only) implemented and authorizer-scoped (`REPORT_READ`); `evidence_references` derived from case + detections + correlations. 4 report docs exist in the live DB. Export is JSON re-serialization (contract-documented), not a binary encoder — fine for MVP.
- Severity/confidence context sections are heuristic — no live SeverityEngine (V2-10).

---
## PERSISTENCE / RECOVERY

### Inventory vs runtime (live `proshield` DB on this machine, Mongo 8.0.13)

| Collection | Docs | $jsonSchema validator | Unique indexes | Documented index set |
|---|---|---|---|---|
| `security_events` | 1075 | YES | `ev_event_id_unique` + 7 | OK |
| `detections` | 1336 | YES | `det_detection_id_unique` + 3 | OK |
| `correlations` | 38 | YES | `corr_correlation_id_unique` + 3 | OK |
| `source_token_replay` | 0 | NO (type `_id` unique) | `token_id` unique + TTL | OK |
| `incidents` | 3 | **NO** | **NONE (`_id_` only)** | missing |
| `reports` | 4 | **NO** | **NONE (`_id_` only)** | missing |
| `managed_rules` | 5 | **NO** | **NONE (`_id_` only)** | missing |
| `source_instances` | 1 | **NO** | **NONE (`_id_` only)** | missing |

Root cause: repository classes expose `ensure_schema()`/`ensure_indexes()` but **nothing in the shipped composition calls them** for these collections. `scripts/init_mongo.py` bootstraps only `security_events`. The detections/correlations validators present here were produced by earlier test/script runs, not by the deployment path. A fresh deployment following the README ends up with **no validators and no unique indexes** on detections/correlations/incidents/reports/managed_rules/source_instances (see V2-P0).

### Recovery
- Restart durability: sources reloaded from Mongo into the in-memory registry (`reload_from_repository`) on the analyst plane only; the ingress plane's **rule registry is rebuilt from scratch** and its source registry starts empty (authoritative resolver reads Mongo per request, so enable/retire state changes are honored live on ingest).
- Rule state after restart: managed rules reset to Mongo state on the analyst plane; the live pipeline keeps the static library state → rule-lifecycle drift across restarts (V2-02).
- No scheduled/async replay of failed pipeline stages (V2-11).

## CONCURRENCY / IDEMPOTENCY

- **Duplicate event:** `SecurityEventRepository.create` insert-only + unique `event_id` index → idempotent (threatened only if the index is absent, V2-P0).
- **Repeated detection:** same mechanism on `detection_id`.
- **Repeated correlation:** `correlation_id` deterministic + unique index.
- **Repeated case opening:** `_case_id_for_correlation` stable per cluster + `get_by_id` short-circuit + `IncidentRepository.create` duplicate-tolerant **only when the unique incident_id index exists**. In the live DB it does NOT (V2-P0) → two concurrent pipeline instances (multi-worker ingress, or retry races) can both pass `get_by_id is None` and both insert → **duplicate case documents with the same incident_id**. This is the highest-risk concurrency finding.
- **Event-loop note:** single FastAPI worker runs the synchronous pipeline on the event loop; requests serialize on blocking Mongo/pipeline calls. Multi-worker or multi-process deployments introduce the real races above.
- **Rate limiters** (`_RateLimiter`) are in-memory per process → per-subject/per-source budgets silently relax as worker count grows (V2-15, P3, recognized MVP limitation).
- **Partial processing states:** ingress persists events, then the pipeline fails mid-chain → events persisted without detections (or detections without correlations/cases) with only a log line; no marker, no reconciliation job. `PipelineRunOutcome.errors` is produced but the ingress listener only logs it.

---
## NEW CODE / ARCHITECTURE FINDINGS

Each finding follows the audit format: ID · Severity · Category · Owning Layer · File · Class/function · Expected · Actual · Root Cause · Evidence · Reproduction · Impact · Why earlier audits missed it · Recommended fix · Confidence.

### V2-P0 — Live deployment never applies documented schemas/indexes to core collections
- **Severity:** CRITICAL (concurrency/idempotency integrity)
- **Category:** Persistence / Runtime composition / DB contract
- **Owning Layer:** Deployment composition (`scripts/*_server.py`, `app/persistence/*`)
- **Exact file:** `app/incidents/repository.py` (`ensure_schema`/`ensure_indexes` ~212-234), `app/reports/repository.py` (~66+), `app/rules/repository.py` (`RuleRepository` ~279+), `app/sources/repository.py` (~215+); `scripts/proxy_server.py::_build_mongo_backend` (~728-790), `scripts/ingress_server.py::_build_mongo_ingress` (~256-298), `scripts/init_mongo.py` (only security_events).
- **Expected:** Every repository's documented `$jsonSchema` validator + unique-index set exists in the live DB so idempotency and schema defence-in-depth hold.
- **Actual:** Live `proshield` DB (Mongo 8.0.13): `incidents` (3 docs), `reports` (4), `managed_rules` (5), `source_instances` (1) all have `validator=NO` and **only `_id_` index**. `detections`/`correlations` validators+indexes exist only because earlier script/test runs created them; the shipped composition never calls `ensure_schema()`/`ensure_indexes()` for them.
- **Root cause:** `scripts/init_mongo.py` bootstraps only `security_events`. Neither server calls any `ensure_schema`/`ensure_indexes`; repositories merely expose the methods.
- **Evidence:** live DB query above (collections + indexes + validator flags); `init_mongo.py:28-31` imports only `SecurityEventRepository`.
- **Reproduction:** fresh Mongo + `python -m scripts.init_mongo` → `incidents` has no unique index; two overlapping `LivePipeline` runs (or two ingress workers) racing on the same cluster both pass `get_by_id is None` in `create_case_for_correlation` (app/incidents/service.py:305-306) and both insert → duplicate `incident_id` docs.
- **Impact:** The F-2 "no duplicate case ever" guarantee holds only in-process, not in the database. Retries/restarts across workers can silently create duplicate cases with identical ids.
- **Why earlier audit missed it:** V1 focused on composition; the fix proved the chain works, but neither V1 nor the patch report verified the *deployment DB contract* for the new collections.
- **Recommended fix:** Single startup/migration path that calls `ensure_schema()` + `ensure_indexes()` for **all** collections before serving; call from both servers' bundle builders; make failure fatal in `--backend mongo`.
- **Confidence:** CONFIRMED-HIGH (direct live-DB evidence + code inventory).

### V2-01 — Rule lifecycle governance is disconnected from the live detection engine
- **Severity:** HIGH (security detection-degradation)
- **Category:** Rule lifecycle / runtime composition
- **Owning Layer:** Rule management ↔ LivePipeline
- **Exact file:** `scripts/ingress_server.py::_build_ingress_pipeline` (own `RuleRegistry` + `load_rules_from_specs`); `scripts/proxy_server.py::_attach_services` + `_seed_managed_rules`; `app/rules/management/service.py` (reconcile only on analyst plane).
- **Expected:** `rule.disable` / `rule.retire` / operator-created rules are honored by the live detection engine ("registry is the single source of truth for which rules are live").
- **Actual:** The ingress-plane registry is seeded only from `app.rules._library.nginx` at startup. `RuleManagementService.reload_from_repository()` is never invoked on it; no refresh exists. Operator actions in the Rules UI have no effect on live detection; operator-created rules never fire.
- **Root cause:** Two independent in-memory registries per plane, without shared persistence reconciliation in the detection path.
- **Evidence:** `ingress_server.py::_build_ingress_pipeline` code; proxy-side `RuleManagementService` wiring only in `proxy_server.py::_attach_services`.
- **Reproduction:** disable `NGINX-AUTH-FAILURE-001` in the Rules page, send a 401 event → detection still emitted.
- **Impact:** An admin believing she disabled a noisy/dangerous rule is wrong; live detections keep firing (alert fatigue), or a false-positive rule keeps opening cases.
- **Why earlier audits missed it:** V1 verified *operation names* (F-3) but not *live-plane evaluation sourcing*.
- **Recommended fix:** Make the ingress pipeline load managed rules from `managed_rules` via the same reconcile step, plus a periodic/signal-driven refresh; decide explicitly whether library rules can be overridden by managed lifecycle state.
- **Confidence:** CONFIRMED-HIGH (code composition; no cross-plane refresh path exists).

---
### V2-02 — Auto-opened case evidence is frozen at first trigger
- **Severity:** HIGH (analyst workflow integrity)
- **Category:** Case / evidence / correlation-drift
- **Owning Layer:** `app/incidents/service.py`, `app/pipeline/service.py`
- **Exact file:** `app/incidents/service.py::create_case_for_correlation` (305-329 returns existing case unchanged), `app/pipeline/service.py::_open_case_for_correlation` (289-311).
- **Expected:** A growing brute-force cluster should keep accumulating evidence (events/detections/correlations) into the open case, or at least expose a merged view.
- **Actual:** `create_case_for_correlation` returns the existing case unchanged; `case.evidence` keeps only the first batch. New correlations are persisted to `correlations` but never linked into the case.
- **Root cause:** The idempotency design ("reuse existing case") returns before any evidence merge; no update path appends evidence.
- **Evidence:** live DB: 3 incidents but 38 correlations → case documents cannot reference the later correlations; `Incident.to_dict()` evidence shape.
- **Reproduction:** send 10 auth-failure events in one cluster → case shows 1 event; `correlation.list` shows 9+ correlations.
- **Impact:** Case detail timeline/report understates the attack; evidence fusion missing; reports miss most evidence.
- **Why earlier audits missed it:** The patch proved "one case per cluster" idempotency (correct) but never checked *evidence completeness* over the cluster lifetime.
- **Recommended fix:** When the case exists, perform an idempotent evidence-append (insert-new-ids only) + append a lifecycle transition; keep the deterministic case id.
- **Confidence:** CONFIRMED-HIGH (code path + DB counts).

### V2-03 — Case page calls `detection.list`/`correlation.list` with `incident_id` those ops ignore
- **Severity:** MEDIUM-HIGH (frontend wiring, wrong-scope data)
- **Category:** Frontend wiring / API contract
- **Owning Layer:** `frontend/js/components/case.js`, `app/proxy/proxy.py`
- **Exact file:** `case.js:38-54` (`loadDetections`, `loadCorrelations`); `app/proxy/proxy.py::_handle_detection_list` (1502-1518: reads `rule_id`/`event_id`, ignores `incident_id`), `_handle_correlation_list` (1566-1584: reads `pattern_id`/`since`/`until`, ignores `incident_id`).
- **Expected:** Case detail shows only evidence bound to that case.
- **Actual:** `detection.list {incident_id}` → `rule_id=None,event_id=None` → `DetectionReadService.list` returns `[]` (always empty); `correlation.list {incident_id}` → **global recent correlations** (up to 500), displayed as if they belonged to the case.
- **Root cause:** Patching aligned op *names* (F-3) but not *request payloads*; the service returns `[]`/global rows instead of rejecting the unknown param.
- **Evidence:** `case.js` calls; `DetectionReadService.list` `else: return []`; `CorrelationReadService.list` unfiltered find_recent.
- **Reproduction:** open any case → "Correlations" panel shows unrelated global clusters; "Detections" panel empty.
- **Impact:** Analyst sees wrong evidence on the case page (cross-case correlation leakage in the UI) and an empty detections panel; investigation quality suffers.
- **Recommended fix:** `case.js` should call `detection.list_for_incident` / `correlation.list_for_incident` (they exist and are correctly scoped), or the handlers should 400 on unknown `incident_id`.
- **Confidence:** CONFIRMED-HIGH (code + service semantics).

---
### V2-04 — Analyst UI renders fields the backend never emits (decorative tables)
- **Severity:** MEDIUM (visible false data / misleading SOC tool)
- **Category:** Frontend state/rendering vs API contract
- **Owning Layer:** `frontend/js/components/`, backend wire payloads
- **Exact file:** `cases.js` (uses `c.severity`, `c.confidence`, `c.correlation_kind`, `c.source_id`, `c.asset_id`, `c.last_activity_at`, `c.description`); `detections.js` (uses `d.severity`, `d.source_id`, `d.incident_id`, `d.confidence`); `correlations.js` (uses `c.kind`, `c.strategy`, `c.score`, `c.primary_incident_id`, `c.related_incident_ids`); `case.js` (uses `c.severity`, `c.source_id`, `c.asset_id`, `c.confidence`, `c.correlation_kind`). Backend: `Detection.to_dict()` has none of `severity/source_id/incident_id/confidence`; `Correlation.to_dict()` has none of `kind/strategy/score/primary_incident_id/related_incident_ids`; `Incident.to_dict()` has none of `severity/confidence/source_id/asset_id/last_activity_at/description`.
- **Expected:** UI columns are populated from contract fields.
- **Actual:** every listed field is `undefined` → pill/badge shows `—`, `0%`, or "uncorrelated" regardless of real data; severity pills on incidents/correlations always placeholder.
- **Root cause:** Frontend built against a richer Phase 4.0-era model; backend `to_dict()` never emitted those fields; the F-3 patch aligned op names but not render contracts.
- **Evidence:** compare `Detection/Correlation/Incident.to_dict()` (read above) with `*.js` references.
- **Reproduction:** any populated DB → incidents list shows `—` severity and `0%` confidence.
- **Impact:** SOC operators see empty/misleading metrics; dashboards decorative; undermines trust.
- **Why earlier audit missed it:** V1 found 10 dead ops (name-level); the state-shape mismatch remained under the surface.
- **Recommended fix:** extend backend `to_dict()` contracts with the displayed derived fields (severity/confidence computed live), or rewrite the frontend columns to the real contract.
- **Confidence:** CONFIRMED-HIGH (both sides read).

### V2-05 — `case.centralized` from the case page is a no-op (empty evidence)
- **Severity:** MEDIUM-HIGH (feature advertised but inert)
- **Category:** Centralized analysis wiring
- **Owning Layer:** `frontend/js/components/case.js`, backend contract
- **Exact file:** `case.js::runCentralized` (156-176 sends only `{incident_id, reason}`); `app/proxy/proxy.py::_handle_request_centralized` (detections=`body.detections or []`, events=`body.events or []`); `app/incidents/service.py::request_centralized_analysis`.
- **Expected:** Centralized analysis retrieves/applies the case's wider evidence, or the UI assembles the evidence catalogue.
- **Actual:** payload empty → `CorrelationEngine.run` over zero detections → 0 correlations, case flips PENDING→OPEN with a success toast and "0 new correlations".
- **Root cause:** patch wired the operation name but not the evidence supply; the wire op is pull-shaped client-side and the UI has no assembly logic; the service refuses to self-retrieve case evidence.
- **Evidence:** code above.
- **Reproduction:** open any case → click "Centralized analysis" → success toast, 0 new correlations every time.
- **Impact:** documented analyst capability is inert; a misleading "analysis ran" success path.
- **Why earlier audit missed it:** F-4 claimed "verified end-to-end live" — verified the 200 response, not the analytical output (0 new correlations).
- **Recommended fix:** handler defaults to the case's own evidence when the payload is empty, or the UI populates detections/events via `list_for_incident` ops before calling.
- **Confidence:** CONFIRMED-HIGH (code path).

---
### V2-06 — Unmatched (no-enabled-rule) events have zero analyst visibility
- **Severity:** MEDIUM (security-relevant gap; not a spec escalation violation)
- **Category:** Unknown-event model / analyst visibility
- **Owning Layer:** product surface (no `event.*` op; no events page)
- **Exact file:** `app/proxy/proxy.py` (no event op in `ALLOWED_OPERATIONS`); `frontend/` (no events page).
- **Expected (documented):** "make the event available for human review" (`docs/PHASE 0/INITIAL_SECURITY_EVENTS.md` §488-491).
- **Actual:** valid/trusted/persisted/no-match events exist only in `security_events`; no read path, no UI, no classification. `LivePipeline.process` returns early with `detections=()`.
- **Root cause:** MVP shipped the ingestion+detection path but no event-browse surface; unmatched events treated as "ingested only" with no visibility.
- **Evidence:** proxy op list; frontend NAV list; detection boundary tests (no-match → 0 detections).
- **Reproduction:** ingest a `tls_anomaly` (valid source/type, no rule) → invisible everywhere in the UI.
- **Impact:** attacks that fall outside the rule set are invisible to analysts; documented "available for human review" unmet.
- **Why earlier audits missed it:** V1 focused on the composition gap (rules that *matched* never ran); the no-match visibility gap is orthogonal.
- **Recommended fix:** add a read-only `event.list`/`event.get` op (scoped, bounded) + an events page or "recent unmatched events" panel; do NOT auto-escalate (not a documented requirement).
- **Confidence:** CONFIRMED-HIGH (code + docs comparison).

### V2-07 — Correlation window scan is full-collection per detection-bearing event
- **Severity:** MEDIUM (scalability, live-path latency)
- **Category:** Persistence/query design, live pipeline hot path
- **Owning Layer:** `app/persistence/detection_repository.py`, `app/pipeline/service.py`
- **Exact file:** `DetectionRepository.find_recent` (358-418: `find({})` + in-Python `$gte` filter + sort), invoked from `LivePipeline._run_correlation`.
- **Expected:** indexed `det_detected_at_desc` query (`find({"detected_at": {"$gte": cutoff}})`), bounded, no full scan.
- **Actual:** every event that produces a detection pulls the ENTIRE `detections` collection into Python. At 1336 rows that is already wasteful; at production scale it dominates ingest latency.
- **Root cause:** written to be "portable" across FakeDatabase and pymongo; chose the portable worst case.
- **Evidence:** method body; call site in pipeline.
- **Reproduction:** scale detections; observe ingress latency grow linearly with total collection size, not window size.
- **Impact:** live ingest latency grows without bound; the synchronous pipeline blocks the HTTP 200 (see V2-11).
- **Why earlier audits missed it:** component reviews tested correctness, not load; the live fix verified counts, not performance.
- **Recommended fix:** use the indexed range query on MongoDB (sort/limit) and keep the Python fallback only for FakeDatabase; cap the window read.
- **Confidence:** CONFIRMED-HIGH (code path; DB has the index but it is not used).

### V2-08 — Correlation rows proliferate per detection-set; `correlation.list` noisy
- **Severity:** MEDIUM (data semantics/UX, report noise)
- **Category:** Correlation id determinism
- **Owning Layer:** `app/correlation/patterns.py`
- **Exact file:** `BruteForceClusteringPattern._run` (`_build_correlation_id` includes `window_start`, `window_end`, `detection_ids`), lines 350-406.
- **Expected:** one stable correlation id per logical cluster over the window.
- **Actual:** each re-run over a growing window yields a new correlation_id (new detection set / window boundary); the same cluster accumulates many correlation docs and UI rows.
- **Root cause:** correlation id mixes volatile grouping artifacts (exact detection set + window times) with the stable cluster key.
- **Evidence:** live DB 38 correlations vs 3 cases; unfiltered `correlation.list`.
- **Reproduction:** send 10 events over 2 min → 6+ correlation docs.
- **Impact:** correlation listing/counts mislead; reports include near-duplicate correlation evidence; unnecessary dedup pressure on `corr_correlation_id_unique`.
- **Why earlier audits missed it:** the pattern threshold/window correctness was reviewed; *id stability over cluster growth* was not.
- **Recommended fix:** derive correlation_id from the stable cluster signature (`pattern_id + key parts`, like the case id) and update window bounds in place.
- **Confidence:** CONFIRMED-HIGH (code + counts).

---
### V2-09 — SeverityEngine / confidence never composed in the live chain
- **Severity:** MEDIUM-HIGH (missing capability the docs treat as core)
- **Category:** Severity/confidence composition
- **Owning Layer:** `app/severity/`, `app/routing/`, live pipeline
- **Exact file:** `app/severity/engine.py` (class exists; no caller outside its own package), `app/routing/service.py::_derive_severity/_derive_confidence` (heuristic substitute), all of `app/pipeline/`, `app/incidents/`, `app/reports/`.
- **Expected:** the documented severity/confidence engines attach assessments to detections/correlations and feed case priority + reports.
- **Actual:** no live code path calls `SeverityEngine`; `Detection`/`Correlation`/`Incident` carry no severity/confidence; routing uses a hard-coded heuristic; report severity/confidence sections are heuristic/absent.
- **Root cause:** engines were built in Phase 4.6 but never wired into ingestion/detection/case/report composition; the patch closed event→case wiring but not severity wiring.
- **Evidence:** search for `SeverityEngine(` across `app/` found only its own module; wire payloads have no severity fields.
- **Reproduction:** generate a case → severity/confidence everywhere is `None`/`—`.
- **Impact:** no prioritized analyst queue (Overview "Critical / High" KPI is always 0), routing recommendations heuristic-only, reports lack severity/confidence.
- **Why earlier audits missed it:** V1 audited the correlation→case chain; severity was documented as "future slice" in early phases and never re-verified.
- **Recommended fix:** compose `SeverityEngine` in the live pipeline (per detection/correlation + bundle), persist the assessment, expose in `to_dict()`; use it as routing input.
- **Confidence:** CONFIRMED-HIGH (code search + wire shapes).

### V2-10 — Detection persistence failure is silently dropped (no retry / dead-letter)
- **Severity:** HIGH (event/detection loss without observable marker)
- **Category:** Failure propagation / observability
- **Owning Layer:** `app/detection/pipeline.py`, `app/pipeline/service.py`, ingress listener
- **Exact file:** `DetectionPipeline.run` (154-169: non-duplicate `DomainError` on `repo.create` → `_log.warning` + `continue`; detection absent from `persisted_detections`, error not propagated), `LivePipeline.process` (detections empty → returns early, `errors=()`).
- **Expected:** a failed detection write is visible to operations and recoverable.
- **Actual:** transient Mongo error during detection write → unstructured warning log; never retried; HTTP layer still reports the event accepted; pipeline outcome hides the loss (ingress listener logs only counts).
- **Root cause:** the pipeline is designed "total" (never raises) with silent per-row degradation; no dead-letter/outbox exists.
- **Evidence:** `DetectionPipeline.run` body; `LivePipeline.process` early return.
- **Reproduction:** momentarily make `detections` writes fail → events still 200, detections silently missing.
- **Impact:** false-negative detections without operator-visible signal; contradicts `app/pipeline/service.py` docstring "No silent event loss between ingestion and detection".
- **Why earlier audits missed it:** unit tests assert non-raising total behavior; no test asserts observability of partial failure.
- **Recommended fix:** surface stage failures in `PipelineRunOutcome.errors` to the ingress log line, add a failed-detection/outbox collection or a `pipeline_failures` marker for reconciliation.
- **Confidence:** CONFIRMED-HIGH (code read; logic deterministic).

### V2-11 — Synchronous in-request pipeline; source waits on correlation full-scan; no async boundary
- **Severity:** MEDIUM (latency/availability coupling)
- **Category:** Runtime composition / failure propagation
- **Owning Layer:** `scripts/ingress_server.py`
- **Exact file:** `ingress_server.py::_run_live_pipeline_after_ingest` (474-478 synchronous call before HTTP response), `app/pipeline/service.py`.
- **Expected:** documented pipeline suggests ingestion ack then async analysis (or at least a bounded, failure-isolated stage).
- **Actual:** the HTTP 200 to the source waits for full detection→correlation→case including the full-collection `find_recent` scan (V2-07). If Mongo slows or the pipeline raises, the source still gets 200 (exceptions swallowed) but processing is blocked behind the chain; no retry/queue.
- **Root cause:** the F-1 fix chose the simplest synchronous hook; no worker infrastructure exists.
- **Evidence:** listener body; `find_recent` scan; exception-swallow loop.
- **Reproduction:** load test ingress as detections grow → p95 latency correlates with collection size.
- **Impact:** source-side timeouts/retries during peak; blocked event loop within the ingress process.
- **Why earlier audits missed it:** correctness proven at small volumes; no load/availability review.
- **Recommended fix:** respond to the source after event persistence only; move detection→case to a worker with a queue + idempotent consumers (safe: ids are deterministic); keep a backfill/reconcile job.
- **Confidence:** CONFIRMED-MEDIUM (behavior certain; load-impact scale inferential).

---
### V2-12 — `simulator` advertised as a supported connector but has no rule library → live simulator-zero detection
- **Severity:** LOW-MEDIUM (functional inconsistency)
- **Category:** Connector advertising / rule coverage
- **Owning Layer:** `app/sources/registry.py`, rule library
- **Exact file:** `registry.py::SUPPORTED_CONNECTOR_TYPES` ({nginx, simulator}); `app/rules/_library/` (only `nginx` has rules); `app/connectors/simulated.py` (connector exists).
- **Expected:** every advertised connector type has an implementable detection path, or the claim is narrowed again.
- **Actual:** registering+enabling a `simulator` source lets telemetry in and the live pipeline evaluates it against the nginx-only rule catalogue → zero detections, zero cases. The F-6 criterion was "implementation AND rule library", which `simulator` violates.
- **Root cause:** the F-6 fix applied the rule-library criterion to the declared types but kept `simulator` for tooling reasons.
- **Evidence:** `SUPPORTED_CONNECTOR_TYPES`; rule-library inventory; boundary test (simulator events → 0 detections).
- **Reproduction:** register/configure/validate/enable a simulator source; ingest simulator events → nothing downstream.
- **Impact:** a dev source that consumes compute but produces no signal; may mislead an operator into thinking simulator telemetry is analyzed.
- **Why earlier audit missed it:** F-6 measured "advertised types ⊆ implemented connectors", not "advertised types ⊆ rules".
- **Recommended fix:** drop `simulator` from `SUPPORTED_CONNECTOR_TYPES` (or label "dev tool only") or ship a small simulator rule package.
- **Confidence:** CONFIRMED-HIGH (inventory + boundary-test evidence in prior report).

### V2-13 — `check_wiring.py` (repository's own static wiring check) is red on current MAIN
- **Severity:** LOW (maintenance/CI correctness)
- **Category:** Tooling
- **Owning Layer:** `scripts/check_wiring.py`
- **Exact file:** `scripts/check_wiring.py:27` expects `correlations.js` to reference `rule.list`; `frontend/js/components/correlations.js` no longer does (F-3 removed it).
- **Expected:** the repo's own wiring verifier passes on MAIN.
- **Actual:** `python scripts/check_wiring.py` → `WIRING CHECK FAILED — correlations.js: expected op 'rule.list' not present`.
- **Root cause:** F-3 changed the component but not the check's expectations.
- **Evidence:** live run of the script this pass.
- **Reproduction:** run the script.
- **Impact:** a red check any engineer will ignore; undermines the "aligned" claim.
- **Why earlier audit missed it:** the check was written for the pre-F-3 behavior.
- **Recommended fix:** update the check to the current op matrix and wire it into CI.
- **Confidence:** CONFIRMED-HIGH (script output).

### V2-14 — `health.js` probes the non-existent `timeline.list` op
- **Severity:** LOW (health page false-negative)
- **Category:** Frontend wiring / dead op
- **Owning Layer:** `frontend/js/components/health.js`
- **Exact file:** `health.js:37` → `PSAPI.callOrThrow("timeline.list", {limit: 1})`; no such op in `ALLOWED_OPERATIONS` (`timeline.build_for_incident` is the real op).
- **Expected:** every probe is a real op.
- **Actual:** the Health page always shows `timeline.list ERR` even on a fully healthy backend.
- **Root cause:** another op-name alignment miss (F-3 fixed `case.js`/`rules.js` but not `health.js`).
- **Evidence:** `health.js` vs `app/proxy/proxy.py` op constants.
- **Reproduction:** open `/static/health.html` → timeline.list row ERR.
- **Impact:** operator sees a spurious failure; health page loses credibility.
- **Recommended fix:** change the probe to `timeline.build_for_incident` (with a valid incident_id) or drop it.
- **Confidence:** CONFIRMED-HIGH (both sides read).

### V2-15 — Rate limiters are per-process in-memory; multi-worker deployments silently relax budgets
- **Severity:** LOW-MEDIUM (documented MVP limitation; security-relevant at scale)
- **Category:** Concurrency / abuse protection
- **Owning Layer:** `app/proxy/proxy.py::_RateLimiter`, `app/sources/ingress.py` rate limiter
- **Exact file:** `proxy.py::_RateLimiter` (in-memory dict, no shared store); ingress sliding window (in-memory per process).
- **Expected:** per-subject/per-source budget holds across the fleet.
- **Actual:** with N uvicorn workers, each worker has its own budget → effective limits ×N.
- **Root cause:** MVP in-memory choice; no Redis/external store.
- **Evidence:** code.
- **Reproduction:** run 4 ingress workers, send 4× burst → each 429 threshold is per-process.
- **Impact:** abuse protection weaker than documented under multi-worker production.
- **Why earlier audits missed it:** single-process test/dev runs dominate.
- **Recommended fix:** shared counter (Mongo atomic ops or Redis) when scaling workers; document the single-worker contract otherwise.
- **Confidence:** CONFIRMED-HIGH (code); impact scale inferential.

---
## PREVIOUS FINDINGS — FINAL STATUS

| V1 / patch finding | Status | V2 evidence |
|---|---|---|
| F-1 — No live detection pipeline composition | **RESOLVED (PARTIAL)** | composition exists and runs (DB counts prove it); limitations V2-01 (rule governance), V2-07 (full scan), V2-10 (silent detection loss), V2-11 (synchronous) |
| F-2 — No live case-creation mechanism | **RESOLVED (PARTIAL)** | `create_case_for_correlation` deterministic; risks V2-P0 (missing unique index → race), V2-02 (evidence frozen) |
| F-3 — 10 dead frontend ops | **PARTIAL** | op names aligned (`timeline.build_for_incident`, `rule.retire`, unfiltered `correlation.list`); new dead/wrong calls remain: V2-03, V2-14, V2-13 |
| F-4 — Centralized analysis + reports un-wired | **PARTIAL** | reports genuinely work (4 docs); centralized analysis from UI is a no-op (V2-05) |
| F-5 — Pydantic errors became 401 | **RESOLVED** | 400 `source_configuration_error` verified |
| F-6 — 6 connector types, only 2 implemented | **PARTIAL** | advertised set nginx+simulator; simulator has no rule library (V2-12) |
| F-7 — Unexpected exceptions became 401 | **RESOLVED** | `ProxyInternalError` 500 verified |
| N-1 — `[object HTMLTableRowElement]` | **RESOLVED** | `layout.js::el()` recursive flatten verified |
| N-2 — `source.validate` label | **RESOLVED** | relabelled "Validate" |

## FALSE-POSITIVE CHALLENGE

Counter-evidence actively sought for the serious findings:

- **V2-P0 (missing indexes/validators):** re-queried collections live — `incidents/reports/managed_rules/source_instances` show `_id_` only + `validator=NO`; `init_mongo.py` imports only `SecurityEventRepository`; neither server calls `ensure_schema()`. No counter-evidence. **Stands.**
- **V2-01 (rule lifecycle not applied live):** all `reload_from_repository` call sites are analyst-plane only; ingress registry built purely from `app.rules._library.nginx`. No counter-evidence. **Stands.**
- **V2-03 (incident_id ignored):** handlers read only documented fields; services return `[]`/global rows; `loadDetections`/`loadCorrelations` are called from `render()`. **Stands.**
- **V2-04 (decorative fields):** `Incident/Detection/Correlation.to_dict()` emit none of the displayed fields. **Stands.**
- **V2-05 (centralized no-op):** handler reads only `body.detections`/`body.events`. **Stands.**
- **V2-08 (correlation proliferation):** only one pattern exists; growth is per-cluster-set. **Stands.**
- **Composition really works:** the inverse check confirms V1's "0 detections live" is now superseded — DB counts show the chain produced rows. **Not a false positive.**
- **V2-02 (evidence frozen):** no client-side merge exists; page renders `case.evidence` only. **Stands.**

## REMAINING UNCERTAINTIES

- **Concurrency at scale** is reasoned, not stress-tested: the V2-P0 duplicate-case race is deterministic-in-code but was not reproduced by concurrent load; the missing unique index itself is CONFIRMED-HIGH.
- A **fresh deployment** (not this machine's accumulated DB) reproducing the exact gaps is certain by code, but I did not wipe a live DB to prove it.
- Whether operators will actually use `rule.disable/retire` (making V2-01 operational) is a workflow assumption; the code disconnection is certain.
- Multi-worker deployment config is not covered by any shipped script/README; behavior under it (rate limits, races) is inferential.
- The frontend *visual* truth of V2-04/V2-05 will be formally confirmed by Prompt 2's browser pass; code-level items are certain.

---
## CODE / END-TO-END EVIDENCE MATRIX

| Causal path | Component files | Live-proven (this pass) | Blocking issue |
|---|---|---|---|
| external event → trust (HMAC token) | `app/sources/trust.py`, `app/sources/ingress.py` | yes (live DB + patch-report evidence) | — |
| replay protection (single-use) | `app/sources/replay_store.py` | yes (Mongo unique token_id + TTL; verified in DB) | — |
| canonical event → persistence | `app/ingestion/service.py`, `app/persistence/security_event_repository.py` | yes (1075 events) | — |
| detection | `app/detection/engine.py`, `app/rules/_library/nginx/*` | yes (1336 detections) | V2-01 (rule governance), V2-10 (silent loss) |
| correlation | `app/correlation/engine.py`, `app/correlation/patterns.py`, `app/pipeline/service.py` | yes (38 correlations) | V2-07 (full scan), V2-08 (proliferation) |
| case | `app/incidents/service.py`, `app/incidents/repository.py` | yes (3 cases) | V2-P0 (no unique index), V2-02 (evidence frozen) |
| timeline | `app/timeline/` | yes (op exists) | V2-02 (scope limited to first evidence) |
| routing | `app/routing/service.py` | recommendation-only | no frontend surface (documented OK) |
| centralized analysis | `app/incidents/service.py`, `app/proxy/proxy.py` | op exists; UI no-op | V2-05 |
| reports | `app/reports/service.py` | yes (4 report docs) | V2-09 (severity/confidence heuristic) |
| frontend → SecureProxy → service → repo | `frontend/js/services/api.js`, `app/proxy/proxy.py`, repos | yes (ops live) | V2-03, V2-04, V2-14 mismatches |

## FINAL CODE / END-TO-END JUDGMENT

- **Correct:** engines and repositories are internally coherent and match their docs.
- **Connected:** the previously-missing live chain (event→case) is now connected and runs against Mongo.
- **Secure:** ingress/auth/RBAC boundaries, replay, rate limiting, safe errors, and IDOR→404 are sound at the current level.
- **Coherent:** *not fully* — rule management vs live detection, analyst UI claims vs backend contract, and case evidence vs correlation growth disagree.
- **Extensible:** architecture is clean enough to extend; the two-plane split isolates concerns.
- **Idempotent:** by construction at rest, but **not at the DB boundary** for cases (V2-P0) and not evidence-complete over cluster lifetime (V2-02).
- **Observable:** partial — structured logs exist; pipeline-stage failures are under-logged (V2-10), no event browse exists (V2-06).
- **Recoverable:** restart-safe for events/detections/correlations *if* indexes exist; rule-plane state and failed pipeline stages are not recoverable (V2-01, V2-10).
- **Testable:** yes — unit+integration suites green (1190 + 86).

> **VERDICT: NOT READY — IMPORTANT GAPS.**

The shipped product can now detect, correlate, and open cases from live external telemetry — a real step from V1. It is not yet production-ready because the DB contract that makes that output trustworthy (validators/unique indexes), the rule-lifecycle link that makes detection governable (managed rules), and the analyst-facing truth (scoped case evidence, real severity, honest centralized analysis, event visibility) are missing or contradictory.

---
## ROUND-2 VISUAL / HUMAN-OPERATOR REVALIDATION

**DATE:** 2026-09-05 (second pass)
**PASS:** V2–R2 (live human-operator / browser / Playwright / external-source / end-to-end)
**Scope note:** This round is the dedicated human-operator pass (Prompt 2). Prompt 1's code/architecture findings are preserved above; this section adds live browser/runtime/external-source proof and reconciles all three reports plus the running product.

### Real product run (fresh dedicated audit database)
- Analyst plane: `python -m scripts.proxy_server --backend mongo --port 8000 --seed-credentials`
- Ingress plane: `python -m scripts.ingress_server --backend mongo --port 8089`
- **Database:** fresh `proshield_strix_v2_audit` (Mongo 8.0.13), dedicated to this audit so no historical data could contaminate evidence.
- Both servers confirmed `backend_kind=mongo`; startup logs verified.
- Both planes were launched initially with **no `PROSHIELD_SOURCE_SIGNING_KEY`** (the README's default deployment shape). Both silently generated their **own ephemeral source keys**, and every issued source token was rejected by the ingress with `source identity token signature mismatch`. Restarting both planes with one shared `PROSHIELD_SOURCE_SIGNING_KEY` fixed the topology. **This is a real deployment foot-gun:** nothing validates at startup that the two planes share the key; a split-key deployment produces 401s with no config error anywhere.
- Baseline: 5 managed rules, 0 sources, 0 events, 0 detections, 0 correlations, 0 incidents, 0 replay records.

### PLAYWRIGHT STATUS
- Chromium via Playwright MCP against the real product on `http://localhost:8000`. Every workflow below was driven through the actual UI; network, DOM, console, and response bodies were captured at each step.

### THREE-REPORT RECONCILIATION
| Stage | V1 report | Patch report claim | V2 (Prompt 1) code finding | LIVE browser/runtime result (this pass) |
|---|---|---|---|---|
| Live detection pipeline | "not composed" | fixed | composition exists | **CONFIRMED LIVE**: 5 aligned 401 events → 18 detections → 2 correlations → 1 auto-case |
| Auto case | "no case mechanism" | fixed, idempotent | exists; DB index gap (V2-P0) | **CONFIRMED LIVE** (1 case opened) but **duplicate event rows prove the idempotency gap** (V2-P0) |
| Rule disable | untested | "wired" | ingress registry disconnected (V2-01) | **CONFIRMED LIVE**: rule disabled in UI + `managed_rules.enabled=false`, yet the live pipeline still fired it on a fresh 401 |
| Case evidence | untested | "one case per cluster" | frozen at trigger (V2-02) | **CONFIRMED LIVE**: case evidence has 1 event/2 detections vs 4–5 events/10 detections in the cluster; timeline reports `events_available=1/4, detections_available=2/8` |
| Case page data | 10 dead ops (F-3) | aligned op names | `incident_id` ignored (V2-03) | **CONFIRMED LIVE**: `detection.list {incident_id}` → `[]`; `correlation.list {incident_id}` → global rows mislabeled as this case's |
| Centralized analysis | untested | "wired" | empty-payload no-op (V2-05) | **CONFIRMED LIVE**: `case.centralized` returned `centralized produced 0 new correlations`; `new_correlation_ids: []` |
| Reports | untested | "wired" | works but evidence-thin | **CONFIRMED LIVE**: report generated, but `what_was_detected/sources/detections/specialized_correlation` sections all EMPTY |
| Source/connector model | untested | nginx+simulator | Model A (connector→source instance) | **CONFIRMED LIVE**: UI creates a source instance with independent `source_instance_id` |

---
### BROWSER WORKFLOWS TESTED
Login → Overview → Sources (Add/Register/Configure/Validate/Enable/Edit/Disable) → Rules (view/Disable/Enable) → Cases (open case, Generate report, Centralized analysis, Export JSON) → Detections → Correlations → Health.

### HUMAN-OPERATOR ACTION LOG
1. Signed in as `admin/admin-dev-credential` (login page, redirect to Overview). Overview showed correct fresh-DB zeros and "Active Rules 5".
2. Sources → **+ Add Source**. Register dialog asks: **Connector Type** (nginx/simulator), Display Name, Description, Tags. Submitted `SOC-TEST-NGINX-01`.
3. Source row appeared: `src-01a0728c-a5b6-73a4-81fb-fbd845a8a508-soc-test-nginx-01`, status `registered`; configure dialog auto-opened. Set endpoint `https://nginx-prod-01.example.internal:8443`, destination `soc-triage`.
4. **Validate** clicked. State → `validated` with `health.status="ok"`, **even though the endpoint is a non-resolvable fake host** → Validate is configuration-only, NOT a connectivity test. The UI label "Validate" (N-2 patch) still does not perform any network probe.
5. **Enable** clicked → `enabled`.
6. Registered a second source `SOC-TEST-SOURCE-02` (id `src-01a0728f-8e54-7c29-a28e-8ec320634f1d-soc-test-source-02`) → `configured` (independent identity).
7. Restarted both servers (shared source key). **F-6 durability confirmed**: both sources survived with their states intact.
8. Rules → selected `NGINX-AUTH-FAILURE-001` → detail panel shows **Disable** / **Revoke** buttons; also renders `Confidence: undefined%` and `Definition: {}` (render gaps).
9. Clicked **Disable** → UI badge `Enabled: no`. Sent a fresh 401 → **detection still fired** (V2-01 live).
10. Re-enabled the rule.
11. Disabled source (409 state guard observed), re-pointed its endpoint to `/login` (matching the wire events, as the shipped integration test does), validated, enabled.
12. Sent a 5× 401 aligned batch from the external-like endpoint → full chain fired (detection → correlation → case).
13. Opened the case in the UI → detail page (findings below). Generated a report; ran centralized analysis.
14. Detections/Correlations/Health pages inspected.

### CONNECTOR / SOURCE CREATION RESULTS
- **WHAT THE UI SAYS IS BEING CREATED:** "Register new source" with a "Connector Type" dropdown. An operator believes she is creating an external source instance of a connector family.
- **WHAT THE API ACTUALLY CREATES:** `source.register {source_type, display_name,...}` → a `SourceInstance` row with deterministic `source_instance_id`; no separate connector/sub-connector document.
- **WHAT MONGODB STORES:** one doc in `source_instances` with `source_instance_id`, `source_type=nginx`, tags, config endpoint, state machine fields.
- **WHAT THE RUNTIME USES:** the `SourceRepository.get(sid)` row is the authoritative resolver for both token verification (ingress) and source.list (proxy).
- **DO THESE AGREE? YES.** The product implements **MODEL A (Connector → Source Instance)**, and the UI/API/persistence/runtime all agree. No sub-connector exists and none is required by the spec or code paths exercised.

### MULTIPLE CONNECTOR RESULTS
- **Connector-family creation is not available in the current implementation.** The only "connector" choice is the single `source_type` dropdown (nginx/simulator). There is no connector-registration UI, no connector family document, no sub-connector. This matches Model A and does not contradict documentation.

### MULTIPLE SOURCE RESULTS
- Two nginx source instances created via the UI with **independent `source_instance_id` values**, independent configurations, independent tokens, and independent states (`enabled` vs `configured`). Both survived a full process restart. Source identity and state isolation are correct at the instance level.

---
### REAL EXTERNAL TEST SOURCE
- Created `_audit_external_source.py`: a real network HTTP endpoint on `127.0.0.1:9091` ("SOC-TEST-NGINX-01 external-like nginx telemetry endpoint"), which sends real HTTP/JSON `source.ingest` requests (with the real HMAC token) to the real ingress at `:8089`, and records every inbound request. It is test infrastructure only; it is not a product connector.

### EXTERNAL SOURCE MAPPING
- The external endpoint's token was issued for source A only; verification against `SourceRepository.get(sid)` succeeded; events were attributed to `source_instance_id=src-01a0728c-…` and `provenance.source_instance_id` was stamped on every persisted canonical event. **Mapping works.**

### RULE-PRESENT POSITIVE DETECTION
- After aligning the registered endpoint with the wire endpoint (the ST-04 precondition the shipped integration test itself uses), a 5× 401 batch produced the full pipeline live:
  - 5 accepted events → 10 detections (NGINX-AUTH-FAILURE-001 + NGINX-AUTH-BRUTEFORCE-001 per event) → 2 correlations → **1 auto-opened case** (`case-04861cab-9581-746c-9d55-4f1618921011`, state `open`, created by `internal_service`).
- Correlation key `['203.0.113.42','/login']`, threshold 4 within 300 s — matches `BruteForceClusteringPattern` defaults.

### RULE-ABSENT / UNKNOWN-EVENT TEST
- Sent a **valid, authenticated, persisted** `tls_anomaly` nginx event (no rule anywhere matches it).
  - Accepted (200), persisted, **0 detections, 0 correlations, 0 cases**.
  - **No event-classification, severity, priority, or analyst-visible artifact of any kind.** The event is only reachable by raw DB query; no `event.*` read op exists in `ALLOWED_OPERATIONS`, and no events page exists in the frontend.
- Sent a benign `authentication_success` nginx event (no rule) → accepted, persisted, 0 detections (correct false-positive boundary).

### UNKNOWN-EVENT SEVERITY / ESCALATION
- **DOCUMENTED BEHAVIOR:** the spec does not require auto-escalation of unmatched events to high/critical; it requires the event to remain present/queryable (documented as "visible in the event store").
- **ACTUAL BEHAVIOR:** the event is queryable only in Mongo; there is no analyst-facing visibility path, no severity, no priority, no dashboard/queue entry. The "visible in the event store" requirement is not met from the analyst's perspective.
- **OPTIONAL SECURITY RECOMMENDATION (not a defect):** add a read-only event browser / "recent unmatched events" panel; do not auto-escalate.

### NO-RULE INVESTIGABILITY
- **Not investigable from the UI.** No events page, no global search over events, no timeline entry, no centralized-analysis reach-in. The event cannot be found by an analyst using the product UI.

### FALSE-POSITIVE TEST
- Benign `authentication_success` (close boundary) → accepted + persisted, **no detection/correlation/case**. Correct.

### FALSE-NEGATIVE TEST
- With **misaligned** source config (registered endpoint ≢ wire endpoint) the same attack burst produced per-event detections, then **0 correlations** because ST-04 nulls the canonical `source_ip` (recorded as `details._untrusted_source_ip`), and the correlation pattern's `select()` requires `source_ip` and `endpoint` on the canonical event. **The realistic external telemetry shape (config endpoint ≠ wire path) is a systematic false-negative path** for the brute-force correlation. This is confirmed live (12 events + 6 detections in the first misaligned batch produced 0 correlations until endpoint alignment).

---
### RULE DISABLE / RETIRE TEST
- **Disable:** UI + `managed_rules.enabled=false` persisted. Fresh 401 still produced a live `NGINX-AUTH-FAILURE-001` detection. **Confirmed: the live detection engine does not read managed rule state** (V2-01). Disable is cosmetic.
- Retire: not separately executed; same code path as disable (`rule.retire` writes managed_rules only) → same live-pipeline disconnection.

### CORRELATION TEST
- Threshold semantics: at threshold-4 with 4 distinct events a correlation fired; 5 distinct events produced a second overlapping correlation row. **V2-08 confirmed live**: the same cluster produced 2 correlation docs differing only by window/detection-set (id includes `window_start/window_end/detection_ids`).
- Source isolation: single-source test confirmed. Only source A's events entered A's detections; no contamination to source B (B received nothing).

### CASE TEST
- Auto case creation confirmed live (internal_service actor, state open). Case summary derives from correlation reasoning. Re-issue of a duplicate event (same event_id as an already-ingested event) was **accepted again** (200) and created an additional detection — rest-level idempotency does not hold (V2-P0).

### TIMELINE / EVIDENCE TEST
- `timeline.build_for_incident` returned 4 rich items (event, correlation, 2 detections) but the **frontend reads `d.timeline.items`/`d.events` while the API returns `items` at the top of `data`**, so the case page always renders "Timeline — 0 events / No timeline events yet" (`case.js:33`).
- The timeline engine's own reasoning string literally reports `detections_available=2/8; events_available=1/4` → **evidence truncation is a backend reality, not only a UI bug** (V2-02).

### ROUTING TEST
- Routing is **recommendation-only** (no transport/queue). No dispatch occurs. This matches documented behavior; nothing to dispatch to in the MVP.

### CENTRALIZED ANALYSIS TEST
- UI click sent `case.centralized {incident_id, reason}` (no evidence). Response: `centralized produced 0 new correlations; 0 not already in case`, `new_correlation_ids: []`, lifecycle recorded `centralized_pending → open`. **No-op confirmed live** (V2-05).

### REPORT / EXPORT TEST
- **Generate report** produced `rpt-01a072a7-47c4-7cbb-8ad6-ad8ccd6391c0` with sections `what_was_detected: []`, `sources: []`, `detections: []`, `specialized_correlation: []`, only `rule_references` + `investigation_metadata` populated. **The report is practically empty of security content** because it is derived from the case's truncated evidence (V2-02 cascade).
- Export JSON works (re-serialization).

### SECUREPROXY / API FAILURE TESTING
- Verified directly (API) against the running proxy:
  - No session → `401 authentication_required`.
  - Unknown op → `400 validation_error`.
  - Collector on `case.list` / `rule.create` → `403 forbidden`.
  - Source config on an enabled source → `409 source_instance_state_error` (truthful state guard, but the UI lets you attempt it).
  - Ingress: missing token → `401 source_identity_token_error`; malformed token → 401; unknown ingress op → `400 unknown_operation`.
- **Since these HTTP codes are truthful at the transport layer, but the frontend API client reports every `{"error":...}` response as `ok:true`, none of these failures surface in the UI.** (See NEW finding V2-16.)

---
### BROWSER / DOM / CONSOLE RESULTS
- Overview, Sources, Rules, Cases, Case detail, Detections, Correlations, Health pages all load (only favicon 404 noise).
- console errors observed only when performing invalid/error operations (400s from my probes) — i.e., the browser logs real failures even where the UI reports success.
- Case detail DOM shows: `Source: undefined · —`, empty severity pill, `uncorrelated` badge on a correlation-opened case, `Confidence: 0%`, `Detections: 0`, `Correlations: 0` (header count) while the panel below shows "Correlations (2)" — two different counts on the same page.
- Detections page: Severity pill shows the rule **category** (`source specific`), Source column shows the **event_id**, Confidence/Incident/Asset `—`.
- Rules detail: `Confidence: undefined%`, `Definition: {}`.

### NETWORK RESULTS
- All UI actions are `POST /api/proxy`; session token via `X-ProShield-Session`.
- `source.register`, `source.configure`, `source.validate`, `source.enable`, `rule.disable`, `rule.enable`, `case.get`, `timeline.build_for_incident`, `detection.list {incident_id}`, `correlation.list {incident_id}`, `case.centralized`, `report.generate_normal`, `source.issue_token` all captured with bodies/responses.
- `detection.list {incident_id}` → `{"detections": []}`; `correlation.list {incident_id}` → unfiltered global list.

### BACKEND / MONGODB CORRELATION
- All IDs trace: external event UUIDv7 → canonical `event_id` (same) → `detection_id` (det-prefixed, deterministic) → `correlation_id` (corr-prefixed) → `incident_id` (case-prefixed). Provenance carries `source_instance_id`; detection event references carry the canonical event_id and rule_id/version.
- Final audit-DB state: 30 event rows (only 12 unique event_ids — duplicates from double-persist + replay test), 18 detections, 2 correlations, 1 incident, 1 report, 7 replay token claims, 5 managed rules, 2 source instances.
- Replay protection live-proven: reuse of a consumed token → `source identity token replay rejected` (401); 7 token claims stored.

### NEW VISUAL/RUNTIME FINDINGS
- **V2-16 (NEW, HIGH): `PSAPI.call` reports every SecureProxy error as success.** `frontend/js/services/api.js:67` computes `ok: parsed.ok !== false`; the proxy error envelope is `{"error":{...}}` (no `ok:false`) → HTTP 400/401/403/409/500 are all surfaced to pages as `ok:true`. `callOrThrow` therefore never throws for backend errors; pages render empty/silent or false-success toasts. Empirically captured in the running browser: `PSAPI.call("totally.bogus")` → `{ok:true, status:400, error:{...}}`.
- **V2-17 (NEW, MEDIUM): Health page shows a false-green `timeline.list OK`** (the op does not exist; backend 400s; the client swallows it). This *refutes the exact symptom* claimed in V2-14 (ERR row) while *confirming the underlying dead-op* — the visible truth is worse (false healthy).
- **V2-18 (NEW, MEDIUM): Case timeline always renders empty** — `case.js:33` reads `d.timeline.items`/`d.events`, but `timeline.build_for_incident` returns `{items:[...]}` directly under `data`; plus an orphaned dead-code expression on `case.js:34`.
- **V2-19 (NEW, MEDIUM): Realistic external telemetry (config endpoint ≠ wire path) yields systematic false-negative correlation** (ST-04 nulls source_ip). The shipped integration test only passes by registering the source with the exact wire endpoint.
- **V2-20 (NEW, LOW): Rule/UI renders undefined values** — `Confidence: undefined%` on rules page; `Source: undefined · —` and conflicting `Detections: 0`/`Correlations 0` vs panel counts on the case page.
- **V2-21 (NEW, LOW): No startup cross-plane key consistency check** — with no `PROSHIELD_SOURCE_SIGNING_KEY`, both planes generate ephemeral keys and every token 401s; no error surfaces besides per-request 401s.
- **V2-22 (NEW, LOW): The 409 source-state guard is truthful but unguided** — the UI offers Edit on enabled sources and reports no explanation; the operator must discover Disable→Edit→Validate→Enable.
- **V2-23 (Observation): Double event persistence confirmed live** — each accepted event produced exactly two `ingest.persisted` log lines and two DB rows (ingress insert + DetectionPipeline re-ingest insert), blocked only if a unique `event_id` index existed (it does not on a fresh deploy).

---
### V2 FINDINGS — VISUAL CONFIRMATION
| V2 finding | Beam | Live visual result |
|---|---|---|
| V2-P0 (missing indexes) | CONFIRMED | 18 rows for 12 unique event_ids; duplicate event re-accepted; 2x ingest.persisted per event |
| V2-01 (rule lifecycle disconnection) | CONFIRMED | disabled rule still fires live |
| V2-02 (case evidence frozen) | CONFIRMED | case evidence 1 event/2 dets vs 4–5/10 in cluster; timeline `events_available=1/4`; report sections empty |
| V2-03 (incident_id ignored) | CONFIRMED | detection.list→[]; correlation.list→global rows |
| V2-04 (decorative fields) | CONFIRMED | undefined/null severity/confidence/source/asset pills + wrong column mapping on detections page |
| V2-05 (centralized no-op) | CONFIRMED | 0 new correlations, empty payload |
| V2-06 (no unmatched-event visibility) | CONFIRMED | tls_anomaly persisted; no event op/page; nothing analyst-reachable |
| V2-08 (correlation id proliferation) | CONFIRMED | 2 correlations for same cluster, differing only by window/detections |
| V2-14 (health probes timeline.list) | PARTIALLY REFUTED | the op is dead as stated, but the page shows false OK (V2-17), not ERR |

### FALSE-POSITIVE CHALLENGE
Active counter-evidence sought for each new/live finding:
- **V2-16 (error swallowed):** proved by directly evaluating `PSAPI.call` in the live browser — 400 returned `ok:true`. Not an inference.
- **V2-01 (rule disable ignored):** confirmed `managed_rules.enabled=false` in Mongo AND a fresh detection in Mongo after re-sending the attack. Not an inference.
- **V2-02 (evidence frozen):** counts from Mongo (case evidence vs cluster detection sets) plus the timeline's own `events_available=1/4` string. Not an inference.
- **V2-P0 (no unique index):** `security_events.index_information()` on the live DB shows only `_id_`. Not an inference.
- **ST-04 false-negative correlation:** proven by re-running the same burst before/after endpoint alignment (0 vs 2 correlations). Not an inference.
- Could the case page have rendered detections if the DB schema differed? No — the `detection.list` op ignores `incident_id` at the handler and returned `[]` on the wire regardless.
- Could "Validate" actually perform connectivity? The endpoint used was a non-resolvable internal host and still produced `health.status="ok"` — the only correct conclusion is configuration-only.

---
### CLEANUP RESULTS
- **TEMPORARY FILES CREATED:** `_audit_external_source.py`, `_audit_issue_token.py`, `_audit_push_events.py`, `_audit_secureproxy_tests.py`, `_audit_token.txt`, `_audit_external_requests.jsonl`, `_audit_proxy.log`, `_audit_proxy_err.log`, `_audit_ingress.log`, `_audit_ingress_err.log`, `_audit_external.log`, `_audit_external_err.log`, Playwright screenshots (`v2-01-overview-initial.png`, `v2-02-sources-empty.png`, `v2-health-page.png`).
- **KEPT (reusable regression harness):** `_audit_external_source.py`, `_audit_issue_token.py`, `_audit_push_events.py`, `_audit_secureproxy_tests.py`.
- **DELETED:** none beyond the transient files listed for deletion above are removed at this time; the harness files are retained for regression reuse. Log files and the transient token are regenerable.
- **NEVER deleted:** any product code, existing tests, existing documentation, `managed_rules`/`source_instances`/report docs, or pre-existing project assets. The dedicated `proshield_strix_v2_audit` DB is left as evidence and is clearly named as audit data.

### REMAINING UNCERTAINTIES
- Retire (vs disable) was not separately clicked in the UI; its effect is identical to disable at the managed-rule layer and is covered by V2-01.
- A two-worker ingress concurrency race was not stress-tested (single-process run); the missing-index duplicate risk is proven at rest, its concurrent manifestation is inferred.
- HTTPS/secret-store paths were not exercised (documented as not configured).
- The `simulator` connector was not registered (not required to prove the nginx path); its lack of rules was covered in Prompt 1's V2-12.
- The transient harness files and audit database remain in the workspace for reproducibility; the final cleanup decision is left to the repository owner per the audit rules (do not delete anything uncertain).

### FINAL V2 HUMAN-OPERATOR EVIDENCE MATRIX
| Stage | Expected | Actual | Browser | DOM | Network | SecureProxy | Backend | Mongo | Status |
|---|---|---|---|---|---|---|---|---|---|
| connector | create connector family | only source_type choice | sources dialog | 2 options | source.list_types | OK | source registry | 2 instances | PARTIAL (family not a real object; Model A OK) |
| source | independent instance | independent sid+state | ✔ | ✔ | source.register/configure | 200 | SourceRepository | 2 docs | PROVEN |
| external mapping | endpoint/token → instance | token verified vs repo | n/a (API) | n/a | HMAC header | 200/401 | verifier | provenance stamped | PROVEN |
| trust | valid token accepted | accepted | n/a | n/a | 200 | source_identity_token_error on bad | replay store | 7 claims | PROVEN |
| ingress | events accepted | accepted (double row) | n/a | n/a | 200 | 400/401 boundary | ingest.persisted×2 | 30 rows/12 unique | PROVEN (duplication bug) |
| canonical event | source_ip/endpoint preserved | ST-04 nulls on mismatch | n/a | n/a | wire body | reconciliation | details._untrusted_* | stored | PROVEN |
| detection | rule fires | fires when rules enabled | ✔ | detections page | detection.list | 200 | DetectionEngine | 18 detections | PROVEN |
| unknown/unmatched | analyst-visible | persisted only | no events page | n/a | no op | n/a | n/a | row only | BLOCKED (V2-06) |
| correlation | cluster created | created only on aligned events | ✔ | case page correlations | correlation.list | 200 | BruteForceClustering | 2 correlations | PROVEN (false-negative path noted) |
| case | auto-opened idempotent | 1 case, evidence-thin | ✔ | case detail | case.get | 200 | IncidentService | 1 incident | PROVEN (V2-02/P0 gaps) |
| timeline | case timeline shows chain | renders empty | ✗ | "0 events" | build_for_incident returns 4 items | 200 | TimelineEngine | n/a | BLOCKED (V2-18) |
| routing | recommendation | recommendation only | n/a | no route UI | routing.compute (backend) | — | — | — | PROVEN (documented) |
| centralized analysis | adds evidence | empty no-op | ✗ | 0 new correlations toast | case.centralized | 200 | IncidentService | no new rows | BLOCKED (V2-05) |
| report | evidence-rich report | empty sections | ✔ | report JSON pane | report.generate_normal | 200 | ReportService | 1 report | PROVEN (content gap V2-02) |
| analyst UI | truthful pillars | placeholder/mislabeled | ✔ | wrong pills/columns | 200 | — | — | — | PARTIAL (V2-04/16/17) |
| unknown severity/escalation | none required | none present | ✗ | no artifact | no op | — | — | row only | PROVEN-matches-docs (visibility gap) |

---
### FINAL END-TO-END PROOF
**DEMO 1 — positive chain (fully aligned source config):**
`external endpoint 127.0.0.1:9091 → HMAC token → ingress :8089 → canonical event (source_ip 203.0.113.42, endpoint /login) → NGINX-AUTH-FAILURE-001/NGINX-AUTH-BRUTEFORCE-001 detections → BruteForceClusteringPattern (threshold 4/300s) → correlation ×2 → auto-case case-04861cab… (open) → timeline engine (partial: only 1/4 events available) → routing (recommendation only) → centralized analysis (empty no-op) → report (empty evidence sections) → analyst UI (case listed, detail mostly placeholder).`
Marked: **PROVEN** external→trust→ingress→canonical→detection→correlation→case; **PARTIAL** timeline (evidence-thin) / centralized (no-op) / report (empty content) / analyst UI (placeholder fields).

**DEMO 2 — valid event with no matching rule:**
`external endpoint → valid tls_anomaly nginx event → trusted → persisted (accepted 200) → rule evaluation (NO applicable rule) → 0 detections → 0 correlations → 0 cases → OBSERVED: no severity, no priority, no analyst visibility, no investigation path, no timeline, no reportability — event reachable only via raw Mongo query.`
Marked: **PROVEN** (accept+persist+no-match), **MISSING** (analyst visibility, investigation, reporting).

---

### FINAL VERDICT

> **NOT READY — IMPORTANT GAPS.**

The V1/Patch fixes are real and the product now demonstrably performs live detection → correlation → automatic case creation from genuine external HTTP telemetry against real MongoDB. However, the human-operator pass proved that the analyst-facing product contradicts the backend in the analyst's most important workflows: disabling a rule does not stop live detection; the case page shows wrong data (global correlations misattributed, empty detections/timeline); centralized analysis is a no-op; generated reports contain no detections/sources; severity/confidence/source/asset are placeholders everywhere; unknown events are invisible; the frontend API layer silently swallows every backend error (400/401/403/409/500 reported as success); and the missing unique indexes at rest create duplicate event rows and unguarded race conditions. Any SOC operator depending on the current UI for triage, rule control, or reporting would be misled.

---
## V2 PATCH IMPLEMENTATION / REVALIDATION

**DATE:** 2026-09-06
**PASS:** V2 patch implementation + full regression + live E2E revalidation
**MODEL ROLE:** Principal Security Architect / Backend + Frontend + Distributed Systems / Database / Adversarial QA
**VERIFICATION DB:** `proshield_v2_patch_verify` (fresh, Mongo 8.0.13); test DBs `proshield_test_v2_patch`, `proshield_test_strix_wire`
**METHOD:** every fix verified at the owning layer, then regression-tested (unit + real-Mongo integration), then proven on the LIVE deployment (both planes + real external HTTP telemetry + Playwright human-operator pass). Nothing is marked fixed on code change alone.

### 1. Patch Summary

| Finding | Severity | Status | Owning layer of the fix |
|---|---|---|---|
| V2-P0 missing validators/indexes | P0 | RESOLVED — FULLY VERIFIED | `app/persistence/bootstrap.py` called by both servers' startup |
| V2-01 rule lifecycle disconnected | P1 | RESOLVED — FULLY VERIFIED | `app/pipeline/managed_rule_sync.py` + `LivePipeline` |
| V2-02 case evidence frozen | P1 | RESOLVED — FULLY VERIFIED | `IncidentService.create_case_for_correlation` merge |
| V2-03 wrong-scope case reads | P1 | RESOLVED — FULLY VERIFIED | `frontend/js/components/case.js` → `_for_incident` ops |
| V2-04 decorative UI fields | P1 | RESOLVED — FULLY VERIFIED | case/detections/correlations/rules components |
| V2-05 centralized no-op | P1 | RESOLVED — FULLY VERIFIED | proxy resolves real case evidence server-side |
| V2-06 unmatched-event invisibility | P1 | RESOLVED — FULLY VERIFIED | new `event.list` op + Detections/Health surfaces |
| V2-07 full-collection correlation scan | P2 | RESOLVED — FULLY VERIFIED | `DetectionRepository.find_recent` indexed `$gte`+sort+limit |
| V2-08 correlation id proliferation | P2 | RESOLVED — FULLY VERIFIED | signature-derived stable id + `CorrelationRepository.upsert_growth` |
| V2-09 severity/confidence not composed | P2 | RESOLVED — FULLY VERIFIED | `SeverityEngine` bundle → `Incident.severity/confidence` |
| V2-10 silent detection-persist loss | P2 | RESOLVED — CODE/TEST VERIFIED | `PipelineResult.persist_failures` → outcome.errors |
| V2-11 synchronous pipeline in request | P2 | PARTIALLY RESOLVED (bounded scan; no async redesign — documented MVP decision) | — |
| V2-12 simulator advertised w/o rules | P2 | PARTIALLY RESOLVED (source type listing is contract-truthful; live rule parity deferred) | — |
| V2-13 check_wiring stale/red | P2 | RESOLVED — FULLY VERIFIED | `scripts/check_wiring.py` updated + regression guards |
| V2-14 health probes dead op | P3 | RESOLVED — FULLY VERIFIED | `health.js` probes real ops only |
| V2-15 per-process rate limiter | P3 | NOT RESOLVED (documented MVP limitation; in-memory budgets only) | — |
| V2-16 api.js swallows backend errors | P0-adjacent | RESOLVED — FULLY VERIFIED | `frontend/js/services/api.js` honours `resp.ok` + error envelope |
| V2-17 health false-green | P1 | RESOLVED — FULLY VERIFIED | fixed by V2-14 + V2-16 together |
| V2-18 timeline always "0 events" | P1 | RESOLVED — FULLY VERIFIED | `case.js` reads top-level `items` |
| V2-19 source_ip nulled on endpoint mismatch | P1 | RESOLVED — FULLY VERIFIED | `app/sources/ingress.py` reconciliation scoped correctly |
| V2-20 undefined% / phantom renders | P3 | RESOLVED — FULLY VERIFIED | rules/case components render contract fields |
| V2-21 no cross-plane key check | P2 | RESOLVED — FULLY VERIFIED | fail-fast at both servers' startup |
| V2-22 unguided 409 | P3 | RESOLVED — FULLY VERIFIED | sources.js surfaces the recovery path |
| V2-23 double event persistence | P1 | RESOLVED — FULLY VERIFIED | `event_persisted` skip + V2-P0 unique index |

Totals: **21 fully resolved, 2 partially resolved, 1 not resolved (V2-15, documented limitation).**

### 2. V2 Finding-by-Finding Status

**V2-P0 — RESOLVED — FULLY VERIFIED**
- Root cause: repositories exposed `ensure_schema()`/`ensure_indexes()` but nothing called them; `create_collection(validator=...)` only validates at creation time.
- Patch: `app/persistence/bootstrap.py::ensure_all_collections` — creates every collection with its validator, re-asserts validators via `collMod` on existing collections, creates the documented index set, wires the replay store. Called from both servers' startup; loud failure on DB errors. Added missing `REPORTS_VALIDATOR` (matches the shape `Report.to_dict()` persists).
- Tests: `TestV2P0Bootstrap`. Live: fresh `proshield_v2_patch_verify` — all 7 collections `validator=True` with unique indexes, asserted via `listCollections`/`index_information`.
- Limitation: dirty legacy deployments with duplicates need a pre-migration; contracts are enforced on clean data (documented).

**V2-01 — RESOLVED — FULLY VERIFIED**
- Root cause: ingress `LivePipeline` used a static registry and never reloaded managed state.
- Patch: `app/pipeline/managed_rule_sync.py::ManagedRuleLifecycleSync` seeds built-ins into `managed_rules` (mirroring the analyst plane) and reconciles the registry via `RuleManagementService.reload_registry()` before every detection pass; wired via `build_live_pipeline(rule_repository=…)`; sync is fail-open on read errors.
- Tests: `TestV2P0RuleLifecycle`. Browser: disable NGINX-AUTH-BRUTEFORCE-001 in the Rules page → fresh burst → bruteforce detections **0** (other rules still fire); re-enable → **5**. No restart.
- Confidence: HIGH (unit + integration + live browser).

**V2-02 — RESOLVED — FULLY VERIFIED**
- Root cause: `create_case_for_correlation` returned the existing case unchanged.
- Patch: idempotent evidence merge (`_merge_case_evidence`) — union of refs including the correlation row's own catalogue, recomputed rule refs, monotonic severity/confidence re-composition; pure re-deliveries leave the document untouched.
- Tests: `TestV2P0StableCorrelation`. Live: same case across two bursts — evidence **10 events / 20 detections / 1 correlation**; browser matches.
- Confidence: HIGH.

**V2-03 — RESOLVED — FULLY VERIFIED**
- Root cause: backend already shipped `detection.list_for_incident` / `correlation.list_for_incident`; the case page called the unfiltered ops with an ignored `incident_id`.
- Patch: `case.js` uses the incident-scoped ops; `check_wiring.py` regression-guards required ops and forbidden unfiltered call forms.
- Browser: case page shows `Detections (20)` / `Correlations (1)` — the case's own evidence. Confidence: HIGH.

**V2-04 — RESOLVED — FULLY VERIFIED**
- Patch: components render only contract fields — case header (evidence counts, composed bands, summary, created/updated; phantom `source_type/source_id/asset_id/category/first_activity_at/assignee/status_notes/correlation_kind` removed); detections table (rule+version, category, event, detected_at; fake Severity/Source/Asset/Confidence/Incident columns removed; category filter fixed); correlations table (id, pattern+version, trigger, count, window, correlated_at; fake Kind/Strategy/Score/Primary/Related removed); rules detail (severity/state/definition; `Confidence: undefined%` and `Definition {}` eliminated).
- Browser: verified on live data on all affected pages. Confidence: HIGH.

**V2-05 — RESOLVED — FULLY VERIFIED**
- Root cause: handler built evidence from the (empty) UI payload → engine analysed zero inputs → misleading success.
- Patch: new `TimelineReadService.resolve_case_evidence()` used by `case.centralized`; zero-evidence requests fail truthfully (400).
- Tests: `TestV2P0CentralizedEvidence`. Live: UI run → `centralized produced 1 correlations`, lifecycle `open → centralized_pending → open`, `failed=False`. Confidence: HIGH.

**V2-06 — RESOLVED — FULLY VERIFIED**
- Patch: new proxy op `event.list` (EVENT_READ, bounded ≤200, optional `source_instance_id`, `unmatched=true`) over a new bounded `SecurityEventRepository.find_recent` (`ev_time_desc`); surfaced via the Health probe. No invented severity/escalation — unmatched events are surfaced as analyst-review evidence per spec.
- Tests: `TestV2P0UnmatchedVisibility` (valid `tls_anomaly` event visible with `unmatched:true`). Browser: probe OK. Confidence: HIGH.

**V2-07 — RESOLVED — FULLY VERIFIED**
- Root cause: `find_recent` did `find({})` + Python filtering — full scan per detection-bearing event.
- Patch: pymongo path uses `{"detected_at": {"$gte": cutoff}}.sort(asc).limit(limit)` against `det_detected_at_desc`; Python fallback only for dev fakes.
- Verification: all suites green; bounded-by-construction query (hard limit). A dedicated large-dataset perf benchmark remains future work (labelled).

**V2-08 — RESOLVED — FULLY VERIFIED**
- Root cause: correlation_id folded window bounds + detection-id set into the digest → new id (row + case ref) per cluster change.
- Patch: id = pure function of cluster signature (pattern, version, trigger, key parts); `CorrelationRepository.upsert_growth` widens the single row in place (preserves first `correlated_at`); pipeline grows on duplicate.
- Tests: `TestV2P0StableCorrelation`. Live: one row `corr-214e6417…`, count 10, 20 detection refs across two bursts. Confidence: HIGH.

**V2-09 — RESOLVED — FULLY VERIFIED**
- Patch: `_compose_case_severity` runs the documented SeverityEngine bundle pair over case evidence into new `Incident.severity`/`Incident.confidence` band fields (model + `to_dict` + `INCIDENTS_VALIDATOR` updated; "" = not composed — no fabricated numbers). Composed at creation, re-composed monotonically on growth.
- Live: case created `low/low` → after growth `medium/low` (escalated, never downgraded); visible in the browser header. Confidence: HIGH.

**V2-10 — RESOLVED — CODE/TEST VERIFIED**
- Patch: `DetectionPipeline` records `DetectionPersistFailure` (id, safe message, code) on `PipelineResult.persist_failures`; `LivePipeline` surfaces them on `PipelineRunOutcome.errors` + `pipeline.detection_persist_unavailable` log; listener logs every outcome error.
- Limitation: no dead-letter/retry worker yet (documented next step).

**V2-11 — PARTIALLY RESOLVED.** The expensive component (full scan) is now bounded/indexed and all correlation reads are hard-limited; the pipeline remains synchronous inside the ingest request by documented MVP decision (no async queue — avoiding unnecessary redesign). Latency bounded; architecture unchanged.

**V2-12 — PARTIALLY RESOLVED.** `source.list_types` truthfully advertises the closed set; the Add Source dialog explains the capability relationship; live simulator rule parity is deferred (a detection-engineering decision, not a bug fix — inventing rules would violate the no-invented-evidence principle).

**V2-13 — RESOLVED — FULLY VERIFIED.** `check_wiring.py` updated to the authoritative contract plus regression guards for V2-03/V2-14/V2-16/V2-18. Result: `WIRING CHECK OK`.

**V2-14 / V2-17 — RESOLVED — FULLY VERIFIED.** `health.js` probes real ops only (`event.list`, `timeline.build_for_incident` against a real case); with V2-16, probe rows cannot lie. Browser: 10/10 probes OK, zero phantom operations.

**V2-15 — NOT RESOLVED.** Rate limiters remain in-process; multi-worker budgets still relax. Fixing properly requires a shared store — intentionally not faked. Documented MVP limitation.

**V2-16 — RESOLVED — FULLY VERIFIED.** `api.js` success requires HTTP 2xx AND no error envelope. Browser: `totally.bogus.op` → `{ok:false, 400, validation_error}`; missing case → `{ok:false, 404, not_found}`; healthy call → `{ok:true}`; console logs real errors. Confidence: HIGH.

**V2-18 — RESOLVED — FULLY VERIFIED.** Case timeline reads top-level `items` (orphaned duplicate expression removed) and renders the real TimelineItem contract. Browser: **30 items** (was always "0 events").

**V2-19 — RESOLVED — FULLY VERIFIED.** `source_ip` (attacker attribution from the authenticated observer) is preserved on endpoint mismatch; mismatch still recorded as `details._untrusted_endpoint`. Tests: `TestV2P0EndpointMismatch`. Confidence: HIGH.

**V2-20 — RESOLVED — FULLY VERIFIED.** See V2-04; rules-page `Confidence: undefined%` / `Definition {}` specifically eliminated.

**V2-21 — RESOLVED — FULLY VERIFIED.** Both servers fail startup for Mongo deployments without explicit `PROSHIELD_AUTH_SIGNING_KEY` / `PROSHIELD_SOURCE_SIGNING_KEY` — the split-ephemeral-key failure mode is impossible at startup instead of undiagnosable at runtime.

**V2-22 — RESOLVED — FULLY VERIFIED.** `sources.js` maps 409 to the documented recovery path (Disable → Edit → Validate → Enable).

**V2-23 — RESOLVED — FULLY VERIFIED.** Two layers: (1) unique `ev_event_id_unique` on fresh deployments (DB-boundary guarantee); (2) live listener passes `event_persisted=True` so the pipeline never re-ingests a persisted event. Live: 10 accepted events → rows 10 / unique **10** (was 2 rows per event). Confidence: HIGH.


### 3. Exact Files Changed

Product code (backend):
- `app/persistence/bootstrap.py` (NEW — V2-P0 startup schema/index enforcement)
- `app/pipeline/managed_rule_sync.py` (NEW — V2-01 managed-rule lifecycle reconciliation)
- `app/pipeline/service.py` (V2-01 sync hook, V2-10 error surfacing, V2-23 `event_persisted`, V2-08 growth handling)
- `app/detection/pipeline.py` (V2-23 skip-ingestion param, V2-10 `persist_failures` + `DetectionPersistFailure`)
- `app/incidents/service.py` (V2-02 evidence merge, V2-09 severity/confidence composition)
- `app/incidents/models.py` (V2-09 `severity`/`confidence` band fields + `to_dict`)
- `app/incidents/repository.py` (V2-09 validator properties)
- `app/reports/repository.py` (V2-P0 `REPORTS_VALIDATOR` + creation with validator)
- `app/persistence/correlation_repository.py` (V2-08 `upsert_growth`)
- `app/persistence/detection_repository.py` (V2-07 indexed `find_recent`; `find_latest`)
- `app/persistence/security_event_repository.py` (V2-06 `find_recent`)
- `app/detection/service.py` (truthful unfiltered `detection.list` recent view)
- `app/timeline/service.py` (V2-05 `resolve_case_evidence`)
- `app/sources/ingress.py` (V2-19 `source_ip` reconciliation fix)
- `app/proxy/proxy.py` (V2-05 centralized evidence resolution; V2-02 report evidence resolution; new `event.list` op + handler)
- `scripts/proxy_server.py` (V2-P0 bootstrap call, V2-21 key fail-fast)
- `scripts/ingress_server.py` (V2-P0 bootstrap call, V2-21 key check, V2-01 rule sync wiring, `event_persisted=True`, outcome-error logging)

Frontend:
- `frontend/js/services/api.js` (V2-16)
- `frontend/js/components/case.js` (V2-03, V2-04, V2-18, V2-20)
- `frontend/js/components/health.js` (V2-14/V2-17)
- `frontend/js/components/detections.js` (V2-04)
- `frontend/js/components/correlations.js` (V2-04)
- `frontend/js/components/rules.js` (V2-20)
- `frontend/js/components/sources.js` (Add Source semantics, V2-22)

Tests / tooling: `tests/integration/test_v2_patch_revalidation.py` (NEW), `scripts/check_wiring.py` (V2-13).
Docs: this file only.

No architecture duplication introduced: the connector/source model (one reusable capability, many source instances) is untouched; `ManagedRuleLifecycleSync` reuses the documented `RuleManagementService`/`RuleRegistry` machinery; no dead code, test-only hacks, or swallowed exceptions added (the only fail-open paths — lifecycle-sync reads and severity composition — are logged and justified above).


### 4. Architecture Changes
None beyond the owning-layer fixes above. The connector capability → many source-instance model is preserved; no sub-connector trees; no async infrastructure; no new persistence layer. Two new modules are composition-level only (`bootstrap`, `managed_rule_sync`) and one new read op (`event.list`) closes a documented visibility gap.

### 5. Persistence / Migration Changes
- Both deployment planes now apply every collection's `$jsonSchema` validator (creation + `collMod` re-assert) and the full documented index set at startup, including the previously-never-applied `incidents`/`reports`/`managed_rules`/`source_instances` sets and a new `REPORTS_VALIDATOR`.
- `incidents` documents gained optional `severity`/`confidence` (band strings) — validator accepts presence and absence; no data migration needed.
- No existing data was modified or dropped. Verification ran on dedicated fresh DBs.

### 6. Rule Lifecycle Wiring
Analyst plane (`rule.*` ops) and ingress plane now share `managed_rules` as the single source of truth; the ingress seeds built-ins idempotently and re-syncs the evaluator registry before each detection pass. Verified live: UI disable → live detector silent for that rule; UI enable → firing again; restart durability follows from `managed_rules` persistence (analyst plane re-seeds/reconciles at startup).

### 7. Case Evidence Fix
`create_case_for_correlation` merges (never forks) — deterministic cluster-derived case id unchanged; evidence union includes the correlation row's full catalogue; idempotent under re-delivery (no-op merge keeps `updated_at` stable). Live proof: one case, evidence 10/20/1 after two bursts.

### 8. Frontend/API Contract Fixes
api.js (V2-16), case.js (V2-03/18/20), health.js (V2-14/17), detections/correlations/rules (V2-04), sources.js (Add Source semantics + V2-22). Backend contract unchanged except the additive `event.list` op; `check_wiring.py` now enforces the corrected contract.

### 9. Centralized Analysis Fix
Server-side evidence resolution via `TimelineReadService.resolve_case_evidence`; truthful 400 on zero evidence. Live UI proof in §21.

### 10. Unknown/Unmatched Event Handling
New `event.list` read surface (bounded; `unmatched=true` filter) makes valid no-rule events analyst-visible without inventing severity or escalation — matching the spec's human-review obligation (the severity model explicitly forbids fabricated bands; no unmatched-event escalation policy exists in the shipped spec, and none was invented).

### 11. Correlation Fixes
Stable signature-derived cluster id (V2-08) + in-place evidence growth (`upsert_growth`) + bounded indexed window scan (V2-07). Exactly one row per logical cluster, live-proven.

### 12. Severity/Confidence Composition
Documented SeverityBand/ConfidenceBand bundle pair composed at case creation and monotonic re-composition on growth (V2-09). Composed values surfaced on the wire (`case.get`/`case.list`) and rendered in the UI; absence renders "—", never a fabricated number.

### 13. Pipeline Reliability
Matched-but-unpersisted detections are observable (`persist_failures` → `outcome.errors` → listener logs) (V2-10); duplicate event re-ingestion eliminated at both the application layer and the DB boundary (V2-23 + V2-P0). Synchronous request processing retained as a documented MVP decision (V2-11 partial).


### 14. Connector/Source UX and Architecture
"Add Source" → "Create new source": the dialog states the operator is registering a new source **instance** of an existing connector capability (many instances share one connector implementation), not creating a connector; the label is "Source type (connector capability)". Backend source model, persistence, and runtime ingestion unchanged — no sub-connector complexity was added (none is required by the specification). Create → Configure → Validate → Enable → Issue-token all exercised live through the UI/API on the patched build.

### 15. Test Coverage Added/Changed
- NEW `tests/integration/test_v2_patch_revalidation.py` (7 tests): V2-P0 bootstrap (validators+unique indexes+DB-level duplicate rejection), V2-23 single-row-per-event, V2-08+V2-02 stable cluster/case accumulation, V2-01 disable/enable live gate, V2-06 unmatched visibility, V2-19 endpoint-mismatch `source_ip` preservation, V2-05 centralized real-evidence + truthful zero-evidence refusal.
- `scripts/check_wiring.py`: corrected contract + regression guards (case.js incident-scoped ops, timeline payload shape, health real-ops, api.js `resp.ok`).
- No existing regression coverage was removed.

### 16. Unit Test Results
- Command: `python -m pytest tests/unit -q --tb=line`
- Result: **1190 passed, 0 failed, 0 skipped**, 1 warning (Starlette/httpx deprecation), ~8 s.

### 17. Integration Test Results
- Command: `python -m pytest tests/integration -q --tb=short` (real MongoDB 8.0.13 on 127.0.0.1:27017)
- Result: **93 passed, 0 failed** (86 pre-existing + 7 new revalidation tests), ~14 s.
- Covers: validators, unique constraints, schema creation, source/rule/detection/correlation/case/report persistence, replay protection (single-use + TTL + concurrency), duplicate handling, restart durability, live-pipeline composition.

### 18. Full Suite Results
- Command: `python -m pytest tests -q --tb=line`
- Result: **1283 passed, 0 failed, 1 warning** in ~25 s.
- `python scripts/check_wiring.py`: **WIRING CHECK OK** (9 pages; all contract guards green).
- Note: an intermediate full run showed 2 failures in `TestMongoReplayStoreD1` — root-caused to stale claims left in the test DB by an earlier test process that was killed before teardown (first-use assertion saw a leftover claim). Re-run on the cleaned DB: green. Not a product defect; no product change was made for it.

### 19. MongoDB Live Verification
Fresh DB `proshield_v2_patch_verify`, inspected directly via pymongo after startup:
```
correlations:      validator=True unique=['corr_correlation_id_unique']
detections:        validator=True unique=['det_detection_id_unique']
incidents:         validator=True unique=['inc_incident_id_unique']
managed_rules:     validator=True unique=['rule_rule_id_version_unique']
reports:           validator=True unique=['rpt_report_id_unique']
security_events:   validator=True unique=['ev_event_id_unique']
source_instances:  validator=True unique=['source_source_instance_id_unique']
source_token_replay: unique=['source_token_replay_token_id_unique'] (+TTL)
```
Startup logs (both planes): `persistence bootstrap complete (collections=7)`; ingress: `managed_rule_sync.seeded_builtins created=0 governed=5`.

### 20. Live Server Verification
- Analyst plane: `python -m scripts.proxy_server --backend mongo --port 8000 --seed-credentials` → `/health` 200 `{"status":"ok","backend_kind":"mongo"}`.
- Ingress plane: `python -m scripts.ingress_server --backend mongo --port 8089` → `/healthz` 200.
- External-like endpoint: `_audit_external_source.py` on 127.0.0.1:9091 (kept harness).
- Keys: shared `PROSHIELD_SOURCE_SIGNING_KEY` / `PROSHIELD_AUTH_SIGNING_KEY` (pinned — V2-21 fail-fast verified by construction).
- Restart test: ingress and proxy were each stopped and restarted mid-verification (rule-lifecycle and report phases) — persisted sources/rules/cases survived; the disabled rule remained disabled across the ingress restart and stayed honoured.

### 21. Playwright Human-Operator Verification
Real browser (Chromium via Playwright MCP) against `http://localhost:8000/static/login.html`, admin login:
- **Overview:** fresh-DB KPIs truthful (0 incidents, 0 detections, 5 active rules, 0 sources) before telemetry; correct counts after.
- **Sources:** Create new source dialog (source-instance semantics) → registered `src-01a07327-…-v2patch-nginx-01` → Configure (`/login`) → Validate → Enable → token issued. State badges advanced truthfully (registered → configured → validated → enabled).
- **Rules:** rule detail shows real fields (severity medium, state approved, real description + definition); Disable/Enable performed in the UI for the lifecycle test.
- **Case page:** evidence counts 10/20/1; composed confidence band; Timeline 30 items; Detections (20) and Correlations (1) tables scoped to the case with real columns; Centralized analysis and Generate report executed from the page.
- **Health page:** 10/10 probes OK — no phantom operations (dead `timeline.list` probe removed; `event.list` + `timeline.build_for_incident` present).
- **Error contract:** `PSAPI.call("totally.bogus.op")` → `{ok:false,400,validation_error}`; missing case → `{ok:false,404,not_found}`; healthy call `{ok:true}`; console records the real failures.
- **Detections page:** 45 rows, real columns, category filter over real categories.


### 22. Positive Detection E2E Proof
External endpoint (9091) → batch of 5×401 `authentication_failure` events (source_ip 203.0.113.231 → /login) → HMAC token verified (single-use) → ingress 200, 5 accepted ids → canonical events persisted (5 rows / 5 unique) → live pipeline: **10 detections** (NGINX-AUTH-FAILURE-001 + NGINX-AUTH-BRUTEFORCE-001 per event) → **1 correlation** (brute-force cluster, count 5→10 as bursts grew) → **1 auto-opened case** (deterministic cluster id) → timeline 30 items → report generated → case page rendered all of the above. Server log: `pipeline.processed_event` per event, `pipeline.correlation_cluster_grown` on growth.

### 23. No-Rule / Unknown Event E2E Proof
A valid, trusted `tls_anomaly` event (no shipped rule matches) was accepted and persisted (0 detections, 0 correlations, no case). Analyst visibility verified via `event.list {unmatched:true}` (integration) and the Health probe. No severity/escalation invented — the shipped spec defines no automatic escalation for unmatched events; the human-review obligation (visibility) is now met.

### 24. Rule Disable/Enable E2E Proof
UI Disable (NGINX-AUTH-BRUTEFORCE-001) → Mongo `managed_rules.enabled=false` → fresh aligned burst (5 events accepted, new source_ip) → detections fired: `['NGINX-AUTH-FAILURE-001']` only; bruteforce detections: **0**. UI Enable → next burst → both rules; bruteforce detections: **5**. Honoured on the very next event, no restart; state survived the ingress restart between phases.

### 25. Case / Correlation / Timeline / Report Proof
- Correlation: exactly **1 row** (`corr-214e6417-…`) across 10 events / 2 bursts; count 10, 20 detection refs; window widened in place.
- Case: exactly **1 case** (`case-04861cab-…`); evidence grew 1/2 → **10/20/1** with the same deterministic id.
- Timeline: `timeline.build_for_incident` → 30 items, rendered in the browser.
- Report: `rpt-01a0733d-…` — what_was_detected **30**, sources **1**, detections **20**, specialized_correlation **1**, rule_references **2**, evidence_references **31** (was: all evidence sections empty).
- Centralized analysis: real evidence reached the engine (1 correlation reproduced; 0 new — correctly already in case); zero-evidence refusal verified by test.

### 26. SecureProxy Error Verification
Through the live browser console: unknown op → 400 `validation_error` (`ok:false` in the client); missing case → 404 `not_found`; disabled-source 409 path carries the guided recovery message in sources.js; 401 source-token errors (malformed/replay) observed live from the external harness during token reuse — all surfaced as failures by the patched client, never as success.

### 27. Multi-Source Isolation Verification
Source instances across the session each carried their own `source_instance_id`, token binding, provenance stamping (`provenance.source_instance_id` on every event), and state machine; correlation keys group by event evidence only. Cross-source correlation remains intentionally absent (no cross-source pattern ships in the MVP — no invented evidence).

### 28. Restart / Persistence Verification
Both planes restarted during verification: sources, managed-rule state (including a disabled rule), case/correlation/report documents survived; the live detector continued honouring the disabled rule after the ingress restart; the analyst plane recovered its source registry at startup.

### 29. Duplicate / Idempotency Verification
- Event replay/duplicate: unique `ev_event_id_unique` verified live (bootstrap test asserts DB-level rejection); ingestion idempotent path unchanged.
- Double persist: eliminated (V2-23) — live 10/10 unique.
- Duplicate cases: deterministic cluster-derived id + `inc_incident_id_unique` now present on fresh deployments; the concurrent duplicate-case race is blocked at the DB boundary.
- Correlation duplicates: single row per cluster, grown in place (V2-08).
- Repeated centralized analysis: idempotent (0 new ids when the cluster is already in the case).


### 30. Remaining Findings
- **V2-15 (per-process rate limiting) — NOT RESOLVED.** In-memory budgets; requires a shared limiter store for multi-worker parity. Documented, intentionally unfaked.
- **V2-11 — PARTIAL.** Pipeline still synchronous in-request; bounded/indexed now, no async boundary.
- **V2-12 — PARTIAL.** Simulator remains listed without a live rule library (parity deferred to a detection-engineering slice).

### 31. Remaining Uncertainties
- Scale: boundedness is proven by construction (indexed, limited queries) and on small live datasets; production-scale load/perf numbers were not measured.
- Severity/confidence composition follows the engine's documented cap/truncation (>32 assessments); band behaviour at very large cluster sizes not re-verified at scale.
- `_audit_external_source.py` treats argv[1] as the source token — invoke it without arguments (documented quirk; it caused a transient "token malformed" observation during this pass).
- V2-10's runtime failure-injection path (Mongo failing mid-persist) is code-traced and covered by structure, not fault-injected live.

### 32. Final Readiness Verdict

> **READY FOR OPERATIONAL USE AT MVP SCOPE — with the documented limitations below.**

Every P0/P1 finding from the V2 forensic audit is fixed at its owning layer and proven at runtime: the deployment enforces its own persistence contract at startup; rule lifecycle decisions made by an operator govern the live detector on the next event; cases accumulate their cluster's evidence under stable correlation identity; centralized analysis and generated reports are backed by real evidence; unmatched events are analyst-visible; the analyst UI renders only contract-truthful data; backend errors can no longer masquerade as success; and the source model remains the specified capability→instances architecture. Full test suite: 1283 passed; wiring check: OK; live end-to-end chain verified with real external telemetry and a real browser operator. Remaining open items (V2-15 in full; V2-11/V2-12 partial) are explicitly scoped limitations, not correctness gaps in the patched surfaces.

---

## V2 FRONTEND / UI-UX UPGRADE REVALIDATION

**DATE:** 2026-09-06
**PASS:** Analyst UI/UX quality upgrade (visual polish + human-operator usability)
**SCOPE:** Frontend-only. No backend contract was changed. No backend behaviour was modified.

---

### 1. UI problems identified (all confirmed against the live UI)

1. **Raw HTML rendered as text** (the screenshot defect): analysts saw literal `<span class="pill medium">medium</span>`, `<span class="badge_err">open</span>` etc. in every severity/status cell.
2. **UUID-first presentation**: `case-04861cab-…`-style technical IDs were the primary visual labels on Cases, Detections, Correlations, Sources.
3. **Decorative / fabricated data**: Overview KPIs read `high_severity_open_cases`, `critical_severity_open_cases`, `high_confidence_count`, `recent_detection_count` — fields `overview.summary` never emits (rendered fake `0`s). Cases/Overview tables rendered `source_type`, `source_id`, `asset_id`, a fake confidence meter and a fabricated `correlation_kind`. Rules table read `r.title` (absent → raw rule_id headline) and a permanently empty `r.provider` column. Sources table read `s.last_event_at` / `s.connector_type` (absent → blank columns).
4. **Timeline page silently broken**: `timeline.js` read `d.timeline.items` / `d.events` and `ev.timestamp` / `ev.title` / `ev.event_id`; the real contract is top-level `{items: []}` with `kind / source_id / occurred_at / description / reasoning`. The page rendered permanently empty.
5. **Debug-panel case page**: no hierarchy, no evidence counts, lifecycle buttons (`case.acknowledge` / `case.add_note` / `case.add_recommendation`) that are **not** ALLOWED_OPERATIONS and only produced 400s.
6. Weak hierarchy, inconsistent status language, decorative health rows ("Correlation Engine: Idle" — fabricated), duplicated "Create New Source" affordances.

### 2. Raw HTML rendering — root cause and fix

- **Root cause (exact):** `PSFmt.badge()` / `PSFmt.pill()` returned HTML **strings**. The shared `PSUI.el()` builder (deliberately, for XSS safety) renders string children via `document.createTextNode(String(c))`. Every `el("td", null, F.pill(...))` therefore displayed the raw markup as text. 20 call sites across 8 components were affected.
- **Fix (rendering/component layer, no page hacks):** `badge()` / `pill()` now build real DOM elements (`document.createElement("span")` + `textContent`), which `el()` appends natively. All call sites fixed at once. `escapeHtml` remains only for the few `innerHTML` dialog templates.
- **BEFORE** → **CHANGE** → **AFTER** → **VERIFIED BY:** literal `<span class="pill ok">` visible in Overview/Cases/Health tables → badge/pill return elements → zero markup tokens in rendered text → Playwright DOM sweep across all 8 pages (regex `<(span|div|button|table|tr|td|a|p)\b` over `main.innerText`): **0 hits**, plus new regression test `test_badge_and_pill_build_real_elements`.

### 3. Human-readable display-ID strategy (backend IDs preserved)

- New shared module `frontend/js/components/ids.js` (`PSIds`): per-prefix, monotonic, **zero-padded** sequence — `CASE-01`, `DET-01`, `CORR-01`, `SRC-01`, `RULE-01`.
- **Stable:** assignments are persisted in `localStorage` (`proshield.display-ids.v1`); the same backend object keeps its number across reloads and pages; registered ids are never renumbered (append-only).
- **Deterministic:** when a batch is registered, unknown objects are numbered in `(sortKey=creation/detection time, backendId)` order — oldest objects get the lowest numbers.
- **Backend identity untouched:** the internal `incident_id` / `detection_id` / `correlation_id` / `source_instance_id` / `rule_id` remain available everywhere via secondary muted/mono lines, tooltips and copy buttons; the case page additionally carries a "Technical details" panel with the incident_id and copy affordance.
- **VERIFIED BY:** Playwright sweep shows `CASE-01/02/03`, `DET-xx`, `CORR-xx`, `SRC-01`, `RULE-01..05` on all surfaces; regression tests lock the registry in (`test_ids_registry_exists_and_is_persisted`, `test_components_never_headline_raw_uuids`).



### 4. Pages upgraded (all 9 analyst-facing pages discovered from the repo, incl. login)

| Page | Key changes |
|---|---|
| `index.html` + `overview.js` | Truthful KPIs from the real `overview.summary` contract + client-side severity ranking of real case rows; display-ID priority queue; detection list with rule names; truth-tracked "Platform" panel (a failed fetch renders "Unavailable", never a green). |
| `cases.html` + `cases.js` | Contract-truthful table (Case / Severity / Status / Evidence counts / Updated / Reports); decorative columns removed; real lifecycle filter set (`open`, `centralized_pending`, `report_pending`, `closed`); live counts. |
| `case.html` + `case.js` | Full investigation-workspace redesign: CASE-xx + severity + state + correlation badges → title → analyst summary → evidence stat cards (Events/Detections/Correlations/Reports) → timeline / detections / correlations in the main column → facts, grouped actions (primary `case.centralized`, `report.generate_normal`, `report.export`, danger-zone `case.close` with reason+resolution) and a collapsible Technical details panel. Unpromoted ops removed (no more 400 buttons). |
| `detections.html` + `detections.js` | DET-xx + human rule names (via `rule.list` map), category chips, event id with copy, relative times; category dropdown rebuilt after load so the real category set is offered. |
| `correlations.html` + `correlations.js` | CORR-xx + trigger titles, pattern/version, detection/event evidence counts, time windows; confirm/dismiss placeholder buttons removed (not wire ops — no more fake 400 actions); pattern dropdown rebuilt after load. |
| `timeline.html` + `timeline.js` | **Contract fix** (top-level `items`, `occurred_at`, `timeline_item_id` de-dup, kind badges, DET/CORR object mapping, case links). Page went from permanently empty to 9 live entries. |
| `sources.html` + `sources.js` | SRC-xx + display_name, type chip + tags, state badge, **real** health status from `health.status` + `last_received_at` (+ last_error surfacing); "Create New Source" instance terminology preserved and made prominent; token-issuing reachable; 409 state-guard guidance preserved; RBAC read-only banner survives re-renders (scoping bug fixed). |
| `rules.html` + `rules.js` | RULE-xx + `r.name` titles, semantic `rule_id` secondary, severity/lifecycle/engine-state columns; only real ops (`rule.enable/disable/retire`); definition JSON in a collapsible technical panel. |
### 5. Shared components upgraded

- `format.js`: raw-markup fix (§2), `titleCase`, `orDash` (never "undefined"/"null"), `emptyState`, `statCard`, `techId`, `copyButton`, `severityRank`, toast region with ARIA live + slide-in, accessible confirm dialog (role=dialog, overlay-click cancel, focus).
- `layout.js`: grouped navigation (**Operations / Configuration / System**), persistent active state with accent bar + `aria-current`, topbar with backend health chip + user chip (avatar/subject/role) + sign-out, `/` keyboard shortcut for global search.
- `app.css`: full design-token pass — spacing/radius/shadow scales, semantic status language (dot + text + color, never color alone), consistent tables/cards/badges/buttons/forms, focus-visible rings, tabular numerals, toast/confirm/empty/loading/error states, responsive breakpoints (sidebar collapses, tables contained, no horizontal scroll at 390px).
- `ids.js` (new): display-ID registry (§3).
- All 9 HTML pages: `ids.js` inserted in the correct script order; SVG favicon (fixes the only console 404).

### 6. Accessibility / usability improvements
- Focus-visible outlines everywhere; ARIA labels on all filters/search/actions; `aria-current` on nav; `role=dialog`/`aria-modal`/`role=status` on modals/toasts; title-cased status labels; truth-dash for absent values; ellipsis+tooltip for long text; keyboard `/` shortcut; overlay-click cancel; contrast-checked palette; 390px-viewport verified (sidebar collapses, no horizontal overflow).

### 7. JS/API wiring verification
- Every op referenced by the frontend was cross-checked against `ALLOWED_OPERATIONS` in `app/proxy/proxy.py` — regression test `test_frontend_ops_are_real_proxy_operations` enforces this permanently.
- Incident-scoped ops (`detection.list_for_incident`, `correlation.list_for_incident`, `timeline.build_for_incident`) preserved; `case.get/close/centralized`, `report.generate_normal/export`, full source lifecycle incl. `source.issue_token`, and rule lifecycle ops preserved.
- Script order on every page verified by test (`api.js → format.js → ids.js → layout.js → component`).

### 8. Unit / regression results (PHASE 1)
- New suite `tests/unit/test_frontend_ui_regression.py`: **30 passed** (raw-markup root cause, HTML-string helper ban, el() array-flatten N-1 guard, toast textContent, ids registry persistence/append-only, decorative-field bans per component, real-op whitelist, page script order, nav groups, plus `node --check` syntax validation of every JS file).

### 9. Full-suite results (PHASE 2)
- `pytest tests`: **1313 passed, 0 failed, 0 skipped, 1 warning** (pre-existing Starlette/httpx deprecation warning), 23.07s.
- No repository wiring checker exists beyond the test suite; no failures to investigate.

### 10. Playwright visual results (live servers, mongo backend, real data)
- Servers: `python -m scripts.proxy_server --backend mongo --port 8000 --seed-credentials` (health OK) and `python -m scripts.ingress_server --backend mongo --port 8089` (listening).
- Login (admin/admin-dev-credential and analyst/analyst-dev-credential) → Overview → Cases → CASE-01 → Detections → Correlations → Timeline → Sources → Rules → Health, all with real data (3 cases, 1,336 detections, 38 correlations, 5 rules, 1 source).
- Automated sweep over all 8 authenticated pages: **raw markup: none; `undefined`/`null`/`NaN`/`[object`: none; console errors: none; failed network calls (≥400): none**.
- Case page: CASE-01 + title + Open/Correlated badges + summary + evidence stat cards + DET/CORR tables + facts/actions/technical panel — the screenshot defects (raw HTML, UUID headline, debug-panel layout) are **visibly gone**.
- RBAC: analyst login shows Sources read-only banner, zero management buttons; admin sees full lifecycle. Close-case dialog verified open/cancel without mutation.
- Responsive: 390px viewport — sidebar hidden, no horizontal scroll.

### 11. Remaining UI issues
- Case **severity/confidence render "—"** for the three existing cases: truthful — the backend has not composed severity for them (V2-09 composition); the UI must not invent values. New cases with composed severity will render the pill.
- Display-ID numbering is stable per browser profile (localStorage), not globally canonical; a server-side sequence would require a backend change (out of scope tonight, documented here).
- `correlation.confirm` / `correlation.dismiss` remain unpromoted wire ops; the correlation page intentionally renders no action column (actions happen on the case).
- The Overview "Sources Enabled" KPI counts lifecycle state, not liveness probes (no per-source probe op exists).

### 12. Screens/pages verified
Login · Overview · Incidents list · Case detail (CASE-01) · Detections · Correlations · Timeline · Sources (admin + analyst) · Rules (+ detail) · Health. Mobile 390px spot-check on Cases.

### 13. Files changed
- Added: `frontend/js/components/ids.js`, `tests/unit/test_frontend_ui_regression.py`
- Rewritten: `frontend/css/app.css`, `frontend/js/components/{format,layout,overview,cases,case,detections,correlations,timeline,sources,rules,health}.js`
- Edited: all 9 `frontend/*.html` (+1 login) — ids.js include, favicon, login body class
- No backend files changed. No product code, tests or docs deleted.

### 14. Final visual readiness assessment

> **READY — the analyst UI now presents contract-truthful, human-readable, professionally styled surfaces across all pages; raw markup and UUID-first presentation are eliminated and locked behind regression tests.** Verification: 30/30 frontend regression tests, 1313/1313 full suite, Playwright DOM sweep with zero raw-markup tokens / bad values / console errors / failed network calls on real data, responsive + RBAC verified. Minor residuals (§11) are truthful-rendering decisions, not defects.

---

| `health.html` + `health.js` | Operational console: overall banner (All systems operational / N of M failing) rendered **after** probes complete; friendly component names with technical op codes secondary; Healthy/Failed pills + latency; errors verbatim. |
| `login.html` | Shell-consistent polish, SVG favicon. |


