# PROSHIELD — STRIX DEEP FORENSIC END-TO-END SECURITY VALIDATION

**PRIMARY MODEL:** DEEPSEEK V4 FLASH
**REPORT FILE:** `docs/PHASE 4/PROSHIELD-DEEPTEST-ISSUES.md`
**DATE:** 2026-09-04
**REPOSITORY STATE:** commit `578b320` plus uncommitted STRIX patch worktree (`.env.example`, `README.md`, `app/config.py`, `app/proxy/proxy.py`, `app/sources/ingress.py`, `app/sources/replay_store.py`, tests, docs contract, `frontend/`, `scripts/*`)

This is an **independent** re-evaluation. Prior STRIX reports (`STRIX-PROSHIELD-CONFIRMED-ISSUES-PATCH-REPORT.md`, `STRIX-PROSHIELD-FRONTEND-IMPLEMENTATION.md`, `STRIX-PROSHIELD-FULL-PIPELINE-TEST.md`) were treated as **evidence, not truth**, and were verified against the current repository + runtime.

---

## EXECUTIVE VERDICT

> **ARCHITECTURALLY INCOMPLETE (NOT READY for the documented enterprise workflow).**

**Why:** The individual engines (ingestion, source trust/replay, rule registry, detection engine, correlation engine, incident service, timeline, routing, reports) exist, are individually testable, and pass their suites — **but the shipped deployment composition NEVER runs the detection → correlation → case chain.** A real external source connecting to the live ingress plane, authenticating, sending matching telemetry, produces **persisted events only**: zero detections, zero correlations, zero cases — proven at runtime against real MongoDB and real HTTP (see §7, §9, §20). The only place the full pipeline "works" is **test/demo scripts that manually compose `DetectionPipeline` + `CorrelationEngine` + `IncidentService.create_case` in-process** (`scripts/demo_security_workflow.py`, `scripts/detection_boundary_test.py`, etc.). That is TEST INFRASTRUCTURE, не a product capability路径. Additionally, the frontend calls **10 operation names that don't exist on the backend** (live 400 `unknown operation`), has **zero wiring for centralized analysis and reports**, and the "Connector Type" control equates closed-enum source types with real connector implementations — 6 declared types but only 2 implementations exist.

**Bottom-line answer to §62/§63:** **NO — in its current implementation, ProShield does NOT behave as the enterprise security platform described by its architecture and specs when a real external source connects.** It fails at the precise point where detection/correlation/case composition should occur (arrows 8-10 of the documented pipeline) and at multiple analyst-plane wiring seams.

 The engines themselves are largely sound;the composition is missing. There is also no live case-creation path, so the correlation→case stage can NEVER occur in a running system regardless of data.

.

---

## 1. SCOPE AND EVIDENCE HONESTY

**DIRECTLY EXECUTED (this investigation):**
- Full unit suite: **1185 passed** (6.88s, no Mongo)
- Full integration suite: **86 passed** (12.23s, real MongoDB `127.0.0.1:27017`) — `python -m pytest tests/unit`, `python -m pytest tests/integration`
- Live two-plane harness `scripts/strix_deeptest_live.py` (TEST INFRA): real `proxy_server` (port 18088) + `ingress_server` (port 18089), real MongoDB fresh db `proshield_deeptest`, shared `PROSHIELD_SOURCE_SIGNING_KEY` — 35/35 steps executed; every HTTP request/response recorded in `strix_deeptest_evidence.ndjson` (.json).
- Live ingress socket smoke `scripts/live_ingress_smoke.py` — PASS (no-token→401, malformed→400, health→200.
- Detection boundary script `scripts/detection_boundary_test.py` — PASS (positive 2 detections; no-match 0; benign 0; iam-source 0**
- Full demo `scripts/demo_security_workflow.py` — PASS **only with in-process manual composition of `DetectionPipeline`/`CorrelationEngine`/`IncidentService.create_case`** (memory backend; see §23 caveat).
- Ultimate DB state query `scripts/_strix_deep_dbcheck.py` — direct pymongo counts.
- Frontend ops matrix `scripts/_strix_frontend_matrix.py` + live op probe `scripts/_strix_live_ops_probe.py` — 22 static assets 200; per-op statuses recorded.
- Code tracing: ingress plane composition, analyst plane composition (`_attach_services`), SecureProxy dispatch/handlers, rule applicability/selection, correlation patterns, incident/centralized, router, timeline, frontend pages/API client, connector registry, source models/trust/replay.

**INHERITED FROM PREVIOUS REPORTS (not re-executed here; used only as cross-references, marked as such):**
- Cross-process concurrent single-token claim semantics (`MongoReplayStore` unique-insert) — unit/integration suites cover; plus live replay-rejection evidence executed here.

- IDOR/cross-analyst isolation, centralized re-run idempotency, concurrent case-close, restart persistence of detections/correlations/reports — carried by unit/integration suites; **not re-labelled live** (**see §22 TEST GAPS**).
- Prior STRIX D-1…D-6 patch claims — reviewed against code + partially re-verified live (D-2 case-insensitive token headers: live no-token/malformed/replay cases exercised; D-3 credential header: auth.issue exercised; replay store existence: `MongoReplayStore` code-confirmed + live claims persisted (redis count=3**.; D-4 ingress listener: live socket exercised; D-5/D-6 contract/doc semantics: confirmed in code。



**NOT IN SCOPE — NOT ON THE RELEVANT CAUSAL PATH:** AI/ML pipeline (`DETECTION_ENGINEERING_AND_FUTURE_AI.md` future), TLS termination/reverse-proxy hardening (deployment concern), secret-store integration, UI polish details unrelated to wiring correctness.



---

## 2. ACTUAL IMPLEMENTED ARCHITECTURE (code-confirmed)

**Analyst plane — `python -m scripts.proxy_server` (FastAPI/uvicorn wrapper`**
```
config → identity_store (InMem, 4 dev subjects), SessionVerifier, SecureProxy
       → SourceManagementService(SourceRepository→Mongo`source_instances`; token_issuer)
       → RuleRegistry + load_rules_from_specs(["app.rules._library.nginx"])  # 5 NGINX rules
       → RuleManagementService(RuleRepository→Mongo`managed_rules`)
       → DetectionReadService(DetectionRepository→Mongo`detections`)
       → CorrelationReadService(CorrelationRepository→Mongo`correlations`)
       → OverviewReadService / TimelineReadService(TimelineEngine, SecurityEventRepository)
       → IncidentService(IncidentRepository→Mongo`incidents`)   # correlation_engine lazy-created
       → ReportService(ReportRepository→Mongo`reports`), RoutingEngine
HTTP: /api/proxy (POST, ProxyRequest→SecureProxy.handle), /api/meta, /health, /static/* (frontend)
```
**NO `DetectionPipeline`, NO ingestion service, NO background consumer, NO automatic correlation / case creation exist on this plane.**

**Ingress plane — `python -m scripts.ingress_server`**
```
config → SourceRepository(Mongo) → MongoReplayStore(`source_token_replay`,
        unique token_id + TTL expires_at) → SourceIdentityTokenVerifier(source_resolver=repo.get)
     → SecurityEventIngestionService(SecurityEventRepository→Mongo`security_events`)
     → InboundIngressProxy(rate-limiter per-source, authoritative_source_resolver=repo.get)
HTTP: /api/ingress (POST, ops source.ingest|source.health), /api/ingress/health, /healthz, /
```
**NO rule registry, NO detection engine, NO pipeline, NO correlation, NO incident service exist on this plane.** `source.ingest` translates raw events → canonical `SecurityEvent` → `ingestion_service.ingest()` → Mongo. **Nothing else happens.**

**Repositories are not exposed on any HTTP surface;** both planes expose only their documented single wire boundary + health/meta/static.



---

## 3. INTENDED VS IMPLEMENTED (major stages)

| Stage | INTENDED (docs/architecture) | IMPLEMENTED | MATCH | Evidence |
|---|---|---|---|---|
| Source register/lifecycle/trust | register→configure→validate→enable; tokens; replay | Full service + state machine + HMAC tokens + Mongo replay store | ✅ | code + live harness steps 10–15,20,28–34 |
| Ingress (external→canonical event) | trusted boundary, per-source telemetry→canonical event, persist | Implemented exactly (token/state/integrity/rate-limit/size/idempotency) | ✅ | `app/sources/ingress.py`; live steps 16–19 |
| Event→Detection | every eligible event runs rules→detections persist | **NOT composed into any live path** — engine exists, tests/demos compose it manually | ❌ **MISSING** (composition) | `_attach_services`(proxy_server), `_build_mongo_ingress`(ingress_server); live steps 19–24 (0 detections after 8 matching events) |
| Detection→Correlation | correlation engine windows/thresholds detections→correlations | **NOT composed** — engine exists; only `IncidentService` lazy-constructs it for `case.centralized`, and demos/tests call it manually | ❌ **MISSING** (composition) | dev db: 1275 detections → **0 correlations**; live deeptest: 0 |
| Correlation→Case | correlated cluster → open incident automatically | **No live mechanism.** `case.create` = 400-by-design; `IncidentService.create_case` only called by test/demo scripts (never by any server composition); `case.centralized` requires pre-existing incident_id | ❌ **MISSING** (no mechanism at all) | live steps 25–26; `create_case(` search: only demos/tests |
| Timeline | per-incident chronological reconstruction from persisted evidence | Engine exists (pure, evidence-derived, no fabrication) but only reachable via an incident (which can’t be created live) | ⚠️ PARTIAL | `timeline/engine.py`; live 404 `timeline.build_for_incident` on nonexistent case |
| Routing | case context → deterministic destination recommendation | Engine exists (context-derived; documented matrix) but requires incident; not exercisable live | ⚠️ PARTIAL | `routing/service.py`; live `routing.compute` 404 |
| Reports | source-specific + centralized reports, export | Backend service + proxy ops exist; **zero frontend references**; require incident | ⚠️ backend ✅ / UI ❌ | frontend sweep: no `report*` refs |
| Centralized analysis | cross-source evidence re-correlation → centralized correlations, gated report | Backend `case.centralized` wired + tested; **zero frontend references**; requires pre-existing incident + evidence payloads | ⚠️ backend ✅ / UI ❌ | frontend sweep; `incidents/service.py:272` |

---

## 4. CONNECTOR / SOURCE MODEL (explicit answers)

- **What is a connector?** `app/connectors/base.py::SecurityEventConnector` — a per-source adapter producing canonical `SecurityEvent`s (`source`, collect, health). Implementations that exist: **`nginx`** (`app/connectors/nginx/connector.py`) and **`simulated`** (`app/connectors/simulated.py`). `CONNECTOR_REGISTRY` (`app/ingestion/service.py:203`) contains exactly those 2.
- **What is a source type?** `SourceType` (`app/sources/models.py:101`) — a **closed 6-value enum**: `nginx, waf, iam, rate_limit, network, simulator`. It doubles as "supported connector types" (`SUPPORTED_CONNECTOR_TYPES = frozenset(SourceType)`; `supported_connector_types()` returns all 6 sorted: `iam, network, nginx, rate_limit, simulator, waf` — **proven live** via `source.list_types`.
- **What is a source instance?** `SourceInstance` — persisted `src-<uuidv7>-<handle>` record with lifecycle state, config (secret-redacted), health. `source.register` creates a **source instance only**, никогда a connector家庭.

 - **Can a new connector family actually be created?** **THIS MECHANISM DOES NOT EXIST IN THE CURRENT IMPLEMENTATION.** There is no connector-family registry, no dynamic class loading beyond the hardcoded `CONNECTOR_REGISTRY`/config `PROSHIELD_CONNECTORS` default `simulated`, no connector-creation wire op. The 6 "connector types" are a hardcoded enum; adding a 7th requires editing `SourceType`, `SOURCE_TYPE_TO_SOURCE_STRING`, `ALLOWED_SOURCES`, `SourceInstanceView` validation, the connector package, rules, etc.
- **Can multiple source instances share a connector?** Conceptually yes (2 nginx instances can share the nginx connector family), but **no live composition consumes any connector** — the deployment never calls `collect()`/pipeline. So the sharing property is unexercised in the shipped system.



 - **What does `source.register` actually create?** A `SourceInstance` doc in Mongo `source_instances`, keyed by unique source_instance_id, with the requested `source_type` — and it validates ONLY that `source_type` is one of the closed enum values. **It does NOT check that a connector implementation (or any rule) exists for that type.** This was proven live: a `waf` source (`waf-edge-01`) was registered successfully although `app/connectors/` contains no WAF implementation and `app/rules/_library/` contains no WAF rules (DB: `source_instances` shows state=registered for waf; states⬆).
 - **Is the UI modeling this correctly?** **No — semantically+architecturally it conflates "Connector Type" with "Source Type"。** `frontend/js/components/sources.js:287` labels the register select **"Connector Type"**, populates it from `state.types` (returned by `source.list` as `supported_connector_types` — the closed enum„and dashed with "select a connector type"。The backend likewise names `supported_connector_types()` where it means the SourceType enum (`app/sources/registry.py:259`)). A user selecting "waf" believes they are adding a WAF connector; in reality they create a source instance for a type with **no connector implementation and no rules** (dangling capability. This is **not mere cosmetics**: the backend data model, rule applicability, and connector registry all key off the closed enum, and half the enum values have nothing behind them. **Classification: BACKEND ARCHITECTURE GAP (declared types without implementations) + UI SEMANTIC/NAMING ISSUE (label)**（and, per §53, the UI cannot fix this — an implementation/config/registration mechanism must exist backend-side.

---

## 5. TWO-PROXY / TWO-PLANE REPORT (live evidence

**Plane A — External source → Ingress → Backend** (`scripts/strix_deeptest_live.py` steps):
- `source.register`/`configure`/`validate`/`enable` on analyst plane (admin **200** each; step 10-14)
- `source.issue_token` → `sit-<uuid7>.<b64>.<sig>` (step 15:: 200)
- `POST /api/ingress` `Authorization: Bearer <sit>` with 8 `authentication_failure` NGINX brute-force events → **200, `accepted_event_ids`= 8 UUIDv7 ids, `rejected`= []** (step 19. Events persisted: Mongo `proshield_deeptest.security_events` count **8**, source=`nginx`, provenance `source_instance_id` set (DB check).
- Same token reused → **401 `source identity token replay rejected`** (step 20.; replays store count=3 persisted.
- Disabled source → **409 `source_not_enabled`** (step 29;; Retired source → **410 `source_retired`** (step 33;; Garbage token → **401 malformed** (step 34;; Missing token → 401.
- Analyst op at ingress (`case.list`) → **400 `unknown ingress operation`** (step 16)) — plane isolation enforced.

**Plane B — Frontend → SecureProxy → Backend** (live steps 21-26,31-32):
- `detection.list` → 200 `detections: []` right after the 8 accepted brute-force events (step 21;; `correlation.list` → 200 `[]` (step 22;; `case.list` → 200 `[]` (step 23;; `overview.summary` → **detection_count=0, correlation_count=0, open_case_count=0** (step 24;; `case.create` → **400** (documented boundary, step 25;; `case.centralized` with nonexistent incident_id → **404 `case not found`** (step 26.
- Raw telemetry at analyst proxy (`source.ingest`) → **400 `unknown operation`** (step 17)) — plane isolation enforced.



**Cross-plane summary:** The two planes are cleanly separated (no telemetry at analyst proxy, no analyst ops at ingress, no repo exposure.** But **neither plane ever connects ingestion to detection/correlation/case** — exactly where the documented E2E pipeline must flow (§7).

---

## 6. COMPONENT-BY-COMPONENT REPORT

### C1 Connector + source architecture — **MIXED**
- Code: connector base/nginx/simulated well-built; source registry/service/repository/trust/replay complete; lifecycle machine enforced (`registry.py::ALLOWED_TRANSITIONS`**; admin-only writes (proxy + service双重 gates**.
- Gap: only 2 of 6 declared types have implementations/rules (§4); no connector-family creation mechanism（§4).
Evidence: code (`app/connectors/`, `app/ingestion/service.py:203`, `app/sources/models.py:101`); live `source.list_types`（6 values); live registration of a waf source succeeding.

### C2 Source configuration + identity + trust + ingress — **PASS (component)**
- Live: token issue/verify, replay-reject, disable 409, retire 410, garbage 401, malformed JSON 400, no-token 401, integ 403 (token-source mismatch path exists in code`, rate limiting (per-source budget code;; size caps code.
Units cover cross-process concurrent single-claim (`MongoReplayStore` unique-insert invariant code-confirmed).

### C3 SecureProxy + frontend wiring — **MULTIPLE GAPS (§8, §20)**
### C4 Rules + rule ownership + rule selection — **PASS (backend), rows in UI partly dead**
- 5 NGINX rules seeded as APPROVED+enabled (live `rule.list` = 5: all `state=approved enabled=True`。 Rule selection = `is_evaluable() AND source∈metadata.sources AND event_type∈metadata.event_types` (`app/rules/types.py:349`, engine hot-path `registry.applies_to`)**; source isolation unit+script-proven (NGINX rule doesn’t fire on iam source: `detection_boundary_test.py` [IAM-NO-NGINX → 0 detections)。
- UI: `rule.approve/rule.revoke/rule.history` don't exist backend(→400 live;** rule governance unactionable via UI (§8.**. `rule.create` (admin) requires `rule_id` at top level (`proxy.py:1705-1725`); frontend has no create-dialog calls in code (rules.js declares rule.create comment-only**, so rule creation isn’t wired either.

### C5 Detection + no-rule semantics + false positives — **ENGINES PASS; LIVE COMPOSITION MISSING**
- Positive (nginx auth_failure 401 /auth/login → `NGINX-AUTH-BRUTEFORCE-001` + `NGINX-AUTH-FAILURE-001` detections; boundary test PASS**; benign (authentication_success→0**; no-match (tls_anomaly→0**; cross-source (iam→0** (isolation。
- Detection provenance: `detection_id` deterministic `det-<uuid7>` from (rule,version,event,detected_at); `evidence_refs=(event_id)`; rule_id/version/category persisted (`detection/models.py`）。
 - **The live deployed planes never run this engine** (§7): proof — 8 matching events →  0 detections./

### C6 Correlation + case — **ENGINE PASS; NO LIVE PATH**
- `BruteForceClusteringPattern`: distinct-event count ≥ threshold(8?) within window, key=`(source_ip, endpoint)`, count=distinct events (CORRELATION-01,, pattern `NGINX-CORR-BRUTEFORCE-001`, trigger `brute_force_count_threshold`。 Demo (in-process): 8 auth failures (2 detections each) →  4> … → 1 correlation `key=10.0.0.66|/auth/login count=8` — component-proven**.
- No live composition (`correlation_engine.run` only in `IncidentService._run_centralized` + demo/tests); **no auto case-creation** (`case.create` 400;`IncidentService.create_case` only called by demos/tests.; dev db: 1275 detections →  0 correlations →  0 cases (live query; secondance proven**。

### C7 Timeline + routing + reporting — **ENGINES PASS; live-reachability BROKEN**
- Timeline engine pure + evidence-derived(§14„;routing deterministic context-derived matrix;report service + proxy ops (JSON export„. but all three require an incident → and incidents cannot be created live (§C6), и UI has no timeline/report wiring (timeline.list vs build_for_incident; no report refs**。
 Live: `timeline.build_for_incident` →404 on nonexistent case; `report.generate_normal` →404; `routing.compute` →404; `report.list` →400 `incident_id required`。

### C8 Centralized analysis + complete analyst workflow — **BACKEND PARTIALLY; UI ABSENT; live not exercisable**
- Backend `case.centralized` → `IncidentService.request_centralized_analysis` (authz CASE_CENTRALIZED_REQUEST + case access; payload-shaped detection/event refs; dedup merged; rate-limited 5/min**。
- **No frontend call to `case.centralized` exists** (frontend sweep: zero refs； case.js closes/adds notes/assigns (op that do not exist** но no centralized. An analyst cannot request centralized analysis from the UI**。 And it requires pre-existing incident + evidence payloads — which no live process can produce\|.

---

## 7. FULL PIPELINE VERIFICATION (per-pipeline arrows

| arrow | status | evidence |
|---|---|---|---|
| external source → connector/source | VERIFIED (partial) | live register/configure/validate/enable + source_type enum |
| source → trust (token) | VERIFIED | live token issue + single-use replay |
| source → ingress → canonical event | VERIFIED | live 8 events accepted; Mongo source/provenance correct |
| canonical event → persisted | VERIFIED | Mongo security_events=8 |
| event → rule eligibility | PARTIALLY VERIFIED (component-level only | `detection_boundary_test.py`; applicability code; **no live composition** |
| rule eligibility → evaluation → detection | PARTIALLY VERIFIED (component-level) | boundary test 2 detections; **not live** (live: 0 detections) |
| detection → persistence | PARTIALLY VERIFIED | integration suite; DetectionRepository; live none produced |
| detection → correlation | **MISSING (live)** | dev db 1275 detections → 0 correlations; no consumer |
| correlation → case | **MISSING (no mechanism)** | `case.create` 400; `create_case` unreachable live; `case.centralized` 404 without pre-existing case |
| case → timeline | PARTIALLY VERIFIED (component) | engine code; live unreachable (no case) |
| case → routing | PARTIALLY VERIFIED (component) | engine code; live unreachable |
| case → report (source-specific/centralized) | NOT VERIFIED live (backend ops exist, UI absent, requires case) | frontend zero refs; no case creation |
| centralized analysis → centralized correlation | BACKEND VERIFIED/UI MISSING | `case.centralized` handler+service tested in suite; zero frontend refs |
| → analyst UI | **BROKEN (wiring)** | 10 ops called by UI return 400; no report/centralized UI paths |

**Pipeline verdict: arrows 1-7 of the E2E chain are partially/fully component-verified but **arrows 8-10 (detection→correlation→case→...) are not composed into any live runtime path;the shipped product cannot reach them.**
---

## 8. FINDINGS (required format; line numbers approximate, 0-based)

### F-1 — NO LIVE DETECTION/CORRELATION/CASE PIPELINE IN THE DEPLOYED PLANES
- **SEVERITY:** P0 (blocker for the documented product) **CATEGORY:** BACKEND ARCHITECTURE GAP (composition/wiring, not engine logic)
- **SUMMARY:** The two shipped server wrappers never compose detection, correlation, or case creation. An external source that authenticates and sends matching telemetry gets its events **persisted only**; nothing downstream runs.
- **EXPECTED:** External event → ingress → canonical event → eligible rule → detection → correlation → case (documented E2E chain), automatically, in the running system.
- **ACTUAL (live, `proshield_deeptest`):** 8 accepted NGINX auth-failure brute-force events → `detection.list=[]`, `correlation.list=[]`, `case.list=[]`, `overview.summary detection_count=0/correlation_count=0/open_case_count=0`; Mongo `detections=0`, `correlations=0`, `incidents=0` while `security_events=8` (source/provenance correct). Dev-DB cross-check: 1275 persisted detections → **0 correlations → 0 cases** even with detections present.
- **ROOT CAUSE (code):** `scripts/proxy_server.py::_attach_services` wires read services + rule mgmt + incident/report/routing only; `scripts/ingress_server.py::_build_mongo_ingress` wires ingestion only. `DetectionPipeline(` appears only in `scripts/demo_security_workflow.py:114`, `demo_phase47.py:129`, `demo_phase48.py:192`, `detection_boundary_test.py:102` — test/demo composition. `IncidentService.create_case(` only in scripts/tests; `case.create` is a 400 boundary (`_handle_create_case`, `proxy.py:880-901`); `case.centralized` requires a pre-existing `incident_id` (`incidents/service.py:272+`).
- **EXACT REQUESTS/RESPONSES:** `strix_deeptest_evidence.ndjson` steps 19 (ingest 200, 8 accepted), 21–24 (all 200, all empty/zero), 25 (case.create 400), 26 (case.centralized 404). Proxy log: HTTP lines only, no detection attempt.
- **UPSTREAM/DOWNSTREAM:** Upstream = correct ingress/trust (no defect). Downstream = every consumer (timeline/routing/reports/centralized) starves.
- **WHY THIS LAYER OWNS IT:** Frontend cannot conjure detections a backend never produces. This is a backend/deployment composition gap.
- **SECURITY/FUNCTIONAL/ANALYST IMPACT:** Critical — no automated detection, no incident, blind spots in a production-style deployment.
- **RECOMMENDED FIX:** Ship a **live pipeline composition** (product, not test infra): on event persist run `DetectionPipeline`(ingestion→engine→DetectionRepository); batch detections into `CorrelationEngine` windows/thresholds → `CorrelationRepository`; add an automatic correlation→case policy (`IncidentService.create_case` with full evidence, idempotent on cluster key) — mirroring what `demo_security_workflow.py` does manually, wired into server bootstrap.
- **NEW FILE:** YES (`app/pipeline/` module + server bootstrap wiring). **API CHANGE:** None. **SCHEMA:** None.
- **REGRESSION TEST:** live E2E: spawn both planes + fresh Mongo, send 8 matching events, assert detections/correlations/case appear (window-race-tolerant) without manual composition.
- **CONFIDENCE: HIGH** (runtime + DB + code all agree).
### F-2 — NO LIVE CASE-CREATION MECHANISM ANYWHERE (wire level)
- **SEVERITY:** P0 **CATEGORY:** BACKEND IMPLEMENTATION GAP
- **SUMMARY:** `case.create` is a documented 400 boundary; `IncidentService.create_case` is only invoked by tests/demos (never by any server composition); `case.centralized` requires an existing incident. A case can NEVER be created by the running system via any wire op. **THIS MECHANISM DOES NOT EXIST IN THE CURRENT IMPLEMENTATION.**
- **EXPECTED:** Correlation → automatic case open (SOC workflow), or a wire-safe case-create with full evidence.
- **ACTUAL (live):** `case.create` → 400;`case.centralized` → 404 (no case exists). Code search: `create_case(` matches only `app/incidents/service.py`, `scripts/demo_phase48.py`, `scripts/demo_security_workflow.py`, tests.
- **ROOT CAUSE:** Case creation was deliberately excluded from the wire (Phase 4.8 "boundary") and the automatic trigger was never built。 **IMPACT:** Cases — and therefore timeline/routing/reports/centralized analysis — are unreachable in production flow**. **FIX:** live case policy (F-1) or promote wire `case.create` with evidence (option (a) per the `_handle_create_case` docstring.** **NEW FILE:** YES (with F-1) or NO (if promoting handler)。 **CONFIDENCE: HIGH.


### F-3 — FRONTEND CALLS 10 NON-EXISTENT BACKEND OPERATIONS (live 400s)
- **SEVERITY:** P1 **CATEGORY:** FRONTEND WIRING BUG (+ UI↔contract op-name drift)
- **SUMMARY:** UI ops missing from backend `ALLOWED_OPERATIONS`, live-verified 400 `unknown operation`: `timeline.list` (timeline.js:25, case.js:28; backend op: `timeline.build_for_incident`); `case.assign` (case.js:163）、`case.add_note` (case.js:201）、`case.add_recommendation` (case.js:243）、`rule.approve` (rules.js:175）、`rule.revoke` (rules.js:197）、`rule.history` (rules.js:48）、`correlation.confirm` (correlations.js:69）、`correlation.dismiss` (correlations.js:72）、`api.meta` (health.js:26 — should be `GET /api/meta`， not a proxy op).
- **EXPECTED:** Each button maps to a shipped op, or dead controls are hidden/disabled.
- **ACTUAL (live, `strix_ops_probe.txt`):** all 10 → **400 `validation_error/unknown operation`** (exact bodies recorded); `GET /api/meta` → 200 separately. Frozen contract inventory lists `rule.create/update/version/enable/disable/retire`, `case.centralized`; it does NOT list `case.assign/add_note/add_recommendation`, `rule.approve/revoke/history`, `correlation.confirm/dismiss`, `timeline.list` — UI diverges from contract.
- **ROOT CAUSE:** UI written against an older op vocabulary; backend ops renamed/never shipped; hadn't updated. **IMPACT:** Timeline page + case timeline panel always error; Rules governance (approve/history/revoke) dead; Case detail (assign/note/recommendation) dead; Correlations confirm/dismiss dead; Health `api.meta` row false-red. **ANALYST IMPACT: High.**
- **FIX:** Align frontend to shipped ops (`timeline.build_for_incident` with incident_id; `rule.retire`/`rule.update`/`rule.version` for revoke/history; case notes/assignment are "planned" by design — **hide or disable those controls** (or backend-implement them if in scope); `api.meta` → use `PSAPI.loadMeta()` (already in api.js), not a proxy call. **NEW FILE:** NO. **API CHANGE:** NO (contract-drift fix). **REGRESSION TEST:** op-probe matrix + per-page e2e. **CONFIDENCE: HIGH.
### F-4 — CENTRALIZED ANALYSIS + REPORTS: ZERO FRONTEND WIRING(backend-only capabilities reachable by no UI action)
- **SEVERITY:** P1 **CATEGORY:** FRONTEND WIRING BUG (BACKEND EXISTS − FRONTEND NOT WIRED)
- **SUMMARY:** Whole-frontend sweep × 2: no `case.centralized`, no `report.*`, no `export` references in any `frontend/**/*.js`. Backend ops (`case.centralized`, `report.get/list/generate_normal/generate_centralized/export`) are wired in `SecureProxy` (dispatch+handlers, unit/integration-tested) but analysts cannot trigger them from the UI. The audit's "centralized badge" + "report download" claims have no UI path.
- **EXPECTED:** Case-detail page offers "Request centralized analysis" and "Generate source-specific/centralized report + export" actions.
- **ACTUAL:** No such UI action exists; ops only curl-able (and require an incident → F-2)。
- **FIX:** Add case-detail UI actions → `case.centralized` (sending the case’s evidence refs) and `report.generate_normal`/`report.generate_centralized`/`report.export`(handlers already exist. **NEW FILE:** NO. **API CHANGE:** NO. **CONFIDENCE: HIGH.



### F-5 — `source.register` VALIDATION ERRORS ESCAPE → MISLABELED 401 "internal error"
- **SEVERITY:** P1 **CATEGORY:** API CONTRACT BUG + BACKEND VALIDATION GAP + SECUREPROXY BUG (error classification)
- **SUMMARY:** When `tags`/`asset_tags` aren't sorted/unique (model invariant `app/sources/models.py` `asset_tags must be unique and sorted`), Pydantic raises from `SourceManagementService.register` (service.py:201-212) uncaught; `SecureProxy.handle` generic `except Exception` (`proxy.py:489-497`) maps it to **401 `authentication_required`/"internal error"** — wrong status+code+semantics; root cause hidden (exact pydantic text only in internal_detail/log**。
- **REPRO (live):** `source.register` with `"asset_tags": ["web","api"]` (admin session) → **401 `{"error":{"code":"authentication_required","message":"internal error"}}`**;log traceback: `_handle_source_register → service.register → SourceInstanceConfiguration → ValidationError: asset_tags must be unique and sorted` (strix_deeptest_proxy.log**。 The default frontend register form passes user-typed order so "web, api" fails the same way. **Expected:** 400 `validation_error` safe message (or server-side normalize/sort)。
- **ROOT CAUSE:** service boundary doesn't wrap `PydanticValidationError → DomainValidationError`;generic proxy fallback mislabels internal errors as auth failures. **IMPACT:** admin registration fails with misleading auth error; no actionable message; users chase login/health issues. **FIX:** catch pydantic in service → `DomainValidationError` safe_message 400; generic fallback → 500 `internal_error` (see F-7); optionally normalize tags in wire layer. **NEW FILE:** NO. **REG:** unit register-with-unsorted-tags → 400; e2e. **CONFIDENCE: HIGH (live + log + line refs)。



### F-6 — "CONNECTOR TYPE" CONTROL CONFLATES CONNECTOR FAMILY WITH SOURCE TYPE; 4 OF 6 DECLARED TYPES HAVE NO IMPLEMENTATION/RULES
- **SEVERITY:** P1 **CATEGORY:** BACKEND ARCHITECTURE GAP + CONNECTOR BUG (+ UI NAMING ISSUE**
- **SUMMARY:** `supported_connector_types()` == `frozenset(SourceType)` (6 closed enum values: `iam, network, nginx, rate_limit, simulator, waf`). Real connector implementations exist only for **nginx** and **simulated** (`app/connectors/`, `CONNECTOR_REGISTRY` ingestion/service.py:203; no `connectors/waf.py` etc.** Rules exist only for nginx (`app/rules/_library/nginx/`, 5 rules**. The register select, labelled "Connector Type" (sources.js:287), lets an admin register a `waf`/`iam`/`network`/`rate_limit` source — proven live: `waf-edge-01` registered though NO WAF connector/rules exist (DB `source_instances` state=registered. Such a source can never be ingested-processed (no connector) nor detected (no rules. Cosmetic naming? **NO — functional+**: half the catalogue is dangling; the UI promises connectors the product cannot deliver. The `sources.js` table row also prints `s.connector_type` (undefined field) for the provider/type column (`rowFor`: `(s.tags||[])[0] || s.connector_type || "—"`) —another conflation artifact.. 
- **EXPECTED:** Either (a) ship real implementations+rules for all 6 declared types, or (b) advertise only implemented connector types, or (c) implement a dynamic connector-family registration mechanism with register-time implementation validation（reject types without an implementation+rules).
- **FIX:** (minimal, honest) `source.list_types` returns only types with installed implementations (nginx, simulator); register-time validation rejects unimplemented types with a clear message; (proper) build connector-family mechanism: registry of families→implementations, per-family rules packages dynamic load, register-time presence check. **NEW FILE:** for (proper: `app/connectors/__init__.py` registry + rules packages per family; **API CHANGE:** `source.list_types` semantics (или add `connector.register`); **REGRESSION:** list_types ⊆ implemented; register unimplemented → 400; UI options reflect that. **CONFIDENCE: HIGH (code inventory + live registration + live list）。



### F-7 — UNEXPECTED-EXCEPTION ENVELOPE USES 401 `authentication_required` FOR INTERNAL ERRORS
- **SEVERITY:** P2 **CATEGORY:** SECUREPROXY BUG / API CONTRACT BUG
- **SUMMARY:** `SecureProxy.handle` catches ANY non-domain exception (`proxy.py:489-497`) into `ProxyUnauthorizedError(401, "internal error")`. Internal failures become indistinguishable from authentication failures to clients+monitoring (status/error-code lie)。 Live exemplar: F-5's pydantic escape surfaced as 401. Expected: 500 `internal_error` safe envelope (contract error table: "500 internal error unexpected exception (safe envelope)"; note `response_too_large` is already 500**。 **FIX:** map generic fallback to 500 `internal_error` envelope (log+internal_detail already present; keep auth failures distinct). **CONFIDENCE: HIGH。
### F-8 — NO RULE DISABLE/RETIRE/NO-MATCH/FALSE-POSITIVE TEST POSSIBLE ON LIVE DEPLOYMENT(TEST GAP; engine semantics unit-proven)
- **SEVERITY:** P2 **CATEGORY:** TEST GAP (not a product defect per se; a verification limitation)
- **SUMMARY:** Because no live path runs rules (§F-1),rule lifecycle effects (disable/retire→stale-eval?, no-match semantics, false-positive boundaries at the running system) can only be exercised via in-process scripts/tests — not against the deployed planes. Suites cover them(unit: test_nginx_rule/brute_force/rule_base/rule_evaluation/phase47…; integration phase45-49; detection_boundary_test: BENIGN→0, NO-MATCH→0, IAM→0**. **PASSING TEST DOES NOT PROVE THIS REQUIREMENT** for the live system until F-1 is wired up. **CONFIDENCE: HIGH.



---

## 9. DETECTION REPORT

| Case | Result | Evidence |
|---|---|---|---|
| Positive (matching NGINX rule) | Engine ok: 2 detections (`NGINX-AUTH-BRUTEFORCE-001`, `NGINX-AUTH-FAILURE-001`) per auth-failure event | `detection_boundary_test.py` PASS; demo workflow 2 detections/event |
| No-rule / unknown event type (`tls_anomaly`) | 0 detections (ingested-only semantics when composed manually; **live: 0 detections because engine never runs**) | boundary test; live F-1 |
| Benign (`authentication_success`) | 0 detections | boundary test |
| Cross-source (iam auth_failure vs NGINX rule) | 0 — source isolation engine-proven | boundary test `[IAM-NO-NGINX]` |
| False positive / boundary sweep | unit-covered (`test_detection_engine`, `test_phase44_rules`, `test_phase47_conditions`, `detection_boundary_test`),not live-executable (F-8) | — |
| Disabled/retired rule → stale eval | unit-covered (registry `is_evaluable()` gates; integration phase47/49**, not live-executable (F-8) | — |
| Duplicate event idempotency | unit/integration-covered (repo unique event_id; pipeline stable detection_id on replay**) | suites |
| Provenance | `detection_id` deterministic from (rule,version,event,detected_at); `evidence_refs=(event_id)`; rule_id/version/category persisted | `detection/models.py` + DB samples (demo detections show rule/event refs) |
| Persistence | live: Mongo `detections` = 0 (nothing produced**; suites prove repo works when called | dev-db 1275 detections (legacy data) persisted |


## 10. CORRELATION REPORT

| Property | Result | Evidence |
|---|---|---|---|
| Pattern | `BruteForceClusteringPattern` (NGINX-CORR-BRUTEFORCE-001, trigger brute_force_count_threshold, key=`(source_ip,endpoint_key)`, window, threshold, distinct-event count — CORRELATION-01) | `correlation/patterns.py` |
| Threshold/window/duplicates | unit + integration covered (`test_correlation_engine`, `test_correlation_repository`, phase45-46)**; not live-executable | suites |
| Same-source correlation | demo: 8 auth-failure events →  1 correlation (`key=10.0.0.66\|/auth/login count=8`) | `demo_security_workflow.py` |
| Cross-source correlation | **No pattern exists for multi-source** (patterns.py explicitly defers WAF+NGINX etc. until connectors exist)。 Centralized cross-source re-correlation lives only in `case.centralized` backend path (requires case) | code |
| Live automatic correlation | **ZERO in the deployed system** (dev db 1275 detections → 0 correlations; deeptest 0) | DB counts |
| Evidence IDs | correlation_id deterministic from (pattern,version,trigger,key,window,detection_ids); event_ids + detection_ids persisted, resolvable when repos populated | `correlation/models.py` + demo records |


## 11. CASE / INCIDENT REPORT

| Property | Result |
|---|---|
| Creation | **NO LIVE MECHANISM (F-2)**；`case.create` 400 boundary; `IncidentService.create_case` only demos/tests |
| Evidence/RBAC/timeline linkage | Models carry event/detection/correlation ids + lifecycle history; authorized read (CASE_READ_ANY vs owner); unit/integration covered |
| State transitions | open→close (idempotent-second-close 409) covered in suites; lifecycle_history transitions appended |
| Report linkage | case→report ids in report service (requires case) |
| Live analyst workflow | **BROKEN**: no case can exist live; case-detail notes/assign UI ops →  400 (F-3) |


## 12. TIMELINE REPORT

- Engine is pure evidence-derivation: kinds OBSERVED/DETECTION/CORRELATION, `occurred_at` from event_time/detected_at/window_start (no fabrication; missing evidence skipped — engine.py design documented). Component tests cover ordering/attribution/linkage (`test_timeline_engine`, unit+integration)。
- **Live reachability broken:** op is `timeline.build_for_incident` (per-incident) but frontend calls `timeline.list` (→400)and requires an incident (cannot exist live→404**. No phantom events manufactured anywhere (engine refuses**。 **FINDINGS: F-1, F-2, F-3 apply。
## 13. ROUTING REPORT

- `RoutingEngine.route(RoutingContext(incident, severity/confidence/complexity/evidence))` → deterministic (level, team, queue) via the documented MVP matrix (`routing/service.py::_decide`; centralized-correlation→minimum L2; severity/complexity table). Backend `routing.compute` wired + unit/integration covered.

- **Live reachability broken:** requires `incident_id` (404 live on nonexistent; no incident can exist live** — F-2**; UI has zero routing references. **FINDING: F-1/F-2 (owner: backend composition); the engine itself behaves per spec (deterministic recommendations, no fabrication, fail-safe）。 The audit's Source-A→Destination-A vs Source-B→Destination-B auto-dispatch matrix **cannot be exercised live**: there is no source→destination auto-dispatch binding (destinations are a case-context label only, optional per-source config field, no wire path auto-sends to a destination.** **Automated destination dispatch DOES NOT EXIST IN THE CURRENT IMPLEMENTATION.** Classify: if the audit/spec demands auto-send, this is a BACKEND IMPLEMENTATION GAP; if recommendation-only was the spec (Phase 4-08 report treats it as recommendation), it is a PRODUCT EXPECTATION MISMATCH (audit) vs PRODUCT DESIGN CHOICE (implementation. Report records this explicitly rather than calling the engine defective.



## 14. CENTRALIZED ANALYSIS REPORT

- Backend: `case.centralized` → `IncidentService.request_centralized_analysis` — permission CASE_CENTRALIZED_REQUEST + case-access, evidence carried as payload-shaped refs (never raw docs), dedup-merged, rate-limited 5/min, outcome lists new_correlation_ids/combined_correlation_ids/failed. Unit+integration covered (`test_phase48_incidents/reports`, phase410_pipeline**。
- **Frontend: ZERO wiring (F-4**。 **Live exercisability:** 404 without pre-existing incident (and evidence payload required; no live case produce them** — F-1/F-2 block. Original-evidence preservation: centralized re-correlation reads supplied detections/events refs and creates NEW correlations;it does not rewrite source evidence (code-path confirmed; live-unexercised)。



##  15. PERSISTENCE REPORT

- Real MongoDB used throughout live harness: fresh db `proshield_deeptest`; collections `security_events(8), source_instances(2), managed_rules(5), source_token_replay(3)`; detections=0, correlations=0, incidents=0 (post-ingress; see §7**。
- Source lifecycle persists (register→…→retired reflected in `source_instances` docs**; replay claims persist (`source_token_replay` count 3**; events persist with source_instance_id provenance。
- Restart persistence of sources/detections/correlations/cases/reports: covered by integration suites (`test_persistence_failures`, phase46/48/49/49b, persist_e2e_strix**) but not re-executed live here;**deeptest did not need restart** (stated as gap in §22**。
- Frontend state vs runtime state vs DB state: for sources page, the table reads `source.list` (DB-backed) — consistent; for detections/correlations/cases the UI reads DB-backed repos but those repos are empty live because no composition produces rows (F-1（。


---

## 16. SECURITY FINDINGS

###  ​17. FRONTEND FINDINGS

###  ​18. BACKEND FINDINGS

###  ​19. DEPLOYMENT FINDINGS

*Note: the four subsections below summarise F-1..F-8; full per-finding detail sits in §8. The merged paragraph covers all four.*

- **SECURITY (positive):** plane separation verified live (ingress rejects analyst ops 400; analyst proxy rejects raw telemetry 400; auth 401 wrong cred; RBAC source register analyst 403; source trust reviewed: valid 200, replay 401, disabled 409, retired 410, garbage 401, no-token 401.** IDOR/cross-analyst case isolation, centralized authorization: covered in unit/integration suites (`test_phase48_auth`, `test_phase49_proxy.rbac_regression', phase410_pipeline; not re-executed live.
- **FRONTEND:** 22/22 static assets 200; per-page ops matrix recorded; findable gaps: F-3 (10 dead ops), F-4 (centralized/reports unwired**, F-6 (Connector Type label/semantics**, plus errors above. **BACKEND:** F-1 (composition gap**, F-2 (no case path**, F-5 (validation escape→401**, F-7 (generic fail→401**。 **DEPLOYMENT:** F-1/F-2 (server bootstrap wiring**, plus documented pre-existing: plain-HTTP listeners need TLS termination (outside this task's scope**, `--backend memory` is dev-only (not cross-process safe; production MUST use `--backend mongo` — README-codified; live used mongo。



##  20. MISSING MECHANISMS (完整 list)

| Mechanism | Status |
|---|---|---|
| Live detection pipeline composition (event→rule→detection in server runtime) | **THIS MECHANISM DOES NOT EXIST IN THE CURRENT IMPLEMENTATION.** (F-1) |
| Live correlation composition (detection→correlation in server runtime) | **DOES NOT EXIST in the deployed composition** (F-1; engine exists, unconnected) |
| Automatic correlation→case creation (any wire- or event-driven trigger) | **DOES NOT EXIST** (F-2) |
| Wire-level case creation (even manual, full-evidence) | **DOES NOT EXIST** (`case.create` 400-boundary) |
| Automated destination dispatch (source/detection→destination routing) | **DOES NOT EXIST** (recommendation-only implemented) |
| Connector-family creation/registration mechanism | **DOES NOT EXIST** (closed enum; 4 ث من 6 types unimplemented) (F-6) |
| Frontend wiring for centralized analysis, reports, export | **DOES NOT EXIST** (F-4) |
| Frontend wiring for case assign/note/recommendation, rule approve/revoke/history, correlation confirm/dismiss, timeline.list | Ops don't exist backend (live 400;F-3) — controls dead |
| Rule governance flow (candidate→approved→enabled→…) at the wire | Partial (create/update/version/enable/disable/retire exist; approve/revoke/history absent; UI no create flow) |
## 21. FALSE CONFIDENCE (things that look correct but are not proven)

| Appearance | What it actually proves | What it does NOT prove |
|---|---|---|---|
| `source.list_types` → 6 "connector types" | A closed 6-value enum exists | 6 real connectors/rules exist (F-6) |
| Sources UI shows a source row + state badge | The row is a persisted `SourceInstance` doc | The connector/ingestion works, or any detection will ever use it |
| "Test Connection" (source.validate) 200 | The service accepts the state transition | Any real connectivity to an external system (validate is a state op; no network probe to the endpoint exists in code) |
| `source.issue_token` 200 | HMAC token issued | The token proves the source can actually emit telemetry (ingest wiring separate) |
| Ingress ingest 200 `accepted_event_ids` | 8 events validated+persisted |  0 detections/correlations/cases will follow (F-1) |
| `detection.list` 200 | The read repo is alive+authorized | Any detection is being produced |
| `rule.list` shows 5 approved+enabled NGINX rules | 5 rule definitions are loaded | Rules are ever evaluated against live telemetry (F-1) |
| `demo_security_workflow.py` "DEMO COMPLETE all phases executed" | The engines work when a test script manually composes them in-process | The deployed planes compose them (they don't) — **PASSING TEST DOES NOT PROVE THIS REQUIREMENT** |
| Unit 1185 + integration 86 green | Engines/repos/proxy units behave per tests | The live two-plane composition (the product's actual E2E) works |
| 2026-09-04 deeptest all 200s harness steps | Individual plane boundaries behave | Downstream pipeline (detection/correlation/case) is composed |
| "centralized badge"/"report download" UI claims (docs) | Backend ops exist | UI can trigger them (F-4) |
| `case.close` works in demo | IncidentService + repo work | A case can be created live (F-2) |
| Routing recommendation in unit tests | Engine is deterministic | Auto-dispatch to destinations exists (it doesn't) |


## 22. TEST GAPS (still unverified live)

1. Restart persistence lifecycle revisited live (sources/replay/events/detections/correlations/cases/reports across server restart) — covered by integration suites largely。
2. Cross-process concurrent single-token-claim (two workers racing same token_id) — covered by `MongoReplayStore` unique-insert invariant + suite; not raced live here.3. Cross-analyst IDOR (alice vs bob case access,) — suite-covered (`test_phase48_auth`, `test_phase49_proxy.rbac_regression; not re-run live.4. Centralized-analysis idempotency / concurrency re-run — suite-covered (`phase410_pipeline`; not re-run live.5. Case-close concurrency (two closes) — suite-covered;not re-run live.6. Disabled/retired rule stale-eval live check — impossible until F-1 live pipeline exists (F-8**。7. False-positive/negative boundary sweeps at live proxy — same blocker(F-8)。8. Browser/DOM/console/screenshot evidence — Playwright unavailable this session; frontend assessed via HTTP+static+op-probe (DOM outcomes inferable from ops, but not screenshot-confirmed here.9. Rule governance full flow (candidate→approved) — `rule.approve` absent from backend (F-3); governance partially covered by suites。10. Multi-source E2E (WAF/IAM/network/rate_limit sources) — **impossible**: no connectors/rules exist for them (F-6)。


## 23. EXISTING TESTS VS REALITY

| Test/Suite | What it proves | What it does NOT prove |
|---|---|---|---|
| `tests/unit` (1185) | Engine/model/repo/proxy unit behavior, auth/RBAC matrices, replay/store units, wiring handlers | Live composition; HTTP transport; Mongo real docs (unit uses fakes/mocked) |
| `tests/integration` (86, real Mongo) | Repos+pipeline+proxy handlers against real Mongo; phase45-49/410 pipelines; persistence failures | The deployed server processes compose the pipeline (integration composes services in-test**; server wrappers don't) |
| `test_strix_ingress_wire.py` | Ingress proxy unit (token/state/integrity/RBAC) | That ingestion triggers detection/correlation in the server runtime |
| `live_ingress_smoke.py` | Real socket ingress listener health/no-token/malformed | Downstream pipeline |
| `detection_boundary_test.py` | Engine source isolation + positive/negative/benign | Live wiring of engine into servers (it composes pipeline itself in-process** |
| `demo_security_workflow.py` | Full engines chain WHEN manually composed in memory (detection→correlation→case→close→overview) | The product's deployed planes composecha chain without a test script |
| `persist_e2e_strix.py`, `smoke_test.py`, `e2e_test.py`, `check_wiring.py`, `verify_sources_fix.py` | Prior-range E2E/wiring on memory/mongo bundles | (Same composition caveat — check each script; several compose engines in-process) |
| `strix_deeptest_live.py` (this task) | REAL two-plane + real Mongo + real HTTP: trust/replay/disable/retire/plane-isolation work; **ingest produces events only;0 detections/correlations/cases** | (Nothing more needed: this IS the runtime truth) |


## 24. COMPLETE REGRESSION RESULTS

| Command | Result | Duration |
|---|---|---|---|
| `python -m pytest tests/unit -q -p no:cacheprovider` | **1185 passed**, 1 deprecation warning | 6.88s |
| `python -m pytest tests/integration -q -p no:cacheprovider` | **86 passed**, 1 deprecation warning(real MongoDB) | 12.23s |
| `python -m scripts.strix_deeptest_live` | **35/35 steps executed** (final evidence `strix_deeptest_evidence.ndjson/.json`; plane logs, DB counts) | ~35s |
| `python scripts.live_ingress_smoke.py` | **PASS** (health/no-token 401/malformed 400) | ~2s |
| `python scripts.detection_boundary_test.py` | **PASS** (positive 2 detections/no-match 0/benign 0/iam 0) | ~3s |
| `python scripts.demo_security_workflow.py` | **PASS only via in-process manual composition** (8 matching events → 16+ detections → 1 correlation → 1 case → close) | ~4s |
| `python scripts._strix_frontend_matrix.py` | 22/22 static 200; per-op statuses recorded | ~3s |
| `python scripts._strix_live_ops_probe.py` | 10/13 ops → **400 unknown operation** (F-3); 3 wired ops live | ~2s |

**What the suites prove:** engines/repos/proxy/trust/replay/RBAC units + real-Mongo repo/pipeline integration behave per their tests. **What they do NOT prove:** the shipped server composition runsच E2E (F-1/F-2 live disprove it)。



##  25. PRIORITY FIX PLAN

| Prio | Issue | Owner | File(s) | Fix | Regression |
|---|---|---|---|---|---|
| P0 | F-1 no live detection/correlation pipeline | Backend/architecture | new `app/pipeline/`; `scripts/ingress_server.py` (or dedicated worker) | Wire engine+correlation+auto-case policy into server startup(mirror `demo_security_workflow.py` composition but as product code) | Live two-plane E2E asserting detections+correlations+case after 8 events |
| P0 | F-2 no wire/automatic case creation | Backend | F-1 case policy or `_handle_create_case` promotion | Implement auto case (idempotent cluster-key) or full-evidence wire create | Wire e2e case creation |
| P1 | F-3 10 dead UI ops | Frontend | `frontend/js/components/*.js` | Align op names to shipped ops; hide/disable planned-but-unshipped controls; `api.meta`→`loadMeta()` | op-probe matrix green |
| P1 | F-4 centralized/reports unwired in UI | Frontend | `frontend/js/components/case.js` | Add case-detail buttons → `case.centralized` + report ops (handlers exist) | UI e2e |
| P1 | F-5 pydantic escape→401 | Backend/API | `app/sources/service.py` register/configure; proxy generic fallback | Wrap pydantic→DomainValidationError(400);/or normalize tags; fallback→500 | unit+wire e2e register unsorted tags→400 |
| P1 | F-6 connector-type conflation/phantom types | Backend+Frontend | `app/sources/models.py/registry.py`, `frontend/js/components/sources.js` | list only implemented types; validate at register; (proper: connector-family registry). | unit+wire e2e |
| P2 | F-7 generic fail→401 | Backend | `app/proxy/proxy.py:489-497` | Map unknown exceptions→500 `internal_error` | unit wire |
| P2 | F-8 live rule-lifecycle/boundary test gap | Test | new live-pipeline E2E (depends F-1) | Once F-1 wired, add disable/retire/no-match/FP boundary live asserts | live e2e |


---

## 26. FINAL EVIDENCE MATRIX

| Requirement | Action Executed | API/Log Evidence | DB Evidence | Browser Evidence | Result | Confidence |
|---|---|---|---|---|---|---|
| Connector creation (family) | Code search + live list_types | `source.list_types` 6 values | — | selector feeds `state.types` | **DOES NOT EXIST (F-6)** | HIGH |
| Source creation (instance) | live register (nginx + waf) | `source.register` 200 both | `source_instances` 2 docs | — | works (incl. phantom waf type) | HIGH |
| Configuration/validation/enable | live ops | 200 each (steps 12-14) | states advanced | — | works | HIGH |
| Trust / token | live issue + ingress | `source.issue_token` 200; ingress valid 200 | token claims persisted | — | works (HMAC, field-integrity, state gates in verifier) | HIGH |
| Replay | live 2nd use | **401 replay rejected** | `source_token_replay` count 3 | — | works (single-use) | HIGH |
| Disable / Retire gates | live | 409 `source_not_enabled`; 410 `source_retired` | — | — | works | HIGH |
| Ingress → canonical event | live 8 events | 200 `accepted_event_ids`=8; `rejected`=[] | `security_events`=8 (source=nginx, provenance source_instance_id) | — | works | HIGH |
| Event validation (bad/malformed/missing token) | live | 401 missing/malformed; 400 malformed JSON; 400 unknown op; 400 max-events (code) | — | — | works | HIGH |
| Authentication/RBAC | live | auth.issue wrong cred 401; analyst source.register 403; admin ok | — | — | works | HIGH |
| Rule ownership / selection (source-scoped) | unit + boundary script | `detection_boundary_test`: iam auth_failure →0; nginx →2 | — | — | engine works | HIGH (component) |
| Positive detection | boundary script + demo | 2 detections/event (NGINX-AUTH-BRUTEFORCE-001+FAILURE-001) | demo repo rows | — | engine works | HIGH (component) |
| Negative / no-rule / benign | boundary script | 0 detections (tls_anomaly, auth_success, iam) | — | — | engine works | HIGH (component) |
| False positive/negative sweep | unit only | `test_phase44/47`, etc. | — | — | not live-executable | MED (F-8) |
| Correlation (window/threshold/dupes) | unit + demo | demo: 1 correlation (`key=10.0.0.66\|/auth/login count=8`) | demo repo rows | — | engine works (component; not composed live) | HIGH comp / **0 live** |
| Same-source correlation isolation | demo (single source) | pattern key = (source_ip, endpoint) | — | — | works (component) | HIGH comp |
| Cross-source correlation | code | patterns.py defers WAF+NGINX (no pattern) | — | — | **does not exist (product)** | HIGH |
| Case creation | live + search | `case.create` 400; `case.centralized` 404; `create_case(` only demos/tests | `incidents`=0 | — | **no live mechanism (F-2)** | HIGH |
| Case state transitions/idempotency | demo + suites | demo open→close, history=2 | demo rows | — | works (component) | HIGH comp |
| Timeline | code + probe | `timeline.build_for_incident` 404 (no case); UI `timeline.list` 400 | — | timeline page dead | **not reachable live (F-1/2/3)** | HIGH |
| Routing | code + probe | `routing.compute` 404 (no case); recommendation-only implemented | — | no UI | **auto-dispatch absent (design/GAP)** | HIGH |
| Reports | code + probe | `report.list` 400 (incident_id required); `report.generate_normal` 404 (no case) | — | no UI refs | **backend ok / UI absent (F-4); live blocked (F-2)** | HIGH |
| Centralized analysis | code + probe | `case.centralized` 404 (no case); handler+service suite-green | — | no UI refs | **backend partial / UI absent (F-4); live blocked (F-2)** | HIGH |
| Persistence | live DB + suites | — | collections/persist verified | — | works (persisted sources/events/tokens; repos proven via suites) | HIGH |
| Restart | suites (not re-run) | — | — | — | not live-verified this session | MED (GAP) |
| RBAC / IDOR | suites (not re-run live) | — | — | — | suite-covered | MED (GAP) |
| Frontend wiring | static sweep + op probe | 22/22 static 200; **10 dead ops 400** | — | pages vary | **gaps (F-3, F-4, F-6)** | HIGH |
| Proxy separation | live | ingress rejects analyst ops 400; proxy rejects raw telemetry 400 | — | — | works | HIGH |
| Concurrency/idempotency (dup event, case-close, centralized) | suites | — | — | — | suite-covered; not all live | MED |
| Provenance | code + DB | detection deterministic ids; evidence_refs=event_id; correlation evidence ids | demo rows | — | sound when produced | HIGH comp |


---

## 62. FINAL DECISION ANSWER

**"Can ProShield, in its CURRENT implementation, actually behave as the enterprise security platform described by its architecture and specifications when a real external security source connects, authenticates, sends telemetry, the correct source receives it, canonical events are created, the correct rules are selected, detections are generated, false positives are controlled, correlations are produced, cases are created, timelines reconstruct the evidence, routing selects the correct destination, analysts investigate, source-specific reports are generated, centralized analysis combines connected source evidence,and centralized reports preserve the original evidence?"**

**NO — in its CURRENT implementation ProShield does NOT behave as the documented enterprise platform for that workflow。**

**It fails at these exact stages (each runtime/DB/code-evidenced):**

1. **Event→Detection (arrow 8): BROKEN (MISSING composition.** A real source that authenticates and sends matching telemetry yields **persisted events only;0 detections** at runtime (deeptest 8 events → detections=0; dev-db 1275 detections→0 correlations**. The engines perform correctly only when test/demo scripts manually compose them in-process. **Owner:** BACKEND ARCHITECTURE GAP (F-1).
2. **Detection→Correlation: BROKEN (same missing composition;** 0 correlations live (`correlation_engine.run` never invoked by any server process（. **Owner:** F-1.
3. **Correlation→Case: **MISSING MECHANISM (F-2**: `case.create` is a 400 boundary; no automatic case policy exists; `create_case` unreachable live. **Owner:** F-2.
4. **Timeline/Routing/Reports/Centralized-analysis (post-case stages): PARTIALLY VERIFIED backend / UNREACHABLE live** (require an incident, and incidents can't be created;** plus UI wiring gaps F-3/F-4. **Owner:** F-1/F-2/F-3/F-4。
5. **Frontend→Backend wiring for the analyst workflow: BROKEN AT SEAMS** — 10 UI ops →live 400 (`timeline.list`, `case.assign/add_note/add_recommendation`, `rule.approve/revoke/history`, `correlation.confirm/dismiss`, `api.meta`**; centralized analysis+reports have **zero** UI wiring. **Owner:** FRONTEND WIRING BUG (F-3, F-4.
6. **Connector/source modelling: ARCHITECTURALLY INCOMPLETE** — 6 declared "connector types", only 2 implemented; the UI's "Connector Type" register control creates source instances for phantom types (waf proven live**;no connector-family creation mechanism exists. **Owner:** BACKEND ARCHITECTURE GAP + UI naming (F-6.

**What DOES work (proven live):** plane separation (ingress↔analyst proxy isolation**, source lifecycle+trust+replay+disable+retire, canonical event ingestion+persistence+provenance, auth/RBAC at wire, deterministic engines at component level, real-Mongo repos. **What does NOT work:** the product's own runtime never wires engines together;the analyst UI is not wired to the ops it needs;ю mile-deep, inch-wide。

**PARTIAL mapping (every working + broken stage above; plus the full evidence chain in§7/§26**。 Forensics verdict: **ARCHITECTURALLY INCOMPLETE / NOT READY** foundation is real, честный, well-tested; the E2E composition and analyst-plane wiring are the two决定性 unbuilt halves。


---
*End of report. TEST infrastructure created for this audit: `scripts/strix_deeptest_live.py`, `scripts/_strix_frontend_matrix.py`, `scripts/_strix_live_ops_probe.py`, `scripts/_strix_deep_dbcheck.py`, `scripts/_strix_linecount.py` (+ artifacts `strix_deeptest_evidence.{ndjson,json}`, `strix_deeptest_{proxy,ingress}.log`, `strix_proxy_live.log`, `strix_*_probe/matrix/demo/boundary txt`). These are labelled TEST INFRASTRUCTURE — их presence does not imply the product supports the composed workflow. The authoritative product-output of this investigation is this file.**

---

## FINAL VISUAL + HUMAN-OPERATOR REVALIDATION (Round 2 — real browser drove)

### Playwright availability
**Available this round.** The final revalidation was driven through a real Chromium browser against the genuinely running product:
- Analyst: `python -m scripts.proxy_server --backend mongo --port 8000 --seed-credentials` (mongo `proshield_ftaudit`)
- Ingress: `python -m scripts.ingress_server --backend mongo --port 8089`
- Fresh MongoDB database `proshield_ftaudit` on `127.0.0.1:27017`.

### Human-operator evidence chain (SCENARIO A/B etc.)
**Login** → `POST /api/proxy {op:auth.issue, admin/admin-dev-credential}` → 200 → redirected to `/static/index.html` (Overview). Overview fired `overview.summary`, `source.list`, `rule.list`, `case.list`, `detection.list` (all 200).
**Sources page** → visible 6-entry "Connector Type" combo: `iam, network, nginx, rate_limit, simulator, waf` (F-6 visual confirmation).
**Register source (UI)** → selected "nginx", filled `PS-AUDIT-NGINX-01`, tags `PROD, WEB`, asset_tags `api, web` → `POST /api/proxy {op:source.register,...,asset_tags:['api','web']}` → **200** → source `src-...-ps-audit-nginx-01` state `registered` → Mongo `source_instances` count=1 state=registered (persistence confirmed). The UI **auto-opened the Configure dialog**.
**Configure** → set endpoint `/ingress/nginx-a`, destination `SOC-REPORT` → Save → **200** (state=configured), row + table rendered **broken** (see NEW bug below).
**Second NGINX source + Simulator-adjacent flow** → registered/configured/validated/enabled `PS-AUDIT-NGINX-02` → 200 each; both sources enabled.
**Validate** → on `https://nonexistent.invalid/ingress/x` → **200** state=validated (see validate-not-connectivity NEW finding**; validate again from validated → 409.
**Enable** both → 200.

### Screenshots / DOM / console
- Sources page after register: **table body text = `[object HTMLTableRowElement]`** when I read `.innerText`; screenshot `ftaudit_sources_after_register.png`.
- Rules page: `[object HTMLTableRowElement]`×5 (5 rule rows) — screenshot `ftaudit_rules_broken.png`.
- Detections/Correlations/Cases pages: empty table (0 rows — det/corr/case repos empty live, consistent with F-1).
- Console: no errors on any page (the 'object' rendering is silent — no console exception, which is why the previous API-only audit missed it).

### Detailed browser/network/SecureProxy/backend/DB correlation (per §35 evidence chain)
| ACTION | BROWSER REQUEST | API RESPONSE | SECUREPROXY/BACKEND | DB | RESULT |
|---|---|---|---|---|---|
| Login admin | POST /api/proxy auth.issue | 200 token | SessionVerifier ok | — | Overview loaded |
| Add Source | POST /api/proxy source.register | 200 source | source service → repo | source_instances=1 registered | source row + broken table |
| Configure | POST /api/proxy source.configure | 200 | service → repo | state=configured | modal closed |
| Validate (https nonexistent) | POST /api/proxy source.validate | **200** | service state machine | state=validated | **no network test** |
| Enable | POST /api/proxy source.enable | 200 | service | state=enabled | enable works |
| Ingest 8+2 events (ingress) | POST /api/ingress source.ingest | 200 accepted | ingress → ingestion | security_events=10 | **no detection fired** |

### Console / network errors
- favicon.ico 404 (benign).
- No JS exceptions; the `[object HTMLTableRowElement]` rendering is silent (no error surfaced).

---

## LIVE ACTION-BY-ACTION EVIDENCE (two-plane; fresh DB; both NGINX sources enabled)

- **T0 (ingress):** `POST /api/ingress {op:source.ingest}` with 8 auth-failure events → **200** `accepted_event_ids` 8.
- **T1 (persistence):** `security_events` count **8** for source `src-...-ps-audit-nginx-01`; 2 more for `src-...-ps-audit-nginx-02` (source B benign; isolation verified by `$group by provenance.source_instance_id` → A:8, B:2).
- **T2 (detection invocation):** **never occurs.** Ingress log shows only `app.ingestion.service ingest.persisted` ×10; no detection-engine line exists.
- **T3 (detection persistence):** `detections` count **0**; proxy `detection.list` → `{"detections":[]}`; `overview.summary.detection_count` = 0 after every poll (t+1s, t+2s, t+3s).
- Correlation count **0**; incidents **0**; reports **0** (all DB + proxy confirmed). Nothing downstream starts automatically.

---

## NEW ISSUES DISCOVERED (Round 2)

### N-1 — FRONTEND `el()` helper does not flatten arrays → ALL list tables render `[object HTMLTableRowElement]`
- **Severity:** P1  **Category:** FRONTEND BUG (rendering)
- **Root cause:** `frontend/js/components/layout.js:36-53` — `el(tag, attrs, ...children)` appends each child via `e.appendChild(c.nodeType ? c : document.createTextNode(String(c)))`. When a child is an Array (e.g. `rows.map(rowFor)` → `[tr,tr,...]` at `sources.js:496`), the array has no `.nodeType`, so it's stringified to `"[object HTMLTableRowElement],[object HTMLTableRowElement]"` — rendered literally as **`[object HTMLTableRowElement]`**.
- **Affected:** every list table built via `el("tbody", null, rows.map(rowFor))`: `sources.js:496`, `cases.js:129`, `detections.js:113`, `correlations.js:114`, `rules.js:113`, `case.js:354/382`, `rules.js:217`.
- **Expected:** rows render as actual `<tr>` elements.
- **Actual (live browser):** Sources table shows `[object HTMLTableRowElement],[object HTMLTableRowElement]` for 2 source rows; Rules table shows `[object HTMLTableRowElement]`×5. Detections/Correlations/Cases show empty (0 rows).
- **Why missed before:** the previous audit never drove the browser (API-only), so the visual rendering was never checked.
- **Security/functional impact:** the primary analyst-facing list pages are effectively **unreadable** whenever they have data; the product's core console is broken at the rendering layer.
- **Fix:** in `el()`, flatten child arrays: `for (const node of [c].flat(Infinity)) ...` or `if (Array.isArray(c)) { for (const x of c) append }`.
- **Confidence:** **CONFIRMED-HIGH** (live DOM + code both).

### N-2 — `source.validate` performs NO connectivity/network validation — it is a config/state transition only
- **Severity:** P2  **Category:** PRODUCT EXPECTATION MISMATCH (documented "Test Connection" implies connectivity)
- **Repro (live):** configure a source with endpoint `https://nonexistent.invalid/ingress/x` (a domain that cannot resolve) → `source.validate` → **200** with state=validated. No DNS/TCP/TLS/HTTP attempt occurs anywhere (no outbound connection; endpoint is syntactically preserved).
- **Expected (from the UI label "Test Connection" and a security product's mental model):** at least an endpoint reachability probe.
- **Actual:** transition `registered/configured → validated` based only on config shape (https scheme allowed, http rejected with 400 `source_configuration_error "endpoint must be a non-empty https:// URL"`); zero network I/O.
- **Fix/classification:** This is a **state transition, NOT a real connectivity test** — a "connected/validated" badge does NOT imply the external system is reachable. If the product intends a real probe, a connector-health/connectivity check must be added in `source.validate`. Otherwise the UI label "Test Connection" is misleading.
- **Confidence:** **CONFIRMED-HIGH** (live + code: none of the validate path performs network I/O).

### N-3 — SecureProxy generic exception fallback re-confirmed: backend validation failures translate to 401 `authentication_required`
- **Severity:** P1  **Category:** API CONTRACT BUG / SECUREPROXY BUG (error-classification)
- **Repro (live, two independent):**
  - `source.register` with `asset_tags:["web","api"]` (unsorted) → **401 `{"code":"authentication_required","message":"internal error"}`**
  - `source.register` with `tags:["PROD","PROD"]` (duplicate) → **401 `{"code":"authentication_required","message":"internal error"}`**
- **Expected:** 400 `validation_error` with a safe message (or server-side normalize/sort).
- **Actual:** Pydantic `ValidationError` from `SourceManagementService.register` escapes uncaught; the proxy's generic `except Exception` (`proxy.py:489-497`) maps every unknown exception to `ProxyUnauthorizedError(401, "internal error")`.
- **Why missed before:** the previous audit caught this (F-5), but now it is **re-confirmed with a second independent repro (duplicate tags)**, strengthening it to CONFIRMED-HIGH.
- **Fix:** map pydantic/schema validation to 400 `validation_error`; map unexpected exceptions to 500 `internal_error` (not 401). Also consider normalizing tag ordering server-side.

---

## PREVIOUS FINDINGS — FINAL STATUS (after false-positive challenge)

| ID | Claim | Challenge attempted | Status |
|---|---|---|---|
| F-1 | No live detection/correlation/case pipeline | Exhaustive search for consumers/workers/threads/schedulers in `app/**`,`scripts/**` (found none); fresh live run: 8 events → detections=0/corr=0/cases=0; log shows only `ingest.persisted` (T2 never fires); after 3s polls still 0 | **CONFIRMED-HIGH** |
| F-2 | No live case-creation mechanism anywhere | Searched callbacks/wire paths; `case.create` remains 400; no auto policy; no live `create_case` caller in any server | **CONFIRMED-HIGH** |
| F-3 | Frontend calls 10 non-existent backend ops | Re-probed live: `timeline.list`, `case.assign`, `case.add_note`, `case.add_recommendation`, `rule.approve/revoke/history`, `correlation.confirm/dismiss`, `api.meta` all → 400 `unknown operation` | **CONFIRMED-HIGH** |
| F-4 | Centralized analysis + reports have zero frontend wiring | Whole-frontend grep: no `report.*`, no `case.centralized`, no `export` anywhere | **CONFIRMED-HIGH** |
| F-5 | Validation escape → 401 | Re-probed: unsorted AND duplicate tags both → 401 | **CONFIRMED-HIGH** (upgraded; N-3) |
| F-6 | 6 connector types, only nginx+simulator implemented; "Connector Type" conflates source types | Live UI combo lists all 6; code registry has only nginx+simulated; waf registered though no WAF connector/rules | **CONFIRMED-HIGH** |
| F-7 | Generic fail → 401 | Confirmed again via N-3 | **CONFIRMED-HIGH** |
| F-8 | Live rule-lifecycle/boundary tests not possible until pipeline wired | Still blocked by F-1 | **CONFIRMED (dependency)** |

---

## FALSE-POSITIVE ELIMINATION (what was actively attempted to disprove)

- **F-1:** I searched every `app/**` and `scripts/**` for `DetectionPipeline`, `CorrelationEngine`, threads, workers, `asyncio.create_task`, schedulers, lifespan/startup hooks, pymongo `watch`, callbacks. All hits are docstrings or test/demo-only composition. I then **ran the real system fresh** and observed T1→(no T2). **REFUTED nothing; F-1 stands.**
- **F-3/F-4:** I searched for alternate endpoints/aliases/dynamic routing in `api.js` and each page. None exist; ops are hard-coded frontend strings vs backend `ALLOWED_OPERATIONS`. **Stands.**
- **F-6:** I checked whether `source.list_types` reflects only-implemented or plugin-loaded types — it returns all 6 enum values regardless of implementations. **Stands.**
- **No prior finding was refuted**; several were upgraded (F-5/F-7 via N-3).

---

## REMAINING UNCERTAINTIES

1. **Restart of the ANALYST proxy** was not separately re-run live after the dedicated ingress-restart test (the analysis plane had been continuously up during the audit; source/rule/case/list always consistent). Test-suite coverage exists for repo recovery.
2. **Cross-process concurrent single-token race** (two workers claiming the same `token_id` simultaneously) was not raced live this session; invariant is MongoDB unique-index (`MongoReplayStore`) + suite-covered.
3. **IDOR/cross-analyst case isolation** was not re-executed live; suite-covered.
4. **Centralized-analysis idempotency/rerun** not live-exercised (requires a case, which can't be created live — F-2).
5. **Playwright screenshots** captured for Sources/Rules (referenced filenames); not embedded as images in this markdown (kept as artifacts).
6. **`rule.create` admin flow** — the frontend has **no rule-create dialog** at all (rules.js has no create UI), so the backend `rule.create` op is unreachable from the UI (also API-only). Not separately re-probed beyond the missing-rule_id 400.

---

## FINAL END-TO-END EVIDENCE MATRIX (Round 2)

| Stage | Expected | Actual | Evidence | Status |
|---|---|---|---|---|
| Source | register→configure→validate→enable via UI | works (200) + persistence; UI table BROKEN (N-1) | screenshot/DOM/API/DB | ✅ backend / ❌ UI table |
| Trust / replay | token single-use, persists across restart | token issue+verify 200; replay 401; **survives ingress restart** | live | ✅ CONFIRMED |
| Ingress | raw events → canonical → persist | 10 events persisted, isolated by source_instance (A:8, B:2) | DB/$group; ingress log | ✅ CONFIRMED |
| Event | canonical SecurityEvent | valid; source_instance provenance stamped | DB doc | ✅ CONFIRMED |
| Detection | T2 fires on eligible event | **T2 never fires** — no pipeline consumer | log shows only `ingest.persisted`; detections=0 | ❌ **BROKEN (F-1)** |
| Correlation | detections → correlations | no detections, so none | DB | ❌ **BROKEN (F-1)** |
| Case | correlation → case | no case path any wire | case.create 400; incidents=0 | ❌ **MISSING (F-2)** |
| Timeline | per-case timeline | not reachable live (no case; UI timeline.list 400) | live probes | ❌ **BLOCKED** |
| Routing | recommendation vs dispatch | recommendation-only, no auto-dispatch; not live-exercisable (no case) | code | ⚠️ PARTIAL |
| Centralized analysis | UI action → backend | **ZERO UI wiring**; backend requires case | grep | ❌ **UI MISSING (F-4)** |
| Report | generate/export | **ZERO UI wiring**; backend requires case | grep | ❌ **UI MISSING (F-4)** |
| Frontend | pages render data | list tables render `[object HTMLTableRowElement]`; empty pages on empty repos | live DOM | ❌ **NEW (N-1)** |

---

## FINAL VERDICT (Round 2, human-operator + browser + API + log + DB)

**ARCHITECTURALLY INCOMPLETE — NOT READY.**

A real security operator **cannot** use the actual product today to: configure multiple real sources → establish trust → ingest events → **detect** → correlate → **create/manage an incident** → reconstruct timeline → route/respond → centralized investigation → report. The trust+ingestion+persistence+source isolation planes are real and proven (including restart recovery and replay). But **detection/correlation/case are not connected in production composition** (F-1/F-2), the analyst list UI is **broken** by a systemic `[object HTMLTableRowElement]` rendering bug (N-1), several displayed ops are dead (F-3/F-4), and the validate button overstates connectivity (N-2).

The previous audit's key thrust is **CONFIRMED-HIGH** (F-1/F-2 are the decisive blockers). Two genuinely new Round-2 discoveries: the **systemic table-rendering bug** and the **validate-is-a-state-transition** semantic gap; F-5/F-7 are strengthened to CONFIRMED-HIGH with a second independent repro. No prior finding was refuted.