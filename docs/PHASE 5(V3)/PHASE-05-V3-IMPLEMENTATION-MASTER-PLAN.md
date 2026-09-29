# PROSHIELD V3 — PHASE 5 IMPLEMENTATION MASTER PLAN

**Document ID:** `PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN`
**Location:** `docs/PHASE 5/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md`
**Status:** IMPLEMENTATION-READY PLAN — NO PRODUCT CODE CHANGED
**Authority chain:** Phase 1–4 docs → Current repo (main @ f674f09 + capability patch 2026-09-07) → V3 Master Plan (`frontend/docs/PHASE 5(V3)/FINAL PROSHIELD V3 IMPLEMEATION PLAN RELOADED.txt`) → Phase 5.0 Freeze (`frontend/docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md`) → THIS DOCUMENT → 5.1→5.9
**Repo truth date:** 2026-09-10. All repo claims verified by file read in this session unless marked UNKNOWN.

> NOTE ON PATHS: the task brief says `docs/PHASE 5/`. The actual repo on disk keeps versioned docs under `frontend/docs/PHASE 5(V3)/` (there is NO root `docs/` dir — verified by `find_file relative_path=docs` → FileNotFound). This file is therefore created at the brief-required `docs/PHASE 5/...` AND must be mirrored/copied to `frontend/docs/PHASE 5(V3)/` by the operator. All `docs/PHASE x/...` references below mean `frontend/docs/PHASE x/...` on disk.

---
# 1. Executive Summary

ProShield main is a **working rule-based SOC foundation**, not a slide-ware MVP. After the 2026-09-07 capability patch: 1373 pytest pass, 23/23 fresh-DB audit, 43/43 live-wire + 9/9 restart + 5/5 rule-live, browser-verified analyst journey. Chain `source.ingest → SecurityEvent → DetectionPipeline → CorrelationEngine → auto-case → triage → notes → reports → export` runs in production composition (`app/pipeline/service.py::LivePipeline`, ingress hook in `scripts/ingress_server.py::_run_live_pipeline_after_ingest`).

V3 does NOT rewrite this. V3 adds: (a) reusable **Capability** layer above SourceInstance (does not exist today — this is the single biggest schema change); (b) **Source 2.0** binding to Capability with preserved token trust; (c) **human-authoritative CaseResolution** (verdict, not bare close); (d) explicit **temporary-vs-durable lifecycle**; (e) **SecurityEvidence archive** distinct from raw telemetry; (f) **Dataset/DatasetVersion** system producing controlled exports (no auto-training); (g) future-ready seams for Learning App (5.3 HOLD) and Guide (5.9 HOLD).

Recommended implementation order (dependency-derived, §37): **5.1 → 5.2 → 5.4 → 5.5 → 5.6 → 5.7 → 5.8**, with 5.3/5.9 held but future-readiness stubs inside 5.1/5.2/5.4. First work item: 5.1 Capability Registry (collection + validator + indexes + service + proxy ops + admin UI list/detail) behind `capability.*` ops, zero change to live detection until 5.2 migration.

# 2. Repository / Documentation Analysis Summary

**Evidence inspected (this session, file-read verified):**
- Phase 1: `ARCHITECTURE.md`, `ARCHITECTURE_DECISIONS.md`, `THREAT_MODEL.md`
- Phase 2: `API_CONTRACTS.md`, `CONTRACT_DECISIONS.md` (via refs), `DOMAIN_DATA_MODEL.md`, `SECURITY_EVENT_SCHEMA.md`
- Phase 3: `AUTH_RBAC.md`, `SECURE_FOUNDATION.md` (via refs), `SECURITY_CONFIGURATION.md` (via config.py), `SECURITY_TEST_PLAN.md` (via refs)
- Phase 4: `backend-missing-features.md` (15 gaps), `PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md`, `PHASE-A-GAP-MATRIX.md`, `PROSHIELD-DEEPTEST-ISSUES.md` (V1 STRIX), `PROSHIELD-DEEPTEST-ISSUES-V2.md` (V2), `PROSHIELD-FINAL-BACKEND-VERIFICATION.md`, `PROSHIELD-FINAL-BACKEND-READINESS.md`, `PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md` (frozen 40 ops), `DETECTION_ENGINEERING_AND_FUTURE_AI.md`, `GEMINI-FRONTEND-INTEGRATION-REVIEW.md`, `STRIX-PROSHIELD-FULL-PIPELINE-TEST.md`, per-phase 4.01–4.09 reports/reviews (listed, sampled 4.01–4.06 E2E + correlation E2E)
- V3: `FINAL PROSHIELD V3 IMPLEMEATION PLAN RELOADED.txt` (full read), `PHASE-05-00-V3-ARCHITECTURE-FREEZE.md` (full read, 48 sections)
- Code: `app/config.py`, `app/domain/security_event.py`, `app/connectors/base.py`, `app/ingestion/service.py`, `app/detection/{engine,pipeline,models,service}.py`, `app/correlation/{engine,patterns,models,service}.py`, `app/persistence/{schema,mongo,bootstrap,human_ids,telemetry,security_event_repository,detection_repository,correlation_repository,rule_repository}.py`, `app/rules/{registry,loader,rule,types}.py`, `app/rules/management/{definition,service,generic_rule}.py`, `app/sources/{models,registry,repository,service,ingress,trust,replay_store}.py`, `app/incidents/{models,repository,service}.py`, `app/pipeline/{service,managed_rule_sync}.py`, `app/proxy/proxy.py` (ops set), `app/auth/{identity,session,permissions}.py`, `app/observability/health.py`, `app/overview/service.py`, `app/timeline/service.py`, `app/notifications/service.py`, `app/reports/exporter.py`, `scripts/{proxy_server,ingress_server}.py`

**Method:** DOCUMENTED vs IMPLEMENTED vs WIRED vs PERSISTED vs RUNTIME-VERIFIED vs BROWSER-VERIFIED vs ADVERSARIALLY-TESTED kept distinct (§5).

**Headline contradictions found (all recorded, none silently reconciled):**
| # | Older claim | Current truth (file) | Impact |
|---|---|---|---|
| C1 | Contract says 39 wired + 1 boundary = 40 ops | `app/proxy/proxy.py::ALLOWED_OPERATIONS` now 51 ops (40 + 11 patch: acknowledge/investigate/note/create_from_correlation/list_patterns/health.deep/notification×3/global_query/timeseries) | Contract doc stale; freeze addendum required in 5.1 |
| C2 | `SourceType` advertises 6 kinds (nginx/waf/iam/rate_limit/network/simulator) | `app/sources/registry.py::SUPPORTED_CONNECTOR_TYPES={NGINX,SIMULATOR}` only; `source.list_types` serves supported-only (F-6 fix) | Any Capability seed claiming 6 ready capabilities is a fake-capability violation; 5.1 must seed exactly 2 active + 4 `planned` |
| C3 | RELOADED.txt lifecycle CREATED→…→ARCHIVED; states ARCHIVED, ConfigurationRecycleBin, KnowledgeItem, OnboardingSession | Code lifecycle REGISTERED→CONFIGURED→VALIDATED→ENABLED⇄DISABLED→RETIRED (no ARCHIVED, no recycle bin) | RELOADED is roadmap, NOT contract; 5.0 freeze wins; recycle-bin deferred to 5.5 decision |
| C4 | RELOADED verdict taxonomies (6 verdicts, 12 TP classes, 10 FP reasons) | No CaseResolution model exists; `Incident.state=closed` is bare | Taxonomy source = RELOADED.txt only (no Phase 0–4 authority); 5.4 must ratify taxonomy explicitly, not silently adopt |
| C5 | V1 STRIX "pipeline never runs live" | Fixed: `LivePipeline` + ingress hook + `ManagedRuleLifecycleSync` per-event sync (V2-01) | V1 finding CLOSED; V2 findings V2-P0 (validators), V2-P1 (rule sync) fixed; residual V2-P1 case-evidence-freeze REQUIRES VERIFICATION in 5.4 |
| C6 | Docs path `docs/` | Disk path `frontend/docs/` | Tooling/scripts referencing `docs/` break; migration must not hardcode either |

# 3. Phase 1–4 Foundation Reconstruction

**WHAT WAS PLANNED:** Phase 0 product scope (15-stage flow source→…→human); Phase 1 modular deterministic backend-first arch, trust boundaries, threat model; Phase 2 canonical SecurityEvent + domain separation observed/derived/recommended/decided + API contracts; Phase 3 auth/RBAC, secure foundation, config, security test plan; Phase 4 slices 4.1–4.10 (ingestion→detection→correlation→severity→rules-mgmt→incidents/reports/routing→sources/ingress→proxy-wiring→frontend-integration→capability-patch).

**WHAT WAS REQUIRED:** Deterministic rule-based core with no AI dependency; adapter boundary per source; versioned audited rules; evidence traceability; backend-authoritative authz; bounded validated inputs; idempotent ingestion.

**WHAT WAS IMPLEMENTED (verified):** All of the above for nginx/simulator path + 15 patch gaps (human_ids, ack/investigate, attribution, notes, severity/confidence composition, pattern catalogue, deep health, per-source telemetry, structured-rule authoring verified live, case-from-correlation op, notifications, global timeline, multi-format export, server timeseries).

**WHAT REVIEWS FOUND:** STRIX V1 (arch incomplete — live composition missing) → fixed. STRIX V2 (validators missing at runtime; rule-sync disconnected; evidence frozen; wire mismatches; centralized no-op; unmatched-event invisibility) → P0/P1 fixed except evidence-accumulation needs re-verification. Gemini review (15 gaps, all deferred) → all 15 implemented by patch.

**WHAT WAS FIXED:** See patch report §1 table (15/15) + V2-P0 bootstrap + V2-01 sync + V2-05 resolve_case_evidence + V2-10 persist-failures observable.

**WHAT WAS VERIFIED:** 4 channels (§2): unit 1373, fresh-DB 23/23, live 43/43 + restart 9/9 + rule-live 5/5, Playwright journey (login→overview→incidents→case→notes→detections→correlations→sources→health→notifications, responsive 1440/768/390, zero console errors).

**LIMITATIONS REMAIN:** PDF Unicode→`?` (Latin-1); legacy rows null human_id/severity/confidence (no backfill by design); pipeline-owned cases hidden from analysts (IDOR-by-design, needs sharing feature); `received` counts batches-offered; `generate_centralized` truthful 400 refusal when no context; single brute-force pattern only; nginx+simulator only; case evidence growth unverified; no Capability abstraction; no CaseResolution; no evidence/dataset layer; no TTL lifecycle.

**FOUNDATION EXISTS:** See §6 table. **PHASE 5 MUST CHANGE:** add Capability; bind Source→Capability; add Resolution; add lifecycle/evidence/dataset/export; future-ready (not build) learning/guide.

# 4. Current Architecture Baseline (runtime truth)

```
External source --HMAC sit-token--> InboundIngressProxy (scripts/ingress_server.py :8089)
  -> validate/token/state/rate/size -> canonical SecurityEvent (provenance.source_instance_id stamped)
  -> SecurityEventRepository (unique event_id; idempotent; conflict on same-id-different-content)
  -> LivePipeline.process (app/pipeline/service.py; ManagedRuleLifecycleSync.sync() per event)
     -> DetectionPipeline (DetectionEngine over RuleRegistry.applies_to; enrich_detection severity+source_instance_id)
     -> CorrelationEngine (BruteForceClusteringPattern only) -> CorrelationRepository (confidence composed)
     -> IncidentService.create_case_for_correlation (deterministic case id; idempotent)
  -> SourceTelemetryStore bump; notification sink
Analyst browser --session ps.*--> SecureProxy (scripts/proxy_server.py :8088, POST /api/proxy, 51 ops)
  -> SessionVerifier -> has_permission + object-authz (case owner or case:read:any; 404 hides existence)
  -> services -> repositories -> Mongo (bootstrap.ensure_all_collections applies validators+indexes at boot)
Frontend: legacy multi-page (frontend/*.html+js) + React SOC (frontend/src_upgraded_gemini -> frontend/soc/index.html)
```

# 5. Phase 5 V3 Goals (from V3 Master + 5.0 freeze, filtered through repo truth)

G1 One Capability→many SourceInstances, no subconnectors. G2 Rules belong to Capability (today: `RuleDefinition.sources[]` strings — must migrate). G3 Source token identifies Source, source resolves Capability. G4 Event≠Detection≠Correlation≠Case≠Threat≠TrainingData. G5 Analyst verdict authoritative via CaseResolution. G6 Observed vs derived vs recommended kept distinguishable end-to-end. G7 Evidence archive ≠ dataset; quality-gated promotion. G8 Immutable versioned datasets + deterministic exports (EXPORT AI DATASET, not TRAIN AI). G9 Learning/Guide future-separate, HOLD, but seams ready. G10 Local-first modular monolith; no new infra without demonstrated need.

# 6. V3 Non-Goals (binding)

No arbitrary code upload as "capability install"; no subconnector hierarchy; no microservices/event-bus/new DB; no Sigma/YARA/CEL (no spec authority); no auto-training/fine-tune; no autonomous response; no Guide LLM in security path; no backend clone for learning; no separate learning DB without demonstrated requirement; no backfill fabrication of verdicts/provenance/confidence; no casual rewrite of stable pipeline.

# 7. Phase 5.0 Architectural Constraints (22 invariants — all preserved in this plan)

§7 of brief (items 1–22) adopted verbatim. Conflict rule: 5.0 wins over RELOADED.txt; repo-impossibility must be recorded explicitly (none found that blocks 5.1; two flagged UNKNOWN: evidence-accumulation semantics, centralized payload size under 32 KiB cap).

# 8. V3 Domain Model (target; NEW items marked ★)

- ★Capability{capability_id (e.g. `cap-nginx`), human_id (`CAP-000001`), name, responsibility, implementation_ref (registry key, NOT code blob), version, status(enabled/disabled/retired), config_schema (JSON-schema), mapping_profiles[], rule_ids[], pattern_ids[], created/updated} — reusable, no secrets.
- SourceInstance += ★capability_id + capability_version + mapping_profile_id (existing: identity, token config, connection, lifecycle, health, telemetry, provenance; RETIRED preserves history).
- SecurityEvent UNCHANGED (add optional `capability_id` DERIVED at ingress from source→capability, never client-supplied).
- Rule += ★capability_id (single owner; migration from `sources[]`).
- Detection += `capability_id` (copied from rule at fire time) — existing severity/source_instance_id kept.
- Correlation += `capability_ids[]` (derived from member detections).
- Case (Incident) UNCHANGED shape + ★CaseResolution{verdict, classification, benign_reason, analyst_confidence, reasoning, evidence_reviewed[], detection_assessment, severity_assessment, analyst_id, resolved_at} — one resolution per case; reopen creates new resolution (history preserved).
- ★SecurityEvidence{evidence_id, category, provenance chain (event/detection/correlation/case/resolution ids + versions), analyst context, quality_state CANDIDATE→REVIEW_REQUIRED→VALIDATED/REJECTED→DATASET_ELIGIBLE}.
- ★Dataset{dataset_id, name, filter_spec, member_refs[], stats, created_by/at} + ★DatasetVersion{version, immutable snapshot, checksum, export_manifest}.
- Future (HOLD, seams only): LearnerIdentity, LabSource, GuideKnowledge (NOT collections now).

# 9. Cross-Domain Relationships

Capability 1—N SourceInstance; Capability 1—N Rule; Capability 1—N CorrelationPattern; SourceInstance 1—N SecurityEvent; Event 1—N Detection; Detection M—N Correlation (via pattern); Correlation 1—N Case (auto 1:1 initially, analyst create_from_correlation N:1); Case 1—N Resolution (history; latest authoritative); Resolution 0—N SecurityEvidence; Evidence M—N Dataset (membership, never moved); Dataset 1—N DatasetVersion (immutable).

# 10. Trust Boundaries

B1 External source→Ingress: HMAC single-use sit-token, source-state check, per-source rate (600/min, 100/batch), 32 KiB cap, ST-04 reconciliation (server-controlled asset/endpoint win, client values → `details._untrusted_*`). B2 Browser→SecureProxy: session ps-token, per-subject rate 120/min (centralized 5/min), 32 KiB req / 1 MiB resp caps, role+object authz, IDOR 404. B3 (FUTURE) Learning→Gateway→Restricted ProShield APIs: scoped learner identity, lab-source isolation, TTL state, allowlisted ops only. B4 (FUTURE) Guide→Safe tools→scoped context: read-only allowlist, no mutations, no secrets, untrusted-output treatment.

# 11. Data Lifecycle (binding)

RAW/OBSERVED Event → DETECTION → CORRELATION → CASE → INVESTIGATION → ANALYST VERDICT (CaseResolution) → CURATED EVIDENCE (quality gate) → DATASET ELIGIBILITY → DATASET VERSION → EXPORT. Live/investigation data is TEMPORARY (TTL/retention, §5.5); curated evidence is DURABLE (archive, §5.6); datasets are IMMUTABLE snapshots (§5.7/5.8). Observed evidence never rewritten to match verdict; derived analysis stored separately with provenance.

# 12. Database Strategy

Existing (UNCHANGED foundation): security_events, detections, correlations, incidents, reports, managed_rules, source_instances, source_telemetry, notifications, counters, source_token_replay — all with $jsonSchema + documented indexes via ensure_all_collections.
MODIFIED: source_instances (+capability refs), managed_rules (+capability_id), detections (+capability_id), correlations (+capability_ids). NEW: capabilities, case_resolutions (or embedded? decision: separate collection — see 5.4), security_evidence, datasets, dataset_versions, retention_policies (5.5). OPTIONAL: investigation_evidence (only if profiling proves needed; default: keep live collections + TTL index). FUTURE: learning/lab/guide stores (HOLD). NOT NEEDED: config recycle bin collection (soft-retire flags suffice), separate telemetry DB, event-bus outbox.
Per-object owner/purpose/schema/validator/indexes/lifecycle/retention/concurrency/authz/migration/deletion/audit specified per-phase (§18–26).

# 13. API Strategy

All ops via SecureProxy.handle (no direct repo exposure; no HTTP router — FastAPI wrappers only). Naming: `capability.*`, extended `source.*`, `case.resolution.*`, `evidence.*`, `dataset.*`, `export.*`. Every op spec: purpose, read/write, identity, permission, scope, input schema, validation, response, errors (canonical envelope), idempotency key, concurrency rule, pagination (bounded, allowlisted sort/filter), audit record, sensitivity, frontend consumer, future-learning reuse flag. New permissions: `capability:read/write`, `evidence:read/write`, `dataset:read/write`, `case:resolve` (or reuse case:read + admin? decision in 5.4: new `case:resolve` to separate triage from verdict authority).

# 14. SecureProxy Strategy

Extend ALLOWED_OPERATIONS + _dispatch per phase; keep shape validation, auth extraction (Bearer/X-ProShield-Session + X-ProShield-Credential for issue), rate limits, size caps, safe-error envelope, 404-IDOR, 409-conflict, 429, 501-reserved. Ingress unchanged except capability stamp + mapping-profile hook (5.2). Learning gateway (future) is a SEPARATE FastAPI app that calls a restricted SecureProxy bundle — never exposes admin ops.

# 15. Authentication / Authorization Strategy

Unchanged primitives: HMAC sessions, 4 roles, closed permission catalogue with override-tuple semantics, object-level case ownership. Add per §13. Source tokens: keep single-use + hash-at-rest evaluation (5.2 must decide: store token_id hash vs full claim doc — replay collection already stores token_id plaintext; recommend HMAC-hash the token_id at rest in 5.2). Rotation/revocation: issue new (old single-use already dead) + retire source revokes future issuance; explicit revocation list only if scale demands (defer).

# 16. Frontend Strategy

Current SOC app only; no redesign. Add: Capabilities list/detail/create/edit/rules/patterns/sources/health (5.1); Source wizard 6 steps with capability picker (5.2); Resolve-Case dialog with verdict taxonomy (5.4); Evidence browser + quality actions (5.6); Dataset builder + version list + export buttons (5.7/5.8); retention visibility banners (5.5). Each feature: page/component/state/API/permission/loading/empty/error/reload-persist/responsive/a11y. Learning app reuses TOKENS (CSS primitives) only, never SOC components.

# 17. Migration Strategy

Assume legacy DB: missing capability fields, old severity/confidence nulls, old sources without capability, old rules with sources[] and no capability_id, pre-human_id rows (""). Classes: MIGRATION REQUIRED (source_instances/rules backfill capability refs — deterministic map, never invented verdicts), NEW DATA ONLY (resolutions/evidence/datasets), NO SAFE BACKFILL (human_id/severity/confidence/verdict/provenance stay null/—). Startup migration runner idempotent, audited, restart-safe; each migration has forward + rollback + dry-run count.

# 18. PHASE 5.1 — CAPABILITY MANAGEMENT & REGISTRY (ACTIVE, FIRST)

1 Objective: real Capability registry owning reusable connector responsibility. 2 Product: admin defines capabilities; sources/rules/patterns attach. 3 Arch: introduces the 1→N root the freeze mandates. 4 Current: NOTHING exists — no model/collection/service/op/UI; closest analogues: SourceType enum (closed 6), SUPPORTED_CONNECTOR_TYPES (2), connector impls (nginx/simulator), RuleDefinition.sources[]/event_types[]. 5 Target: `capabilities` collection + CapabilityService + `capability.*` ops + UI + seed of 2 active (nginx, simulator) + 4 planned (waf/iam/rate_limit/network status=planned, no impl). 6 Preconditions: 5.0 frozen (done). 7 Dependencies: none (first). 8 Reused: SourceType strings (as seed ids), connector health(), RuleDefinition shape, bootstrap pattern, HumanIdAllocator (new kind `capability` → `CAP-000001`). 9 New: model/validator/indexes/repository/service/proxy ops/permissions/UI/migration. 10 Domain: §8 Capability. 11 Data: {capability_id ^[a-z][a-z0-9-]{2,48}$, human_id, name≤128, description≤1024, responsibility, implementation_ref (enum: nginx/simulator/planned), version int, status active/deprecated/retired/planned, config_schema (object), mapping_profiles[] {profile_id, source_type, field_map}, rule_ids[] (derived view, not stored authority), pattern_ids[], created/updated_by/at}. 12 DB: NEW `capabilities`; validator additionalProperties:false; unique capability_id + human_id; indexes (status, implementation_ref, updated_at). 13 Validators: Pydantic extra=forbid + $jsonSchema mirror. 14 Indexes: as above + text name (optional). 15 IDs: technical `cap-<slug>` stable + human CAP-; counters kind `capability`. 16 API: create/get/list/update/enable/disable/retire (+list_rules/list_sources/list_patterns views) — admin write (`capability:write`), analyst/admin read. Idempotent create on capability_id (409 conflict). Pagination bounded 50/200. 17 SecureProxy: extend ALLOWED + dispatch + permission gates + audit. 18 Authz: new perms; object-authz N/A (global catalogue). 19 Frontend: Capabilities nav + list/detail/create/edit + tabs (Rules/Sources/Patterns/Health/Versions). 20 Runtime: construct CapabilityService in proxy_server bundle; bootstrap.ensure_all_collections += capabilities; seed_builtins idempotent. 21 Deploy: no new env; doc mirrors path note. 22 Migration: seed-only; no legacy rewrite. 23 Security: no code upload — implementation_ref is allowlist key; config_schema validated; mapping profiles bounded; audit all writes. 24 Concurrency: unique index is arbiter; allocator atomic. 25 Failure: seed failure blocks boot (fail-loud like other collections); op failures safe-envelope. 26 Observability: deep-health += capability probe (9th subsystem). 27 Audit: actor/action/capability_id/diff. 28 Testing: unit (model/lifecycle/registry), integration (mongo validator rejection), contract (51+8 ops), live seed idempotency. 29 Adversarial: anon→401, analyst create→403, dup id→409, bad impl_ref→400, oversized schema→400, direct-DB bad doc rejected, concurrent creates→one 409. 30 Browser: list→detail→create→disable→retire round-trip, reload persistence. 31 Restart: seed + created capabilities survive; counters monotonic. 32 Rollback: drop collection + remove ops (sources/rules untouched — no refs yet). 33 Acceptance: seed 2 active + 4 planned; CRUD audited; UI truthful; suite green; audit 23+capability checks. 34 Non-goals: no source/rule rewiring (5.2), no pattern migration. 35 Risks: taxonomy drift (mitigate: freeze seed in doc); docs-path confusion. 36 Evidence: pytest + audit script + live probe + screenshots. 37 Next: 5.2 consumes capability_id.

# 19. PHASE 5.2 — SOURCE ARCHITECTURE 2.0 (ACTIVE, SECOND)

Objective: SourceInstance bound to Capability. Target: source.capability_id (required for new; backfilled for legacy via deterministic SourceType→capability map: nginx→cap-nginx, simulator→cap-simulator, others→matching planned capability, unknown→UNKNOWN REQUIRES VERIFICATION quarantine), capability_version, mapping_profile_id. Token model UNCHANGED (HMAC sit-token, single-use, VALIDATED/ENABLED issue, ENABLED ingest). Add: token-id hashing at rest (evaluate; default: keep MongoReplayStore, add hashed secondary lookup if audit demands), rotation (issue new; single-use makes old dead) + retire revokes issuance + stops ingest (410) while preserving history. Rules relationship: rule.capability_id authoritative; source→capability→rules resolution replaces sources[] string match (dual-read during migration, capability wins). Ingress stamps event.capability_id (derived, never client). UI: 6-step wizard (Identity→Capability→Connection→Credentials→Validation→Enable&Verify) + token management + retire/archive views. Migration REQUIRED for sources/rules (deterministic, audited, dry-run). Adversarial: cross-capability token replay→403, retired source ingest→410, mismatched source triple→403, mapping-profile injection→400, concurrent enable/disable→409/serialised. Acceptance: every source has capability; live nginx event carries capability_id end-to-end to detection; old sources work post-migration.

# 20. PHASE 5.3 — SEPARATE BLUE TEAM LEARNING APPLICATION [HOLD — FUTURE DESIGN ONLY]

FUTURE DESIGN: separate app `PROSHIELD SECURITY PLATFORM --controlled API--> BLUE TEAM LEARNING APP` (learner identity, workspace, curriculum/labs as versioned files, progress, challenge state, Guide host). IMPLEMENT NOW: NOTHING except seams — (a) `lab` tag + `lab_learner_id` optional fields on SourceInstance/Event (nullable, unused), (b) capability `supports_lab` flag, (c) BFF permission stubs (`learning:read`) defined but ungated. Comparison (detail in §28): A direct-API (cheapest, weakest isolation — REJECT for prod), B rate-limited Learning BFF over restricted proxy bundle (RECOMMENDED first release), C dedicated learning backend+DB (defer until multi-tenant/progress-audit demands), D allowlisted Lab Adapter inside BFF (adopt as part of B). No new backend clone (§13 evaluated: rejected — cost/isolation unjustified). No learning DB now (§14: content=files, progress=lab-source-scoped TTL docs in ProShield DB or localStorage; separate DB only when instructor/commercial multi-tenancy proven).

# 21. PHASE 5.4 — INVESTIGATION + HUMAN AUTHORITY / CASE RESOLUTION (ACTIVE, THIRD)

Objective: closing a case = structured analyst verdict. New: `case_resolutions` collection + CaseResolutionService + `case.resolution.*` ops (submit/get/history/reopen) + new `case:resolve` permission (analyst+admin; separates triage ack/investigate from verdict). Verdicts/classifications/reasons: ADOPT RELOADED taxonomy PROVISIONALLY (6 verdicts, 12 TP classes, 10 FP reasons + Other) — MUST be ratified in 5.4 spec review; source recorded as RELOADED-roadmap, not Phase 0–4 authority. Rules: one open resolution per case; submit requires evidence_reviewed[] non-empty + reasoning ≥20 chars + confidence; closed→reopen appends history (never deletes); resolution NEVER mutates observed evidence; evidence-promotion boundary explicit (resolution proposes, 5.6 disposes). Permissions: resolver identity recorded (subject_id+role+timestamp); pipeline-owned cases require admin or explicit assignment (fixes IDOR-hidden triage gap truthfully — no silent ownership rewrite). Verify evidence-accumulation (V2 residual): if `create_case_for_correlation` still returns-first-unchanged, 5.4 MUST add monotonic evidence-append (never lower severity) — flagged UNKNOWN, spike required first week. Adversarial: analyst resolves others' case→404, resolve without evidence→400, double-resolve→409, reopen→new resolution, direct-DB resolution without actor→rejected.

# 22. PHASE 5.5 — TEMPORARY SECURITY DATA LIFECYCLE (ACTIVE, FOURTH)

Objective: intentional TTL for candidate data; durable only what verdict/quality promotes. Classes: LIVE (events/detections/correlations/open cases — TTL only after case closure + grace, default 90d unresolved visible, 30d post-resolution grace — TUNABLE via `retention_policies` collection), INVESTIGATION (open case evidence pinned while open), CURATED (resolutions), ARCHIVED (evidence), DATASET (immutable). NO new `investigation_evidence` collection by default (reuse live collections + `expires_at` + TTL indexes + retention job audit log); create only if profiling proves scan cost. Job: `retention_sweep` (idempotent, dry-run, audited, crash-safe, restart resumes), never deletes evidence referenced by open case/resolution/evidence/dataset; unresolved-case data NEVER auto-deleted before grace + analyst banner. Crash/restart: sweep cursor persisted; replay idempotent. Adversarial: sweep skips pinned refs; clock-skew safe (server time only); partial failure leaves audit + continues.

# 23. PHASE 5.6 — SECURITY EVIDENCE ARCHIVE (ACTIVE, FIFTH)

Objective: analyst-context-preserving archive, not a label table. New `security_evidence` collection + EvidenceRepository/PromotionService/QualityService + `evidence.*` ops (propose/promote/review/validate/reject/search). Categories: Confirmed-Threats/FP/Benign/Suspicious/Undetermined (map from verdicts). Provenance: full chain ids+versions (event/detection/correlation/case/resolution/capability/source+version/rule+version) + analyst reasoning + severity/confidence assessments at resolve time. Quality CANDIDATE→REVIEW_REQUIRED→VALIDATED/REJECTED→DATASET_ELIGIBLE; analyst label ≠ eligibility (separate quality gate with second-reviewer rule for DATASET_ELIGIBLE where staffing allows; single-analyst self-approval explicitly flagged in record). Search/filter paginated; access analyst-read/admin-write; audit all transitions. Adversarial: promote without resolution→400, double-promote→idempotent, learner-lab data→rejected with lab-contamination code.

# 24. PHASE 5.7 — AI DATASET SYSTEM (ACTIVE, SIXTH)

Objective: quality-controlled reproducible datasets, NOT training. New `datasets` + `dataset_versions` + DatasetBuilder/QualityService + `dataset.*` ops (create/define-filter/preview/build/version/get/list). Membership by filter_spec (verdict/class/capability/source/rule-version/confidence/severity/date/analyst/quality) resolved at build time into immutable member_refs[] + stats (counts, class balance, date range, leakage check: same event_id/correlation cluster never split across train/eval splits — builder enforces cluster-aware split or refuses). Versions immutable (checksum sha256, member count, provenance manifest); no in-place edit (new version only). Duplicate/leakage handling explicit; class-balance reported, never silently rebalanced. Initially PRODUCES CONTROLLED DATASETS only.

# 25. PHASE 5.8 — EXPORT / DATASET VERSIONING (ACTIVE, SEVENTH)

Objective: deterministic human + AI exports. Human: PDF/CSV/Markdown via existing exporter (fix PDF Unicode only by embedding font — dependency decision, else keep `?` limitation honestly). AI/ML: JSONL (canonical, one evidence record/line, UTF-8) + CSV (flat projection) + Parquet deferred until scale justifies (dependency decision recorded). Guarantees: deterministic byte output for same version (sorted keys, UTC ISO), manifest (version, checksum, filter_spec, provenance, generated_by/at), audit + `dataset:read` authz, sensitive-data redaction (no secrets — ingestion already rejects; exporter re-scans), large-data strategy (cursor streaming, 1 MiB proxy cap bypassed via file artifact + download token — design in 5.8, not in earlier phases). Language: EXPORT AI DATASET everywhere.

# 26. PHASE 5.9 — PROSHIELD GUIDE MINI-AGENT [HOLD — FUTURE DESIGN ONLY]

FUTURE DESIGN: learner-home Guide (NOT SOC path): LearnerIdentity→Learning/Guide API→AI Safety Gateway→scoped context+tools→model (GLM 5.3 Flash compatible, provider-abstracted). Context allowlist (page/workflow/learner state/lab case + curated knowledge items); denylist (org cases, full telemetry, evidence archive, credentials, admin identities, DB). Tools allowlist (read lab case, explain concept, suggest next lab step — NO shell, NO mutations, NO analyst actions). Defenses: prompt-injection (telemetry treated as untrusted data, instruction hierarchy), secret redaction, output validation (OBSERVED/DERIVED/RECOMMENDATION/UNKNOWN/UNSUPPORTED labels required), refusal/escalation paths, full audit, eval harness, model swap without pipeline change. IMPLEMENT NOW: NOTHING except (a) knowledge-item schema draft (versioned markdown in repo, not DB), (b) `guide_context` stub field never populated.

# 27. Cross-Phase Dependencies (derived, not assumed sequential)

Graph: 5.1 → 5.2 → {5.4, 5.5} → 5.6 → 5.7 → 5.8; 5.3/5.9 isolated (read-only consumers of 5.1/5.2/5.4 seams). 5.4 needs 5.2 (capability provenance on resolution) but NOT 5.5; 5.5 needs 5.4 (resolution drives retention) + 5.2; 5.6 needs 5.4+5.5; 5.7 needs 5.6; 5.8 needs 5.7. Parallelisable: 5.1 UI + 5.4 taxonomy ratification. Recommended order == numeric order (no reorder justified). Future-readiness stubs from HOLD phases ride inside 5.1/5.2/5.4 at near-zero cost.

# 28. Future Learning Architecture (recommendation)

Options evaluated (security/isolation/complexity/audit/Guide-fit): A direct-existing-APIs (REJECT prod: no learner isolation, privilege-escalation via IDOR-shape, lab/prod mixing). B Learning BFF→restricted proxy bundle (RECOMMEND first release: scoped learner JWT audience `learning`, allowlisted ops `source.ingest(lab-only)+case.get(own-lab)+timeline(own-lab)`, isolated lab sources per learner/cohort with TTL, BFF enforces lab guard, no admin ops reachable, audit per learner). C dedicated backend+DB (DEFER: justified only at multi-cohort persistence/instructor/commercial scale). D lab-adapter-inside-B (ADOPT as B component: explicit allowlisted lab actions, validation, audit — never shell). First release CAN reuse existing backend ONLY behind B (never direct); BFF REQUIRED (§43-Q5 YES). Lab isolation: per-learner source_instance (`lab-<cohort>-<learner>`), events tagged, cases auto-tagged, quality gate refuses lab data for DATASET_ELIGIBLE, retention sweeps lab data aggressively (24–72h).

# 29. Future Guide Architecture

Per §26 + §16 brief: identity (learner JWT), retrieval (versioned knowledge files + lab context builder), model abstraction (provider interface; GLM 5.3 Flash first target, no fine-tune in V3), orchestration (stateless per-turn, no memory across learners), tool allowlist (read-only lab tools), injection resistance (delimit+label untrusted telemetry, refuse instruction-override), redaction (central scrubber before model call), validation (labelled output schema, refuse on unsupported), escalation (to curriculum, never to analyst action), audit (every prompt/tool/output hash-chained), eval (adversarial prompt suite in 5.9 phase report).

# 30. Security Threat Model (per-phase checklist + V3 deltas)

Per phase evaluate: authn/authz/object-authz/source-trust/token audience+lifetime+replay+rotation/validation (in+out)/rate-limit/idempotency/concurrency/secrets/PII/provenance/audit/retention-deletion/migration/failure-isolation/restart/abuse/priv-esc/confused-deputy. V3 deltas: capability-squatting (attacker registers lookalike capability — mitigate: admin-only create + unique slug + audit), cross-capability rule fire (mitigate: capability-scoped applies_to), lab→prod contamination (mitigate: lab guard at promotion + TTL), evidence forgery (mitigate: provenance chain validation + immutable versions), dataset poisoning (mitigate: quality gate + cluster-aware splits + second reviewer).

# 31. Runtime / Deployment Strategy

Modular monolith, two planes (analyst :8088, ingress :8089) + future BFF (learning :8090) — no new infra. Bootstrap extends per phase (fail-loud). Config: add `PROSHIELD_RETENTION_*`, `PROSHIELD_LAB_*` (HOLD, parsed but unused), no secrets in logs (safe_summary pattern). Wiring checklist per phase (bundle construction + service injection + sink hooks + health probe). Local-first: Mongo single-node sufficient; document resource bounds.

# 32. Testing Strategy

Gate per phase: unit → integration (real Mongo) → validator/index tests → contract tests → live runtime → browser (Playwright journey + responsive) → adversarial (HTTP-status-exact matrix: 400 validation, 401 anon, 403 wrong-role, 404 IDOR-hidden, 409 conflict/replay, 410 retired, 429 rate, 500 safe-envelope, 501 reserved) → restart/recovery → phase approval. Fresh-DB audit script extended per phase; `verify_live_capability.py` pattern cloned per phase (`verify_live_<phase>.py`). "Tests passed" never suffices without live+browser+adversarial+restart evidence.

# 33. Rollback Strategy

Per phase: migration down-script + collection-drop guard (refuses if dependent refs exist) + op-deregistration + UI feature-flag off. Order reverse of §37. Data: resolutions/evidence/datasets never hard-deleted by rollback (flagged inactive); capability rollback blocked once sources bound (requires unbind migration first). Retention sweep has kill-switch env.

# 34. Risk Register

R1 Capability taxonomy wrong (P:med I:high — mitigate: seed minimal, version capabilities, mapping-profile indirection). R2 Migration mis-binds legacy rules (P:med I:high — dual-read + dry-run + audit). R3 Evidence growth semantics unknown (P:high I:med — spike week 1 of 5.4). R4 Retention deletes needed data (P:low I:critical — pin-refs + grace + kill-switch + dry-run). R5 Lab contamination (P:med I:high — lab guard + TTL + quality refusal). R6 Scope creep into training/Guide (P:med I:high — HOLD gates + language rule). R7 Docs-path drift (P:high I:low — mirror step in every phase exit). R8 Single-pattern detection ceiling (P:high I:med — document as limitation; new patterns only with connector evidence).

# 35. Open Questions

Q1 Evidence-accumulation: does auto-case append new detections/correlations today? (UNKNOWN — spike). Q2 Centralized payload under 32 KiB for large cases? (UNKNOWN — measure). Q3 Token-id hashing required by deployment policy? (assumption: no; confirm). Q4 Second-reviewer staffing for DATASET_ELIGIBLE? (product decision). Q5 Parquet threshold? (defer to usage metrics). Q6 PDF Unicode font dependency approved? (defer). Q7 Learning cohort scale for C-vs-B decision? (HOLD). Q8 Recycle-bin needed beyond soft-retire? (default no; revisit in 5.5 profiling).

# 36. Architectural Decisions (log)

AD-V3-01 Capability as allowlisted registry, no code upload (WHY: supply-chain; HOW: implementation_ref enum; OWNER: backend; ROLLBACK: drop). AD-V3-02 Source→Capability required, deterministic backfill (WHY: ownership; DATA: migration audited). AD-V3-03 Separate case_resolutions collection (WHY: history preservation vs embed-bloat; OWNER: backend). AD-V3-04 No investigation_evidence collection until profiling proves need (WHY: over-engineering). AD-V3-05 Evidence≠Dataset with second-reviewer gate flag (WHY: poisoning resistance). AD-V3-06 Immutable dataset versions + JSONL/CSV now, Parquet later (WHY: determinism). AD-V3-07 Learning BFF (B+D) first, no clone, no DB (WHY: isolation/cost; FUTURE: C on scale proof). AD-V3-08 Guide HOLD with scoped allowlist design (WHY: safety before intelligence).

# 37. Final Implementation Sequence

5.1 Capability Registry → 5.2 Source 2.0 (+migration) → 5.4 CaseResolution (+evidence-growth spike) → 5.5 Lifecycle/TTL → 5.6 Evidence Archive → 5.7 Datasets → 5.8 Export/Versioning. 5.3/5.9 HOLD throughout (seams only). Each phase exits only on: suite green + fresh-DB audit + live probe + browser + adversarial matrix + restart + phase report.

# 38. Master Exit Criteria

V3 complete when: every ACTIVE phase met its §18–25 acceptance; invariants §7 hold under adversarial suite; provenance traceable event→export for a live nginx lab case; lab data provably excluded from datasets; no HOLD scope built; docs mirrored to both paths; rollback tested; risks retired or accepted in writing.

---
# SELF-REVIEW (brief §42 A–AE)

A Phase1–4 studied ✓ (listed §2). B V3 master read ✓. C 5.0 freeze read ✓. D repo inspected ✓ (files §2). E contradictions recorded ✓ (C1–C6). F Capability≠Source ✓. G no subconnectors ✓. H Event≠Detection≠Correlation≠Case ✓. I analyst final ✓. J temp≠evidence ✓. K evidence≠dataset ✓. L no auto-training ✓. M provenance ✓. N no fabrication ✓. O 5.3 HOLD ✓. P 5.9 HOLD ✓. Q analyst app = learning env now ✓. R learning separate future ✓. S reuse evaluated ✓. T BFF evaluated ✓. U learning DB evaluated ✓. V clone evaluated+rejected ✓. W real-activity→real-pipeline ✓. X learner/security boundary ✓. Y guide identity/scope/tools ✓. Z adversarial/status-exact ✓. AA wiring ✓. AB migration ✓. AC rollback ✓. AD unknowns explicit ✓ (Q1–Q8). AE order dependency-derived ✓.
