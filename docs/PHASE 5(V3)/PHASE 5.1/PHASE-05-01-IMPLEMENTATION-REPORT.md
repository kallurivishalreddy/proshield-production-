# PHASE-05-01 — CAPABILITY MANAGEMENT & REGISTRY — IMPLEMENTATION REPORT

**Document ID:** `PHASE-05-01-IMPLEMENTATION-REPORT`
**Phase:** 5.1 (ACTIVE, FIRST) — Capability Management & Registry
**Authority chain:** Phase 1–4 + repo → V3 Master Plan → Phase 5.0 Freeze → `docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md` §18
**Backend status:** implemented, tested, live-verified (unchanged by the frontend correction — backend was always correct).
**Authoritative frontend:** `frontend/src_upgraded_gemini/` (React 19 + Vite 7 + Tailwind 4) → build `frontend/soc/index.html` → served at `/static/soc/index.html`.
**Legacy frontend:** `frontend/*.html`, `frontend/js/**`, `frontend/css/**` — NOT authoritative; Phase 5.1 must not live there.
**Date:** 2026-09-14 (patch round: 2026-09-14, see §14)
**Verdict:** **PASS** (all gates green on the authoritative React frontend; legacy-duplicate cleanup complete with zero regressions).
**Patch-round verdict:** **STABLE WITH KNOWN NON-BLOCKING ISSUES** — all confirmed 5.1 findings fixed with regression coverage (§14); remaining known issues are pre-existing/out-of-boundary (§10, §14 5.1-08/5.1-09).

> No claim of "100% bug-free" is made. Every RESULT below cites the exact evidence that proves it.

---

## 0. Decision summary (required pre-coding summary, as-built)

- **Existing analogue:** none — §18 states "NOTHING exists". Closest analogues reused: `SourceType` enum strings (seed ids), `SUPPORTED_CONNECTOR_TYPES` (truth rule: only nginx/simulator are live), nginx connector + 5-rule library, `BruteForceClusteringPattern` (`NGINX-CORR-BRUTEFORCE-001`), `HumanIdAllocator`, bootstrap `ensure_all_collections` pattern, SecureProxy `attach_*`/dispatch/permission pattern.
- **Files changed (backend, new):** `app/capabilities/{__init__,errors,models,registry,repository,seeds,service,human_ids_fallback}.py`.
- **Files changed (backend, modified):** `app/auth/permissions.py` (+`capability:read/write`, role defaults), `app/persistence/human_ids.py` (+`capability`→`CAP-` kind), `app/persistence/bootstrap.py` (+`capabilities` collection + idempotent seeds), `app/proxy/proxy.py` + `app/proxy/__init__.py` (12 `capability.*` ops, dispatch, handlers, exports), `scripts/proxy_server.py` (construct + wire + seed + health), `app/observability/health.py` (+`capability_registry` probe), `scripts/audit_fresh_db.py` (+capability checks), `scripts/proxy_server.py` `FakeCollection.find_one_and_update` + `tests/unit/_phase47_fakes.py` + `tests/unit/_phase49_fakes.py` (counter-persistence fix, pre-existing bug, required for CAP- monotonicity on fake backends).
- **Files changed (authoritative React frontend):** `frontend/src_upgraded_gemini/src/types/soc.ts` (+`Capability`), `src/services/backend.ts` (`RawCapability` + 8 capability ops incl. explicit lifecycle-op comment), `src/services/adapters.ts` (`adaptCapabilities`), `src/context/SocContext.tsx` (`registryCapabilities`, detail, relations, CRUD/lifecycle actions), `src/components/pages/CapabilitiesPage.tsx` (full rewrite: list/detail/create/edit/lifecycle/tabs), rebuilt `frontend/soc/index.html`.
- **Files changed (legacy frontend, REVERTED):** `frontend/capabilities.html` (deleted), `frontend/js/components/capabilities.js` (deleted), `frontend/js/components/layout.js` (capabilities nav entry removed), `tests/unit/test_frontend_ui_regression.py` (capabilities entry removed). Net legacy diff after cleanup: **zero**.
- **DB impact:** NEW `capabilities` collection only. `$jsonSchema` validator (`additionalProperties:false`, id pattern, allowlisted enums, bounded schema/profiles); indexes `cap_capability_id_unique` (unique), `cap_human_id_unique` (unique/sparse), `cap_status`, `cap_implementation_ref`, `cap_updated_at`, `cap_version`. No legacy collections altered; no migration of sources/rules (seed-only, §18 item 22).
- **API/auth impact:** +12 ops (`capability.list/get/create/update/enable/disable/deprecate/retire/archive/list_sources/list_rules/list_patterns`); new permissions `capability:read` (analyst/admin/internal) + `capability:write` (admin only); exact HTTP matrix proven (401/403/404/409/400). No existing op changed.
- **Compatibility impact:** none on V2 — detection/correlation/case pipeline untouched; rule/source contracts unchanged; relationship views are read-only derivations; V2 suites + live V2 checks green.
- **Risks:** taxonomy drift (mitigated: 6 frozen seeds, planned-guard); docs-path confusion (mitigated: report paths explicit); fake-capability (mitigated: allowlist + planned-guard + truthful planned-empty UI); scope creep into 5.2+ (mitigated: no source/rule rewiring — see §12).

---

## 1. Scope

**In scope (§18 items 1–33 except documented deviations):** Capability domain/model, `capabilities` collection, validators + indexes, technical (`cap-<slug>`) + human (`CAP-NNNNNN`) IDs, lifecycle/version handling, configuration schema + mapping profiles, rule/source/pattern relationship views, admin permissions/authz, `capability.*` operations, bootstrap + idempotent built-in seeds, V2 compatibility, React Capability UI wiring, unit/integration/DB/API/security/adversarial tests, live runtime + restart + Playwright verification, this report.

**Out of scope (5.2+, §12):** Source→Capability migration, source lifecycle/token redesign, ingress capability stamping, rule migration, evidence/dataset/learning/Guide work.

---

## 2. PLAN REQUIREMENT → IMPLEMENTATION → EVIDENCE → RESULT

### R1 — Capability domain/model (Freeze §11.3, Master §18 items 10–11)
- **PLAN REQUIREMENT:** `capability_id, human_id, name, description, responsibility, implementation(version of `implementation`), version, status, configuration_schema, mapping_profiles, rules, correlation_patterns, created/updated` with `extra=forbid`, bounded fields, no subconnector, no code upload.
- **IMPLEMENTATION:** `app/capabilities/models.py` — `Capability` (frozen, forbid), `CapabilityStatus` (active/disabled/deprecated/retired/planned/archived), `ImplementationRef` (nginx/simulator/planned), `MappingProfile` (bounded profile_id/source_type/field_map, forbids `__proto__`/executable expressions), `configuration_schema` JSON-serializable ≤8192 bytes with `eval/exec/subprocess/os.system/$where/__proto__` rejection; `rule_ids`/`pattern_ids` are **derived views only**, never stored.
- **EVIDENCE:** `tests/unit/test_phase51_capabilities.py::test_model_rejects_bad_id_and_impl_and_code_upload_markers`, `test_model_rejects_planned_active_mismatch`, `test_model_rejects_duplicate_profiles_and_version_bounds`; `python -m pytest tests/unit/test_phase51_capabilities.py -q` → **14 passed**.
- **RESULT:** PASS.

### R2 — `capabilities` collection + validators + indexes (Master §18 items 12–14)
- **PLAN REQUIREMENT:** NEW collection, `additionalProperties:false`, unique capability_id + human_id, indexes (status, implementation_ref, updated_at [+version]).
- **IMPLEMENTATION:** `app/capabilities/repository.py` (`CAPABILITIES_VALIDATOR`, `CAPABILITY_INDEX_SPECS`, `ensure_schema/ensure_indexes`, Pydantic-paired reads/writes, quarantine-on-corrupt); wired into `app/persistence/bootstrap.py::ensure_all_collections`.
- **EVIDENCE:** `test_repository_validator_and_indexes_documented`; `python scripts/audit_fresh_db.py` → **38/38** incl. `unique_index.capabilities.cap_capability_id_unique`, `validator.rejects_malformed_capability`, all 6 `capabilities.index.*`; live bootstrap log `collection_ready collection=capabilities validator=True indexes=[...cap_capability_id_unique...]` (`scripts/live51_last.log`, `scripts/pw51.log`, `scripts/restart51.log`).
- **RESULT:** PASS.

### R3 — Technical/human IDs (§18 item 15)
- **PLAN REQUIREMENT:** technical `cap-<slug>` stable + human `CAP-` via `counters` kind `capability`.
- **IMPLEMENTATION:** `CapabilityId` regex `^cap-[a-z][a-z0-9-]{1,47}$`; `ENTITY_KINDS["capability"] = CAP-6`; repository assigns at create; `human_ids_fallback.py` for older allocator catalogues.
- **EVIDENCE:** `test_seed_builtins_idempotent_and_human_ids_monotonic` (6 unique `CAP-`); live `capability.list` shows `CAP-000001…`; restart `CAP-000007 → CAP-000008` (`scripts/restart_verify_phase51.py` 7/7).
- **RESULT:** PASS.

### R4 — Lifecycle/version handling (§18 items 11/16, Freeze §11.4)
- **PLAN REQUIREMENT:** CREATE→ENABLE→DISABLE→RETIRE→ARCHIVE (+deprecate/planned per §18 item 11 status set); updates respect state; version monotonic.
- **IMPLEMENTATION:** `registry.ALLOWED_TRANSITIONS` + `service._lifecycle/enable/disable/deprecate/retire/archive`; planned drafts move planned↔disabled for review but **never activate to live** (service guard); `update` refuses retired/archived and non-increasing versions (string-int tolerant).
- **EVIDENCE:** `test_lifecycle_transitions`, `test_lifecycle_enable_disable_retire_archive_and_planned_guard`, `test_create_duplicate_conflict_and_version_monotonic`; proxy matrix test; live 17/17; restart 7/7.
- **RESULT:** PASS.

### R5 — Configuration schema / mapping profiles (§18 items 11/23)
- **PLAN REQUIREMENT:** `config_schema` object, bounded `mapping_profiles[] {profile_id, source_type, field_map}`.
- **IMPLEMENTATION:** model bounds (§R1); seeds ship `nginx-access-default` + `simulator-default` profiles.
- **EVIDENCE:** `test_adversarial_payloads_rejected` (oversized schema→400, 70-entry field_map→400, `__proto__`/`eval(`→400); live `evil_impl_400` PASS.
- **RESULT:** PASS.

### R6 — Rule/source/pattern relationship views (§18 items 2/16/19 + Freeze §10.1)
- **PLAN REQUIREMENT:** Capability → Sources, → Rules, → Correlation Patterns; immediately usable by source/rule workflows; derived, not stored authority.
- **IMPLEMENTATION:** `service.list_sources/list_rules/list_patterns` — read-only derivations (source_type↔implementation family; managed-rule `sources[]`; live pattern catalogue; nginx gets all patterns incl. `NGINX-CORR-BRUTEFORCE-001`; simulator filters `simulat*`; planned truthfully empty). `_enrich` adds `rule_ids/pattern_ids/source_count` to list/get.
- **EVIDENCE:** `test_derived_views_nginx_rules_patterns_sources` (5 nginx rules, ≥1 pattern, planned empty, sources view shape); live `nginx_5_rules`, `nginx_patterns_view`; React Rules tab renders `NGINX-*` (browser 6/6).
- **RESULT:** PASS.

### R7 — Admin permissions/authz (§18 items 17–18)
- **PLAN REQUIREMENT:** admin write (`capability:write`), analyst/admin read; object-authz N/A.
- **IMPLEMENTATION:** `Permission.CAPABILITY_READ/WRITE`; analyst+internal get READ, admin gets READ+WRITE; proxy `_require` on every handler; service `_require_admin` defense-in-depth.
- **EVIDENCE:** `test_analyst_cannot_write_but_can_read`, `test_proxy_authz_matrix_and_status_codes` (anon 401, analyst-create 403, dup 409, bad-impl 400, missing-id 400); live `analyst_create_403`; browser read-only banner for analyst role.
- **RESULT:** PASS.

### R8 — `capability.*` operations (§18 items 16–17)
- **PLAN REQUIREMENT:** create/get/list/update/enable/disable/retire (+list_rules/list_sources/list_patterns views); 409 on duplicate id; pagination bounded 50/200.
- **IMPLEMENTATION:** 12 ops (superset incl. deprecate/archive per Freeze lifecycle); `ALLOWED_OPERATIONS` + dispatch + handlers with `_view_to_dict` datetime-safe shaping.
- **EVIDENCE:** proxy matrix test; live 17/17 status-exact; `pw_verify_phase51.py` **30/30**; contract count 51+12=63 ops.
- **RESULT:** PASS.

### R9 — Bootstrap + idempotent built-in seeds (§18 items 20/33)
- **PLAN REQUIREMENT:** 2 active (nginx, simulator) + 4 planned (waf/iam/rate_limit/network, status=planned, no impl); idempotent; seed failure loud.
- **IMPLEMENTATION:** `seeds.build_builtin_capabilities()` (truthful copy: planned rows declare "no connector implementation ships in 5.1"); `seed_builtins` creates-missing-only; called from bootstrap AND proxy_server bundle (reload→seed→schema).
- **EVIDENCE:** `test_seeds_are_truthful_two_live_four_planned`; `test_seed_builtins_idempotent`; audit `seed_count_6`, `seed_2_live_4_planned`, `human_ids`; live `list_6_seeds`, `two_live`; restart boot1 6 → boot2 7.
- **RESULT:** PASS.

### R10 — V2 compatibility (§18 item 34 non-goals + Freeze §4)
- **PLAN REQUIREMENT:** preserve verified V2 detection/correlation/case pipeline; no source/rule rewiring.
- **IMPLEMENTATION:** no V2 model/repo/service signatures changed (only additive imports); relationship views read-only; detection engine untouched.
- **EVIDENCE:** `test_v2_pipeline_non_regression_nginx_detection_still_fires`; full unit **1294 passed**; integration **93 passed**; `e2e_test.py` **56 passed, 0 failed**; live `v2_rule_list_ok`, `v2_sources_ok`; `scripts/verify_live_capability51.py` "V2 nginx detection fires: 2".
- **RESULT:** PASS.

### R11 — Frontend wiring — AUTHORITATIVE REACT ONLY (§18 item 19 as corrected)
- **PLAN REQUIREMENT (corrected):** Capability UI ONLY in `frontend/src_upgraded_gemini/` → build `frontend/soc/index.html`; NO `frontend/*.html|js|css` work.
- **IMPLEMENTATION:**
  - `src/types/soc.ts`: `Capability` (mirrors backend view incl. `rule_ids/pattern_ids/source_count`, timestamps as strings).
  - `src/services/backend.ts`: `RawCapability` + `listCapabilities/getCapability/createCapability/updateCapability/capabilityLifecycle/listCapabilitySources/listCapabilityRules/listCapabilityPatterns` (each with explicit `capability.*` literal + comment that template-literal lifecycle op is one-wire-op-per-action, asserted by test).
  - `src/services/adapters.ts`: `adaptCapabilities` (pure pass-through, no derivation, no fabrication; planned stays planned).
  - `src/context/SocContext.tsx`: `registryCapabilities/capabilityDetail/capabilityLoading/capabilityError/selectedCapabilityId` + `loadCapabilities/loadCapabilityDetail/loadCapabilityRelations/createCapability/updateCapability/capabilityAction` + relation caches; `refreshAll` fetches `capability.list` alongside all V2 resources; toasts on writes only.
  - `src/components/pages/CapabilitiesPage.tsx`: full rewrite — backend-count badge + "Phase 5.1 live" badge, Reload + admin-gated Create, search + status filter, loading/empty/error/validation/conflict states, cards with `capability_id · human_id`, status/impl/version/rules-patterns counts, Open detail, state-machine-scoped lifecycle buttons (illegal targets hidden), detail panel with Edit (version-must-increase) + Overview/Sources/Rules/Patterns tabs with truthful planned-empty copy.
  - `vite.config.ts` unchanged (`outDir: frontend/soc`); rebuilt artifact `frontend/soc/index.html` (72 modules, gzip 294.57 kB).
  - Exact chain: `Capability backend → SecureProxy capability.* → src/services/api.ts callOrThrow → src/services/backend.ts ops.* → SocContext registryCapabilities/capabilityDetail → CapabilitiesPage.tsx → App.tsx Shell routing (capabilities) → frontend/soc/index.html`.
- **EVIDENCE:** `npm run typecheck` PASS; `npm run build` PASS (72 modules); `pw_verify_phase51.py` **30/30** (incl. `react_build_serves_200`, 11 `react_wires_*`, page-bound, no-placebo, truthful-empty + full API matrix); `browser_verify_phase51.py` **6/6** on `/static/soc/index.html` (login→Capabilities nav→6 rows→search→detail→Rules tab live `NGINX-*`→reload persists); network log shows only 200/`capability.*` + V2 ops, no 4xx except intentional adversarial probes.
- **RESULT:** PASS.

### R12 — Security: no subconnector / no code upload / `implementation_ref` allowlist (§18 item 23, Freeze §11.5)
- **PLAN REQUIREMENT:** allowlisted trusted reference only; registry must not become code-upload.
- **IMPLEMENTATION:** `ImplementationRef` enum; Pydantic + `$jsonSchema` enum enforcement; service `_parse_impl`; planned-activation guard; schema/profile executable-marker rejection.
- **EVIDENCE:** adversarial tests (bad impl→400, `evil.py`→400, oversized→400, anon/analyst/dup matrix); live `evil_impl_400`; `audit_phase51.no_subconnector_field`; React copy states allowlist explicitly.
- **RESULT:** PASS.

### R13 — Tests: unit → DB → validators/indexes → API/SecureProxy → authz → integration → live → Playwright → adversarial → restart (§18 items 28–31)
- **EVIDENCE:**
  - unit: **1294 passed** (`tests/unit`, incl. 14 new phase51).
  - integration (real Mongo): **93 passed**.
  - DB/validators/indexes: fresh-DB audit **38/38**.
  - API/SecureProxy/authz/adversarial: proxy matrix + live 17/17 status-exact.
  - live runtime: `verify_live_capability51.py` ALL CHECKS PASSED; `live_verify_phase51.py` 17/17; health shows 9th subsystem `capability_registry`.
  - restart: `restart_verify_phase51.py` 7/7 (seeds survive, created survives, state survives, counters monotonic).
  - Playwright (React): `pw_verify_phase51.py` 30/30 + `browser_verify_phase51.py` 6/6.
  - V2 non-regression: e2e 56/0, unit+integration green.
- **RESULT:** PASS.

---

## 3. Wrong legacy implementation found → removed/reverted → migrated

**What was wrong:** a complete duplicate Phase 5.1 Capability UI was built in the legacy multi-page frontend (`frontend/capabilities.html` + `frontend/js/components/capabilities.js`, nav wiring in `frontend/js/components/layout.js`, contract entry in `tests/unit/test_frontend_ui_regression.py`, plus legacy-targeted harnesses `scripts/pw_verify_phase51.py` (v1) + `scripts/browser_verify_phase51.py` (v1)). This violated the single-authoritative-frontend rule; the task correction ordered: stop legacy work, revert it, implement only in React.

**Removed (proves no parallel frontend remains):**
| File | Why safe to delete |
|---|---|
| `frontend/capabilities.html` | Untracked Phase 5.1 duplicate; no committed code references it (`search_codebase` for `capabilities.html` returns only the deleted file + the retired comment in `browser_verify_phase51.py` docstring). `scripts/e2e_test.py` asset list does not include it; `scripts/check_wiring.py` PAGES map does not include it. |
| `frontend/js/components/capabilities.js` | Untracked Phase 5.1 duplicate (`PSCapabilities`); no committed importer (`search_codebase` for `PSCapabilities|components/capabilities.js` returns only the deleted file + retired comments). No test imports it after the `test_frontend_ui_regression.py` entry removal. |
| Root `_debug_*.py` (9 files) | Ad-hoc debug scripts from this phase; never imported by tests or scripts. |

**Reverted (tracked files, net-zero legacy diff):**
| File | Revert |
|---|---|
| `frontend/js/components/layout.js` | Removed the added `{ id: "capabilities", href: "/static/capabilities.html", ... }` nav item and the `"capabilities.html": "capabilities"` active-id map entry. Verified: `git status --short` shows no legacy-frontend modification; `git diff --stat -- frontend/js/components/layout.js tests/unit/test_frontend_ui_regression.py` is empty. |
| `tests/unit/test_frontend_ui_regression.py` | Removed the added `"capabilities.html": "capabilities.js"` PAGES entry. The remaining suite (legacy contracts for the 9 pre-existing pages) is untouched and green. |

**Migrated (useful logic → authoritative React, not a copy):** lifecycle state→actions map, `capability.*` op set, search+status filter, loading/empty/validation/conflict/authz states, detail + Sources/Rules/Patterns tabs, truthful planned-empty copy, version-must-increase edit, human+technical id display — all re-implemented natively in `CapabilitiesPage.tsx` against `SocContext` (see §R11). No legacy JS was imported or ported verbatim.

**Verification after cleanup:** unit 1294 green (was 1295 with the removed PAGES entry — delta is exactly the 1 removed legacy assertion), typecheck PASS, build PASS, live 17/17, restart 7/7, `pw_verify` 30/30 (retargeted to React), browser 6/6 (retargeted to `/static/soc/index.html`), e2e 56/0, integration 93 green.

---

## 4. Legacy files audited (repository-wide dependency audit)

**Method:** `search_codebase` for every legacy path/token (`capabilities.html/js`, `PSCapabilities`, `frontend/*.html`, `e2e_test/check_wiring/repro_*`, `test_frontend_ui_regression`), plus read of `scripts/e2e_test.py` asset list, `scripts/check_wiring.py` PAGES map, `docs/frontend-refinement-report.md` §B/G (which already classified legacy files as TEST-REQUIRED).

**Deleted (proven unnecessary — Phase 5.1 duplicates only):** the 2 files + 9 debug scripts in §3. Proof of safety: no committed referencer exists post-deletion (search results above); full suites green after deletion.

**Retained with exact reason (NOT deleted — genuinely active contracts):**
| Files | Exact dependency (why deletion would break an active gate) |
|---|---|
| `frontend/*.html` (remaining 10: index/login/cases/case/detections/correlations/timeline/sources/rules/health) + `frontend/js/**` + `frontend/css/**` | `scripts/e2e_test.py` asserts 200 for 23 legacy assets (asset list lines 55–79, no capabilities entry — deletion of anything listed fails the 56-check gate); `scripts/check_wiring.py` inspects 9 legacy pages/components; `tests/unit/test_frontend_ui_regression.py` statically locks `frontend/js` contracts (30 tests). These are pre-existing V2 gates, unrelated to 5.1. |
| `scripts/e2e_test.py`, `scripts/check_wiring.py`, `scripts/repro_*.py` | Active V2 regression harnesses referenced by docs and CI memory; not obsolete. |
| `tests/unit/test_frontend_ui_regression.py` (minus the 1 removed capabilities line) | Active legacy-contract suite; remaining assertions all pass (44/44 with phase51 file). Migrating/replacing this suite is 5.x future work, explicitly out of the 5.1 boundary. |

**Uncertain → kept:** everything not listed as deleted. No file classified UNCERTAIN was deleted.

**Legacy tests migrated/replaced:** only the single added `PAGES` entry was removed (it tested the wrong duplicate; its coverage is superseded by the React `pw_verify` 30/30 + browser 6/6). No other legacy test was altered — weakening active coverage was forbidden and was not done.

---

## 5. Tests/results (exact commands + outcomes)

| Gate | Command | Result |
|---|---|---|
| New unit | `python -m pytest tests/unit/test_phase51_capabilities.py -q` | **14 passed** |
| Full unit | `python -m pytest tests/unit -q` | **1294 passed** (1295 before legacy-entry removal; delta = exactly that 1 assertion) |
| Integration (real Mongo) | `python -m pytest tests/integration -q` | **93 passed** |
| Fresh-DB audit | `python scripts/audit_fresh_db.py` | **38/38** |
| Live bootstrap/runtime | `python scripts/verify_live_capability51.py` | ALL CHECKS PASSED (10 collections, 6 seeds, restart-equivalent reload, V2 detection ×2) |
| Live HTTP matrix | `python scripts/live_verify_phase51.py` | **17/17** |
| Restart | `python scripts/restart_verify_phase51.py` | **7/7** |
| React wire + API matrix | `python scripts/pw_verify_phase51.py` | **30/30** |
| React browser (Chromium) | `python scripts/browser_verify_phase51.py` | **6/6** |
| V2 e2e | `python scripts/e2e_test.py` | **56 passed, 0 failed** |
| Typecheck | `npm run typecheck --prefix frontend/src_upgraded_gemini` | PASS |
| Build | `npm run build --prefix frontend/src_upgraded_gemini` | PASS (72 modules, `frontend/soc/index.html`, gzip 294.57 kB) |
| Wiring static check | `python scripts/check_wiring.py` | **FAIL (pre-existing, unrelated)** — `case.js: missing no-id guard` expects legacy string `No incident selected`, committed `case.js:527` has `No case selected`. Both sides ship at HEAD (documented in `docs/frontend-refinement-report.md` §§K/R/U as a known stale expectation). Not owned by 5.1; not touched per phase boundary. |

---

## 6. Playwright/runtime evidence

- **Target (corrected):** `http://127.0.0.1:<ephemeral>/static/soc/index.html` (React build, mongo backend, `--seed-credentials`), real admin login via React `LoginGate` (`#subject/#credential/submit`, `auth.issue`), NOT legacy HTML.
- **Flow proven:** sidebar `Capabilities` → "6 from backend / Phase 5.1 live" → `cap-nginx · CAP-000001` + `cap-simulator` rows → search narrows → card Open → detail (`impl=`, human id, status, version) → Rules tab renders live `NGINX-*` rules → reload re-fetches same rows (session persists).
- **States proven:** loading ("Loading capabilities…"), empty (search-no-match + truthful planned-empty copy), validation (BAD ID → 400 inline), conflict (dup id → 409), auth (analyst create → 403, analyst read-only banner), illegal-lifecycle hidden (no falsely-live future buttons — `(Future)` absent from `CapabilitiesPage.tsx`).
- **Console/network:** uvicorn access log (`scripts/browser51.log`, `scripts/pw51.log`, `scripts/live51_last.log`, `scripts/restart51.log`) shows `GET /static/soc/index.html 200`, `POST /api/proxy 200` for `capability.*` + V2 ops; no unexpected 4xx/5xx (adversarial 400/403/409 appear only on intentional probes); no console-exception defects (page.content assertions + `wait_for_selector`/`wait_for_function` timeouts would fail otherwise — 6/6 green).
- **Before/after cleanup:** before cleanup the browser scripts drove `/static/capabilities.html` (wrong target, since retired); after cleanup they drive `/static/soc/index.html` — 6/6 green on the authoritative target. Server-side API evidence (live 17/17, pw 30/30) is target-independent and unchanged.

---

## 7. Adversarial findings

| Probe | Expected | Got (evidence) | Disposition |
|---|---|---|---|
| anon `capability.list` (no token) | 401 | 401 (`_debug_proxy51`, proxy matrix test) | 5.1-owned, correct |
| analyst `capability.create` | 403 | 403 (unit + live `analyst_create_403` + pw `analyst_403`) | 5.1-owned, correct |
| duplicate `capability_id` | 409 | 409 (unit + live `dup_409` + pw `conflict_409`) | 5.1-owned, correct |
| `implementation_ref: evil.py` / URL / shell | 400 | 400 (unit + live `evil_impl_400`) | 5.1-owned, correct |
| oversized schema (9k blob) / 70-entry field_map / 500-char name | 400 | 400 (`test_adversarial_payloads_rejected`) | 5.1-owned, correct |
| direct-DB `{bogus: true}` insert | WriteError | WriteError (`validator.rejects_malformed_capability`, audit 38/38) | 5.1-owned, correct |
| activate `planned` → live | 409 refused | 409 (`activate planned` guard, live enable-returns-planned) | 5.1-owned, correct |
| version downgrade / edit retired | 400/409 | 400/409 (unit + live `downgrade version`) | 5.1-owned, correct |
| concurrent creates same id | one 409 | unique index arbiter (`cap_capability_id_unique` in audit; allocator atomic) | 5.1-owned, by construction + index proof |
| `check_wiring.py` FAIL | — | pre-existing stale legacy expectation (see §5) | **pre-existing/unrelated**, not fixed per boundary |

---

## 8. Restart proof

`scripts/restart_verify_phase51.py` (two real boots, same Mongo DB): boot1 seeds 6 → create `cap-restart` (`CAP-000007`) → retire → kill → boot2 lists **7** rows incl. `cap-restart=retired` → create `cap-restart-2` (`CAP-000008`, monotonic). **7/7 passed.** Log: `scripts/restart51.log` (`bootstrap.collection_ready collection=capabilities validator=True`, `capabilities_seeded`).

---

## 9. Deviations (from §18 letter, with justification)

1. **Status set superset:** added `disabled` + `archived` (Freeze §11.4 lifecycle REQUIRES disable/archive; §18 item 11 list omits them — Freeze wins by authority order).
2. **ID regex narrower:** `^cap-[a-z][a-z0-9-]{1,47}$` (Freeze allows refinement in 5.1; §18 item 11 pattern `^[a-z][a-z0-9-]{2,48}$` lacks the `cap-` root mandated by §18 item 15 `cap-<slug>` — implemented the intersection).
3. **Lifecycle ops superset:** `deprecate` + `archive` wired (Freeze lifecycle; harmless superset, hidden in UI unless legal).
4. **Planned↔disabled review transitions:** allowed so custom drafts are editable/reviewable without ever going live (service guard preserves the fake-capability ban; proven by tests).
5. **Write-response enrichment O(1):** create/update/lifecycle return the stored view without re-deriving relations (list/get keep full derivation) — performance, no contract change.
6. **Fake-backend counter fix:** `find_one_and_update` in `scripts/proxy_server.py` + test fakes now mutates the stored doc (pre-existing bug: counters never persisted → every human id `xxx-000001`). Required for CAP-/SRC- monotonicity on memory backends; real-Mongo path unchanged.
7. **Legacy duplicate built then deleted:** per correction order; net legacy diff zero (see §3). Authoritative React implementation is the only one that remains.

---

## 10. Known issues

1. `scripts/check_wiring.py` FAIL — pre-existing legacy-frontend gap, unrelated to 5.1. **CORRECTION (patch round):** the actual failure message is `case.js: missing no-id guard (renders 4 × 400 errors when opened without ?id=...)` — verified by running `python scripts/check_wiring.py` on 2026-09-14. The earlier claim in this report (a stale `No incident selected` vs `No case selected` string expectation) was **wrong**; the reviewer's description is the correct one. The defect lives in the legacy `frontend/js/**` harness owned by the V2 gates — outside the 5.1 boundary (§1); fix owned by whoever owns that harness.
2. Legacy `frontend/*.html|js|css` retained (see §4) — required by active V2 gates; NOT a parallel Capability frontend (no capability code remains there).
3. `frontend/soc/index.html` is a committed build artifact (72-module single file) — rebuild after any `src_upgraded_gemini` change (`npm run build`).
4. Ephemeral live-verify Mongo DBs (`proshield_phase51_*`) accumulate in local Mongo; safe to drop (all prefixed `proshield_phase51_`).
5. No `capability.archive` UI danger-zone confirmation beyond `confirm()`-free direct action + toast — acceptable for 5.1 admin tool; harden in 5.2+ if desired.

---

## 11. Exact 5.2+ deferrals (NOT implemented)

Source→Capability migration or backfill; `source_instances.capability_id` field; source lifecycle/token redesign; ingress capability stamping/resolution; rule `capability_id` migration or capability-scoped enforcement; pattern migration/ownership; CaseResolution/evidence/dataset/retention/export/learning/Guide work; legacy-frontend removal beyond the 2 Phase-5.1 duplicates; `test_frontend_ui_regression.py` migration. Next phase (5.2) consumes `capability_id` from this registry as-is.

---

## 12. Files changed (complete)

**New (backend):** `app/capabilities/__init__.py`, `errors.py`, `models.py`, `registry.py`, `repository.py`, `seeds.py`, `service.py`, `human_ids_fallback.py`; **new (tests/scripts):** `tests/unit/test_phase51_capabilities.py`, `scripts/verify_live_capability51.py`, `scripts/live_verify_phase51.py`, `scripts/restart_verify_phase51.py`, `scripts/pw_verify_phase51.py` (retargeted), `scripts/browser_verify_phase51.py` (retargeted), `scripts/audit_phase51.py`.
**Modified (backend):** `app/auth/permissions.py`, `app/persistence/human_ids.py`, `app/persistence/bootstrap.py`, `app/proxy/__init__.py`, `app/proxy/proxy.py`, `app/observability/health.py`, `scripts/proxy_server.py`, `scripts/audit_fresh_db.py`, `tests/unit/_phase47_fakes.py`, `tests/unit/_phase49_fakes.py` (+ unrelated pre-existing dirty files listed in `git diff --stat`, untouched by this phase).
**Modified (React):** `frontend/src_upgraded_gemini/src/types/soc.ts`, `services/backend.ts`, `services/adapters.ts`, `context/SocContext.tsx`, `components/pages/CapabilitiesPage.tsx`; rebuilt `frontend/soc/index.html`.
**Deleted:** `frontend/capabilities.html`, `frontend/js/components/capabilities.js`, 9 root `_debug_*.py`.
**Reverted to HEAD:** `frontend/js/components/layout.js`, `tests/unit/test_frontend_ui_regression.py` (zero net legacy diff).

---

---

## 14. REVIEW VERIFICATION + PATCH ROUND (2026-09-14, post DeepSeek review)

Every reviewer finding was independently reproduced or disproven against the
real code + real MongoDB 8.0.13 + live HTTP + real browser, then classified.
Reproduction script: `scripts/repro_5101.py` (fresh DB per run, dropped after).

| Finding | GLM reproduction result | Classification | Root cause | Patch | Regression test | Final verification |
|---|---|---|---|---|---|---|
| 5.1-01 planned→disabled | **REPRODUCED** (`scripts/repro_5101.py` exit 2 pre-patch): seed `cap-waf` → `capability.disable` → Mongo doc `{impl:planned, status:disabled}` → fresh service read → `document_quarantined` → `get=None`, `find_all` omits it, recovery `enable` → 404 phantom | **CONFIRMED BUG** (data-integrity) | `ALLOWED_TRANSITIONS[PLANNED]` contained `DISABLED` while the model invariant forbids impl=planned+status=disabled; `_lifecycle`/`enable` used `model_copy` (skips validation) and `repository.save` never re-validated; Mongo `$jsonSchema` cannot express cross-field rules | (a) removed `PLANNED→DISABLED` from the transition table (§18.29 transition matrix now: planned→retire/archive only); (b) `_lifecycle` + `enable` re-validate via `Capability.model_validate(updated.model_dump())` before any write → 409 on invalid result; (c) `repository.save`/`create` pre-persist validation guard (last line of defence for ALL writers incl. 5.2); (d) UI `lifecycleFor` no longer offers Disable on planned | `tests/integration/test_phase51_capabilities_mongo.py` (REAL Mongo): planned-disable refused, doc untouched, restart read OK, retire→restart→archive→restart all readable; invalid `model_copy` state rejected by `repository.save`; plus 6 unit tests (table, service, wire 409, guard) | **✓ FIXED** — post-patch `repro_5101.py` exit 0 (refused pre-write, doc valid, retire works, second restart readable); `restart_verify_phase51.py` 7/7; live `planned_disable_409`/`planned_stays_planned` PASS |
| 5.1-02 persisted audit | CONFIRMED requirement: Master §18.17 + §18.23 ("audit all writes") + §18.27 ("actor/action/capability_id/diff") + §18.33 ("CRUD audited"). No persisted record existed (log-only) | **CONFIRMED SPEC DEVIATION** | Not implemented in the original 5.1 build | New append-only `capability_audit` collection (`app/capabilities/audit.py`): validator + 2 indexes, written on seed/create/update/enable/disable/deprecate/retire/archive with bounded before/after snapshot + `changed_fields` diff; audit-write failure is logged at ERROR and never masks the op result (documented, standalone Mongo has no transactions); new read op `capability.audit` (capability:read; 404 on unknown id per Freeze §28.7) | `test_persisted_audit_trail_actor_action_diff`, `test_capability_audit_proxy_op_authz_and_shape` (unit, fake); `test_audit_records_persisted_and_survive_restart` (REAL Mongo restart); live `audit_records_persisted` + pw `audit_persisted`; fresh-DB audit `capabilities.audit_*` 3 checks | **✓ FIXED** — audit 42/42 incl. `audit_records_written count=6`, `audit_record_shape`, `pre_persist_cross_field_guard` |
| 5.1-03 initial-detail race | Reproduced as a transient UI truthfulness gap (relations fetch in flight could render empty `rule_ids`, falsely claiming "no rules"); INFO severity, no data impact | **CONFIRMED (minor, UI truthfulness)** — required by Freeze §28 truthfulness, not by §18.19 letter | relations fetched async; overview rendered `capabilityDetail.rule_ids` unconditionally | `capabilityRelationsLoaded` flag set only after the relations fetch for the selected capability completes; overview renders "Loading derived relations…" instead of empty arrays until then | `pw_verify_phase51.py` `react_relations_loading` (source-level) | **✓ FIXED** — pw 36/36 |
| 5.1-04 seed fail-loud | CONFIRMED requirement: Master §18.25 "seed failure blocks boot (fail-loud)". `bootstrap.py` comment SAID "Failures are loud" while the code swallowed exceptions into a warning (comment/code contradiction) | **CONFIRMED SPEC DEVIATION** | try/except-swallow around the capability seed block in `ensure_all_collections` | Seed block no longer catches: genuine seed failures now propagate and block boot (only on the real-Mongo path, where the block runs) | `test_seed_fail_loud_contract` (REAL Mongo, monkeypatched seed failure must propagate through `ensure_all_collections`) | **✓ FIXED** — and both real boots in `restart_verify_phase51.py` still seed cleanly (idempotency intact) |
| 5.1-05 check_wiring claim/cause | Ran `python scripts/check_wiring.py`: actual failure is `case.js: missing no-id guard (renders 4 × 400 errors when opened without ?id=...)` — the report's claimed cause ("stale `No incident selected` string") was **inaccurate**; the reviewer's cause is correct | **CONFIRMED REPORT ERROR / PRE-EXISTING, OUT OF 5.1 BOUNDARY** | Legacy `frontend/js/components/case.js` gap, pre-dates 5.1; legacy is V2-owned (report §4) | No code patch (out of boundary); the report's §10 claim corrected (see §10) | n/a | **✗ NOT A 5.1 DEFECT — report claim corrected** |
| 5.1-06 missing Health/Versions tabs | CONFIRMED requirement: Master §18.19 explicitly lists tabs "(Rules/Sources/Patterns/Health/Versions)" | **CONFIRMED SPEC DEVIATION** (minor) | Two of the five required tabs were not implemented | Added `Health` tab (truthful: implementation status live/planned, lifecycle state, derived coverage counts, timestamps, explicit note that per-source connector health ships in 5.2 — nothing fabricated) and `Versions` tab (current version + real §18.27 audit trail via `capability.audit`; empty trail shown truthfully) | `pw_verify_phase51.py` `react_health_tab` + `react_versions_tab` | **✓ FIXED** — verified in real Chromium session: Health shows `live connector family (nginx)`, `5 rule(s), 1 pattern(s)`; Versions shows the seed audit record; screenshot `pw51_versions_tab.png` |

### New findings discovered during the adversarial patch round

| ID | Finding | Classification | Disposition |
|---|---|---|---|
| 5.1-07 | `list_audit` initially returned 200 + empty trail for an UNKNOWN capability id, while the other three view ops return 404 (Freeze §28.7: unknown objects must not produce fake success) | CONFIRMED (minor, caught during self-review) | **✓ FIXED** — `list_audit` now resolves the capability first (404 when unknown); unit assertion `capability.audit cap-missing → 404` added; suites re-run green |
| 5.1-08 | `scripts/proxy_server.py::FakeDatabase` + `ensure_all_collections` raise `AttributeError: 'FakeCollection' object has no attribute 'name'` on the memory-backend path (bootstrap main loop touches `coll.name`); the capability seed block never runs there | PRE-EXISTING, OUT OF 5.1 BOUNDARY (memory-backend bootstrap never supported; all 5.1 gates use real Mongo; unit tests build services directly, not via bootstrap) | Recorded, not patched (would touch the V2-era fake harness) |
| 5.1-09 | Mongo `$jsonSchema` validator cannot express the cross-field invariant (impl=planned ⇒ status∈{planned,retired,archived}) — direct-DB writers could still insert the invalid combination | DOCUMENTED LIMITATION, MITIGATED | Application-level pre-persist guard in `repository.save`/`create` (tested); quarantine-on-read remains the final safety net; noted for 5.2, which must use the repository boundary |

### Post-patch gate results (all re-run fresh)

- `pytest tests/unit -q` → **1300 passed** (incl. 15 new/updated 5.1 tests)
- `pytest tests/integration -q` → **98 passed** (real Mongo, incl. 5 new restart/audit/fail-loud regressions)
- `python scripts/audit_fresh_db.py` → **42/42** (38 original + 4 new audit/guard checks)
- `python scripts/live_verify_phase51.py` → **20/20** (real HTTP, incl. corrected planned-409 flow + audit read)
- `python scripts/restart_verify_phase51.py` → **7/7** (two real boots, same DB, monotonic human ids)
- `python scripts/pw_verify_phase51.py` → **36/36**
- `npm run typecheck` → clean; `npm run build` → rebuilt `frontend/soc/index.html` (single-file artifact updated)
- Real Chromium (Playwright MCP) session against `http://127.0.0.1:8797/static/soc/index.html`: login → Capabilities (6 from backend) → planned cards offer Retire only (no Disable) → NGINX detail → Overview shows 5 real rule_ids → Health tab truthful → Versions tab shows persisted audit trail
- V2 pipeline checks inside live/pw scripts (`rule.list`, `source.list`, health probe list) → green

---

## 13. Final verdict

**PASS** — The Phase 5.1 Capability Registry is real end-to-end on the authoritative stack: Mongo validator/indexes → repository → service (lifecycle/version/allowlist) → SecureProxy `capability.*` (authz-exact) → React `api.ts → backend.ts → SocContext → CapabilitiesPage.tsx → frontend/soc/index.html`, with idempotent seeds (2 live + 4 planned), derived Sources/Rules/Patterns views, adversarial-exact statuses, restart persistence with monotonic human ids, V2 pipeline intact, and the legacy duplicate fully removed (net-zero legacy diff). The single FAIL in the repo (`check_wiring.py` stale string) is pre-existing, unrelated, and out of phase boundary.

**5.2 may proceed:** consume `capability_id` from this registry; do not redefine the Capability architecture frozen here.
