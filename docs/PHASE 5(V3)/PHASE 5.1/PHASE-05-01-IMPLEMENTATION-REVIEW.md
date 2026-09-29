# PHASE-05-01 — INDEPENDENT ADVERSARIAL REVIEW

**Document ID:** `PHASE-05-01-IMPLEMENTATION-REVIEW`
**Reviewer:** Independent reviewer (not implementation owner)
**Date:** 2026-09-14
**Scope:** Phase 5.1 Capability Management & Registry ONLY
**Verdict:** **APPROVED WITH REQUIRED PATCHES** (see §23 / §25)
**Post-patch verdict (§26):** **STABLE WITH KNOWN NON-BLOCKING ISSUES** — all required patches applied, independently verified, and covered by regressions.

> This document is an independent audit. It does not reuse the implementation
> report's claims; every major claim was re-proven against the real code, real
> MongoDB 8.0.13, the real HTTP SecureProxy server and the real React frontend.

---

## 1. Review scope

- Phase 5.1 Capability Registry: domain, persistence, SecureProxy ops, authz,
  runtime wiring, React frontend, V2 protection, restart persistence, adversarial
  and security review.
- Phase 5.2+ deferred work was NOT treated as a 5.1 defect (boundary in §6).

## 2. Documents used

- `docs/PHASE 5(V3)/FINAL PROSHIELD V3 IMPLEMEATION PLAN RELOADED.txt`
- `docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md`
- `docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md` (§18)
- `docs/PHASE 5(V3)/PHASE 5.1/PHASE-05-01-IMPLEMENTATION-REPORT.md`
- `.serena/memories/capability-patch-2026-09.md`

## 3. Code reviewed

- `app/capabilities/*` (models, registry, repository, service, seeds, errors,
  human_ids_fallback); `app/auth/permissions.py`; `app/persistence/human_ids.py`;
  `app/persistence/bootstrap.py`; `app/proxy/proxy.py` + `__init__.py`;
  `app/observability/health.py`; `scripts/proxy_server.py`;
  `scripts/audit_fresh_db.py`; `scripts/audit_phase51.py`;
  `scripts/check_wiring.py`; `tests/unit/test_phase51_capabilities.py`;
  `tests/unit/test_capability_patch.py`; React
  `src_upgraded_gemini/src/{services/api.ts,services/backend.ts,services/adapters.ts,
  context/SocContext.tsx,components/pages/CapabilitiesPage.tsx,types/soc.ts,
  App.tsx,components/layout/{Shell,Sidebar,TopBar}.tsx}`; built artifact
  `frontend/soc/index.html`.

## 4. Runtime / database environment

- Python 3.13.3; MongoDB 8.0.13 (`mongod` at 127.0.0.1:27017); FastAPI/uvicorn
  proxy (mongo backend); Node 22.x / npm 11; Vite 7.3.2 build.
- Every DB test used a FRESH database (`proshield_review_*`), dropped afterwards.

## 5. Plan-conformance result

| Master Plan §18 requirement | Actual implementation | Evidence | Result |
|---|---|---|---|
| 1–3 Capability domain, 1→N root | `app/capabilities/*` + derived Source/Rule/Pattern views | code + live UI + live API | CONFORMS |
| 5 Collection+service+ops+UI+6 seeds | done (12 ops, React UI, 2 active + 4 planned seeds) | live list CAP-000001..6 | CONFORMS |
| 11 Data shape | matches §18.11 (rule_ids/pattern_ids derived, not stored) | models.py | CONFORMS |
| 12–14 Validator/indexes | additionalProperties:false; unique id + human_id; status/impl/updated_at indexes | fresh-DB audit 38/38 | CONFORMS |
| 15 IDs | technical cap-<slug>, human CAP- via atomic counters | live CAP-000001..7 + restart | CONFORMS |
| 16 API surface | create/get/list/update/enable/disable/retire + 3 views (+deprecate/archive superset) | live HTTP matrix | CONFORMS (superset) |
| 17 SecureProxy | ALLOWED + dispatch + per-op permission gates | live 401/403/404/409/400 | CONFORMS |
| 18 Authz | capability:read (analyst/admin/internal), capability:write (admin) | live analyst create 403; UI read-only | CONFORMS |
| 19 Frontend | nav + list/detail/create/edit + tabs | real browser session | **PARTIAL — Health/Versions tabs missing** |
| 20 Runtime bootstrap | constructed in proxy_server bundle; ensure_all_collections; idempotent seeds | bootstrap log | CONFORMS |
| 22 Migration | seed-only, no legacy rewrite | git diff | CONFORMS |
| 23 Security | allowlist impl_ref; bounded schema/profiles; no code upload | payload matrix | CONFORMS |
| 24 Concurrency | unique index arbiter; atomic allocator | concurrent create 1 winner; lifecycle race safe | CONFORMS |
| 25 Failure | "seed failure blocks boot (fail-loud)" | try/except logs warning only | **DEVIATION** |
| 26 Observability | deep-health 9th subsystem capability_registry | live health probe | CONFORMS |
| 27 Audit | actor/action/capability_id/diff | only app log lines; NO persisted audit | **DEVIATION** |
| 29 Adversarial | anon 401 / analyst 403 / dup 409 / bad impl 400 / oversize 400 / direct-DB reject / concurrent 409 | all proven live | CONFORMS |
| 30 Browser round-trip + reload persistence | done in real browser (create/disable/enable/edit/tabs/search/reload) | §13 | CONFORMS |
| 31 Restart | seeds + created survive; counters monotonic | live restart | CONFORMS, except finding 5.1-01 |

## 6. 5.1/5.2 boundary assessment

- Production Source→Capability binding (no `source_instances.capability_id`,
  no ingress capability stamping, no rule `capability_id` migration):
  **CORRECTLY DEFERRED TO 5.2** (master §18.34 non-goals, §19).
- Read-only derived relationship views (`capability.list_sources/list_rules/
  list_patterns`) are the intended 5.1 compatibility surface: present, truthful
  (nginx: 5 rules / 1 pattern; planned: empty), and did not modify V2 data.
- **No premature 5.2 implementation was detected.**

---

## 7. DB verification (fresh real MongoDB)

| Check | Result |
|---|---|
| `capabilities` collection + `$jsonSchema` validator installed | PASS (listCollections + audit 38/38) |
| Unique indexes `cap_capability_id_unique`, `cap_human_id_unique` exist and work | PASS (direct duplicate insert → DuplicateKeyError) |
| Malformed docs (null dates / bad impl_ref / extra fields) rejected by validator | PASS (WriteError code 121) |
| Seeds idempotent | PASS (`{'created':6}` first, `{'created':0,'existing':6}` second boot) |
| Human IDs monotonic/unique | PASS (CAP-000001..7 across processes; audit concurrent 25/25 unique) |
| Writes / updates / lifecycle persist across restart | PASS (archived cap-simulator re-read as archived; created caps visible) |
| Concurrent create same id | PASS (exactly 1 winner, 5 conflict) |
| Concurrent lifecycle | PASS (no crash; final state valid) |
| Model-invalid cross-field state {impl:planned,status:disabled} | **FAIL** — accepted by Mongo, then QUARANTINED on read (invisible doc). Finding 5.1-01 |

## 8. API / SecureProxy verification

- All 12 `capability.*` ops dispatch; handlers enforce per-op permission gates.
- Live status matrix on real HTTP: anon→401; analyst create→403; duplicate id→409;
  missing id→400; bad impl_ref→400; oversized schema→400; `__proto__` in schema
  and field_map→400; oversized name→400; version downgrade→400; retired update→409;
  retired enable→409; archived disable→409; planned enable→409;
  create{impl:planned,status:active}→400; missing get→404.
- Error envelope truthful (`error.code/message`); no stack traces leak.

## 9. Authorization / security findings

- **CRITICAL:** none. **HIGH:** none.
- **MEDIUM:** 5.1-01 (planned→disabled restart quarantine).
- **LOW:** 5.1-02 (no persisted audit, §18.27); 5.1-04 (seed failure not fail-loud, §18.25).
- **INFO:** 5.1-03 (frontend initial-detail race); 5.1-05 (report claim inaccuracy on
  check_wiring); 5.1-06 (frontend Health/Versions tabs missing, §18.19).

## 10. Capability/source integration result

- New capability created via live API and React UI persisted to real Mongo,
  survived reload and server restart; human id continued from the atomic allocator
  (CAP-000007).
- Sources/Rules/Patterns views are truthful derivations (cap-nginx 5 rules / 1
  pattern; planned empty). Production Source→Capability binding is **correctly
  deferred**; no 5.2 migration attempted or required.

## 11. V2 regression result

No V2 regression found: unit 1294 passed; integration (real Mongo) 93 passed;
V2 e2e stack 56/56; fresh-DB audit 38/38 (all V2 validators+indexes still
installed); V2 nginx detection fires; React Rules page renders the real 5-rule
library; Overview shows real backend state.

## 12. Positive/negative detection result

Real MongoDB pipeline (same `app.pipeline.build_live_pipeline` code the ingress
uses), fresh DB, 5.1 code present:
- (A) 4 `authentication_failure` events, one source → 8 detections, 1 correlation,
  1 auto-case created and persisted. PASS
- (B) 3 benign `authentication_success` events → 0 detections, 0 cases. PASS
- 5.1 capability stack then seeded cleanly on the same DB (6 capabilities). PASS
## 13. Playwright result

Real browser vs real server (fresh Mongo `proshield_review_browser2`):
- admin login → Overview → Capabilities → real 6-row seed list → create
  `cap-reviewdemo` (CAP-000007) → disable → enable → detail tabs →
  Rules tab shows the 5 real `NGINX-*` rule ids → Patterns tab shows
  `NGINX-CORR-BRUTEFORCE-001` → Edit version bump v1→v2 → search filter ("waf")
  → reload → sign out → analyst login (read-only banner, no Create button) →
  sign out → admin again. All API responses 200; 0 console errors; responsive
  screenshots at 1440/1280/1024/768/390 show no clipping/overflow.

## 14. Frontend wiring trace

Backend → SecureProxy `capability.*` → `api.ts callOrThrow` → `backend.ts ops.*`
→ `SocContext {registryCapabilities, capabilityDetail, capabilitySources/Rules/
Patterns, capabilityAction}` → `CapabilitiesPage.tsx` → `Shell` routing →
`frontend/soc/index.html`.
- No hardcoded registry, no legacy wiring, no duplicate Capability implementation:
  `frontend/capabilities.html` + `frontend/js/components/capabilities.js` deleted;
  `layout.js` has no capability nav entry (only a generic "connector capability"
  label remains in legacy `sources.js`, not a Capability UI).
- `npm run typecheck` clean; `npm run build` reproduces `frontend/soc/index.html`
  BYTE-IDENTICAL to the committed artifact (SHA-256 `b6ee6d…5b72` match).

## 15. Responsive / accessibility review

- Cards, badges, lifecycle buttons, dialogs and tabs readable at all tested widths;
  `role="dialog"`, `role="alert"`, `aria-label`s present; analyst read-only banner
  correct; no horizontal overflow observed.
- **INFO (5.1-03):** after a fresh login the auto-selected detail panel can
  transiently show empty `rule_ids` until the user re-opens the card (frontend
  race; backend returns correct values; re-open fixes; no data impact).
## 16. Test-suite result

| Suite | Result (independent run) |
|---|---|
| Phase 5.1 unit (`test_phase51_capabilities.py`) | 14 passed |
| Full unit (`tests/unit`) | 1294 passed |
| Integration, real Mongo (`tests/integration`) | 93 passed |
| Fresh-DB audit (`scripts/audit_fresh_db.py`) | 38/38 |
| Live HTTP adversarial (this review) | 42/43 (1 fail = 5.1-01 repro) |
| V2 real-Mongo pipeline regression (this review) | 10/10 |
| V2 e2e stack (`scripts/e2e_test.py`) | 56/56 |
| React typecheck / build | clean / byte-identical artifact |
| `scripts/check_wiring.py` | FAIL (pre-existing; legacy-only; report's stated cause inaccurate — 5.1-05) |

## 17. Restart result

- Restart preserves seeds, created capabilities, archived status, and monotonic
  human-id counter. **Exception:** a planned capability disabled via
  `capability.disable` is invisible after restart (5.1-01).

## 18. Git / change audit

Separated work in `git status`/`git diff`:
- **Intended 5.1:** `app/capabilities/*` (new); `app/auth/permissions.py`;
  `app/persistence/human_ids.py`; `app/persistence/bootstrap.py`; proxy capability
  ops; `app/observability/health.py`; `scripts/proxy_server.py`;
  `scripts/audit_fresh_db.py`; React files + `frontend/soc/index.html`;
  `docs/PHASE 5(V3)/`; 5.1 tests/scripts. All uncommitted (untracked).
- **Legacy duplicate work:** `frontend/capabilities.html` +
  `frontend/js/components/capabilities.js` deleted; `layout.js` and
  `test_frontend_ui_regression.py` reverted (no residual capability entry).
- **Unrelated pre-existing dirty work (do not reset):** Phase-4 capability-patch
  files (`app/incidents|correlation|detection|sources|overview|timeline/*`,
  notifications, telemetry, exporter, `app/persistence/*`) — in the tree before
  this phase, not introduced by 5.1.
- **Generated:** `frontend/soc/index.html` (committed artifact, byte-reproducible),
  review artifacts `_review_*.py`, `_*.out`, `_*.log`, screenshots (drop at will).
## 19. Muse-known-issue validation

1. `check_wiring.py` FAIL — REAL, pre-existing, legacy-only harness. **The report's
   stated cause (“No incident selected” vs “No case selected”) is inaccurate**; the
   actual failure is “case.js: missing no-id guard”. The conclusion (pre-existing,
   out of 5.1 boundary) stands.
2. Legacy frontend retained — verified; contains no Capability implementation
   (only generic “connector capability” labels in the legacy sources page).
3. `frontend/soc/index.html` committed artifact — verified byte-reproducible.
4. Ephemeral `proshield_phase51_*` DBs — present; safe to drop.
5. No archive confirmation dialog — confirmed (report accurate; low risk for 5.1).

## 20. Confirmed findings

### 5.1-01 — CONFIRMED BUG (MEDIUM, data integrity): planned→disabled write is read-back-quarantined and the capability disappears after restart
- **Requirement:** planned drafts may move planned↔disabled for pre-live review
  (5.1 report deviation #4; unit test asserts disable→disabled then enable→planned).
- **Actual:** `capability.disable(cap-waf)` returns 200 and shows `disabled`
  in-session, but persists `{implementation_ref:"planned", status:"disabled"}`, which
  the Pydantic model rejects (`_check_status_impl`). Mongo's `$jsonSchema` has no
  cross-field constraint so the write succeeds; on read-back `_document_to_capability`
  quarantines the document (log: `capability_repository.document_quarantined`) and
  returns `None` — so after restart `capability.list` omits it and `capability.get`
  → 404, and `enable()` can no longer restore it. In-session, `update()` of the
  disabled-planned object also 400s ("invalid capability payload").
- **Root cause:** `ALLOWED_TRANSITIONS[PLANNED]` includes `DISABLED` while the model
  invariant forbids the combination; `registry.transition` / `service._lifecycle`
  use `model_copy` without re-validation and `repository.save` uses `replace_one`
  without re-validation.
- **Affected code:** `app/capabilities/registry.py::ALLOWED_TRANSITIONS`,
  `app/capabilities/service.py::_lifecycle/enable/disable`,
  `app/capabilities/models.py::_check_status_impl`,
  `app/capabilities/repository.py::save` (+ the Mongo validator lacks the
  cross-field rule).
- **Exploit path:** admin calls `capability.disable` on any planned capability; the
  document becomes a phantom after restart; recovery requires direct DB surgery.
- **Why it matters:** a supported 5.1 operation writes data that becomes
  unreadable/un-recoverable through the API; violates §18.31 restart persistence and
  the truthful-state principle.
- **Patch recommendation:** (a) remove PLANNED→DISABLED from the transition table
  (planned may retire/archive only), and (b) re-validate
  `Capability.model_validate(updated.model_dump())` in `_lifecycle` (as `update`
  already does) so any future invalid transition is rejected with 409 before write;
  (c) optionally add an application-level write-validation in `repository.save`.
- **Required regression test (real Mongo):** seed → `capability.disable(planned)` →
  assert `repository.get` returns the document (NOT quarantined) → new service
  (restart) → `capability.list` includes it → `enable` round-trip works.
### 5.1-02 — SPEC DEVIATION (LOW): §18.27 audit trail not implemented
- Writes only emit `_log.info(...)` lines; there is no persisted audit record and
  no diff capture anywhere in the repo.
- **Patch recommendation:** add an append-only audit collection/record (actor,
  action, capability_id, before/after) or explicitly document log-based audit as
  the accepted 5.1 control.

### 5.1-03 — RISK (INFO, frontend): initial auto-selected detail can render empty rule_ids
- Transient UI state at login/session boundaries; backend `capability.get` returns
  the 5 rule_ids (verified over HTTP); re-opening the card refreshes. No data impact.
- **Patch (optional):** render rule_ids as "loading" until the relations fetch
  completes.

### 5.1-04 — SPEC DEVIATION (LOW): §18.25 "seed failure blocks boot" not met
- `bootstrap.py` wraps the capability seed in try/except that only logs a warning;
  a failing seed would be skipped and boot would continue without the registry.
  (The validator/index bootstrap path DOES fail loudly; only the seed step is
  swallowed.)

### 5.1-05 — REPORT CLAIM INACCURACY (INFO): check_wiring failure cause mis-described
- Actual failure text is “case.js: missing no-id guard”; the report claims a stale
  string expectation. Both agree it is pre-existing and out of 5.1 boundary.

### 5.1-06 — SPEC DEVIATION (MINOR): frontend tabs omit Health and Versions
- §18.19 lists tabs (Rules/Sources/Patterns/Health/Versions); the page exposes only
  Overview/Sources/Rules/Patterns. No functional harm; document or add in a
  follow-up.

## 21. Potential risks

- The status/impl cross-field invariant lives only in Pydantic; MongoDB cannot
  express it, so every future writer (5.2+) must reuse the same validation or the
  quarantine path will hide malformed rows (this is exactly what 5.1-01 hit).
- Version increments only when the client supplies a higher version (the UI sends
  current+1); clients that forget the version field keep version frozen — no
  auto-bump on material change. Verify 5.2 consumers expect monotonicity.
- Taxonomy drift (documented risk §18.35), dev-only `--seed-credentials`,
  log-based-only audit — accept or mitigate as recorded.

## 22. False positives (reviewed and cleared)

| Suspected issue | Verdict | Evidence |
|---|---|---|
| planned→active bypass | NOT POSSIBLE | transition table + service guard; live 409; create planned+active → 400 |
| Sources lack capability_id | Correctly deferred to 5.2 | §18.34, §19 |
| Legacy duplicate Capability UI | CLEARED | deleted; React is the only implementation |
| Duplicate human_id possible | CLEARED | DB unique index rejects; atomic allocator |
| Oversized proxy response | CLEARED | `_shape_ok` caps at 1 MiB; relation views bounded 50/200 |
| Massive schema via API | CLEARED | 8 KiB bound → 400 |

## 23. Required patches

| # | Requirement | Patch | Regression test | Status (patch round §26) |
|---|---|---|---|---|
| 5.1-01 | Fix planned→disabled | remove PLANNED→DISABLED OR re-validate in `_lifecycle`+`save`; add cross-field write-validation | real-Mongo restart round-trip test (§20) | ✓ FIXED (all three mechanisms applied) |
| 5.1-02 | §18.27 audit | persisted audit record or documented acceptance | audit-write test | ✓ FIXED (persisted `capability_audit` + `capability.audit` read op) |
| 5.1-04 | §18.25 fail-loud | make seed failure raise or document deviation | seed-failure simulation test | ✓ FIXED (fail-loud implemented) |
| 5.1-06 | §18.19 tabs | add Health/Versions tabs or document deviation | browser test | ✓ FIXED (tabs added, browser-verified) |

## 24. Exact deviations from plan

1. `disabled` + `archived` statuses added (superset of §18.11 four-state set).
2. `capability.deprecate` + `capability.archive` ops added (§18.16 lists 7 core
   ops). Additive; authz-exact and needed to reach the added states.
3. ID regex `^cap-[a-z][a-z0-9-]{1,47}$` vs plan §18.11 `[a-z][a-z0-9-]{2,48}`
   (consistent with §18.15 “cap-<slug>” prefix rule).
4. planned↔disabled review transitions (report deviation #4) — **introduced
   5.1-01; FIXED in the patch round (§26): PLANNED→DISABLED removed,
   re-validation + pre-persist guard added.**
5. Seed failure swallowed (deviation from §18.25 fail-loud).
6. Audit trail not implemented (§18.27).
7. Frontend tabs missing Health/Versions (§18.19).
8. `cap_version` index added (harmless superset of §18.14).

## 25. Final recommendation

**APPROVED WITH REQUIRED PATCHES.**

The actual Phase 5.1 implementation satisfies the V3 plan and the Phase 5.1
contract in every material respect: a real reusable Capability domain with the
required 1→N compatibility foundation (Capability → Source/Rule/Pattern views),
no subconnector, no arbitrary code upload, allowlisted implementation references,
correct technical/human IDs with an atomic allocator, real Mongo
validator/indexes with idempotent seeds, exact authorization on all 12 SecureProxy
`capability.*` ops, truthful derived relationship views, authoritative-React-only
frontend wired end-to-end and byte-reproducible, V2 pipeline fully preserved
(positive detection, correlation, auto-case; negative no-false-positive; 1294 unit
+ 93 integration + 56 e2e + 38/38 audit + live HTTP + real browser), and the
5.1/5.2 boundary is respected (production Source→Capability binding correctly
deferred).

One confirmed data-integrity defect (5.1-01) affects a documented lifecycle path
(planned→disabled): it writes a state the model rejects and the document becomes
invisible after restart; it must be patched (with a real-Mongo restart regression
test) before 5.2 consumes the registry. The remaining findings are low-severity
spec deviations/claims (5.1-02, 5.1-04, 5.1-05, 5.1-06) and one benign frontend
race (5.1-03). No security-critical, architectural, or V2-regression defect was
found, and no correctly-deferred 5.2 work was misclassified. Do not merge-grade
without addressing 5.1-01 and recording decisions on the low-severity items.

---

## 26. PATCH VERIFICATION ROUND (independent verification + patch engineer, 2026-09-14)

Every finding in this review was independently re-verified against the actual
code, real MongoDB 8.0.13, live HTTP SecureProxy and real Chromium — none was
accepted or rejected on authority. Reproduction script: `scripts/repro_5101.py`
(fresh DB per run). Implementation report §14 records the same outcomes from
the implementation side.

| Finding | Verification result | Classification | Root cause | Patch | Regression test | Final verification |
|---|---|---|---|---|---|---|
| 5.1-01 | REPRODUCED pre-patch (exit 2): planned→disable persisted `{impl:planned, status:disabled}`; restart read → `document_quarantined` → `get=None`, list omits, `enable` → 404 phantom | **CONFIRMED BUG** | transition table contradicted model invariant; `model_copy` bypassed validation at `_lifecycle`/`enable`; no pre-persist guard in `repository.save` | removed `PLANNED→DISABLED`; re-validation in `_lifecycle` + `enable` (409); pre-persist guard in `repository.save`/`create`; UI planned cards drop Disable | `tests/integration/test_phase51_capabilities_mongo.py::test_planned_disable_refused_document_survives_restart_and_recovers` + `test_invalid_cross_field_state_cannot_be_persisted` (REAL Mongo) + 6 unit tests | ✓ FIXED — repro exit 0; restart 7/7; live planned_disable_409 PASS |
| 5.1-02 | §18.17/23/27/33 all require it; no persisted record existed (log-only) | **CONFIRMED SPEC DEVIATION** | not implemented | append-only `capability_audit` collection (validator+indexes) written on every write; read op `capability.audit` (capability:read, 404 unknown) | unit `test_persisted_audit_trail_actor_action_diff`, `test_capability_audit_proxy_op_authz_and_shape`; REAL-Mongo `test_audit_records_persisted_and_survive_restart`; live+pw audit checks; audit script 3 new checks | ✓ FIXED |
| 5.1-03 | transient empty-`rule_ids` render while relations fetch in flight — real but minor; truthfulness obligation (Freeze §28) supports fixing | **CONFIRMED (minor)** | unconditional render of `capabilityDetail.rule_ids` | `capabilityRelationsLoaded` gate renders "Loading derived relations…" instead of empty arrays | `pw_verify_phase51.py::react_relations_loading` | ✓ FIXED |
| 5.1-04 | §18.25 requires fail-loud; bootstrap comment said "loud" but code swallowed | **CONFIRMED SPEC DEVIATION** | try/except-swallow in `ensure_all_collections` seed block | seed failures now propagate (real-Mongo path) | REAL-Mongo `test_seed_fail_loud_contract` | ✓ FIXED (idempotent seeding still green in restart 7/7) |
| 5.1-05 | ran `check_wiring.py`: failure is `case.js: missing no-id guard` — this review's cause was right, the implementation report's claimed cause was wrong | **CONFIRMED REPORT ERROR / PRE-EXISTING, OUT OF 5.1 BOUNDARY** | legacy `frontend/js/**` gap owned by V2 gates | report §10 corrected; no code change (boundary) | n/a | ✗ NOT A 5.1 DEFECT — report claim corrected |
| 5.1-06 | §18.19 explicitly requires tabs "(Rules/Sources/Patterns/Health/Versions)" | **CONFIRMED SPEC DEVIATION** (minor) | two tabs missing | Health tab (truthful implementation/lifecycle/coverage facts; no fabricated probes) + Versions tab (current version + real audit trail) | `react_health_tab` + `react_versions_tab` | ✓ FIXED — verified in real Chromium; screenshot `pw51_versions_tab.png` |

### Newly discovered issues (adversarial patch round)

| ID | Finding | Classification | Disposition |
|---|---|---|---|
| 5.1-07 | `capability.audit` returned 200-empty for unknown capability (inconsistent with the 404 of the other three views; Freeze §28.7) | CONFIRMED (minor) | ✓ FIXED — 404 on unknown id + unit assertion |
| 5.1-08 | memory-backend `ensure_all_collections` raises `AttributeError` on `FakeCollection.name` before the seed block ever runs | PRE-EXISTING, OUT OF 5.1 BOUNDARY | recorded; not patched (V2-era fake harness) |
| 5.1-09 | Mongo `$jsonSchema` cannot express the cross-field invariant; direct-DB writers bypass it | DOCUMENTED LIMITATION | mitigated by app-level pre-persist guard in the repository (the only supported write boundary); 5.2 must not bypass it |

### Post-patch stability gate (all re-run after the final patch)

- Unit: `pytest tests/unit -q` → **1300 passed**
- Integration (real Mongo): `pytest tests/integration -q` → **98 passed**
- Fresh-DB audit: **42/42** (incl. new `capabilities.audit_collection_exists`, `audit_records_written`, `audit_record_shape`, `pre_persist_cross_field_guard`)
- Live HTTP: `live_verify_phase51.py` **20/20**; `pw_verify_phase51.py` **36/36**
- Restart: `restart_verify_phase51.py` **7/7** (two real boots, same DB, monotonic CAP- ids)
- Real-Mongo restart regressions: `test_phase51_capabilities_mongo.py` **5/5**
- React: `npm run typecheck` clean, `npm run build` rebuilt `frontend/soc/index.html`, real Chromium session verified list/detail/Health/Versions/no-Disable-on-planned
- V2: pipeline probes green in live+pw scripts; full V2 suites inside unit+integration green

### Final verdict (post-patch)

**STABLE WITH KNOWN NON-BLOCKING ISSUES.** All confirmed Phase 5.1 defects and
spec deviations are fixed with regression coverage; every gate is green; V2
shows no regression. Remaining known issues are pre-existing or explicitly
out-of-boundary (5.1-05 legacy harness, 5.1-08 memory-backend bootstrap,
5.1-09 validator-expressibility limitation, report §10 items). Phase 5.2 may
consume `capability_id` from this registry as-is — through the repository
boundary, which now enforces the cross-field invariant at write time.