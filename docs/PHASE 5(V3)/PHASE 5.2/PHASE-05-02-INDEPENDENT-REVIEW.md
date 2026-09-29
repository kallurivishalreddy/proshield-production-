# PHASE-05-02 — INDEPENDENT ADVERSARIAL REVIEW

**Document ID:** `PHASE-05-02-INDEPENDENT-REVIEW`
**Reviewer:** Independent reviewer (not implementation owner)
**Date:** 2026-09-16
**Scope:** Phase 5.2 Source Architecture 2.0 ONLY — current frozen implementation
**Verdict:** **APPROVED WITH REQUIRED PATCHES** (see §23)
**Environment:** Python 3.13.3 · pymongo 4.16.0 · MongoDB **8.0.13** (real, 127.0.0.1:27017, verified `server_info()['version']`) · Windows (cmd) · Playwright real Chromium (headless, `--no-sandbox`)

> This document is an independent audit. It does not reuse the implementation
> report's claims; every major claim was re-proven against the real code, real
> MongoDB, the real HTTP SecureProxy + ingress composition, and the real React
> frontend (`frontend/src_upgraded_gemini/` → `frontend/soc/index.html`).
> No code was patched. No implementation score is given. This review is not a
> declaration that the implementation is bug-free.

---

## 0. How this review was conducted

Authoritative basis read in full:

- V3 Master Plan (`docs/PHASE 5(V3)/FINAL PROSHIELD V3 IMPLEMEATION PLAN RELOADED.txt`)
- Phase 5.0 Architecture Freeze (`docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md`, 48 sections)
- Phase 5 Implementation Master Plan §19 (Phase 5.2 section, the binding contract for this phase)
- Phase 5.1 implementation report + independent review (registry baseline this phase consumes)
- FINAL Phase 5.2 implementation report (`docs/PHASE 5(V3)/PHASE 5.2/PHASE 5.2 IMPLEMENTATION REPORT.md`, round-3 frozen)
- ACTUAL CURRENT REPOSITORY (all code below was read, not inferred)

Code reviewed (file-read verified, current frozen state):

- `app/sources/{models,service,registry,repository,trust,ingress,replay_store,audit,capability_binding,migration,errors}.py`
- `app/rules/{types,registry}.py`, `app/rules/management/{definition,generic_rule,service}.py`, `app/rules/loader.py`, `app/rules/_library/nginx/*`
- `app/detection/{models,engine,pipeline}.py`, `app/severity/enrichment.py`
- `app/correlation/{models,patterns}.py`, `app/pipeline/{service,managed_rule_sync}.py`
- `app/domain/security_event.py`, `app/persistence/{bootstrap,schema,rule_repository,detection_repository,correlation_repository,security_event_repository}.py`
- `app/proxy/proxy.py` (all `source.*` handlers), `app/auth/permissions.py`
- `app/capabilities/seeds.py` (binding authority catalogue)
- `scripts/{proxy_server,ingress_server,verify_phase52_live,verify_phase52_pipeline,browser_verify_phase52,audit_fresh_db,check_wiring}.py`
- `frontend/src_upgraded_gemini/src/{components/pages/SourcesPage.tsx,components/modals/AddSourceModal.tsx,context/SocContext.tsx,services/backend.ts,services/adapters.ts}` + built artifact `frontend/soc/index.html` (1,199,742 bytes, verified to contain the new wizard/binding surface)
- Current Phase 5.2 tests: `tests/unit/test_phase52_{sources,provenance,proxy,migration}.py`, `tests/integration/test_phase52_sources_mongo.py`
- Current screenshots: `docs/PHASE 5(V3)/PHASE 5.2/screenshots/01–12` (12 files, real Chromium renders from the NEW build — see §12)

Runtime re-verification actually executed by this reviewer (fresh throwaway DBs, dropped afterwards):

| Gate | Command | Result (independent) |
|---|---|---|
| Unit (full) | `python -m pytest tests/unit -q` | **1449 passed** (matches report §24.1) |
| Integration (full) | `python -m pytest tests/integration -q` | **112 passed** (matches report) |
| Phase 5.2 unit slice | `test_phase52_{sources,provenance,proxy,migration} + test_phase51_capabilities` | **169 passed** |
| Real-Mongo Phase 5.2 | `tests/integration/test_phase52_sources_mongo.py` | **14 passed** |
| Live composition (F1-plane) | `python scripts/verify_phase52_live.py` | **14/14** (reproduced) |
| Chained pipeline (F3) | `python scripts/verify_phase52_pipeline.py` | **51/51** (reproduced) |
| Real Chromium (F2) | `python scripts/browser_verify_phase52.py` | **34/34** (reproduced, fresh screenshots overwritten) |
| Fresh-DB audit | `python scripts/audit_fresh_db.py` | **42/42** (reproduced) |
| V2 spot | `test_v2_patch_revalidation + test_phase49_pipeline` | **14 passed** |
| Legacy wiring script | `python scripts/check_wiring.py` | **FAILED** — pre-existing legacy-frontend gap (see 5.2-R-07, correctly out of scope) |
| Independent adversarial probes (new, throwaway scripts, since removed) | SecureProxy matrix (anon/collector/analyst/admin, injection, oversize, rotation-before-enable, IDOR-by-role) + ingress spoof/replay/stale-capability + rotation-semantics + planned-binding + 5.2-PRE-01 reproduction | All observations in §4–§15 |

Frontend rule obeyed: every frontend judgement below is against `frontend/src_upgraded_gemini/` and `frontend/soc/index.html`. The legacy `frontend/*.html` / `frontend/js/**` tree was inspected only to confirm it is out of scope, never as evidence for or against Phase 5.2 functionality.

Test rule obeyed: every test claim below cites the CURRENT Phase 5.2 files/scripts above. Historical round-1 counts in the report (§11/§17/§20: 1413/1525/1300, F1/F2/F3 NOT-PERFORMED) are treated as superseded history only.

---

## 1. Review scope

- Phase 5.2 Source→Capability authority, per-source token trust, ingress provenance, event→detection→correlation→case lineage, rule→capability resolution + migration, Mongo validators/indexes/repositories, migration determinism/idempotency/audit/restart, SecureProxy authn/authz/IDOR/error semantics/trust boundaries, NEW React Source wizard against the real backend, REAL current Playwright/Chromium behaviour of the NEW React frontend, current screenshots/evidence correspondence, REAL live ingress→event→detection→correlation→case, restart/recovery, V2 regression, the documented 5.2-PRE-01 classification, and any freeze/master-plan requirement missing or mismatched.
- Phase 5.3 was NOT started and is not discussed beyond the HOLD boundary check (§17).

---

## 2. Plan-conformance result (Master Plan §19 × Freeze)

| §19 requirement | Actual implementation | Evidence | Result |
|---|---|---|---|
| `source.capability_id` required for new; deterministic `SourceType→capability` backfill; unknown→quarantine | `SourceInstance.capability_id/capability_version/mapping_profile_id/capability_binding_status{bound,unbound,requires_verification}` (`app/sources/models.py`); `SOURCE_TYPE_TO_CAPABILITY_ID` 6-entry map (`app/sources/capability_binding.py`); `register()` resolves+validates before persist, never persists half-bound (`app/sources/service.py:423–545`); migration quarantines with `capability_id=None` (`app/sources/migration.py:plan_sources`) | F3 `A derives capability server-side (cap-nginx, bound)`; unit + Mongo quarantine tests; independent probe (unknown type → quarantine path) | CONFORMS |
| Token model UNCHANGED (HMAC sit-token, single-use, VALIDATED/ENABLED issue, ENABLED ingest) + rotation (issue new; single-use makes old dead) + retire revokes issuance + stops ingest (410) preserves history | `trust.py` canonical body + `MongoReplayStore` unchanged semantics; `service.issue_ingress_token/rotate_ingress_token`; ingress retired→410 / not-enabled→409 (`ingress.py`); F3 steps 4+6 | F3 51/51; independent replay/tamper/retire probes | CONFORMS with ONE documented semantic gap (see 5.2-R-02: rotation does not revoke an unused prior token — consistent with the single-use design, but the report's "makes old dead" wording overstates it) |
| Rules: `rule.capability_id` authoritative; source→capability→rules resolution replaces `sources[]` match (dual-read during migration, capability wins) | `RuleMetadata.capability_id + matches_capability + capability_authoritative_for` (`app/rules/types.py:244–403`); `RuleRegistry.list_for_event/applies_to` capability-first with dual-read fallback (`app/rules/registry.py:245–302`); `RuleDefinition.capability_id` persisted nullable (`definition.py`, `rule_repository.py` validator) | `test_phase52_*` rule-resolution + backfill tests; F3 `every detection carries cap-nginx` while legacy rules still fire pre-migration | CONFORMS |
| Ingress stamps `event.capability_id` (derived, never client) | `_capability_id_of(source)` from authenticated `SourceInstance` only; `_build_security_event(..., capability_id=derived)`; client `capability_id` ignored (`ingress.py:438–470, 600–660`); `SecurityEventProvenance.capability_id` + schema validator | Independent spoof probe: forged `cap-simulator` in body → 200 with server `cap-nginx` kept; `source` forced to registered `source.source` | CONFORMS |
| UI: 6-step wizard (Identity→Capability→Connection→Credentials→Validation→Enable&Verify) + token management + retire/archive views | `AddSourceModal.tsx` (steps 1–6, `data-testid=source-wizard`, `wizard-cap-*`, `wizard-deploy-enable`), `SourcesPage.tsx` (token panel, bind, audit, migration, retire gating), `backend.ts` 1:1 `source.*` ops, `SocContext.tsx` actions | F2 34/34 real Chromium; artifact contains new surface | CONFORMS |
| Migration REQUIRED for sources/rules (deterministic, audited, dry-run) | `SourceCapabilityMigration.{plan_sources,plan_rules,run,_apply_sources,_apply_rules}` + `set_capability_binding` `$set`-only + both audit trails | Mongo determinism/idempotency/audit/restart tests; live `migrate defaults to dry-run` + `no-op on second boot` | CONFORMS |
| Adversarial: cross-capability replay→403/401, retired→410, mismatched triple→403/400, mapping injection→400, concurrent enable/disable→409/serialised | Implemented: stale-capability token→401-class reject (`trust.py`); retired→410; impl-mismatch→400 (`capability_binding.py`); mapping-injection→400 (proxy shape validation); state-transition 409s | F3 + independent matrix (§4, §9) | CONFORMS (status-code mapping 400-vs-403 on two sub-cases is documented below as 5.2-R-06, not a boundary failure) |
| Acceptance: every source has capability; live nginx event carries `capability_id` end-to-end to detection; old sources work post-migration | New sources always bound; F3 proves event→detection(`capability_id`)→correlation(`capability_ids`)→case lineage on real Mongo; migration binds legacy deterministically, quarantine blocks ingest honestly | F3 51/51 + Mongo tests | CONFORMS |
| Freeze §7.1 #6/#7 (one capability→many sources; source resolves capability), no-subconnector rule, Event≠Detection≠Correlation≠Case, provenance §38 (never invent historical truth) | 1→N via `capability_id` on many instances; no subconnector field anywhere (`audit_fresh_db no_subconnector_field`); lineage stages distinct with derived-only provenance; quarantine never invents owner | Code + F3 + audit | CONFORMS |
| §19 token-id hashing "evaluate; default: keep" | Kept `MongoReplayStore` plaintext `token_id` + TTL; documented as 5.2-06 | Code | CONFORMS (approved default) |

No freeze/master-plan requirement was found missing or silently redefined. Two deliberate, recorded deviations exist and are accepted as documented (enrichment reads the event rather than the rule — strictly stronger, report §24.3; `MAX_CORRELATION_CAPABILITIES=16` bound — unspecified by the plan, mirrors D-4).

---

## 3. What the implementation report gets right (independently confirmed)

1. **Source→Capability authority is real.** `register()` binds server-side before persistence; the client-supplied `capability_id` is validated, never trusted (`proxy._handle_source_register` forwards both fields; `service._resolve_binding` validates against the live registry with the seed catalogue only as fallback). Mismatched triple (`nginx` source → `cap-simulator`) → 400; unknown capability → 400 with no invented owner. Reproduced via F3 steps 1–2 and independent probes.
2. **Ingress provenance is server-derived end-to-end.** Token authenticates the SOURCE INSTANCE (`sid_a` echoed, `provenance.source_instance_id == sid_a`); capability stamped from the authenticated record; per-event `source` forced to the registered `source.source` (independent probe: body `source=simulator` on an nginx token persisted as `nginx`). Client `capability_id` (top-level and per-event) ignored. The report's "client value ignored; mismatch → 400" row conflates two layers correctly distinguished in the code: *payload* capability is ignored (200, server value kept — correct, F3 step 3), while *binding-request* mismatch is rejected (400 — correct, F3 step 1). Both behaviours verified.
3. **Event→Detection→Correlation→Case lineage carries capability.** `enrich_detection` stamps from `provenance.capability_id` only; `BruteForceClusteringPattern` derives sorted/deduped `capability_ids` from member detections; both fields excluded from id derivation (determinism untouched); validators + indexes + readers round-trip them (`det_capability_id`, `corr_capability_ids`, null-tolerant readers). F3 steps 5–7 + `test_phase52_provenance.py` (36 tests) confirm.
4. **Tokens: per-source identity, replay, rotation, retirement, impersonation.** Distinct credentials per instance (A≠B); A-credential attributes to A, B-credential to B (no impersonation); replay → 401; tamper → 401; stale-capability token (cap-X signed, source now cap-Y) → reject; disabled → 409 on issuance; retired → 409 on issuance + 410 on ingest; history preserved and readable after retire. All reproduced.
5. **Migration is deterministic, idempotent, audited, restart-safe, non-fabricating.** Sorted plan, pure function of persisted state; second run writes zero changes and zero audit records (`is_noop`); dry-run writes nothing; every applied change appends `source_audit` (before/after + changed fields) and rule backfills append `capability_audit`; restart re-reports `already_bound`; half-migrated rows re-derived, never trusted; quarantined rows carry no capability anywhere. Reproduced on real Mongo.
6. **SecureProxy authn/authz and error semantics are correct on the Phase 5.2 surface.** Independent matrix: anon→401; collector/analyst writes→403; analyst reads (`source.audit`, `source.list/get`)→200; unknown op→400; `waf` register→400 (unsupported connector, see §5); mapping-profile injection (non-string)→400; oversize→400; rotate-before-enable→409; analyst `rotate/bind/migrate`→403; collector `audit`→403. Trust boundaries preserved: analyst plane never accepts raw telemetry; ingress plane serves only `source.ingest/health` and never the frontend or analyst ops.
7. **NEW React wizard is real and truthful.** Six steps execute against the real backend in real Chromium (F2 reproduced 34/34 in this review, fresh run); picker lists only real `capability.list` rows and excludes `planned`; preview shows real `capability_id/version`; credential is a real single-use `sit-…` shown once in an explicit panel (never a toast — the round-2 fix verified: card never renders token material); rotation issues a different credential; migration dry-run writes nothing; audit loads real entries; disable/re-enable/retire honoured with truthful gating (`RETIRED`, disabled controls); binding + lifecycle survive reload; no overflow at 5 viewports; no console errors; no 5xx.
8. **Restart/recovery holds.** Binding, lifecycle, quarantine status, human-id monotonicity, audit durability, and migration no-op-on-second-boot all reproduced (Mongo tests 12–15 + live `binding survives a second boot` + F2 reload persistence).
9. **Report hygiene is good.** Round-1 history is explicitly labelled as superseded; no "100% bug-free" claim is made; F1/F2/F3 are each tied to a current script + fresh output; the two round-2 in-scope fixes (toast leak, dropped wizard capability fields) are disclosed with coverage; non-performed UI paths (quarantine→Bind remediation in Chromium, wrong-role UI failures) are disclosed rather than claimed.

---

## 4. Findings

Severity scale used: CRITICAL (exploitable trust break / data loss) · HIGH (security-relevant defect in scope) · MEDIUM (functional defect / misleading behaviour / secret-handling weakness) · LOW (hardening / docs / edge-case).

### 5.2-R-01 — CONFIRMED BUG (MEDIUM) — `validate_capability_binding(allow_non_active=True)` skips the connector-family check, so the migration path can bind a source to a capability whose connector it does not implement

- **ID:** 5.2-R-01 · **Severity:** MEDIUM · **Classification:** CONFIRMED BUG
- **File/function/line:** `app/sources/capability_binding.py::validate_capability_binding` — the `if not allow_non_active:` block (status + `planned`-impl + family checks) vs the always-executed mapping-profile section. The family check (`impl_str != "planned" and impl_str != source_type → 400 "capability does not implement this source type"`) sits *inside* the `if not allow_non_active:` branch even though its own comment says it was "deliberately outside the `allow_non_active` branch".
- **Requirement:** Master Plan §19 (deterministic backfill to the *matching* capability; mismatched triple must not bind) + Freeze §7.1 (a source resolves to the capability that owns its connector family) + the function's own docstring ("a binding is only accepted when …").
- **Observed:** `validate_capability_binding(idx["cap-waf"], source_type="nginx", allow_non_active=True)` returns `ResolvedBinding(capability_id='cap-waf', …)` instead of rejecting. Reproduced by this reviewer (`_review_planned2.py`, since removed). New-source path is unaffected (`allow_non_active=False` rejects correctly).
- **Expected:** the family check applies on both paths; a planned capability accepts only its own family even during backfill (`cap-waf`+`waf` OK, `cap-waf`+`nginx` → 400).
- **Reproduction/evidence:** `python -c "from app.sources.capability_binding import validate_capability_binding, builtin_capability_index; validate_capability_binding(builtin_capability_index()['cap-waf'], source_type='nginx', allow_non_active=True)"` → returns a binding; with `allow_non_active=False` → `SourceCapabilityBindingError: capability is not accepting new sources`.
- **Root cause:** the family check was placed inside the `allow_non_active` gate; the comment describes the intended placement (outside, with a `planned`-impl carve-out for the same-family backfill) but the code does not implement it.
- **Impact:** latent only — the shipped migration never exercises the buggy branch because `plan_sources()` resolves the id from the deterministic map first (`nginx→cap-nginx`, never `nginx→cap-waf`) and `plan_rules()` never calls this function, so no current run can produce a cross-family binding through the supported entry points. A future caller that passes `allow_non_active=True` with an attacker-influenced pair would get a wrong-family binding the validator was supposed to refuse.
- **Phase 5.2 ownership:** YES (binding validator is Phase 5.2 code; the migration is the Phase 5.2 feature).
- **Recommended disposition:** REQUIRED PATCH (move the family check out of the `allow_non_active` branch, keeping the same-family `planned` carve-out; add `cap-waf+nginx allow_non_active=True → 400` + `cap-waf+waf allow_non_active=True → OK` unit cases). Does not block phase acceptance on its own (unreachable via shipped paths), but must not ship to 5.3 as-is.

### 5.2-R-02 — DOCUMENTATION ERROR (LOW, security-adjacent wording) — report's "rotation (issue new; single-use makes old dead)" overstates the implemented rotation semantics

- **ID:** 5.2-R-02 · **Severity:** LOW · **Classification:** DOCUMENTATION ERROR
- **File/function/line:** Report §19/§25.8 narrative vs `app/sources/service.py::rotate_ingress_token` (delegates to `issue_ingress_token`; no `release()`/revocation-list call) + `app/sources/replay_store.py::MongoReplayStore` (claim-on-verify only).
- **Requirement:** Truthful security documentation (Freeze §28; Master Plan §15 "defer [revocation list] until scale demands", correctly recorded as 5.2-07).
- **Observed:** after `t1 = issue(); t2 = rotate()`, the never-used `t1` still verifies successfully against a fresh replay store (reproduced by this reviewer). Rotation issues a *new* single-use credential and audits the intent, but does not invalidate an unused prior credential; the prior credential dies only on first use (replay-reject) or expiry. This is exactly the approved 5.2-07 design — the mechanism is correct, the sentence describing it is not.
- **Expected:** "rotation issues a fresh single-use credential and audits it; outstanding unused credentials expire naturally (no revocation list in this phase — see 5.2-07)".
- **Impact:** none on enforcement; avoids operators assuming rotation kills outstanding credentials.
- **Phase 5.2 ownership:** YES (report wording).
- **Recommended disposition:** REQUIRED PATCH (one-sentence report correction + carry the precise wording into 5.3 planning). Not a code defect.

### 5.2-R-03 — CONFIRMED BUG (MEDIUM) — `adaptRules` still renders legacy `conn-*` pseudo-capabilities for rules, so the Rules UI does not show the Phase 5.2 `rule.capability_id` authority

- **ID:** 5.2-R-03 · **Severity:** MEDIUM · **Classification:** CONFIRMED BUG (frontend truthfulness, in-scope UI surface)
- **File/function/line:** `frontend/src_upgraded_gemini/src/services/adapters.ts::adaptRules` — `capabilityId: r.sources?.length ? \`conn-${r.sources[0]}\` : ""` and `capabilityName: r.sources.join(", ")`.
- **Requirement:** Master Plan §19 ("rule.capability_id authoritative") + report §24.2/F1 (capability relationship shown truthfully) + the adapter file's own truth rules ("a field the backend does not supply is never fabricated").
- **Observed:** the Rules page derives a `conn-nginx`-style pseudo-id from `sources[]` even though the backend now supplies the authoritative owner. The backend `RawRule` type does not yet expose `capability_id`, so the UI cannot display it — the data path, not just the label, is pre-5.2.
- **Expected:** `rule.list/get` serve `capability_id` (nullable, honest `null` for legacy/ambiguous rules) and `adaptRules` renders it (or nothing) instead of a `conn-*` invention.
- **Impact:** analyst-facing ownership confusion on exactly the page that should prove "rules belong to capability"; no backend trust impact (detection uses `RuleMetadata.capability_id` server-side, which is correct).
- **Phase 5.2 ownership:** YES (rules→capability resolution is §19 scope; SourcesPage was fixed to use real `cap-*` ids while RulesPage was left on the legacy derivation).
- **Recommended disposition:** REQUIRED PATCH (add `capability_id` to the rule wire view + adapt it truthfully; regression: Rules page shows `cap-nginx` for an unambiguous migrated rule and empty — never `conn-*` — for an ambiguous one). F2 did not cover the Rules page capability display, so this was never exercised in Chromium.

### 5.2-R-04 — ARCHITECTURAL DEVIATION (LOW) — migration binds legacy `waf/iam/rate_limit/network` sources to `planned` capabilities that can never ingest, with no operator-visible remediation path in the shipped flow

- **ID:** 5.2-R-04 · **Severity:** LOW · **Classification:** ARCHITECTURAL DEVIATION (approved pattern, incomplete operator story)
- **File/function/line:** `app/sources/capability_binding.py::SOURCE_TYPE_TO_CAPABILITY_ID` (waf→cap-waf etc., all `planned`) × `app/sources/migration.py::plan_sources` (binds them via `_load_capability`, which checks presence+version but not liveness) × `app/sources/service.py::_require_bound` (a `bound`-to-`planned` source still cannot validate/enable/ingest — `_resolve_binding` for lifecycle-adjacent writes and `_require_bound` gate lifecycle, and `_handle_source_register` rejects new `planned` bindings).
- **Requirement:** §19 "others→matching planned capability" (the mapping itself conforms) + Freeze §29 lifecycle coherence (a `bound` source should be promotable toward ENABLED).
- **Observed:** a legacy `waf` source migrates to `bound → cap-waf (planned)` yet remains permanently unable to validate/enable/token/ingest (every step → 400/409 "not accepting new sources" / "requires verified binding" semantics). The state says `bound` while the lifecycle says "never runnable". The report never names this dead-end; the UI `bindableCaps` filter (`status==='active' && impl!=='planned'`) correctly hides `planned` from remediation, so the quarantined→Bind flow the report marks NOT PERFORMED is also the *only* flow that could rescue such a row — and it cannot select a `planned` owner either.
- **Expected:** either (a) legacy non-live families migrate to `requires_verification` (honest "no runnable owner yet") instead of `bound`-to-`planned`, or (b) the report documents `bound`-to-`planned` as a terminal parked state with its intended future transition (capability activation → re-bind) and the UI surfaces it distinctly from runnable `bound`.
- **Impact:** no trust break (nothing ingests that should not); operational confusion for exactly the legacy rows migration exists to rescue.
- **Phase 5.2 ownership:** YES.
- **Recommended disposition:** REQUIRED PATCH (documentation decision + UI distinction at minimum; do not change the mapping without a migration-version bump per `CAPABILITY_MIGRATION_VERSION` discipline).

### 5.2-R-05 — CONFIRMED BUG (LOW) — migration `plan_sources()` never validates the resolved capability's mapping profile, so a migrated source can land on `mapping_profile_id=None` where the new-source path would have deterministically selected the declared profile

- **ID:** 5.2-R-05 · **Severity:** LOW · **Classification:** CONFIRMED BUG (consistency)
- **File/function/line:** `app/sources/migration.py::plan_sources` (`mapping_profile_id=None` hard-coded on the `OUTCOME_BOUND` change) vs `app/sources/capability_binding.py::validate_capability_binding` (`elif len(declared)==1: resolved_profile = declared[0]` — e.g. `nginx-access-default` for `cap-nginx`).
- **Requirement:** §19 (mapping-profile handling deterministic) + "migrated rows behave like native rows" (report §17).
- **Observed:** F3 itself shows the asymmetry: natively registered A "resolved the mapping profile declared for nginx" while a migrated legacy nginx row gets `mapping_profile_id=None`. Profiles are currently inert (5.2-08: validated/persisted but never applied as transformations), so there is zero runtime effect today — the defect is a latent inconsistency that will matter the moment profiles gain semantics.
- **Expected:** migration resolves the profile the same deterministic way (or documents why it deliberately does not).
- **Phase 5.2 ownership:** YES.
- **Recommended disposition:** REQUIRED PATCH (one-line alignment + assertion), or an explicit documented deferral tied to 5.2-08. LOW only because profiles are currently inert.

### 5.2-R-06 — FUNCTIONAL ISSUE (LOW) — two adversarial refusals use 400 where the surrounding trust-boundary contract uses 403, weakening machine-readable error semantics (enforcement itself is correct)

- **ID:** 5.2-R-06 · **Severity:** LOW · **Classification:** FUNCTIONAL ISSUE
- **File/function/line:** `app/sources/capability_binding.py` (mismatched `capability_id`→`SourceCapabilityBindingError`, HTTP 400) and `app/sources/trust.py` stale-capability cross-check (→`SourceIdentityTokenError`, HTTP 401-class) vs Master Plan §19 adversarial shorthand ("cross-capability token replay→403", "mismatched source triple→403").
- **Requirement:** §19 adversarial matrix status-exactness (the plan's literal numbers) + Freeze trust-boundary clarity.
- **Observed:** F3 + independent probes confirm every case is *refused* (nothing ingests, nothing binds): mismatched binding request → 400 (not 403); stale-capability token → 401-class `source identity token does not match the registered source capability` (not 403). The report's §25.9 "mismatch → 400" row records the implemented mapping honestly — the deviation is from the plan's shorthand, not a cover-up.
- **Expected:** either align the two cases to the plan's 403 or record the 400/401 mapping as the deliberate contract (authentication-vs-authorization semantics: malformed binding request → 400, failed credential → 401-family, forbidden triple on an authenticated principal → 403 preserved at the ingress integrity check).
- **Impact:** clients keying automation off status codes see 400/401 where the plan says 403; no bypass (all paths refuse).
- **Phase 5.2 ownership:** YES.
- **Recommended disposition:** REQUIRED PATCH (documentation decision; code change optional and NOT recommended without a contract review, since 401-for-bad-credential is the sounder semantic).

### 5.2-R-07 — PRE-EXISTING (no action) — `scripts/check_wiring.py` FAILS on the legacy frontend (`case.js: missing no-id guard`)

- **ID:** 5.2-R-07 · **Severity:** — · **Classification:** PRE-EXISTING
- **File/function/line:** `scripts/check_wiring.py` (legacy `frontend/js/**` static checker) vs legacy `frontend/js/components/case.js`.
- **Requirement:** None in Phase 5.2 scope (legacy tree is explicitly non-authoritative).
- **Observed:** `python scripts/check_wiring.py` → `WIRING CHECK FAILED - case.js: missing no-id guard`. Reproduced by this reviewer. The checker inspects only the legacy tree; it knows nothing about `src_upgraded_gemini/`.
- **Expected:** failure confined to the legacy tree (it is).
- **Impact:** none on Phase 5.2. The report correctly excludes it (5.2-10, 5.1-05 lineage).
- **Phase 5.2 ownership:** NO.
- **Recommended disposition:** none (do not "fix" by touching legacy; optionally note the checker is legacy-scoped so future phases are not confused).

---

## 5. Audit item 1 — Source → Capability authority: PASS

New sources always carry a validated binding (`register()` → `_resolve_binding` → `validate_capability_binding` before persistence; `binding is None` → 400, never a silently unbound row). The deterministic map covers all six `SourceType`s; unknown/unresolvable → quarantine (`capability_id=None`, `requires_verification`), never an invented owner. Explicit client `capability_id` is validated against the live registry (unknown → 400, `planned` → 400 for new sources, cross-family e.g. nginx→cap-simulator → 400). `bind_capability` re-validates, refuses retired (409) and no-op re-binds (409, so no audit record claims an unchanged change). One latent validator flaw found (5.2-R-01) is unreachable via shipped paths.

---

## 6. Audit item 2 — Token identity, replay, rotation, retirement, impersonation: PASS (with wording correction 5.2-R-02)

Per-source identity proven (A→A, B→B; distinct credentials; cross-source attribution impossible because `provenance.source_instance_id` and `source` both come from the authenticated record). Replay → 401 (Mongo-backed single-use claim, fail-closed on store outage → 503, `replay_store_required` default True). Tamper → 401. Stale capability (token cap-X vs current cap-Y) → reject. Rotation issues a new credential and audits `source_token_rotate`, but does not revoke an unused prior credential (see 5.2-R-02 — approved 5.2-07 design, mis-described in one report sentence). Retirement revokes future issuance (409) and blocks ingest (410) while preserving readable history. Token-id hashing at rest remains plaintext (approved 5.2-06 default-keep). No impersonation path found.

---

## 7. Audit item 3 — Client capability/source spoofing: PASS

Payload `capability_id` (top-level and per-event) is ignored; the event is stamped from the authenticated source record. Payload `source` string is forced to the registered `source.source` (independent probe: `simulator` in body on an nginx token persisted as `nginx`). Token `source_type`/`source` are cross-checked against the registry at verify time (mismatch → 403-class `does not match registered source`). Mapping-profile injection (non-string, undeclared) → 400. Oversize/overshaped payloads → 400. The wizard's explicit `capability_id` is a *request* the server validates, never a self-grant (round-2 fix for the "capability choice was a lie" defect verified present: `proxy._handle_source_register` now reads and forwards both fields).

---

## 8. Audit item 4 — Ingress provenance: PASS

`_capability_id_of` yields a capability only for `bound` rows; `unbound`/`requires_verification` yield `None` (honest null, schema-nullable). Quarantined sources cannot ingest at all (409 `source_capability_unverified`) — accepting their telemetry would manufacture unstamped-or-falsely-stamped lineage. Disabled → 409, retired → 410, unknown instance → 404, oversized → 400, unauthenticated → 401-family, store-unavailable → 503 fail-closed. `collector` provenance field is the connector family (not attacker-controlled), `source_ip` preserved as attacker-attribution evidence (V2-19 fix intact), endpoint/asset reconciled against registration with `_untrusted_*` conservatively recorded in `details`.

---

## 9. Audit item 5 — Event→Detection→Correlation→Case lineage: PASS

F3 reproduced end-to-end on real Mongo through the shipped hook (`_run_live_pipeline_after_ingest`, same function the listener calls): suspicious `authentication_failure` ×4 → `NGINX-AUTH-FAILURE-001` detections each carrying `cap-nginx` + source-instance provenance → correlation with `capability_ids==("cap-nginx",)` and evidence referencing the real detections → auto-case whose lineage references the suspicious events and whose detections all carry `cap-nginx`. `Detection.capability_id` / `Correlation.capability_ids` are derived-only, excluded from id derivation, bounded (`^$|^cap-…` / max 16, sorted/deduped), nullable for pre-5.2 rows, indexed, and round-tripped by null-tolerant readers. No fabrication path found (blanks dropped, never defaulted).

---

## 10. Audit item 6 — Rules → Capability resolution and migration: PASS (with UI gap 5.2-R-03)

Registry resolution is capability-authoritative with a safe dual-read fallback: capability-owned rule + stamped event → capability equality decides (legacy `sources[]` cannot veto or admit); legacy rule → unchanged `sources[]` match; capability-owned rule + unstamped event → falls back to string match (no silent rule loss during migration). Migration backfills only unambiguous single-capability rules, audits each via `capability_audit`, leaves cross-source rules `ambiguous` untouched, never rewrites `already_bound`, sorts deterministically, and writes nothing on dry-run. The live detector honours analyst-plane enable/disable/retire via `ManagedRuleLifecycleSync` (V2-01 preserved). Gap: the Rules UI still shows `conn-*` pseudo-ownership because the wire view omits `capability_id` (5.2-R-03) — backend-correct, frontend-misleading.

---

## 11. Audit item 7 — Mongo validators, indexes, repositories, persistence consistency: PASS

Fresh-DB audit 42/42 reproduced. `source_instances` validator gained all five Phase 5.2 properties with `additionalProperties:false` retained; new indexes `source_capability_id` + `source_capability_binding_status` applied. `security_events.provenance.capability_id`, `detections.capability_id`, `correlations.capability_ids` (maxItems 16), `managed_rules.capability_id` validators all present and independently shown to reject malformed direct writes (`WriteError` on `EVIL` for all three probed collections). Repository readers (`_document_to_instance`, `_document_to_detection`, `_document_to_correlation`, `_document_to_definition`) all tolerate pre-5.2 absent fields without inventing values. `set_capability_binding` is `$set`-only (12 lineage fields byte-identical across migration — asserted in tests). `source_audit` collection (validator + 4 indexes) exists via both bootstrap and repository ensure paths.

---

## 12. Audit items 8 + 11 + 12 — Migration behaviour, NEW React wizard, screenshots/evidence: PASS

Migration (§4 detail) + F2 wizard (§3.7 detail) both reproduced. Screenshots: the 12 files in `docs/PHASE 5(V3)/PHASE 5.2/screenshots/` correspond to the NEW build — verified by (a) filenames matching exactly the paths `scripts/browser_verify_phase52.py` writes (`SHOTS / "01-sources-list.png"` … `"12-retired.png"`), (b) F2 re-run in this review overwriting them with fresh Chromium renders and still passing 34/34, and (c) the built artifact (`frontend/soc/index.html`, 1,199,742 bytes) containing the new wizard/binding surface. They are Chromium renders of `…/static/soc/index.html` served by the real analyst plane, not legacy pages, not mockups. Two disclosed non-performances stand: quarantine→Bind remediation in Chromium and wrong-role UI failures (backend-covered; honestly marked NOT PERFORMED).

---

## 13. Audit item 9 — SecureProxy authn/authz, IDOR, error semantics, trust boundaries: PASS (with mapping note 5.2-R-06)

Independent matrix (§3.6): 401/403/404/409/400 all exact on the five new ops; analyst reads allowed, writes refused; collector confined; unknown ops → 400 `unknown operation` (no stack leak); all failures use the safe-envelope (`error.code/message`, internal detail server-side only). No IDOR found: source access is by unguessable `source_instance_id` under role+permission gates with service-layer `_require_role` defence-in-depth; no cross-tenant object-authz concept exists in this phase by design (global catalogue, Freeze §12). Trust boundaries intact: `source.*` writes admin-only (`source:write`); reads analyst/admin (`rule:read` gate on `list/get/list_types` — pre-existing coupling, unchanged, not introduced here); ingress accepts only `source.ingest/health` via HMAC tokens and serves no analyst ops or frontend. Error-mapping note 5.2-R-06 is semantics-only; enforcement refuses in every case.

---

## 14. Audit item 10 — NEW React Source wizard against the real backend: PASS

Covered in §3.7/§12. Additionally verified: wizard `bindable` filter (`status==='active' && impl!=='planned' && supportedTypes.has(impl)`) exactly mirrors the backend `BINDABLE_CAPABILITY_STATUSES` + `planned`-impl refusal; `sourceType` derived from the capability's own `implementation_ref` (identity cannot drift client-side); deploy runs the real lifecycle (`register → configure → validate → [enable] → issue_token`) and never advances past a backend rejection (`deployError` surfaces the backend's safe message; step 6 entered only on `res.ok`); `SourcesPage.bindableCaps` uses the same rule; capability filter fixed to compare real `cap-*` ids (round-3 fix verified present).

---

## 15. Audit items 13 + 14 — Live chain + restart/recovery: PASS

F3 51/51 reproduced verbatim (including the intentionally reproduced 5.2-PRE-01 false-positive checks, which assert the defect exists *and* that provenance is unaffected). Restart: second boot over the same DB preserves binding/lifecycle/quarantine/audit/human-id monotonicity; migration re-reports no-op; F2 reload persistence holds. No recovery path (TTL sweeps, retention kill-switches) is owed by this phase and none is claimed.

---

## 16. Audit item 15 — V2 regression: PASS

Full suites green (1449 + 112, zero failures) including all V2-era pipeline/remediation/validator suites; live + F3 probes preserve retired→410 / disabled→409 / integrity→403 ordering; `rule.list`, `source.list`, health probes green inside the scripts. The single failing repo script (`check_wiring.py`) is legacy-scoped and pre-existing (5.2-R-07), not a V2 regression. 5.2-PRE-01 (below) is the only fidelity defect and is classified correctly.

---

## 17. Audit item 16 — The 5.2-PRE-01 classification: AGREED (PRE-EXISTING, correctly scoped, HIGH severity acknowledged)

Independently reproduced: a metadata-only `GenericDeclarativeRule` (`conditions=None`) matches a benign `request_blocked/200` event that the library `SimpleRule` predicate correctly rejects. Root cause confirmed in `app/pipeline/managed_rule_sync.py::seed_builtins` (+ the analyst-plane mirror `scripts/proxy_server.py::_seed_managed_rules`): both persist library rules as `RuleDefinition`s carrying only metadata, and `sync()` re-registers them as condition-less declarative rules, replacing predicates on the very next live event. The defect predates Phase 5.2 (V2-01/V2-P1 remediation), is untouched by any Phase 5.2 diff (capability fields, binding validator, register pass-through — none affect conditions or sync), and does not implicate capability provenance (false-positive detections still carry the correct `cap-nginx`, asserted by F3). Severity HIGH is appropriate (detection fidelity / alert fatigue → spurious correlations/cases on benign traffic); scope OUT-OF-5.2 is correct (repair means re-architecting library-rule governance — option (a)/(b) in the report — which this phase is forbidden to do). The report's "neither introduced nor worsened" claim holds: pre-5.2 code paths fired the same metadata-only rules for unstamped events; stamping a capability does not change *which* rules fire, only what provenance they carry. **Ownership for the fix belongs to a dedicated remediation phase, not 5.3 feature work.**

---

## 18. Audit item 17 — Freeze/master-plan mismatches: no silent redefinitions found

Checked: capability/source 1→N, no-subconnector, detection/correlation/case distinction, human authority (untouched — no resolution/evidence/dataset code added), temp-vs-durable lifecycle (untouched, correctly deferred to 5.5), evidence≠dataset separation (untouched), provenance §38, trust boundaries, 5.3/5.9 HOLD (no learning/Guide code added; `lab` seams from the plan were not smuggled in — correctly absent), testing gate per phase (met: unit+integration+mongo+live+browser+adversarial+restart+report). Two explicit, justified deviations recorded (§2 tail). New issues found by this review are all owned by Phase 5.2 (R-01–R-06 above); nothing was found that belongs to 5.1 (re-verified green) or 5.3+.

---

## 19. Classification ledger (challenge disposition on every report claim)

| Report claim | Independent verdict |
|---|---|
| F1 implemented (six-step wizard, picker, tokens, lifecycle, audit/migration UI) | CONFIRMED (F2 34/34 reproduced) |
| F2 real-Chromium passed | CONFIRMED (34/34 reproduced fresh) |
| F3 chained live pipeline passed | CONFIRMED (51/51 reproduced fresh) |
| 1449 unit + 112 integration green | CONFIRMED (exact counts reproduced) |
| 14/14 live, 42/42 audit | CONFIRMED (both reproduced) |
| Adversarial/security green | CONFIRMED (matrix + F3 + independent probes; two LOW semantic/documentation notes: R-02, R-06) |
| Restart/recovery green | CONFIRMED |
| V2 no unexplained regression | CONFIRMED (R-07 is legacy-scope, not V2) |
| 5.2-PRE-01 pre-existing/out-of-scope/HIGH | AGREED (§17) |
| 5.2-06/07/08/09/10/11 + 5.1-05/08/09 + UI non-performances | AGREED (all verified as stated; 5.2-07 wording sharpened by R-02) |
| "No open unexplained in-scope defect" | CHALLENGED — four new in-scope items found: R-01 (latent validator), R-03 (Rules UI ownership), R-04 (planned-bound dead-end), R-05 (migration profile asymmetry). All are bounded, none breaks trust enforcement, all have patches scoped. |
| Report-matches-reality / frozen | CONFIRMED modulo the required patches below |

No FALSE POSITIVEs needed against the report (its dismissed false-positive table §24.8 was not re-litigated; the mechanisms described check out). No SECURITY ISSUE rising to CRITICAL/HIGH was found in the Phase 5.2 trust boundary — the strongest new security-relevant item is R-01 at MEDIUM/latent.

---

## 20. New findings not already documented (summary)

- 5.2-R-01 (MEDIUM, latent binding-validator bypass on the migration path)
- 5.2-R-02 (LOW, rotation wording overstatement)
- 5.2-R-03 (MEDIUM, Rules UI `conn-*` pseudo-capability)
- 5.2-R-04 (LOW, `bound`-to-`planned` dead-end, no operator story)
- 5.2-R-05 (LOW, migration drops the deterministic mapping profile)
- 5.2-R-06 (LOW, 400/401-vs-403 status semantics on two adversarial refusals)
- 5.2-R-07 (PRE-EXISTING, legacy checker failure — recorded so it is not mistaken for a 5.2 regression)

---

## 21. Required patches (no code changed by this review)

1. **P-01 (from R-01):** move the connector-family check in `validate_capability_binding` outside the `allow_non_active` gate (keep the same-family `planned` carve-out); add `cap-waf+nginx allow_non_active=True → 400` and `cap-waf+waf allow_non_active=True → OK` unit cases.
2. **P-02 (from R-02):** correct the rotation sentence in the implementation report (and carry the precise semantics into future planning): rotation issues + audits a fresh single-use credential; outstanding unused credentials expire naturally (no revocation list — 5.2-07).
3. **P-03 (from R-03):** serve `capability_id` (nullable) on the rule wire view and render it truthfully in the Rules UI (never `conn-*`); Chromium regression covering migrated-unambiguous vs ambiguous rules.
4. **P-04 (from R-04):** decide and document the `bound`-to-`planned` terminal state (parked vs re-quarantine) with its future transition; surface it distinctly in the Sources UI (minimum: docs + distinct badge/copy; mapping change, if chosen, requires a `CAPABILITY_MIGRATION_VERSION` bump).
5. **P-05 (from R-05):** align migration's `mapping_profile_id` with the deterministic single-declared-profile rule, or explicitly defer it as part of 5.2-08 with a bright-line note.
6. **P-06 (from R-06):** record the deliberate 400/401-vs-403 error contract (or align to the plan — documentation decision required; code change not recommended without contract review).
7. **P-07 (5.2-PRE-01 ownership):** queue the managed-library seeding remediation as its own reviewed phase; forbid silent inclusion in 5.3 feature work.

---

## 22. Non-requirements (explicitly NOT demanded)

- Token-id hashing at rest (approved default-keep, 5.2-06).
- Revocation list (approved deferral, 5.2-07, wording sharpened by P-02).
- Payload transformation via mapping profiles (documented inert boundary, 5.2-08, consistency handled by P-05).
- Unknown-`source_type` persistence (closed-enum boundary, 5.2-09).
- Legacy frontend changes (out of scope, 5.2-10; R-07 stays failing-by-design in its own scope).
- `verify_restart_persistence.py` execution (environment precondition, 5.2-11).
- Quarantine→Bind and wrong-role-UI Chromium coverage (accepted NOT PERFORMED; backend-covered).
- Any 5.3/learning/Guide/dataset/evidence work (HOLD respected).

---

## 23. FINAL VERDICT: **APPROVED WITH REQUIRED PATCHES**

Phase 5.2 delivers what §19 demands: real Source→Capability authority, per-source token trust with replay/rotation/retirement isolation, server-derived ingress provenance, end-to-end capability lineage (event→detection→correlation→case), capability-authoritative rule resolution with a safe dual-read migration, validated/persisted/indexed Mongo consistency, deterministic/idempotent/audited/restart-safe migration, authz-correct SecureProxy and ingress boundaries, a real six-step React Source workflow verified in real Chromium, fresh corresponding evidence, a live 51-check chained pipeline, restart safety, and no V2 regression. The 5.2-PRE-01 HIGH is genuinely pre-existing, correctly scoped out, and does not implicate Phase 5.2 provenance.

The phase is **approved** subject to patches P-01–P-07 (§21) being applied and re-verified (R-01/R-03 unit + Chromium regressions at minimum) before or alongside the opening of Phase 5.4 planning. **BLOCKED is not warranted** — no finding breaks trust enforcement, fabricates provenance, loses data, or admits spoofed telemetry; every refusal path refuses. **Unconditional APPROVED is not warranted** — R-01 leaves a validator bypass (latent) on the migration path, R-03 leaves misleading ownership in the Rules UI, and R-04/R-05 leave migration-state inconsistencies that the next phase will build on.

Do NOT start Phase 5.3 (HOLD — unchanged).

---

## 24. Reproduction appendix (commands actually run by this reviewer)

```bat
python -m pytest tests/unit -q
python -m pytest tests/integration -q
python -m pytest tests/unit/test_phase52_sources.py tests/unit/test_phase52_provenance.py tests/unit/test_phase52_proxy.py tests/unit/test_phase52_migration.py tests/unit/test_phase51_capabilities.py -q
python -m pytest tests/integration/test_phase52_sources_mongo.py -q
python scripts/audit_fresh_db.py
python scripts/verify_phase52_live.py
python scripts/verify_phase52_pipeline.py
python scripts/browser_verify_phase52.py
python scripts/check_wiring.py
```

Plus throwaway adversarial probes (removed after use): SecureProxy role matrix, ingress spoof/replay/stale-capability, rotation semantics, planned-binding matrix, 5.2-PRE-01 predicate-vs-declarative comparison, direct-write validator rejection (`WriteError` on `EVIL` capability in `detections`/`security_events`/`source_instances`). MongoDB version pinned via `server_info()['version'] == '8.0.13'`. All DB-touching runs used fresh `proshield_*` databases, dropped afterwards.

---

## 25. Review-integrity statement

This review inspected and tested the CURRENT frozen Phase 5.2 implementation only: `frontend/src_upgraded_gemini/` and `frontend/soc/index.html` for all frontend judgements; current Phase 5.2 test files and verification scripts for all test judgements. Historical round-1 state, counts, and screenshots were treated as superseded history. Nothing was patched, ranked, or scored. The implementation was challenged rather than accepted — seven findings (R-01–R-07) are recorded above with file/function/line, requirement, observation, expectation, reproduction, root cause, impact, ownership, and disposition. The implementation is not declared bug-free.
---

> **PART III NOTICE (2026-09-17):** two independent Phase 5.2 audits were subsequently compared with
> each other and against the running product by the implementation owner. Part III (below) records the
> adjudication, the four confirmed in-scope defects that were fixed (including one fresh-deployment
> bootstrap race that BOTH this review and the other audit missed), and the post-patch gate results.
> See `PHASE-05-02-OWNER-RECONCILIATION-AND-PATCH-REPORT.md` and `PHASE-05-02-FINAL-BASELINE.md`.

# PART II — IMPLEMENTATION-OWNER VERIFICATION OF R-01–R-07

> Added by the implementation owner on 2026-09-16. **PART I above (Muse's findings
> §1–§25) is preserved verbatim and unedited.** This part is the owner's independent
> re-verification of each finding against the current code, with the resulting
> disposition, patch and fresh evidence. Nothing in Part I has been altered,
> re-scored, or removed.
>
> The owner did **not** accept the findings as given. Each was reproduced from the
> code, with the smallest decisive test, before any change was made.

## 26. Owner dispositions (summary)

| ID | Muse classification | Owner disposition | Patched? |
|---|---|---|---|
| 5.2-R-01 | CONFIRMED BUG (MEDIUM) | **CONFIRMED — and BROADER than reported** | YES |
| 5.2-R-02 | DOCUMENTATION ERROR (LOW) | **CONFIRMED** (report + one UI tooltip) | YES (docs + tooltip) |
| 5.2-R-03 | CONFIRMED BUG (MEDIUM) | **CONFIRMED — but root cause PARTIALLY FALSE POSITIVE** | YES (frontend only) |
| 5.2-R-04 | ARCHITECTURAL DEVIATION (LOW) | **CONFIRMED** (docs + distinct UI state) | YES (docs + UI) |
| 5.2-R-05 | CONFIRMED BUG (LOW) | **CONFIRMED** | YES |
| 5.2-R-06 | FUNCTIONAL ISSUE (LOW) | **CONFIRMED — documented, code deliberately unchanged** | YES (docs) |
| 5.2-R-07 | PRE-EXISTING | **CONFIRMED pre-existing / out of scope** | NO (correct) |
| 5.2-PRE-01 | pre-existing HIGH | **RECONFIRMED pre-existing / out of scope** | NO (correct) |

## 27. Per-finding owner verification

### 5.2-R-01 — CONFIRMED, and the hole was wider than reported

**Verified code path.** `app/sources/capability_binding.py::validate_capability_binding`.
Before the fix the connector-family check sat **inside** `if not allow_non_active:`
while its own comment said "Deliberately outside the `allow_non_active` branch". The
code and the comment disagreed; the comment described the intent, the code was wrong.

**Decisive reproduction** (throwaway probe, pre-fix):

```
R01_waf+nginx_allowTrue        -> BOUND     (cap-waf)        should be REFUSED
R01_waf+waf_allowTrue          -> BOUND     (correct: the migration must keep working)
R01_sim+nginx_allowTrue        -> BOUND     (cap-simulator)  should be REFUSED
R01_nginx+simulator_allowFalse -> REFUSED   (correct, unchanged)
R01_nginx+nginx_allowFalse     -> BOUND     (correct, unchanged)
```

**Owner correction to the finding.** Muse tested only `cap-waf + nginx` and concluded
the flaw was confined to *planned* capabilities. It is not: with
`allow_non_active=True` the whole branch was skipped, so a **LIVE** capability
(`cap-simulator`, a shipped connector) also accepted an `nginx` source. The scope is
therefore slightly *understated* in Part I, not overstated.

**A subtlety that made the prescribed patch insufficient.** A naive "move the check out
of the gate" would **not** satisfy Muse's own proposed test: the check contained
`impl_str != "planned"` and `cap-waf`'s `implementation_ref` is literally `"planned"`,
so `cap-waf + nginx` would still have bound. A planned capability carries no connector
family in its `implementation_ref`. The fix therefore derives that family from the
deterministic map already in the module, in reverse
(`CAPABILITY_ID_TO_SOURCE_TYPE`, generated — never hand-maintained), so nothing is
invented and the two views can never disagree.

**Patch applied** (`app/sources/capability_binding.py`): the family check moved out of
the `allow_non_active` branch; a planned capability's family is resolved from the
derived inverse map; a capability with no declared family abstains rather than guessing.

**Post-fix reproduction** (same probe):

```
R01_waf+nginx_allowTrue        -> REFUSED  "capability does not implement this source type"
R01_waf+waf_allowTrue          -> BOUND    (cap-waf)     <- migration preserved
R01_sim+nginx_allowTrue        -> REFUSED
R01_nginx+simulator_allowFalse -> REFUSED
R01_nginx+nginx_allowFalse     -> BOUND    (nginx-access-default)
```

**Regression coverage:** `tests/unit/test_phase52_sources.py::TestBindingFamilyCheckOnBothPaths`
(7 tests), including an exhaustive seeded-capability × every-source-type matrix. These
would have failed before the patch — the pre-fix probe above is the evidence.

### 5.2-R-02 — CONFIRMED (documentation, plus a UI string the reviewer did not see)

**Verified code path.** `app/sources/service.py::rotate_ingress_token` delegates to
`issue_ingress_token`; `app/sources/replay_store.py::MongoReplayStore` claims on verify
only. Muse is right: rotation issues a fresh single-use credential and audits it, and
does not revoke an outstanding unused one. The mechanism matches the approved `5.2-07`
deferral; only the description overstated it.

**Additional instance found by the owner.** The same overstatement was shipped in the
UI: the "Rotate token" control's `title` in `SourcesPage.tsx` read *"The previous token
is retired"* — the identical false claim in an operator-facing string.

**Patch:** report wording corrected (§25.8 of the implementation report); the tooltip now
states that a fresh single-use credential is issued and audited and that outstanding
unused credentials are **not** revoked in this phase. No token logic changed — the
mechanics were never wrong.
### 5.2-R-03 — CONFIRMED as a frontend defect; the stated ROOT CAUSE is a FALSE POSITIVE

**Owner correction — the most important disagreement with Part I.** Muse wrote:

> "The backend `RawRule` type does not yet expose `capability_id`, so the UI cannot
> display it — the data path, not just the label, is pre-5.2."

**That is wrong, and it was verified as wrong before patching.** The `rule.list` /
`rule.get` wire view is `RuleDefinition.to_canonical_dict()`
(`app/proxy/proxy.py::_handle_rule_list` / `_handle_rule_get`), and that method already
emits `"capability_id": self.capability_id` (`app/rules/management/definition.py`). The
read path is `RuleDefinition.model_validate(payload)` and `RuleDefinition` declares the
field. Probe result:

```
R03_wire_has_key                       -> true
R03_wire_bound_value                   -> "cap-nginx"
R03_wire_ambiguous_value               -> null
R03_roundtrip_through_model_validate   -> "cap-nginx"
```

The backend **does** serve the authoritative owner, including an honest `null` for a
legacy/cross-source rule. The defect is **frontend-only**: the TypeScript `RawRule`
interface omitted the field and `adaptRules` ignored it, inventing `conn-${sources[0]}`.
Consequently patch **P-03's first half — "serve `capability_id` on the rule wire view" —
was already satisfied** and needed no backend change.

**Verified defect** (`frontend/src_upgraded_gemini/src/services/adapters.ts`, pre-fix):
`capabilityId: r.sources?.length ? \`conn-${r.sources[0]}\` : ""` and
`capabilityName: r.sources.join(", ")` — an invented id no capability ever holds.

**A second, unreported consequence.** The Rules-page capability filter compared
`r.capabilityId` (a `conn-*` invention) against `capabilities`, which on that page is the
**legacy `ConnectorCapability[]`** list of `conn-*` chips. That filter therefore "worked"
only because *both* sides were fabrications. Repointing the rule at the real `cap-*` id
without updating the filter would have silently broken it. The patch moves both sides to
the real registry.

**Patch applied (frontend only):** `RawRule.capability_id` added to the wire types;
`adaptRules(raw, detections, capabilities)` renders the backend value resolved to its
registry name, empty when the backend reported no owner; `SocContext` passes
`registryCapViews`; `RulesPage` filters by real registry capabilities and renders the
capability name or an honest "<sources> — no capability owner" fallback, with
`data-capability-id` / `data-testid` hooks. `adaptRules` no longer emits `conn-*`.

**Real-Chromium coverage added** (Muse correctly noted this page had never been
browser-covered). The browser gate gained 4 checks and screenshot
`13-rules-ownership.png`, asserting against real seeded library rules that:

```
[PASS] Rules navigation renders the Rules page
[PASS] rules exist to assert ownership against (real seeded library rules)
[PASS] no rule scope renders a fabricated conn-* capability
[PASS] every rule scope is a real cap-* owner or honestly unowned
```

### 5.2-R-04 — CONFIRMED (documentation + a distinct UI state)

**Verified code path.** `SOURCE_TYPE_TO_CAPABILITY_ID` maps `waf/iam/rate_limit/network`
to `planned` capabilities; `migration.py::plan_sources` binds them; the lifecycle gates in
`service.py` then refuse every runnable step. The probe confirms the row lands as
`outcome: bound` to `cap-waf`.

**Owner decision on the fix.** Muse offered (a) re-quarantine or (b) document + surface.
**(a) was rejected:** Master Plan §19 explicitly requires "others → matching planned
capability", so re-quarantining would deviate from the frozen plan and — per
`CAPABILITY_MIGRATION_VERSION` discipline — would need a migration-version bump. The
binding is correct and truthful; what was missing was an operator-visible distinction
between "bound and runnable" and "bound, parked".

**Patch applied:** documented as a deliberate parked state in the implementation report,
and the Sources UI now labels it distinctly — a `bound`-to-`planned` source renders
`binding_status` in amber with `— parked: no live connector` (backed by
`data-testid="source-binding-status-<id>"`) instead of the green runnable styling. The
mapping itself was **not** changed.
### 5.2-R-05 — CONFIRMED

**Verified code path.** `app/sources/migration.py::plan_sources` hard-coded
`mapping_profile_id=None` on the `OUTCOME_BOUND` change, while
`validate_capability_binding` deterministically selects the single declared profile.

**Decisive reproduction** (pre-fix probe):

```
R05_migrated_nginx.mapping_profile_id -> null
R05_native_nginx.profile              -> "nginx-access-default"
```

**Patch applied (architecture-consistent, not a one-line special case).** A single shared
authority was extracted — `capability_binding.deterministic_mapping_profile()` — and
**both** paths now resolve through it, so they cannot drift. Post-fix probe:

```
R05_migrated_nginx.mapping_profile_id -> "nginx-access-default"   (== native)
R05_migrated_waf.mapping_profile_id   -> null   (planned declares none: honest)
R05_native_nginx.profile              -> "nginx-access-default"
```

**Regression coverage:**
`TestMigrationPlan::test_migrated_row_resolves_the_same_mapping_profile_as_a_new_row`
asserts migrated == native by calling both paths;
`test_planned_family_migrates_with_no_profile_never_a_guess`; and
`TestBindingFamilyCheckOnBothPaths::test_deterministic_profile_helper_matches_the_binding_path`.
F3 re-confirms it live ("A resolved the mapping profile declared for nginx").

### 5.2-R-06 — CONFIRMED; code deliberately NOT changed (documentation decision)

Owner agreement with Muse's own recommendation. Verified: a mismatched source/capability
triple refuses with **400** (`SourceCapabilityBindingError`) and a stale-capability
credential refuses with a **401-class** `SourceIdentityTokenError`, where the plan's
adversarial shorthand says "403". Every path refuses; no bypass exists.

**Disposition: documented, not code-patched.** Changing 400→403 on a malformed binding
*request* would report a malformed request as an authorization failure; changing 401→403
on a bad credential would weaken the sounder authentication semantic (a credential that
fails to authenticate is 401, not 403). The 403 is preserved where it is correct — the
ingress integrity check on an authenticated principal. The exact contract is now recorded
so future phases keying automation off status codes use the recorded mapping.

### 5.2-R-07 — CONFIRMED pre-existing / out of scope; deliberately untouched

`scripts/check_wiring.py` inspects only the legacy `frontend/js/**` tree and fails on
legacy `case.js`. The authoritative frontend is `frontend/src_upgraded_gemini/` →
`frontend/soc/index.html`, which the checker does not know about. No Phase 5.2 code path is
involved. **No change made** (touching the legacy tree is out of scope, `5.2-10`); the
checker's legacy-only scope is recorded so later phases are not misled.

### 5.2-PRE-01 — RECONFIRMED pre-existing / out of scope

Fresh evidence: `git diff --stat HEAD -- app/pipeline/` is **empty** and
`app/pipeline/managed_rule_sync.py` was last changed in `f674f09` (2026-09-06, also
`HEAD`). The chained live run reproduces the behaviour in the same run that proves
Phase 5.2 provenance correct ("KNOWN PRE-EXISTING DEFECT reproduced … the false positives
do NOT indicate a Phase 5.2 capability defect"). Not fixed: the repair changes frozen
detection semantics and belongs in its own reviewed phase (Muse's P-07); it must not be
absorbed silently into 5.3.
## 28. Patch log and post-patch gate results (owner)

| Patch | From | Files changed |
|---|---|---|
| P-01 | R-01 | `app/sources/capability_binding.py` (+ derived `CAPABILITY_ID_TO_SOURCE_TYPE`) |
| P-02 | R-02 | implementation report §25.8 wording; `SourcesPage.tsx` rotate tooltip |
| P-03 | R-03 | `services/backend.ts`, `services/adapters.ts`, `context/SocContext.tsx`, `components/pages/RulesPage.tsx` (backend wire view already compliant) |
| P-04 | R-04 | implementation report (parked state); `components/pages/SourcesPage.tsx` distinct badge |
| P-05 | R-05 | `app/sources/capability_binding.py` (shared helper), `app/sources/migration.py` |
| P-06 | R-06 | implementation report (error contract recorded); **no code change** |
| P-07 | 5.2-PRE-01 | none — queued as its own reviewed phase, forbidden from silent absorption into 5.3 |

New regression tests: 9 unit tests in `tests/unit/test_phase52_sources.py`
(`TestBindingFamilyCheckOnBothPaths`, 7; `TestMigrationPlan` additions, 2) plus 5 new
real-Chromium checks (4 for R-03 + 1 navigation-restore).

**Post-patch gates, all re-run after the changes:**

| Gate | Result |
|---|---|
| Unit (full) | **1458 passed** (was 1449; +9 new) |
| Integration (real Mongo, full) | **112 passed** |
| Combined | **1570 passed, 0 failed** |
| Fresh-Mongo validator/index audit | **42/42 checks passed** (incl. `det_capability_id`, `corr_capability_ids`) |
| Live composition | **14/14** |
| Chained live pipeline (F3) | **51/51** |
| Real Chromium (F2) | **39/39** (was 34/34; +5) |
| React typecheck | clean |
| React build | OK, `frontend/soc/index.html` 1,200,311 bytes |

## 29. Residual issues after owner verification

- **5.2-PRE-01** (HIGH) — pre-existing, out of scope, reproduced, queued (P-07). The only
  open HIGH.
- **5.2-06 / 5.2-07** — token-id hashing at rest and a revocation list remain approved
  deferrals; R-02's wording now describes their consequence truthfully.
- **5.2-08** — mapping profiles are validated, persisted and now exactly resolved, but
  still inert as transformations. R-05 removed the *inconsistency*; the inertness itself
  is the documented limitation.
- R-01–R-07: **no open in-scope defect** remains. R-06 is a recorded contract decision,
  not an open defect.

## 30. Owner statement

The owner did not accept Part I uncritically: R-03's stated root cause was disproven (the
backend already served `capability_id`), R-01 was found to be broader than reported (a
live capability was also affected) and Muse's prescribed patch was found insufficient
without the derived-family step, and R-04's first option was rejected as a plan deviation.
Every confirmed in-scope defect was patched and re-verified with fresh evidence; the
refusal-path findings were left as documented, deliberate contracts where changing code
would have been the weaker engineering choice.

This statement is the **implementation owner's**, not an independent verification. The
implementation is not declared bug-free.
---

# PART III — AUDIT-vs-AUDIT ADJUDICATION AND POST-PATCH BASELINE (OWNER)

**Date:** 2026-09-17 · **Authored by:** implementation owner / adjudicator (not this reviewer).
**Full ledger:** `PHASE-05-02-OWNER-RECONCILIATION-AND-PATCH-REPORT.md` ·
**Authoritative baseline:** `PHASE-05-02-FINAL-BASELINE.md`.

Part I is this reviewer's independent report (preserved verbatim). Part II is the owner's verification
of R-01–R-07 (preserved). Part III records what happened when the TWO independent Phase 5.2 audits were
set against each other and against the running product.

## 31. The two audits, side by side

| Ref | Audit file | Findings | Verdict as received |
|---|---|---|---|
| MUSE | `…AUDIT-AI1(meta muse 1.3).md` | `F-1`…`F-7` | READY WITH DOCUMENTED NON-BLOCKING ISSUES |
| GLM | `…AUDIT-AI2(glm 5.3 flash).md` | `AI1-01`…`AI1-05` | NOT READY — BLOCKERS FOUND |

### 31.1 The only finding both audits agreed on

The case-ownership gap around `case.create_from_correlation` and its consequence (the analyst cannot
work pipeline-created cases). GLM reported the security half (`F-1`); MUSE reported the workflow half
(`AI1-02`, also GLM `F-2`).

**Owner adjudication:** the security half was a real defect and is **fixed** (OWNER-52-01) — the wire
operation returned the complete body of a case the caller cannot read (and could merge evidence into
it) while `case.get` correctly answered 404. The workflow half is a **product decision already owned by
Phase 5.4** (Master Plan §21) and is carried, not patched.

### 31.2 Where each audit was right, wrong, or mis-classified

| Finding | Verdict | Owner adjudication |
|---|---|---|
| GLM `F-1` cross-owner disclosure | real | **fixed** (404 before any mutation; no unauthorized state persisted) |
| GLM `F-3` collector `event.list` unscoped | real | **fixed** (grant removed; the role now has no analyst-plane read) |
| GLM `F-4` residual rotation wording | real (misleading UI text) | **fixed** (wording + rebuilt bundle) |
| GLM `F-2` = MUSE `AI1-02` analyst lockout | real | deferred to Phase 5.4 per the governing plan; documented |
| GLM `F-5` certification not persisted | real, 5.4 scope | documented |
| GLM `F-6` = MUSE `AI1-05` = `5.2-PRE-01` | pre-existing | reproduced; queued |
| GLM `F-7` hygiene | non-defect | documented |
| MUSE `AI1-01` payload triple rewrite (**labelled HIGH / BLOCKER**) | **false positive** | the enforced contract is over the signed token's claims (mismatch → 401); payload declarations are ignored, not trusted |
| MUSE `AI1-03` all-rejected batch (**labelled MEDIUM**) | documentation | the documented Phase 4.9 per-event failure-isolation contract; body truthful, nothing persisted |
| MUSE `AI1-04` rotation limitation | approved deferral | documented |
| MUSE verdict (no blockers) | **not correct as written** | it missed the cross-owner disclosure and the fresh-database bootstrap race that aborts a plane on the shipped start sequence |

## 32. What BOTH audits missed (found by the owner round)

| ID | Finding | Class | Disposition |
|---|---|---|---|
| **L-15** | **Two-plane bootstrap race**: both planes bootstrap the same database and the repositories' check-then-`create_collection` is not atomic; on a FRESH database the loser exits with `PersistenceError`. Reproduced **5/5 failures**; the shipped launcher starts both planes back-to-back, so this blocks a fresh local install | **CONFIRMED DEFECT** | **fixed** (OWNER-52-04): 5/5 → 0/5, and a fresh two-plane start now brings both planes up with the documented validators/indexes |
| **L-08** | `system.health.deep` had **no permission gate**, so a semi-trusted collector session read subsystem names/status/counts | **CONFIRMED DEFECT** | **fixed** (OWNER-52-03): deep health now requires `overview:read`; `notification.*` left ungated because it is audience-scoped by construction |
| L-16 | the notification feed's metadata can name cases the analyst cannot open | confirmed, low | documented with the Phase 5.4 work |
| L-17 | source read ops gated on `rule:read` rather than `source:read` | documentation | documented |
| L-18 | claim/registration mismatch is answered 401 by the verifier (before the 403 ingress check) | documentation | documented |
| L-19 / L-20 | `overview.timeseries` scope label; analyst `case.list` windowing before the ownership filter | documentation / low | documented |

## 33. Post-patch gates (owner-run, after every patch)

| Gate | Result |
|---|---|
| Unit (full) | **1470 passed, 0 failed** (1458 + 12 new owner regression tests) |
| Integration (real Mongo, full) | **112 passed, 0 failed** |
| Combined | **1582 passed, 0 failed** |
| Phase 5.2 + 5.1 focused slice | **190 passed** (was 178) |
| Fresh-Mongo validator/index audit | **42/42** |
| Live composition | **14/14** |
| Chained live pipeline (Source→Event→Detection→Correlation→Case) | **51/51** |
| Real Chromium (current React build, freshly built) | **39/39** |
| React typecheck / build identity | clean / `frontend/soc/index.html`, 1,200,496 B, sha256 `31fcaeee…`, no legacy markers, not stale |
| Security/pentest regression | 18 attack rows refused or correctly attributed; secret leakage **NONE**; no unauthorized state persisted |
| Restart/recovery (both planes, same DB) | **IDENTICAL** (state, counters, bindings, replay store) |
| Two-plane fresh-DB bootstrap race | **0/5 failures** |

## 34. Open items after Part III

1. **`5.2-PRE-01`** (pre-existing, HIGH for SOC usefulness) — queued as its own reviewed phase; must
   not be absorbed into 5.3.
2. **Analyst visibility of pipeline-created cases** — Phase 5.4 (assignment/visibility); currently a
   blocker only for role-separated operation.
3. Notification-feed metadata, structured closure certification, tile scope label, catalogue hygiene —
   documented, low, 5.4-coupled.
4. Approved deferrals unchanged (`5.2-06`…`5.2-11`).

## 35. Part III conclusion

The two audits disagreed fundamentally (one found blockers, one found none) and **both** were partially
wrong. The reconciliation showed the disagreement is resolvable by reproduction: one real security
defect (acknowledged by both, in different halves), two real but lower-severity authorization/read-scope
defects (one reported, one not), one **deployment-blocking** defect that neither auditor could see
because both booted against an already-bootstrapped database, and one high-severity auditor claim that
did not survive reproduction. All confirmed deployment-relevant defects are fixed and re-verified; every
remaining issue is documented, deferred, or owned by a later phase.

**Phase 5.2: READY FOR LOCAL SELF-HOSTED DEPLOYMENT** (single-operator, admin-operated, localhost) —
**Phase 5.3: HOLD** — **post-patch independent verification: REQUIRED.**
