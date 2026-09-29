# PHASE 5.2 — OWNER RECONCILIATION AND PATCH REPORT

**Document ID:** `PHASE-05-02-OWNER-RECONCILIATION-AND-PATCH-REPORT`
**Role:** Implementation Owner / Adjudicator (Phase 4.1 → Phase 5.2)
**Date:** 2026-09-17
**Scope:** reconcile the two independent Phase 5.2 audits against the CURRENT code, reproduce every
finding independently, patch ONLY confirmed current in-scope defects, then run the full post-patch
regression and publish the final baseline.
**Frontend authority:** `frontend/src_upgraded_gemini/` → `frontend/soc/index.html` ONLY.
**Phase 5.3:** HOLD (not started, verified).

---

## 0. Which report is which (naming reconciliation — read this first)

The tasking named the two audits inconsistently. The repository contains exactly two independent
Phase 5.2 audit files; this report identifies them by **content and authoring suffix**, not by the
`AI1`/`AI2` token that both files share in their internal document-ID line:

| Ref | File | Findings | Verdict | Treated as |
|---|---|---|---|---|
| **MUSE** | `PHASE-05-02-FULL-SYSTEM-INTEGRATION-SECURITY-AUDIT-AI1(meta muse 1.3).md` | `F-1` … `F-7` | READY WITH DOCUMENTED NON-BLOCKING ISSUES | Muse |
| **GLM** | `PHASE-05-02-FULL-SYSTEM-INTEGRATION-SECURITY-AUDIT-AI2(glm 5.3 flash).md` | `AI1-01` … `AI1-05` | **NOT READY — BLOCKERS FOUND** | GLM |

Both original files are **preserved verbatim and unmodified**. Neither was treated as truth: every
claim below was re-tested against the current code, the running two-plane product and real MongoDB.

---

## 1. How this reconciliation was performed

* Re-read the governing documents (V3 Master Plan §19/§21, Phase 5.0 Freeze, Phase 5.2 implementation
  report rounds 1–4, Phase 5.2 independent review Parts I–II) and the CURRENT product code (proxy,
  incidents service, pipeline, ingress, permissions, bootstrap, React app).
* Ran the shipped two-plane deployment for real: `scripts/proxy_server.py` (analyst plane :8088) and
  `scripts/ingress_server.py` (trusted-ingress plane :8089) over **real MongoDB 8.0.13**, with the
  deployment's own signing keys/database capture, on **fresh databases**.
* Drove real HTTP for every wire claim, real Mongo inspection for every persistence claim, real
  Chromium (Playwright) for every UI claim, real HMAC tampering (issuer secret in hand) for every
  token claim, and real process restarts for every recovery claim.
* Temporary owner probes live under `_owner_probe/` (all deleted at the end; §12). No conclusion
  below rests on any auditor's prose alone.
* Fixes were applied only **after** the defect was reproduced against the unpatched tree, and each
  fix was re-verified with fresh evidence.

### 1.1 Environment actually used

| Component | Value |
|---|---|
| Host / Python | Windows, Python 3.13.3 |
| MongoDB | 8.0.13, real `mongod.exe`, `127.0.0.1:27017` |
| Analyst plane | `python -m scripts.proxy_server --port 8088 --backend mongo --seed-credentials` (FastAPI/uvicorn, real HTTP) |
| Ingress plane | `python -m scripts.ingress_server --port 8089 --backend mongo` (real HTTP) |
| Databases | fresh `proshield_final52` (BEFORE probes), fresh `proshield_final52_after` (AFTER probes + restart), plus the throwaway DBs the shipped verification scripts create |
| Frontend | `frontend/src_upgraded_gemini/` → rebuilt `frontend/soc/index.html` (1,200,496 B, sha256 `31fcaeee…`, built 2026-09-17 14:03:39) |
| Browser | real Chromium (Playwright) against the current React build served at `/static/soc/index.html` |

## 2. Complete finding ledger (every auditor finding, adjudicated)

Classification legend:
**CD** = CONFIRMED CURRENT DEFECT · **FP** = FALSE POSITIVE · **DOC** = DOCUMENTATION ONLY ·
**PRE** = PRE-EXISTING / OUT OF SCOPE · **TI** = TEST-INFRASTRUCTURE ONLY ·
**FIXED** = was a current defect, patched and re-verified in this round.

| # | Source | Finding (short) | Class | Severity by actual impact | Disposition |
|---|---|---|---|---|---|
| L-01 | GLM `F-1` | `case.create_from_correlation` returned a pipeline-owned case body to an analyst who gets 404 from `case.get` | **CD → FIXED** | **Medium** single-operator / **High** role-separated: cross-owner case disclosure + unauthorized evidence merge via an alternate route | **PATCH-01 / OWNER-52-01** |
| L-02 | MUSE `AI1-02` = GLM `F-2` | analyst locked out of every pipeline-created case | **CD → deferred by the governing plan (PRE)** | **High for role-separated**, none for admin-operated local | Documented; owned by **Phase 5.4** (Master Plan §21); not patched (§8) |
| L-03 | MUSE `AI1-01` | "ingress silently rewrites the payload's source triple under 200 instead of refusing with 403" | **FP + DOC** | None — attribution is always token-derived | Docstring clarified; regression coverage added (§8.1) |
| L-04 | MUSE `AI1-03` | "fully-rejected batch returns 200 `ok:true`" | **DOC** (documented 4.9 batch contract) | Low — envelope only; body is truthful, nothing persists | Documented, not patched (§8.2) |
| L-05 | MUSE `AI1-04` = GLM "rotation must revoke" | rotation does not revoke an outstanding unused credential | **PRE** (approved deferral `5.2-07`) | Low (single-use + TTL + retirement mitigate) | Reproduced, documented (§10) |
| L-06 | MUSE `AI1-05` = GLM `F-6` = `5.2-PRE-01` | managed library rules carry no conditions → benign telemetry false-positives | **PRE** | **High for SOC usefulness**, not a 5.2 trust defect | Reproduced live; queued as its own reviewed phase |
| L-07 | GLM `F-3` | collector could read recent events from every source | **CD → FIXED** | Low (semi-trusted role, unscopable read) | **PATCH-02 / OWNER-52-02** |
| L-08 | Owner (neither auditor) | `notification.list` / `unread_count` / `system.health.deep` had **no permission gate** — any authenticated session, collector included, could read the notification feed and subsystem names/status/counts | **CD → FIXED** | Low–Medium (metadata disclosure to a semi-trusted role) | **PATCH-02/03 / OWNER-52-02/03** |
| L-09 | GLM `F-4` | second, unpatched "rotation revokes the old token" wizard string | **DOC → FIXED** | Low (misleading security claim in shipped UI text) | **PATCH-05** (wording + rebuild) |
| L-10 | GLM `F-5` | the closure certification checkbox is a UI gate only (not persisted) | **PRE / 5.4 scope** | Low — verdict + summary *are* persisted | Documented, not patched (§8.3) |
| L-11 | GLM `F-7` | unauthenticated UI probes before login; `mockData.ts` dead code; legacy `localStorage` | **TI** | None (fail-closed 401s; dead code not in the bundle) | Documented, no product change (§8.4) |
| L-12 | GLM false-positive table | 7 candidates | **FP** (each re-verified) | None | §10 |
| L-13 | MUSE false-positive list | 8 candidates | **FP** (each re-verified) | None | §10 |
| L-14 | Both pre-existing lists | `5.2-06`…`5.2-11`, `5.1-05/08/09`, legacy `check_wiring.py`, PDF Latin-1, dirty tree | **PRE** | None for 5.2 | Carried in the baseline |
| L-15 | Owner (neither auditor) | **two-plane bootstrap race**: starting both planes together on a FRESH database aborts one plane | **CD → FIXED** | **High for a fresh local deployment** — the shipped launcher starts both planes together | **PATCH-04 / OWNER-52-04** |
| L-16 | Owner (neither auditor) | notification feed carries `human_id`/`title`/`incident_id` for cases the analyst cannot open | **CD, coupled to L-02 → PRE** | Low (metadata only, no evidence) | Documented (§8.5) |
| L-17 | Owner (neither auditor) | `source.list/get/list_types` gated on `rule:read`, not `source:read` | **DOC** | None today (both roles hold both) | Documented (§8.6) |
| L-18 | Owner (neither auditor) | claim-vs-registration mismatch answered **401**, not the **403** the 4.9 review matrix records | **DOC** | None (fail-closed; nothing persists) | Documented (§8.7) |
| L-19 | Owner (neither auditor) | `overview.timeseries` labels `scope:"own"` for analysts while counting ALL detections | **DOC** | Low (labeling truthfulness) | Documented (§8.8) |
| L-20 | Owner (neither auditor) | analyst `case.list` windows the newest `limit` rows before the ownership filter | **DOC** | Low (functional edge) | Queued with the 5.4 visibility work (§8.9) |

### 2.1 Common findings (both auditors independently)

* **L-01 + L-02** — the case-ownership model is not applied on the `case.create_from_correlation`
  reuse path (GLM `F-1`); consequently the analyst cannot work pipeline-created cases
  (MUSE `AI1-02` = GLM `F-2`). This is the **only** finding the two audits agreed on, and the only
  one that contains a genuine security defect. **The security half was real and is now fixed; the
  workflow half is a 5.4-owned product decision and is explicitly not patched here.**
* **L-05 / L-09** — rotation semantics: both auditors confirmed rotation does not revoke an
  outstanding unused credential, and both agreed it is an approved documented deferral whose
  *wording* must be truthful.
* **L-06** — `5.2-PRE-01` was independently reproduced by both, and both classified it pre-existing
  and outside 5.2 scope.

### 2.2 GLM-only findings

`F-1` (security — **the one real defect**, fixed), `F-3` (collector event read scope, fixed),
`F-4` (residual rotation wording, fixed), `F-5` (certification not persisted, 5.4),
`F-7` (hygiene, informational).

### 2.3 Muse-only findings

`AI1-01` (payload triple rewrite — false positive; documentation clarified),
`AI1-03` (all-rejected batch envelope — documented contract),
`AI1-04` (rotation limitation — approved deferral, re-confirmed),
`AI1-05` (managed rules — the same `5.2-PRE-01`).

### 2.4 Owner-only findings (neither auditor found these)

`L-08` (ungated `notification.*` + `system.health.deep`), **`L-15` (the two-plane fresh-database
bootstrap race — the defect that actually blocks a fresh local install)**, `L-16`, `L-17`, `L-18`,
`L-19`, `L-20`.

### 2.5 Verdict of the two audits, adjudicated

| Claim | Auditor verdict | Owner verdict |
|---|---|---|
| GLM: "NOT READY — blockers found" | 4 blockers | **Partially correct.** The *security* blocker (GLM `F-1`) was real and is now fixed. The other three (`F-3`, `F-4`, plus `F-2`) were: one fixed (read-scope), one fixed (UI wording), one correctly deferred to 5.4. GLM's severity labels for `AI1-01`-style items do not survive reproduction. |
| Muse: "READY WITH DOCUMENTED NON-BLOCKING ISSUES" | No blockers | **Not correct as written.** Muse reviewed the same code and concluded nothing blocks deployment, yet the `case.create_from_correlation` route disclosed another owner's case, and the two-plane fresh-database start (the shipped launcher's own sequence) aborted a plane. Both are deployment-relevant; both are now fixed. |
| Both: analyst lockout (`AI1-02`/`F-2`) | Blocker/High | **Agreed, with the scope correction**: the governing Master Plan §21 assigns this to Phase 5.4 explicitly. It is carried as a documented limitation of the local baseline, not silently fixed. |
| Both: `5.2-PRE-01` | Pre-existing, out of scope | **Agreed**, reproduced live. |

## 3. Independent reproduction (BEFORE the patches) — raw evidence

All figures below come from the owner's own probes (`_owner_probe/live_probe_before.txt`,
`pentest_after*.txt`, `bootstrap_race_results.txt`/`bootstrap_race_after.txt`) plus direct Mongo
inspection. Nothing here is quoted from an auditor's report.

### 3.1 Case ownership (L-01 / L-02) — reproduced on the live two-plane product

Chain first: 4 `authentication_failure` events pushed through the real HTTP ingress → detections →
1 correlation → **auto-case `case-917cf38f…`, `created_by="pipeline"`**, evidence 1 → 4.

Before the patch (analyst session, real HTTP):

```
analyst case.create_from_correlation -> HTTP 200 returned_case=case-917cf38f… title_returned=True effective_owner=pipeline
analyst case.get on the same id      -> 404 (ownership model)
case.list analyst -> 200 rows=0 ; admin -> 200 rows=1
case.get / case.acknowledge / case.note.add / case.close /
report.generate_normal / routing.compute / timeline.build_for_incident /
detection.list_for_incident / correlation.list_for_incident
        analyst = 404 (all nine)   admin = 200 (all nine)
```

Every documented case route refused (fail-closed), while the *reuse* route handed the analyst the
full case body — and the internal merge could add evidence to a case the caller cannot read.
Nine-of-nine admin success proves the admin-operated path is complete.

### 3.2 Ingress provenance claims (L-03) — reproduced with real tokens

Real HTTP ingress, fresh single-use credentials, issuer-secret re-signing:

```
1a claim source_instance_id=<B>                     -> HTTP 200, persisted provenance = <B> (the CLAIMED instance)
1b claim source="waf" while A is registered "nginx" -> HTTP 401 source_identity_token_error
1c claim source_type="waf"                          -> HTTP 401 source_identity_token_error
1d tampered signature                               -> HTTP 401 source_identity_token_error
   events persisted by the four probes: 1 (the 1a event, attributed to the claimed instance)
```

Per-event payload declarations were separately exercised: an event carrying
`{"source":"waf","provenance":{"source_instance_id":<B>}}` → HTTP 200 with the persisted provenance
rewritten to the **token** identity (A); `capability_id:"cap-simulator"` → HTTP 200 with the
persisted capability `cap-nginx`. Attribution is never taken from the payload.

### 3.3 Batch semantics (L-04)

```
all-invalid batch  -> HTTP 200 ok=True accepted=[] rejected=[{"reason":"ingest_failed",…}] events persisted: 0
mixed batch        -> HTTP 200 accepted=1 rejected=1   (per-event failure isolation preserved)
events not a list  -> HTTP 400 validation_error
```

### 3.4 Rotation, replay, lifecycle (L-05)

```
rotate_token -> 200, the new credential differs
unused credential after rotation          -> HTTP 200  (documented: rotation does not revoke)
replay of that credential after first use -> HTTP 401
the rotated credential itself             -> HTTP 200
issue_token on DISABLED source            -> 409 source_instance_state_error
enable on RETIRED source                  -> 409 source_instance_state_error
replayed single-use credential            -> HTTP 401
```

### 3.5 Read surfaces (L-07 / L-08) — before

```
collector event.list                -> 200  events=5  source_instances=[<every source with telemetry>]
collector notification.list         -> 200  notifications=0 (none addressed to the role)
collector notification.unread_count -> 200
collector system.health.deep        -> 200  status=healthy subsystems=9
collector case.list / detection.list / source.list -> 403
```

### 3.6 Detection fidelity (L-06 / `5.2-PRE-01`)

```
rule.list -> 200 rules=5 unowned=5      (every library rule: capability_id = null)
managed_rules sample: capability_id=None conditions=None
8 ingested events (benign + suspicious) -> 16 detections  (benign traffic fires detections)
```

### 3.7 Persistence / DB validators

`python scripts/audit_fresh_db.py` → **42/42** checks (10 entity collections with `$jsonSchema`
validators, unique + query indexes, `capability_id` cross-field guard, human-id monotonicity incl.
25/25 concurrent uniqueness; `source_telemetry` and `notifications` carry their own validators).

### 3.8 The defect BOTH auditors missed: the two-plane bootstrap race (L-15)

The shipped launcher (`scripts/restart_audit_stack.ps1`) starts the analyst plane and the ingress
plane back-to-back. Against a database whose collections do not exist yet, the repositories'
check-then-`create_collection` pattern is not atomic:

```
BEFORE (5 concurrent bootstrap runs, real Mongo): all 5 FAILED
  run 0 analyst_plane: PersistenceError: could not create correlations collection
  run 1 ingress_plane: PersistenceError: could not create detections collection
  run 2 analyst_plane: PersistenceError: could not create detections collection
  run 3 ingress_plane: PersistenceError: could not create detections collection
  run 4 analyst_plane: PersistenceError: could not create detections collection
```

and on a genuinely fresh deployment the *ingress plane process exited*:

```
pymongo.errors.OperationFailure: namespace proshield_final52.detections already exists,
but with different options …  -> app.domain.errors.PersistenceError: could not create detections collection
```

Impact: on a fresh local install one of the two planes refuses to start; with the ingress plane dead
no telemetry can be ingested at all. Neither auditor saw it because both always booted against an
already-bootstrapped database.

### 3.9 Additional owner observations

```
analyst notification: kind=case.closed case=case-917cf38f… title='Correlated security cluster (198.51.100.…'
analyst case.get on that notified case -> 404                                  (L-16)
source.list / source.get / source.audit / notification.list / capability.list -> leakage hits: NONE
analyst session token on the INGRESS plane -> 401 ; fabricated source credential on the ANALYST plane -> 401
unknown op -> 400 validation_error (no stack) ; empty Authorization -> 401
```

---

## 4. Severity model actually applied

Severity was determined from **impact on the product as deployed**, not from auditor labels:

| Impact class | Definition used | Findings |
|---|---|---|
| **Deployment-blocking (fresh install)** | prevents the shipped deployment from running at all | **L-15** (bootstrap race — one plane died) |
| **Security, isolation-breaking** | lets a principal act outside its authorized scope, or persists unauthorized state | **L-01** (cross-owner case read + unauthorized evidence merge) |
| **Security, scope/lateral** | exposes data the principal should not see (no write) | **L-07/L-08** (collector read surface) |
| **Workflow-blocking for a documented persona** | the planned persona cannot complete the documented loop | **L-02** (analyst vs pipeline cases, 5.4-owned) |
| **Usefulness-degrading, pre-existing** | product works but over-reports | **L-06** (`5.2-PRE-01`) |
| **Misleading / labeling** | no security or functional effect | **L-03, L-04, L-09, L-18, L-19** |
| **Hygiene / informational** | none | **L-11, L-16, L-17, L-20, L-14** |

Corrections applied to the auditors' labels:

* MUSE `AI1-01` was labelled **HIGH** and a **BLOCKER**; by impact it is **none** — attribution is
  always token-derived, and the declarations the auditor treated as an expected refusal were never
  part of the documented event contract (verified: the mismatching *claims* are refused 401, the
  mismatching *payload* is ignored, and no third-party attribution is reachable).
* MUSE `AI1-03` was labelled **MEDIUM**; by impact it is **Low** (the response body is truthful and
  nothing persists; the envelope matches the documented Phase 4.9 batch semantics).
* GLM `F-2` / MUSE `AI1-02` were labelled **blockers**; by impact they are a **High for
  role-separated operation only**, and the governing Master Plan §21 already assigns the remedy to
  Phase 5.4 — so they are carried, not patched.
* GLM `F-1` was labelled **Medium**; by impact on any multi-principal deployment it is the **most
  serious finding of the phase** and the only one that produced an unauthorized disclosure.

## 5. What both auditors missed (fresh bug hunt)

The hunt followed the tasking's checklist: SecureProxy/auth/RBAC, IDOR/BOLA, source ownership,
capability ownership, ingress trust boundary, provenance, alternate routes, state races,
frontend/backend contracts, analyst case workflow, detection/correlation composition, Mongo
validators/persistence, restart/recovery, secret leakage, malformed input, reports/exports/routing.

Method that found the new defects:

* enumerated **every** proxy handler and its permission gate mechanically (not by reading prose),
  which surfaced the two ungated operations (L-08) and the `rule:read` coupling (L-17);
* audited the authorization of *alternate paths* into case state (not just the documented routes),
  which is how L-01's root cause was isolated to a single call site;
* ran the **deployment's own two-plane start sequence against a fresh database** (rather than only
  against an already-bootstrapped one), which is how L-15 surfaced;
* compared the Phase 4.9 review's adversarial matrix against live status codes (L-18);
* scanned every read surface for credential material after the patches (leakage: NONE).

Result: **L-08, L-15, L-16, L-17, L-18, L-19, L-20** — two of which (L-15, L-08) are real defects and
are now fixed; the remainder are documented.

---

## 6. Patches applied (each proven before → after)

### PATCH-01 / OWNER-52-01 — case-ownership gate on the correlation-case reuse path

* **Root cause.** `IncidentService.create_case_for_correlation` is the *automatic* pipeline trigger
  (`created_by="pipeline"`). Because the case id is deterministic per correlation cluster, the same
  function is also the implementation of the wire operation `case.create_from_correlation`. On its
  reuse branch it (a) returned the existing case to the caller and (b) merged evidence into it,
  **without applying `_authorize_case_access`** — the check every other case operation performs. The
  wire handler therefore disclosed (and could mutate) a case the caller cannot read.
* **Exactly affected code.** `app/proxy/proxy.py::_handle_case_create_from_correlation` (wire entry
  point) → `app/incidents/service.py::create_case_for_correlation` (unguarded reuse branch) +
  `app/pipeline/service.py` (the system caller's identity).
* **Fix.** The ownership gate now runs in the service **before any mutation**:
  `self._authorize_case_access(identity, existing)` → `CaseAccessDeniedError` → the proxy's existing
  IDOR mapping (`404 case_not_found`). The live pipeline is the only internal caller and now carries
  an **explicit, wire-unreachable** system grant `(case:read, case:read:any)` on its `pipeline`
  identity, so the V2-02 evidence-accumulation behaviour is preserved. The seeded `internal` session
  subject still resolves with an **empty** permission tuple, so a session identity can never obtain
  `case:read:any` through this change.
* **BEFORE → AFTER (live HTTP, real Mongo).**

  | Probe | Before | After |
  |---|---|---|
  | analyst `case.create_from_correlation` on a pipeline-owned cluster | **200 + full case body** (`returned_case=case-917cf38f… title_returned=True effective_owner=pipeline`) | **404 `case_not_found`**, no `case` key in the body |
  | persisted side effect on that case | merge path reachable | evidence unchanged (4 → 4), `updated_at` unchanged |
  | analyst `case.get` same id | 404 | 404 (consistent) |
  | chain: 4 events → detection → correlation → auto-case | works | **works** (`created_by=pipeline`, evidence 1 → 4 after the later merge) |
  | `verify_phase52_pipeline.py` case-lineage checks | 51/51 | **51/51** |
* **MongoDB: no unauthorized state persisted.** The refused call leaves the case document untouched
  (asserted by the unit test and the live probe) and creates no new document.
* **Regression coverage.** `tests/unit/test_phase52_owner_patches.py::TestCreateFromCorrelationOwnership`
  (4 tests): foreign case → 404 with no mutation; the owner can still reuse its own case
  (200 / `created False`); the pipeline identity carries the cross-owner grant; the pipeline still
  accumulates evidence into a human-owned case.

### PATCH-02 / OWNER-52-02 — collector role carries no analyst-plane read surface

* **Root cause.** `ROLE_PERMISSIONS[COLLECTOR_ROLE]` granted `event:read` with the comment
  "can read its own submitted events", but **there is no wire link from a collector subject to the
  events it submitted** (events are attributed by `provenance.source_instance_id`, a *source*
  credential). The grant therefore exposed recent events of every source to a semi-trusted role, and
  because the operation has no owner filter no scoping was possible.
* **Fix.** The grant is removed (`COLLECTOR_ROLE: frozenset()`), with a comment recording the
  reasoning and the authoritative reference (`docs/PHASE 3/AUTH_RBAC.md` §10–§12: collectors
  authenticate to the ingestion boundary, submit events and read the ingestion response; they must
  not read unrelated incidents).
* **BEFORE → AFTER.** `collector event.list` → **200 (events of every source)** ⇒ **403**.
  Nothing else changed: `case.list`, `detection.list`, `source.list` were already 403 and the
  analyst/admin planes are untouched (both hold `event:read` by role default).
* **Regression coverage.** `TestCollectorReadSurface::test_collector_role_has_no_analyst_plane_read_permission`
  and `::test_collector_cannot_list_events`.

### PATCH-03 / OWNER-52-03 — `system.health.deep` requires the operational read permission

* **Root cause.** `_handle_system_health_deep` was the only reporter handler with **no permission
  gate**: it relied on session authentication alone, so any authenticated principal — including the
  seeded semi-trusted `collector` — received subsystem names, statuses and counts.
* **Fix.** `self._require(identity, Permission.OVERVIEW_READ)` (an existing catalogue permission; no
  new permission invented). Analyst, admin and internal-service hold it; the collector does not.
* **BEFORE → AFTER.** `collector system.health.deep` → **200 (status=healthy, 9 subsystems)** ⇒ **403**.
  Analyst/admin unchanged (**200**, verified).
* **Regression coverage.** `TestCollectorReadSurface::test_collector_cannot_read_deep_health` and
  `::test_analyst_can_still_read_deep_health`.
* The two `notification.*` read operations were re-examined and deliberately **left ungated**: they
  are audience-scoped by construction (`audience_roles` / `actor_subject_id`), and the collector role
  now receives no notifications because every emitter addresses the admin/analyst audience. The
  related metadata observation L-16 is recorded, not patched (§8.5).

### PATCH-04 / OWNER-52-04 — race-tolerant two-plane bootstrap (the fresh-install blocker)

* **Root cause.** Every repository's `ensure_schema()` performs a non-atomic
  `if name in list_collection_names(): return` followed by `create_collection(...)`. The analyst
  plane and the ingress plane both call `ensure_all_collections()` on startup and the shipped
  launcher starts them within the same second, so on a fresh database one plane loses the race,
  MongoDB answers `OperationFailure` (`NamespaceExists` 48 / "already exists, but with different
  options" 85), and the repository translates it into a fatal `PersistenceError` — the plane exits.
* **Exactly affected code.** `app/persistence/bootstrap.py` (the single startup hook both planes
  call) — new `_ensure_collection(db, coll_name, validator)` invoked before `repo.ensure_schema()`
  for every planned collection; `ensure_schema()` then sees the winner's collection and no-ops.
  The helper tolerates a lost race **only** when the collection now exists (any other failure is
  re-raised, so the fail-loud contract is intact) and returns early for backends without an explicit
  `create_collection` (the in-memory dev doubles).
* **BEFORE → AFTER.**

  | Probe | Before | After |
  |---|---|---|
  | 5 concurrent real-Mongo bootstrap runs | **5/5 failed** (`PersistenceError: could not create detections/correlations collection`) | **0/5 failed** |
  | fresh-DB two-plane start (the shipped sequence, real processes) | ingress plane exited with `PersistenceError` | **both planes up** (`PROXY_UP=True`, `INGRESS_UP=True`); the deployment log records `bootstrap.collection_created_concurrently … error=OperationFailure` followed by `bootstrap.collection_ready … validator=True` for every collection |
  | validators/indexes after the tolerated race | n/a | still the documented shape (collMod re-asserts the validator) |
* **Regression coverage.** `TestBootstrapConcurrentCollectionCreate` (4 tests): tolerates a
  concurrent creator, still fails loudly when the create really failed, no-op for lazy backends,
  never recreates an existing collection.

### PATCH-05 — truthful rotation wording in the Phase 5.2 wizard (GLM `F-4`)

`frontend/src_upgraded_gemini/src/components/modals/AddSourceModal.tsx` no longer claims that
"the previous token is then spent". It now states that rotation issues a new credential and audits
the change, and that an unused outstanding credential is **not** revoked (documented deferral).
The authoritative bundle was rebuilt and re-verified (§9.6).

### PATCH-06 — ingress docstring made precise (MUSE `AI1-01`, documentation only)

`app/sources/ingress.py` module contract now says the enforced `(source_instance_id, source_type,
source)` integrity check applies to the **signed token's** claims versus the registered instance
(403 `source_integrity_error`), and that identity fields inside an event payload are never part of
the contract and are never trusted. **No behaviour change** was made for this finding.


---

## 7. Patch log (files changed, regression coverage)

### 7.1 Product files changed by this reconciliation (7)

| File | Change | Driven by |
|---|---|---|
| `app/incidents/service.py` | ownership gate inserted in the reuse branch of `create_case_for_correlation` **before** the evidence merge | L-01 / GLM `F-1` |
| `app/pipeline/service.py` | explicit wire-unreachable system permissions on the pipeline case identity (+ `Permission` import) | L-01 |
| `app/auth/permissions.py` | `COLLECTOR_ROLE` permission set emptied with a documented rationale | L-07/L-08 / GLM `F-3` |
| `app/proxy/proxy.py` | `system.health.deep` now requires `overview:read` | L-08 |
| `app/persistence/bootstrap.py` | new `_ensure_collection` race-tolerant pre-create, called for every planned collection | **L-15** |
| `app/sources/ingress.py` | module contract clarified (documentation only) | L-03 / MUSE `AI1-01` |
| `frontend/src_upgraded_gemini/src/components/modals/AddSourceModal.tsx` | truthful rotation wording (delivered through the rebuilt bundle) | L-09 / GLM `F-4` |

### 7.2 New regression coverage

`tests/unit/test_phase52_owner_patches.py` — **12 tests**, all passing:

| Class | Tests | Pins |
|---|---|---|
| `TestCreateFromCorrelationOwnership` | 4 | foreign case → 404 + no mutation; owner reuse still 200/`created False`; pipeline grant present; V2-02 accumulation preserved |
| `TestCollectorReadSurface` | 4 | collector role has no analyst-plane read permission; `event.list` → 403; deep health → 403; analyst deep health → 200 |
| `TestBootstrapConcurrentCollectionCreate` | 4 | tolerant of a concurrent creator; fail-loud otherwise; lazy-backend no-op; never recreates an existing collection |

No existing test was deleted, weakened or skipped.

---

## 8. Deliberately NOT patched (with the reason)

### 8.1 L-03 / MUSE `AI1-01` — per-event payload declarations (FALSE POSITIVE + doc)

The enforced integrity contract is over the **token's** signed claims versus the registered source
instance — which is what the Phase 4.9 module contract and the 4.9 adversarial matrix (A1–A3)
specify, and which was verified live: a claim/registration mismatch is refused
(`401 source_identity_token_error`) and a mismatching *payload declaration* is ignored, with the
canonical event stamped from the authenticated token. Re-authorising identity fields inside a
telemetry payload would be the weaker design. **No code change**; the docstring is now precise.

### 8.2 L-04 / MUSE `AI1-03` — all-rejected batch returns HTTP 200

The documented Phase 4.9 batch contract states that "one bad event in a batch does not abort the
batch; failures surface as `rejected`", and that a malformed event yields a per-event `rejected[]`
entry. The body is truthful (`accepted_event_ids: []`, one `rejected` entry), nothing persists, and
a strict-400 redesign would contradict the documented per-event failure isolation that
`tests/unit/test_phase49_ingress.py` pins. **No code change** — recorded as an observability/wording
limitation; callers should key on `rejected[]`.

### 8.3 L-10 / GLM `F-5` — closure certification is a UI gate

The verdict and summary **are** persisted (as the closure transition's `reason`,
`"TRUE_POSITIVE: …"`, in `lifecycle_history`). A structured `case_resolutions` record — the natural
home for the certification act — is Master Plan §21 **Phase 5.4** scope. Patching it now would
pre-empt a phase explicitly on HOLD. **No code change.**

### 8.4 L-11 / GLM `F-7` — hygiene

Pre-login unauthenticated list probes return 401 (fail-closed, no data) and stop after login;
`data/mockData.ts` is dead code with zero imports and is not in the bundle (bundle scan verified);
legacy `localStorage` is not written by the current app. **No code change.**

### 8.5 L-16 — the analyst notification feed names cases the analyst cannot open

The feed is honest about what happened, but `human_id`/`title`/`incident_id` point at pipeline-owned
cases. This is the same ownership decision as L-02 and belongs to the Phase 5.4
visibility/assignment work; restricting the feed alone would hide real events without giving the
analyst a way to act. **No code change.**

### 8.6 L-17 — source read operations are gated on `rule:read`

`source.list` / `source.get` / `source.list_types` call `_require(identity, Permission.RULE_READ)`
while the Phase 5.2 operations use `SOURCE_READ`. Both roles hold both permissions today, so there is
no reachable authorization difference; correcting it belongs with the same catalogue review.
**No code change**, recorded so a future catalogue split does not silently break source reads.

### 8.7 L-18 — claim mismatch is 401, not the 403 of the 4.9 matrix

Two layers enforce the triple: the verifier's S-1 source-binding callback refuses a
claim/registration mismatch as a failed credential (**401**), and the ingress-level check refuses a
token/registry mismatch (**403**). Because the verifier runs first, the live status for a mismatching
claim is 401; the 403 path is reached when the registry and the persisted state disagree. Every path
refuses and nothing persists. Recorded for status-code-keyed automation. **No code change.**

### 8.8 L-19 — `overview.timeseries` scope label

The series is a detection aggregate across the collection while the payload's `scope` says `own` for
an analyst. The count is truthful; the label is not. Correcting the label requires deciding the
intended scoping of the tile (a product decision). **No code change.**

### 8.9 L-20 — analyst `case.list` windowing

`list_cases` fetches the newest `limit` rows and *then* filters by owner, so an analyst whose own
cases are older than the newest rows of other owners could see fewer than expected. The remedy
(owner-scoped query or assignment) is Phase 5.4 work. **No code change.**

### 8.10 Deferred / pre-existing items (unchanged, carried)

`5.2-06` token-id hashing at rest · `5.2-07` no revocation list (wording now truthful in code, docs
and UI) · `5.2-08` inert mapping-profile transformation · `5.2-09` closed `source_type` enum ·
`5.2-10` legacy `frontend/*.html` and the legacy-scoped `check_wiring.py` `case.js` failure ·
`5.2-11` `verify_restart_persistence.py` environment precondition · `5.1-05/08/09` inherited
limitations · PDF-export Latin-1 limitation · the dirty working tree vs `f674f09`.

**`5.2-PRE-01`** (managed library rules carry no conditions → live false positives; reproduced again
in this round: 8 events → 16 detections, every library rule reporting `capability_id = null`) remains
**pre-existing and out of 5.2 scope**. `app/pipeline/**` is untouched by 5.2, and the repair changes
frozen detection semantics, so it is queued as its own reviewed phase and must not be absorbed
into 5.3.

---

## 9. FULL POST-PATCH REGRESSION (all gates re-run after every patch)

### 9.1 Unit suite (full)

`python -m pytest tests/unit -q` → **1470 passed, 1 warning, 0 failed** (was 1458; **+12** new owner
regression tests). No pre-existing test failed or was skipped.

### 9.2 Integration suite (full, real MongoDB)

`python -m pytest tests/integration -q` → **112 passed, 0 failed** (unchanged). Combined:
**1582 passed, 0 failed**.

### 9.3 Focused Phase 5.2 + 5.1 slice

`test_phase52_sources + test_phase52_migration + test_phase52_provenance + test_phase52_proxy +
test_phase52_owner_patches + test_phase51_capabilities` → **190 passed** (was 178; +12).

### 9.4 Fresh-database validator / index audit

`python scripts/audit_fresh_db.py` → **42/42 checks passed** (validators on 10 entity collections,
unique + query indexes, capability cross-field guard, human-id monotonicity, 25/25 concurrent
uniqueness, malformed writes rejected).

### 9.5 Live composition + full chain (real MongoDB, both shipped planes)

| Gate | Command | Result |
|---|---|---|
| Live composition (source lifecycle, binding, audit, second boot, migration no-op) | `python scripts/verify_phase52_live.py` | **14/14** |
| Chained live pipeline (source → token → ingress → SecurityEvent → capability derivation → detection → correlation → case → lifecycle gates → retirement history) | `python scripts/verify_phase52_pipeline.py` | **51/51** |
| Owner end-to-end probe (real HTTP, both planes, real Mongo) | `python _owner_probe/live_probe.py after <fresh db>` | logins for all 3 subjects; 4-event chain → auto-case; F-1 refused; collector reads refused; PRE-01 reproduced |

### 9.6 Frontend build identity + Chromium workflow (current React app ONLY)

* `npm run typecheck` (`tsc --noEmit`): **clean**.
* `npm run build`: **OK** → `frontend/soc/index.html`, 1,200,496 bytes, sha256
  `31fcaeee33a104e2cb3f916f4d78e806d62b78cb51fda9d1158f03cbc9c806cb`, built 2026-09-17 14:03:39.
* Build identity proof: React root element present; **no** legacy markers (`PSAPI`, `api.js`,
  `conn-okta`, `auth_via_mfa`); the new rotation wording is present and the old wording is absent;
  the newest source file is older than the bundle (**not stale**).
* `python scripts/browser_verify_phase52.py` → **39/39 checks passed** in real Chromium: LoginGate
  login; Sources page; registry-populated capability picker; six-step wizard; once-only `sit-`
  credential with the signed capability claim; truthful card/detail/binding/lifecycle state; no token
  material in the card; rotation issues a new credential; migration dry-run writes nothing; real
  audit trail; disable/re-enable honoured; binding + lifecycle survive a full reload; Rules page shows
  real `cap-*` ownership (no `conn-*`); navigation restored; no overflow at 1440/1280/1024/768/390;
  retirement honoured with gated controls and truthful `RETIRED` state; **no console errors, no 5xx**.

### 9.7 Security / pentest regression (post-patch, real HTTP + real Mongo)

| Attack | Result |
|---|---|
| analyst `case.create_from_correlation` on a foreign case | **404** (was 200 + body) |
| analyst `case.get` / note / ack / close / report / routing / timeline / detection / correlation on a pipeline case | **404 (all nine)** — fail-closed |
| admin performs all nine | **200** — the operator path is complete |
| collector `event.list` / `system.health.deep` | **403** (were 200) |
| collector `case.list` / `detection.list` / `source.list` / `notification.list` | 403 / 403 / 403 / 200 with zero rows (audience-scoped) |
| re-signed token with a mismatching *claim* (`source='waf'`, `source_type='waf'`) | **401 `source_identity_token_error`** |
| tampered signature | **401 `source_identity_token_error`** |
| replay of a consumed single-use credential (also after a restart) | **401** |
| unused credential after rotation (documented deferral) | 200, then replay 401 |
| `issue_token` on disabled source / `enable` on retired source | **409** |
| unknown operation | 400 `validation_error`, no stack trace |
| malformed batch (`events` not a list) | 400 `validation_error` |
| cross-plane confusion (session token on ingress, source credential on analyst plane) | **401 / 401** |
| secret-material scan of `source.list/get/audit`, `notification.list`, `capability.list` | **NONE** |
| fresh-database two-plane bootstrap race (5 concurrent runs) | **0/5 failures** (was 5/5) |

### 9.8 Restart / recovery (same database, both planes restarted)

Snapshot → restart → re-verify, JSON-normalised comparison: **IDENTICAL** for case id, state,
creator, notes, lifecycle history, evidence counts, `updated_at`, all collection counts
(`security_events` 15, `detections` 30, `correlations` 1, `incidents` 1, `source_instances` 6,
`capabilities` 6, `notifications` 3, `source_audit` 31, `source_token_replay` 20), the human-id
counters (`capability` 9, `source` 6, `detection` 30, `correlation` 1, `incident` 1 — no reset) and
every per-source lifecycle/binding pair. Wire behaviour after the restart is identical, including the
patched 404 and the analyst/admin split.

### 9.9 Phase 4.x regression

Covered by the full unit + integration suites (§9.1–9.2, which contain the Phase 4.1–4.10 slices),
the shipped live-composition gates (§9.5), the fresh-DB audit (§9.4) and the Chromium workflow
(§9.6). **No Phase 4.x gate regressed.** `scripts/check_wiring.py` still fails on the legacy
`frontend/js/case.js` only (pre-existing, legacy-scoped, unchanged).

---

## 10. False positives (investigated and dismissed in this round)

| Candidate | Owner verification |
|---|---|
| "rotation must revoke old tokens" | approved deferral `5.2-07`; the behaviour matches the documented semantics; replay after first use is still refused |
| "stale token of a disabled source returns 409 not 401" | correct fail-closed refusal with a truthful state error |
| "UUIDv7 version-nibble id rejected" | probe artefact — the validator works as designed |
| "future `event_time` rejected" | correct ordering rule |
| "analyst can read `source.audit`" | by design (`source:read`); the trail carries no credential material (leakage scan: NONE) |
| "capability collection missing / registry empty" | seeded by bootstrap on every start (6 capabilities: 2 live + 4 planned) |
| "frontend shows `backend_kind=memory`" | stale legacy `localStorage`, not written by the current app |
| "payload triple accepted ⇒ impersonation possible" (MUSE `AI1-01`) | attribution is token-derived; a third-party identity is unreachable |
| "fully-rejected batch = data loss" | nothing is persisted; the documented batch contract reports per-event rejections |
| "analyst 404 on cases = IDOR leak" | safe refusal; it is a workflow-ownership gap (L-02), now documented |
| "`conn-*` pseudo-capabilities in the UI" | only in dead `mockData.ts`; the served bundle contains no such marker |
| "no rate-limit response at a 30-request burst" | the configured budget (120/min) was simply not reached; not a defect |
| "`check_wiring.py` failure = product defect" | legacy-frontend-only checker; pre-existing and out of scope |

---

## 11. Remaining real issues after this round

| ID | Issue | Class | Blocks the local baseline? |
|---|---|---|---|
| **R-1** | `5.2-PRE-01` — managed library rules carry no conditions, so benign telemetry raises detections (reproduced: 8 events → 16 detections) | **PRE-EXISTING (HIGH for SOC usefulness)** | **No** for running the product; **yes** for relying on detections without analyst triage. Recorded, queued as its own reviewed phase |
| **R-2** | Analyst cannot read/act on pipeline-created cases (L-02). Confirmed: analyst 404 on all nine case/report/routing/timeline ops, admin 200 on all nine | **CONFIRMED (High for role-separated operation)** | **No for the declared admin-operated local deployment; yes for any role-separated deployment.** Owned by Phase 5.4 (Master Plan §21) |
| **R-3** | Notification feed names cases the analyst cannot open (L-16) | CONFIRMED, Low, 5.4-coupled | No |
| **R-4** | Closure certification is not persisted as a structured resolution (L-10) | 5.4 scope | No |
| **R-5** | `overview.timeseries` `scope` label (L-19); source read ops gated on `rule:read` (L-17); claim-mismatch status nuance (L-18); analyst `case.list` windowing (L-20) | Documentation / low | No |
| **R-6** | `5.2-06` token-id at rest, `5.2-07` revocation list, `5.2-08` inert mapping transformation, `5.2-09` closed enum | Approved deferrals / documented boundaries | No |
| **R-7** | Legacy `frontend/*.html`, legacy-scoped `check_wiring.py` failure, dead `mockData.ts`, legacy `localStorage` key | Pre-existing / hygiene | No |
| **R-8** | Working tree is dirty vs `f674f09` (the tested product IS the working tree); `verify_restart_persistence.py` needs a running stack | Pre-existing process issues | No |

**No confirmed deployment-blocking defect remains open.** R-1 and R-2 are carried explicitly and are
the two items a follow-up phase must own; neither is hidden and neither is silently absorbed.

---

## 12. Cleanup and repository accounting

* **Temporary owner artifacts removed.** The entire `_owner_probe/` scratch directory (probes, logs,
  captured outputs) and a stray root-level probe output file were deleted at the end of this round.
  No historical audit report, no shipped verification script and no test was deleted.
* **Pre-existing scratch left untouched** (not created by this round, and deleting another party's
  evidence would destroy reproducibility): `_audit/`, `_audit_*.py`, `_audit_cleanup4.txt`,
  root-level `*.log`, `hc.txt`, `investigate_results.txt`, `t.txt`, `tl.txt`, `valid.txt`.
* **Git accounting (final, after cleanup).** Working-tree entries **before** this round: **89**
  (of which 2 were this round's own scratch items — `_owner_probe/` and
  `_owner_probe_handlers.txt` — leaving **87** genuinely pre-existing entries). Final count:
  **89** entries = 87 pre-existing + 2 additions − 2 scratch removals.
  * **+1 tracked modification:** `app/pipeline/service.py` (previously clean; modified by PATCH-01).
  * **+1 new untracked file:** `tests/unit/test_phase52_owner_patches.py` (the new regression suite).
  * **−2 temporary artifacts removed:** the whole `_owner_probe/` scratch directory and the stray
    root-level `_owner_probe_handlers.txt`.
  * The other five backend/UI edits touched files that were **already** modified/untracked in the
    pre-existing dirty tree (`app/incidents/service.py`, `app/auth/permissions.py`,
    `app/proxy/proxy.py`, `app/persistence/bootstrap.py`, `app/sources/ingress.py`,
    `frontend/src_upgraded_gemini/**`, `frontend/soc/**`), so their status strings did not change.
  * **No other file was deleted** by this round, and **no shipped test, script or report was altered**.
  * The four documents of this round (two updated, two new) live under the untracked
    `docs/PHASE 5(V3)/` tree; both original auditor reports are byte-identical to their received
    state.

---

## 13. Final status of this reconciliation

| Item | Result |
|---|---|
| Both auditor reports preserved | YES (verbatim, unmodified) |
| Every finding classified | YES (§2, 20 ledger entries) |
| Every finding reproduced | YES (§3, §9.7) |
| Common / GLM-only / Muse-only split | YES (§2.1–2.3) |
| Owner-discovered defects | 2 real (L-15, L-08) + 5 documented (§2.4) |
| Confirmed deployment-blocking defects fixed | YES (L-15 bootstrap race; L-01 cross-owner disclosure; L-07/L-08 read surface) |
| Security fixes proven before → after | YES (§6, §9.7) with no unauthorized state persisted |
| Full regression re-run after all patches | YES (§9) |
| Current React workflow verified in Chromium | YES, 39/39 against the freshly built bundle |
| Restart / reload verified | YES (§9.8, identical) |
| Remaining issues explicit | YES (§11) |

**PHASE 5.2 FINAL STATUS: READY FOR LOCAL SELF-HOSTED DEPLOYMENT** — single-operator /
admin-operated, bound to localhost, with R-1 and R-2 carried as documented limitations (see the
baseline document for the exact envelope). **NOT** claimed: 100% secure, bug-free, internet-facing or
role-separated production readiness.

**PHASE 5.3: HOLD** (verified — no 5.3/learning/dataset/evidence functionality was added or touched).

**POST-PATCH INDEPENDENT VERIFICATION: REQUIRED.** This round is the implementation owner's own
reconciliation; the fixes and the new baseline must be re-audited by an independent party before the
`READY` label is treated as reviewed.
