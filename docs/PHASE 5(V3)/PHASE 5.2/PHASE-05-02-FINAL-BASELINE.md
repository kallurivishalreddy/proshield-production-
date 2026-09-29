# PHASE 5.2 — FINAL BASELINE

**Document ID:** `PHASE-05-02-FINAL-BASELINE`
**Date:** 2026-09-17
**Supersedes (as the authoritative baseline record):** the status claims of the Phase 5.2
implementation report rounds 1–4 and of both independent audits. Those documents are preserved as
history; where they disagree with this document, **this document is the baseline**.
**Governing documents:** `docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md` (§19 Phase 5.2,
§21 Phase 5.4), `docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md`.
**Companion documents:** `PHASE-05-02-OWNER-RECONCILIATION-AND-PATCH-REPORT.md` (full ledger and
before/after proof), `PHASE 5.2 IMPLEMENTATION REPORT.md` (rounds 1–5),
`PHASE-05-02-INDEPENDENT-REVIEW.md` (Parts I–III).

---

## 1. Final deployment decision

| Question | Answer |
|---|---|
| Is Phase 5.2 READY FOR LOCAL SELF-HOSTED DEPLOYMENT? | **YES** |
| Envelope of that statement | **single-operator (admin-operated), bound to `127.0.0.1`, one host, local MongoDB.** A production-like LOCAL baseline — not an internet-facing or multi-tenant deployment |
| Role-separated (analyst-operated) operation | **NOT READY** — the analyst persona cannot read/act on pipeline-created cases (R-2, owned by Phase 5.4). The local baseline ships as admin-operated |
| Phase 5.3 | **HOLD** — not started; no learning/dataset/evidence functionality added or touched |
| Claims explicitly NOT made | "100% secure", "bug-free", "universally production-ready" |
| Independent verification of this baseline | **REQUIRED** (this round is the implementation owner's own reconciliation) |

---

## 2. Final architecture (as built, as verified)

```
  Source (external system)
    |  single-use HMAC source-identity token (sit-), per-source credentials
    v
  Ingress plane  (:8089, scripts/ingress_server.py — the ONLY telemetry entry point)
    |  verifies the SIGNED token triple against the registered source instance (401/403)
    |  enforces ENABLED state (409 disabled / 410 retired), capability-binding quarantine (409),
    |  per-source + per-event rate budget (429), size caps (400), single-use replay store (401)
    v
  SecurityEvent  (provenance DERIVED from the token: source_instance_id, source, collector,
    |             capability_id; payload identity fields are never trusted)
    v
  DetectionPipeline  (rule engine over rule.capability_id; severity composed; capability carried)
    v
  CorrelationEngine  (NGINX-CORR-BRUTEFORCE-001; capability_ids from members; confidence)
    v
  IncidentService.create_case_for_correlation  (deterministic case id per cluster; idempotent;
    |             evidence accumulates; case owner = the pipeline SYSTEM identity)
    v
  Case (Incident)  — notes / acknowledge / investigate / close / timeline / routing / reports /
                     notifications / export (md|csv|pdf)

  Analyst plane  (:8088, scripts/proxy_server.py — SecureProxy, 69 operations)
    |  session tokens (ps.), closed permission catalogue, ownership-scoped case access (404-based)
    v
  Current React app (frontend/src_upgraded_gemini -> frontend/soc/index.html), served at
    /static/soc/index.html; every call goes through the same-origin /api/proxy boundary
```

**Invariants re-verified:** Event ≠ Detection ≠ Correlation ≠ Case · Source ≠ Capability (allowlisted
registry: 6 seeded = 2 live + 4 planned) · source identity ≠ analyst identity · provenance is
server-derived · no subconnectors · evidence is not rewritten · a capability is never accepted from a
client · retired/disabled/unverified sources cannot be bypassed on any route.

**Post-Phase-5.2 changes in this baseline:** the case ownership model now also covers the
correlation→case *reuse* route, and the semi-trusted collector role has no analyst-plane read surface.

## 3. Security status

| Control | Status | Evidence |
|---|---|---|
| Authentication (analyst plane) | PASS — credential-verified `auth.issue`; wrong credential 401; empty/absent token 401 | live probes |
| Authorization / RBAC | PASS — closed catalogue; wrong role 403; unknown op 400; the two previously ungated operations are now gated | live probes + unit tests |
| Case ownership (IDOR/BOLA) | PASS — every case read/write route, **including `case.create_from_correlation`**, answers 404 `case_not_found` for a foreign owner; no unauthorized evidence merge | before/after live proof |
| Source identity / token trust | PASS — single-use, keyring-verified, lifetime-bounded; replay 401; tampered signature 401; claim/registration mismatch 401; token/registry mismatch 403 | 5 attack rows |
| Provenance integrity | PASS — payload identity/capability declarations never survive; persisted provenance is token-derived | Mongo inspection |
| Lifecycle gates | PASS — disabled 409, retired 410, `enable` on retired 409, `issue_token` on disabled 409 | live probes |
| Cross-plane isolation | PASS — session token on ingress 401; source credential on analyst plane 401 | live probes |
| Secret leakage | PASS — token material/keys absent from `source.list/get/audit`, `notification.list`, `capability.list`; once-only token panel; no token in UI cards | leakage scan: NONE |
| Database defence-in-depth | PASS — `$jsonSchema` validators + unique/query indexes on 10 entity collections; malformed writes rejected (MongoDB error 121) | `audit_fresh_db.py` 42/42 |
| Deployment start-up | PASS — both planes boot together on a **fresh** database (race tolerated); validators/indexes converge to the documented shape | 0/5 race failures (was 5/5) |
| Restart / recovery | PASS — identical persisted state after a full two-plane restart; counters not reset; replay store retained | snapshot/verify comparison |

Residual security-relevant limitations (documented, not defects): rotation does not revoke an
outstanding unused credential (`5.2-07`); the notification feed is role-broadcast and its metadata can
name cases the analyst cannot open (R-3); token-id hashing at rest is not enabled (`5.2-06`).

---

## 4. Analyst workflow status

| Stage | Status |
|---|---|
| LOGIN (`auth.issue`, real LoginGate) | PASS (analyst / admin / collector subjects) |
| OVERVIEW / TELEMETRY SOURCES / SOURCE LIFECYCLE (six-step wizard) / CREDENTIALS / ROTATION / MIGRATION / AUDIT | PASS — all driven against the real backend in Chromium (39/39) |
| REAL INGESTION → SECURITY EVENT → DETECTION → CORRELATION → **CASE** | PASS end-to-end over real HTTP + Mongo (51/51 chained checks); the auto-case is created by the pipeline system identity with accumulating evidence |
| Analyst triage of **pipeline-created** cases | **NOT AVAILABLE** (R-2) — analyst 404 on all nine case/report/routing/timeline operations; **admin 200 on all nine** |
| Analyst triage of cases it owns | PASS — acknowledge / investigate / note / close / timeline / report / routing / notification all verified |
| REPORT / EXPORT (md, csv, pdf) | PASS |
| RELOAD (binding + lifecycle survive) | PASS |
| Rules ownership display | PASS — real `cap-*` owners or honestly unowned; no fabricated `conn-*` |
| Phase 5.3 surfaces (Learning/Guide/Datasets/Evidence) | Honest disabled previews; no backend calls (HOLD respected) |

**Deployment consequence, stated plainly:** this baseline is operated by the **admin** identity. An
analyst session can drive the whole source-side workflow and can work cases it created itself, but the
system-generated cases must be triaged by an admin until Phase 5.4 adds assignment/visibility.

---

## 5. Frontend build identity (mandatory evidence)

| Item | Value |
|---|---|
| Authoritative source tree | `frontend/src_upgraded_gemini/` (React 19.2.6, Vite 7.3.2, TypeScript 5.9.3) |
| Served artefact | `frontend/soc/index.html` |
| Build result | 72 modules transformed, inlined single file, **1,200,496 bytes** |
| Build time | 2026-09-17 14:03:39 |
| SHA-256 | `31fcaeee33a104e2cb3f916f4d78e806d62b78cb51fda9d1158f03cbc9c806cb` |
| Typecheck | `tsc --noEmit` → clean |
| React root element present | YES |
| Legacy markers (`PSAPI`, `api.js`, `conn-okta`, `auth_via_mfa`) | ABSENT |
| Latest-wording check | new rotation wording present, old wording absent |
| Staleness check | newest source file older than the bundle → **not stale** |
| Legacy frontend used as evidence? | **NO** — `frontend/*.html` and `frontend/js/**` were never used |

---

## 6. MongoDB status

| Item | Value |
|---|---|
| Server | MongoDB **8.0.13**, real `mongod.exe`, `127.0.0.1:27017` |
| Databases used | fresh `proshield_final52` (before-fix probes) and fresh `proshield_final52_after` (after-fix probes + restart); throwaway DBs for the shipped scripts |
| Entity collections with validators + indexes | `security_events`, `detections`, `correlations`, `incidents`, `reports`, `managed_rules`, `source_instances`, `capabilities`, `source_telemetry`, `notifications` (+ append-only `source_audit`, `capability_audit`, `counters`, replay store) |
| Validator/index audit | **42/42** (`scripts/audit_fresh_db.py`) |
| Unique-index guarantees | event / detection / correlation / case / report / source / notification / telemetry / capability ids |
| Human-id counters | native `_id` counters; monotonic across restarts; 25/25 concurrent uniqueness |
| Bypass attempts | malformed/forged writes rejected by the validators (fail-closed) |

---

## 7. Live pipeline (the product's own chain)

`Source → source token → InboundIngressProxy → SecurityEvent (derived provenance) → capability
derivation → rule resolution → Detection → Correlation → auto-Case → lifecycle / reports / routing /
notifications` — executed over real HTTP on both planes and real MongoDB:

* 4 `authentication_failure` events from one enabled source → detections → one correlation
  (`NGINX-CORR-BRUTEFORCE-001`) → **auto-case** created by the pipeline system identity with
  accumulating evidence (1 → 4) and no duplicate case;
* `verify_phase52_pipeline.py` → **51/51** (cross-source attribution, forgery, replay,
  disable/enable/retire gates, post-retirement history);
* `verify_phase52_live.py` → **14/14** (binding, audit trail, second-boot idempotency).

---

## 8. Persistence / restart

Snapshot → full two-plane restart → re-verify: **IDENTICAL** (case id/state/creator/notes/history/
evidence/`updated_at`, every collection count, human-id counters, per-source lifecycle + capability
binding, replay-store entries). No data loss, no fabrication, no counter reset. A full-page Chromium
reload preserves the source binding and lifecycle state (verified inside the 39/39 gate).

---

## 9. Exact regression counts (all re-run AFTER the patches)

| Gate | Result |
|---|---|
| Unit suite (full) | **1470 passed, 0 failed, 1 warning** (baseline 1458; **+12** new owner tests) |
| Integration suite (full, real Mongo) | **112 passed, 0 failed** |
| Combined | **1582 passed, 0 failed** |
| Focused Phase 5.2 + 5.1 slice | **190 passed** (baseline 178; +12) |
| Fresh-DB validator/index audit | **42/42** |
| Live composition | **14/14** |
| Chained live pipeline | **51/51** |
| Chromium (current React build) | **39/39** |
| Two-plane fresh-DB bootstrap race | **0/5 failures** (was 5/5) |
| Security/pentest regression | 18 attack rows, all refused or correctly attributed; leakage NONE |
| Restart/recovery | IDENTICAL |

---

## 10. Browser results (real Chromium, current build)

**39/39** checks: analyst-plane readiness · real LoginGate login · Sources page · registry-populated
capability filter · six-step wizard (Identity → Capability → Connection → Credentials → Validation →
Enable & Verify) · only live capabilities offered · truthful binding preview · backend-issued
once-only `sit-` credential with the signed capability claim · source card + detail with real binding
and persisted lifecycle · credential state truthful · **no token material in the card** · rotation
issues a different credential · migration dry-run writes nothing · real audit trail · disable →
`disabled` · re-enable → `enabled` · binding survives reload · lifecycle survives reload · Rules page
renders real seeded rules · **no fabricated `conn-*` capability** · every rule scope is a real `cap-*`
owner or honestly unowned · Sources reachable again after Rules · no horizontal overflow at
1440/1280/1024/768/390 · retirement honoured with gated controls · retired credential state
`RETIRED` · **no console errors** · **no 5xx**.

---

## 11. Remaining real issues (open, explicit)

| ID | Issue | Severity for this local baseline | Owner |
|---|---|---|---|
| **R-1** | `5.2-PRE-01` — managed library rules carry no conditions, so benign telemetry raises detections (8 events → 16 detections reproduced). Analysts must triage; detections are not a reliable signal by themselves | HIGH for SOC usefulness; not a trust defect | separate reviewed phase (queued) |
| **R-2** | Analyst cannot read/act on pipeline-created cases (404 on all nine ops; admin 200). Remedy = assignment/visibility | Blocker for role-separated operation only | **Phase 5.4** (Master Plan §21) |
| **R-3** | Notification feed metadata can name a case the analyst cannot open | Low | Phase 5.4 |
| **R-4** | Closure certification is not persisted as a structured resolution (verdict + summary ARE persisted) | Low | Phase 5.4 (`case_resolutions`) |
| **R-5** | `overview.timeseries` `scope` label; source reads gated on `rule:read`; claim-mismatch answered 401 vs the documented 403 nuance; analyst `case.list` windowing | Documentation / Low | next catalogue/product review |
| **R-6** | Approved deferrals: token-id hashing at rest; no revocation list; inert mapping-profile transformation; closed `source_type` enum | Documented | as planned |
| **R-7** | Legacy `frontend/*.html` present; legacy-scoped `check_wiring.py` failure; dead `mockData.ts`; stale legacy `localStorage` key | Hygiene | optional cleanup |
| **R-8** | Working tree is dirty vs `f674f09` (the tested product IS the working tree); the restart-persistence script needs a running stack | Process | owner |

## 12. Explicitly deferred / pre-existing (not part of this baseline's obligations)

Deferred by the governing plan: **R-2/R-3/R-4 → Phase 5.4** (`case_resolutions`, `case:resolve`,
explicit assignment, ownership truthfully handled — "pipeline-owned cases require admin or explicit
assignment", "no silent ownership rewrite"); **Phase 5.3 (learning app) stays HOLD**;
**Phase 5.5–5.9** (data lifecycle, evidence archive, datasets, export versioning, Guide) untouched.

Pre-existing / out of scope: `5.2-PRE-01`, `5.2-06`…`5.2-11`, `5.1-05/08/09`, the legacy frontend and
its checker, PDF Latin-1 limitation, the dirty working tree, and the pre-existing `_audit*` scratch
files at the repository root (not created by this round, deliberately left in place).

## 13. Phase 5.3

**HOLD — unchanged and verified.** No learning, lab, dataset, evidence-archive, export-versioning or
Guide functionality was added, modified or exercised in this round. The React app still shows those
surfaces as honest disabled previews with no backend calls.

---

## 14. How to reproduce this baseline

```bash
# 1. MongoDB 8.x on 127.0.0.1:27017
# 2. both planes on a FRESH database (the shipped sequence)
set PROSHIELD_AUTH_SIGNING_KEY=<32+ chars>& set PROSHIELD_SOURCE_SIGNING_KEY=<32+ chars>
set PROSHIELD_MONGO_DB=<fresh-db>& set PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS=admin:adminpw,analyst:analystpw,collector:collectorpw
python -m scripts.proxy_server   --host 127.0.0.1 --port 8088 --backend mongo --seed-credentials
python -m scripts.ingress_server --host 127.0.0.1 --port 8089 --backend mongo

# 3. gates
python -m pytest tests/unit -q                                  # 1470 passed
python -m pytest tests/integration -q                           # 112 passed
python scripts/audit_fresh_db.py                                # 42/42
python scripts/verify_phase52_live.py                           # 14/14
python scripts/verify_phase52_pipeline.py                       # 51/51
npm --prefix frontend/src_upgraded_gemini run typecheck         # clean
npm --prefix frontend/src_upgraded_gemini run build             # frontend/soc/index.html
python scripts/browser_verify_phase52.py                        # 39/39 (real Chromium)
```

---

## 15. Baseline statement

Phase 5.2 is declared **READY FOR LOCAL SELF-HOSTED DEPLOYMENT** as a single-operator (admin-operated)
localhost deployment on real MongoDB, with the current React frontend, after the owner-led
reconciliation of the two independent audits. The three confirmed deployment-relevant defects found by
that reconciliation (cross-owner case disclosure on the correlation-case reuse route; the two ungated
read operations reachable by the semi-trusted collector role; the fresh-database two-plane bootstrap
race) are fixed and re-verified with before/after evidence. Every remaining issue is either a
documented limitation, an approved deferral, or explicitly owned by Phase 5.4, and is listed above.

**No claim of "100% secure", "bug-free", or universal production readiness is made.** This baseline
must receive an independent post-patch verification before the `READY` label is treated as reviewed.