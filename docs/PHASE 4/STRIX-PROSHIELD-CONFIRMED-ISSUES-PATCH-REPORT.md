# STRIX — ProShield confirmed-issues patch report

> Patching + verification report for the confirmed findings in
> `STRIX-PROSHIELD-ISSUE-REGISTER.md` and
> `STRIX-PROSHIELD-EXECUTIVE-SUMMARY.md`.
> Repository state at patch time: commit `578b320`
> ("feat: complete phase 4.10 backend wiring"), branch `main`.

---

## 1. Baseline (recorded before any change)

| Item | Value |
|---|---|
| Working tree | `M tests/unit/test_phase49_proxy.py` (+303 uncommitted RBAC regression tests, pre-existing), untracked `frontend/`, `scripts/*` verification suite, 2 STRIX docs. Backend `app/` clean. |
| Unit tests | **1175 passed** (8.05 s), no MongoDB needed |
| Integration tests | **77 passed** (11.59 s) against real MongoDB **8.0.13** on 127.0.0.1:27017 |
| Stack scripts | `smoke_test.py` 21/21, `e2e_test.py` 56/56, `check_wiring.py` OK, `verify_sources_fix.py` PASS, `demo_security_workflow.py` full pipeline PASS |
| Reproduced defects | D-2 and D-3 both reproduced at the real FastAPI wire boundary before patching |

## 2. Findings reviewed

All 13 numbered findings (D-1…D-6, F-1…F-2, T-1…T-6) from the issue
register plus the executive-summary defect/gap sections.

## 3. Classification of every finding

| ID | Classification | Evidence |
|---|---|---|
| D-1 | **CONFIRMED — patched** | No production replay store under `app/`; verifier required a caller-supplied `replay_store=` |
| D-2 | **CONFIRMED — patched** | Repro: canonical header 200, lowercase header **401 `source identity token missing`** |
| D-3 | **CONFIRMED — patched** | Repro: body credential 200; header-only canonical `X-ProShield-Credential` **401 `credential required`** |
| D-4 | **CONFIRMED — patched** | No ingress listener existed anywhere in the deployment |
| D-5 | **CONFIRMED — fixed by documentation** | Tag regex `^[A-Z][A-Z0-9_-]*$` undocumented on the wire contract |
| D-6 | **EXPECTED / NOT A DEFECT (already correct)** | `ingress.py` returns **410 Gone** for retired sources; contract error table already documented `410 (source retired)`. The harness expectation (409) was wrong, as the register itself states. Added explicit lifecycle note to the contract anyway. |
| F-1 | **CONFIRMED — ALREADY FIXED** | No `overview.html` reference remains anywhere (`frontend/js/components/layout.js` nav uses `/static/index.html`; login redirect uses `index.html`); e2e static sweep 23/23 assets 200 |
| F-2 | Duplicate of F-1 | — |
| T-1…T-5 | **EXPECTED BEHAVIOUR / test-design** | Strict UUIDv7 id, `extra="forbid"`, 60 s clock-skew, closed event-type set, single-use tokens are contract properties; harness corrected itself |
| T-6 | **Test/tooling note** | `_build_config` Namespace requirement only bites out-of-`__main__` callers; my new callers pass a proper Namespace |

## 4. Patches applied

### D-2 — case-insensitive ingress token headers
* File: `app/sources/ingress.py`
* New `_first_ci_header(headers, *names)` helper; `_extract_token` now
  matches `Authorization` **and** `X-ProShield-Source-Token`
  case-insensitively (handles Starlette-lowercased, canonical, and any
  mixed-case delivery). Body `source_token`/`token` fallback unchanged.
* Security: purely additive lookup; no token source added, none removed.

### D-3 — credential-header transport
* Files: `scripts/proxy_server.py` (listener) **and**
  `app/proxy/proxy.py` (proxy).
* Listener: promotes a lowercased `x-proshield-credential` key to the
  canonical `X-ProShield-Credential` so `SecureProxy` sees it. The
  secret is **not** re-inserted into the request body (preserves the
  documented "secret out of body dumps / replay logs" property — this
  is why the register's suggested header→body mirror was deliberately
  replaced by the smaller, security-preserving header canonicalisation).
* Proxy: `_handle_auth_issue` also falls back to
  `PROXY_HEADER_CREDENTIAL.lower()` for in-process callers.

### D-1 — production single-use replay store
* New file: `app/sources/replay_store.py` → `MongoReplayStore`:
  * cross-process safe (atomic insert; unique index on `token_id`),
  * TTL-aware (MongoDB TTL index on `expires_at`, `expireAfterSeconds=1`)
    plus deterministic `gc(now)` / `release()` / `count()` API parity
    with the in-memory double,
  * fail-closed: any driver error raises `PersistenceError`
    (`ingress.py` translates it to **503 `replay_store_unavailable`**
    instead of silently accepting without replay protection),
  * configurable collection: `PROSHIELD_INGRESS_REPLAY_COLLECTION`
    (default `source_token_replay`), field added to `ProShieldConfig`
    + `safe_summary` + `scripts/proxy_server._build_config`.

### D-4 — production ingress HTTP listener
* New file: `scripts/ingress_server.py`, parallel to
  `scripts/proxy_server.py`, sharing its `_build_config`:
  * `POST /api/ingress` → builds `IngressRequest` from the real HTTP
    request (size-capped, JSON-validated) and calls the **real**
    `InboundIngressProxy.handle`; translates `IngressResponse` → HTTP.
  * `GET /api/ingress/health` (+ `/healthz`) → real `source.health`.
  * `--backend mongo` wires the real repositories **and**
    `MongoReplayStore`; `--backend memory` wires a clearly-labelled
    dev-only `_MemoryReplayStore` (never presented as production).
  * No business logic duplicated; plane separation enforced (no
    frontend mount, no analyst ops).
* Deployment documentation: new "Run the deployment listeners" section
  in `README.md`; env vars added to `.env.example`.

### D-5 — tag-format documentation
* `docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md`
  Action 6.4 now documents `tags` regex `^[A-Z][A-Z0-9_-]*$`,
  `asset_tags` regex, count/length bounds, and the 400 error behaviour.
  (The regex itself was NOT widened — no evidence that the closed
  constraint is wrong; widening would be an unrequested contract change.)

### D-6 — 410 documentation
* Same contract section now states explicitly: DISABLED → 409,
  RETIRED → **410 Gone** (terminal).

## 5. Frontend patches

**None required.** F-1 was already fixed in the current tree (nav and
login use `/static/index.html`; `overview.html` no longer referenced).
All 23 static assets serve 200; `check_wiring.py` reports OK
(9 pages, layout fix present, no redundant `source.list_types`,
case no-id guard present); no console-exception-class defects found in
the static wiring sweep.

## 6. Wiring validation (UI action → backend trace)

* `scripts/check_wiring.py`: **WIRING CHECK OK** — pages 9, layout
  `readyState` fix present, `sources.js` `refreshAll()` present with no
  redundant `list_types` round-trip, `case.js` no-id guard present,
  `overview.js` targets `<main class="main">`.
* `scripts/verify_sources_fix.py`: **PASS** — `source.list` 200, no
  errors, toolbar + content rendered, single round-trip.
* `scripts/e2e_test.py`: **56/56 PASS** over the real `/api/proxy`
  boundary — login, auth failures (401), RBAC (collector 403),
  5 seeded NGINX rules, full source lifecycle
  (register→configure→validate→enable→get→issue_token→disable→retire
  with state assertions at every step), frontend HTML content checks.
* `scripts/smoke_test.py`: **21/21 PASS** (health, meta, auth, RBAC,
  rules, sources lifecycle, overview, correlations, detections).

## 7. Source / rule ownership and detection semantics

* Verified through real runs: NGINX `authentication_failure` fires the
  NGINX-applicable rules; the **same** `authentication_failure` on an
  `iam` source fires **nothing** (no cross-source false positive);
  `authentication_success` (benign) fires nothing; `tls_anomaly` on
  nginx fires nothing (no matching rule — ingested only).
  Evidence: `scripts/detection_boundary_test.py` **PASS** (real
  registered source, real `DetectionPipeline`, real persisted
  detections with IDs).

## 8. Persistence validation (real MongoDB)

`scripts/persist_e2e_strix.py` against MongoDB 8.0.13, dedicated DB
`proshield_strix_persist` (dropped afterwards): **PASS**

* create (register/configure/validate/enable) → persisted;
* fresh backend bundle re-instantiated on the same DB ("restart"):
  `source.get` returns the source with `state=enabled`;
* `MongoReplayStore` claim made in pass 1 is still claimed by a brand
  new store instance in pass 2 (restart parity);
* 5 seeded NGINX rules survive reload;
* token re-issuance works on the reloaded backend.

Memory-only verification and MongoDB verification are kept strictly
separate: unit tests + `--backend memory` scripts prove logic; the
integration suite, `test_strix_ingress_wire.py`, and
`persist_e2e_strix.py` prove MongoDB behaviour.

## 9. Regression results (after all patches)

| Suite | Before | After |
|---|---|---|
| `tests/unit` | 1175 passed | **1185 passed** (+10 new STRIX regression tests) |
| `tests/integration` (real Mongo) | 77 passed | **86 passed** (+9 new wire/replay tests) |
| smoke / e2e / wiring / sources-fix / demo | all PASS | all PASS (unchanged) |

New focused tests:

* `tests/unit/test_phase49_ingress.py::TestIngressCaseInsensitiveHeaders`
  (D-2: lowercase / token-header / mixed-case accepted).
* `tests/unit/test_strix_d2_d3_wire.py`
  (D-3 five transport cases incl. secret-not-echoed; ingress listener
  plane separation: frontend 404, analyst op rejected).
* `tests/integration/test_strix_ingress_wire.py`
  (D-2 over real HTTP + shared Mongo source store; D-1 replay store:
  first-use/second-use, 8-thread concurrency with exactly 1 winner,
  expiry + gc, persistence across store instances; D-4: missing token
  401, disabled source rejected, unknown source rejected).
* `scripts/live_ingress_smoke.py`: real uvicorn socket — health 200,
  no-token 401 (documented message), malformed JSON 400. **PASS**.
* `scripts/demo_security_workflow.py` (Phase E): full pipeline —
  11 NGINX events → 36 detections → brute-force correlation
  (`corr-…  pattern=NGINX-CORR-BRUTEFORCE-001 count=8`) → case
  created/opened/closed → overview summary consistent. **PASS**.

## 10. Security regression

All existing security tests re-ran green inside the 1185 + 86 suites:
auth/AUTH-001/AUTH-002, RBAC matrix (incl. the pre-existing RBAC
regression additions in `test_phase49_proxy.py`), source trust
(S-1 binding, S-2 lifetime, keyring rotation), replay (R-1 in-memory),
rate limiting, size caps, IDOR/case isolation, routing authorization,
centralized-analysis authorization. New patches add security coverage
without weakening any boundary: no auth bypassed, no validation
removed, replay is now *stronger* (fail-closed 503 on store outage),
and the credential secret stays out of the request body.

## 11. Git / diff safety

Temp diagnostics deleted (all `*_out.txt`/`*.txt` scratch files and
`scripts/repro_strix_d2_d3.py`). Final tree contains only:

* Modified: `.env.example`, `README.md`, `app/config.py`,
  `app/proxy/proxy.py`, `app/sources/ingress.py`,
  `docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md`,
  `tests/unit/test_phase49_ingress.py`
  (`tests/unit/test_phase49_proxy.py` modification predates this task).
* Added: `app/sources/replay_store.py`, `scripts/ingress_server.py`,
  `tests/unit/test_strix_d2_d3_wire.py`,
  `tests/integration/test_strix_ingress_wire.py`,
  `scripts/persist_e2e_strix.py`,
  `scripts/detection_boundary_test.py`,
  `scripts/live_ingress_smoke.py`, this report.
* Untracked-but-pre-existing (left untouched): `frontend/`,
  `scripts/proxy_server.py` + pre-existing verification scripts, the
  two Phase 4.10 STRIX docs.

## 12. Remaining issues / follow-up

1. **TLS / network ACLs** for the ingress listener are a deployment
   concern (Phase 4.9 review D-1); the listener is plain HTTP — put it
   behind a TLS-terminating reverse proxy.
2. **`SourceType` ↔ `ALLOWED_SOURCES` naming drift** (`rate_limit` /
   `network` vs `rate_limiter` / `tls_network`) documented in
   `test_phase49_proxy.py` — pre-existing, out of patch scope.
3. **JWT/source-token key rotation across processes** works via the
   keyring, but a shared key-store (secret store) integration remains
   future work (`PROSHIELD_SECRET_STORE_CONFIGURED`).
4. `case.acknowledge/assign/add_note/add_recommendation` remain
   documented "planned" in the UI (no wire ops exist — by design).

## 13. Final verdict

* **Fixed + verified:** D-1, D-2, D-3, D-4 (code), D-5, D-6 (contract
  documentation).
* **Already fixed:** F-1 (and F-2).
* **Not reproducible / expected:** T-1…T-6, harness 409-vs-410 note.
* **Backend:** D-2, D-3(proxy half), D-1. **Deployment:** D-4, D-1
  wiring. **Listener transport:** D-3(listener half), D-2.
* **Persistence:** MongoDB verified (persistence E2E + 9 wire tests on
  real Mongo 8.0.13). **Production ingress:** verified (TestClient
  integration + live uvicorn socket smoke). **Replay protection:**
  verified (single-use, concurrent-exactly-one, TTL/expiry, restart
  persistence, fail-closed on store outage).
* **Source/rule relationships:** correct — NGINX events match only
  NGINX-applicable rules; iam/benign/no-match events produce zero
  detections; no cross-source false positives.
* **Full real pipeline works after the patches** (demo + suites green).
* **No existing functionality regressed** (1185 unit + 86 integration,
  all pre-existing scripts still pass).

Not claimed: "zero bugs", "fully secure", or "production ready" —
TLS termination, secret-store integration, and the `SourceType`
naming reconciliation remain open before a hard production cutover.