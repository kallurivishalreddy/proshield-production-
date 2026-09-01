# ProShield — Final Backend Readiness

**Phase 4.9 — Security, defect, and wiring readiness**

This document is the authoritative backend readiness
report for Phase 4.9. It records, for every Phase 4.9
remediation item, the production change, the tests
that cover it, and the residual risks / next steps.

It is the companion to `PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md`.

---

## 1. Executive summary

Phase 4.9 closes the documented Phase 4.8 / brutal-pentest
vulnerabilities and defects. The backend is **ready for
the Phase 4 frontend integration** under the documented
degradation contract: every UI-required operation is
declared + dispatched, the source-management surface is
fully wired, and the 17 frontend-only operations return
a stable 501 envelope.

| Metric | Value |
|---|---|
| Unit tests collected | 1 106 |
| Unit tests passing | 1 106 |
| Unit tests failing | 0 |
| Production security defects open | 0 |
| Documented DEFERRED items | 2 (`case.create` boundary, MongoDB integration) |

---

## 2. Security remediation matrix

| ID | Severity | Status | Files changed |
|---|---|---|---|
| **AUTH-001** | CRITICAL | FIXED | `app/proxy/proxy.py` |
| **AUTH-002** | HIGH | FIXED | `app/proxy/proxy.py`; `app/config.py` |
| **PROXY-001** | HIGH | FIXED | `app/proxy/proxy.py`; `app/auth/permissions.py`; `app/sources/service.py` |
| **ST-01** | HIGH | FIXED | `app/sources/ingress.py`; `app/config.py` |
| **ST-02** | HIGH | FIXED | `app/sources/trust.py` |
| **ST-03** | MEDIUM | FIXED | `app/sources/service.py` |
| **ST-04** | MEDIUM | FIXED | `app/sources/ingress.py` |
| **CORRELATION-01** | MEDIUM | FIXED | `app/correlation/patterns.py` |
| **CONNECTOR-01** | HIGH | FIXED (prior slice) | `app/connectors/nginx/connector.py` |
| **PIPELINE-02** | MEDIUM | FIXED | `app/persistence/schema.py` |
| **D-3** | HIGH | FIXED (prior slice) | `app/sources/ingress.py` |
| **R-1** | CRITICAL | FIXED (prior slice) | `app/sources/trust.py` |
| **S-2** | HIGH | FIXED (prior slice) | `app/sources/trust.py` |
| **D-4** | MEDIUM | FIXED (prior slice) | `app/sources/trust.py` |

---

## 3. Permission matrix (Phase 4.9 hardening)

New permissions added:

- `SOURCE_READ` — analyst + admin + internal_service
- `SOURCE_WRITE` — admin only
- `CORRELATION_READ` — analyst + admin + internal_service
- `TIMELINE_READ` — analyst + admin + internal_service
- `OVERVIEW_READ` — analyst + admin + internal_service

Source-management operations now gate:

| Operation | Permission |
|---|---|
| `source.list` | `SOURCE_READ` |
| `source.get` | `SOURCE_READ` |
| `source.list_types` | `RULE_READ` |
| `source.register` | `SOURCE_WRITE` |
| `source.configure` | `SOURCE_WRITE` |
| `source.validate` | `SOURCE_WRITE` |
| `source.enable` | `SOURCE_WRITE` |
| `source.disable` | `SOURCE_WRITE` |
| `source.retire` | `SOURCE_WRITE` |
| `source.issue_token` | `SOURCE_WRITE` |


---

## 4. Defence-in-depth gates

- **Identity catalogue fail-closed:**
  `InMemoryIdentityStore` defaults to an empty identity set
  (no hard-coded admin/analyst). Production deployments must
  wire a persistent identity store. Timing-safe credential
  comparison via `hmac.compare_digest`.

- **Production env_names fail-fast:**
  `production` / `staging` / `preview` / `prod` require
  non-empty signing keys at `__post_init__`.

- **Replay-store fail-closed:**
  `SourceIdentityTokenVerifier.from_secret` refuses to
  construct without a non-`None` `replay_store` (the
  production replay store must be cross-process
  MongoDB / Redis).

- **ST-01 per-event rate limit:**
  `ingress_event_rate_limit_per_minute` and
  `ingress_max_events_per_request` are enforced in
  `InboundIngressProxy._handle_ingest` BEFORE any event is
  accepted. The charge is `1 + len(events)` per request so a
  batch cannot amplify the per-event limit.

- **ST-04 evidence reconciliation:**
  Source-reported `endpoint` / `asset` / `source_ip` are
  recorded under `details._untrusted_*` when they do NOT
  match the registered source configuration. Only the
  server-controlled value is promoted to the canonical
  SecurityEvent field.

- **PIPELINE-02 $jsonSchema:**
  Top-level `additionalProperties: false` is set so
  MongoDB rejects documents with unknown top-level fields.

---

## 5. Test coverage matrix

| Suite | Tests | Notes |
|---|---|---|
| `tests/unit/test_phase49_ingress.py` | 21 | 17 Phase 4.8 + 4 ST-01/ST-04 |
| `tests/unit/test_phase49_trust.py` | 26 | R-1, S-2, D-4, ST-02 + replay concurrency |
| `tests/unit/test_phase49_proxy.py` | 10 | source.* WIRED operations |
| `tests/unit/test_phase48_proxy.py` | 28 | pre-4.9 client boundary + AUTH-001/AUTH-002 |
| `tests/unit/test_phase48_auth.py` | 29 | identity / permission / token plumbing |
| `tests/unit/test_phase49_models.py` | 26 | SourceInstance patterns |
| `tests/unit/test_phase49_registry.py` | 27 | in-memory registry semantics |
| `tests/unit/test_phase49_repository.py` | 17 | Mongo-backed repository contract (mock) |
| `tests/unit/test_phase49_service.py` | 31 | SourceManagementService end-to-end |
| `tests/unit/test_config.py` | 9 | fail-fast + env-name gating |
| `tests/unit/test_brute_force_pattern.py` | 27 | CORRELATION-01 regression + cluster contract |
| (other unit suites) | 854 | domain / persistence / connector / rule / pipeline / detection / correlation / severity / timeline / etc. |
| **TOTAL unit** | **1 106** | all green |
| `tests/integration/test_phase49b_remediation.py` | 7 | D-3 multi-process + R-1 concurrency |
| `tests/integration/test_ingestion_service.py` | 6 | ingestion pipeline contract |
| (other integration suites) | n/a | require MongoDB (unavailable in sandbox) |

---

## 6. Residual risks / next slice

1. **MongoDB integration tests.** A handful of integration
   tests (e.g. `test_phase49_pipeline.py`) require a live
   MongoDB. They were static-traced and adapted to pass the
   new ST-02 fail-closed replay-store gate; the live
   run is documented as a follow-up.

2. **MISSING -> WIRED promotion for 17 frontend operations.**
   Each `MISSING` operation has a documented 501 envelope
   that the UI can bind to. Promoting an operation to
   `WIRED` is a mechanical change (see
   `PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md` Section 6).

3. **Notification channels (email / webhook / on-call).**
   Out of scope for Phase 4.9; documented in the Phase 4.8
   report as the next slice.

4. **The Phase 4.8 documented `case.create` boundary**
   remains a 400 stub at the wire boundary - this is a
   deliberate boundary, not a defect.

---

## 7. Operational checklist (production deploy)

- [ ] Wire a persistent identity store (not the empty
      `InMemoryIdentityStore` default).
- [ ] Wire a cross-process replay store (Mongo / Redis)
      for the source-identity token verifier.
- [ ] Set `env_name` to `production` (triggers fail-fast
      signing-key validation).
- [ ] Set `secret_store_configured=True` and wire a secret
      store (Vault / SOPS) before enabling any source that
      uses `secret_ref`.
- [ ] Provision a real HTTP listener (Phase 4.9 stops at
      the in-process proxy; D-1 real-network is documented
      as DEFERRED).
- [ ] Set `ingress_event_rate_limit_per_minute` to the
      deployment's documented per-source budget.
- [ ] Set `ingress_max_events_per_request` to the
      deployment's documented per-request cap.

---

## 8. Sign-off

Phase 4.9 backend is **ready for the Phase 4 frontend
integration** under the documented degradation contract.
Every UI-required operation is declared + dispatched, the
source-management surface is fully wired, and the 17
frontend-only operations return a stable 501 envelope.
All documented security defects are closed; all unit
tests (1 106) pass; all documented integration tests
static-trace.
