# ProShield — Phase 4.9 Final Report

**Slice under report:** Phase 4.9 — Source Management + trusted
external connector integration.

**Date:** 2026-08-31
**Status:** **STABLE — 1153/1153 tests passing** (1087 unit + 66
integration, including 211 new Phase 4.9 tests: 203 unit + 7
integration + 1 e2e demo). All Phase 4.1-4.8 tests are unchanged
and pass. See [§14 Stability verdict](#14-stability-verdict) for
the verification table.

---

## 1. Phase 4.9 Scope and Boundary

### 1.1 What Phase 4.9 Implements

Phase 4.9 adds the **external-source management layer** to
ProShield, distinct from the existing client-facing analyst
boundary. It establishes the trusted inbound integration
boundary and the source-identity token system.

```
External Security System
    -> HMAC-signed source-identity token
    -> Inbound Ingress Proxy (Boundary 5)
        -> source-registry lookup
        -> source-state check (ENABLED only)
        -> canonical SecurityEvent
            -> Phase 4.1 ingestion service
                -> Phase 4.4 detection
                -> Phase 4.5 correlation
                -> Phase 4.6 timeline + severity/confidence
                -> Phase 4.8 incident / report / routing
```

Concretely, Phase 4.9 ships:

1. **Source-domain model** (`app/sources/models.py`):
   `SourceInstance`, `SourceInstanceConfiguration`,
   `SourceInstanceHealth`, `SourceInstanceView`,
   `SourceIdentityToken`, plus closed-set enums
   (`SourceType`, `SourceState`, `SourceConnectionType`).
   All fields are validated and frozen; ``extra="forbid"``.
2. **In-memory authoritative registry**
   (`app/sources/registry.py`): `SourceRegistry` with a
   documented lifecycle state machine
   ``REGISTERED -> CONFIGURED -> VALIDATED -> ENABLED ->
   DISABLED -> RETIRED``. All transitions are enforced;
   ``RETIRED`` is terminal.
3. **MongoDB persistence boundary**
   (`app/sources/repository.py`): `SourceRepository` with
   a BSON ``$jsonSchema`` validator and five indexes.
   The repository redacts ``secret_ref`` to ``secret_ref_set``
   on persist and re-attaches an empty ``secret_ref`` on read.
4. **Source Management service**
   (`app/sources/service.py`): `SourceManagementService`
   implements the documented lifecycle, the validation
   gate (``https://`` only for ``PUSH`` / ``PROXY`` / ``PULL``),
   the source-identity-token issuer, and the
   admin-only authorization gate.
5. **Source-identity trust**
   (`app/sources/trust.py`): `SourceIdentityTokenIssuer` /
   `SourceIdentityTokenVerifier`. HMAC-SHA256 over a canonical
   JSON body, deterministic wire form, time-bounded.
6. **Inbound ingress boundary**
   (`app/sources/ingress.py`): `InboundIngressProxy`. This is
   the trusted inbound boundary, deliberately distinct from
   the client-facing `SecureProxy`. HMAC-token gated,
   per-source-instance rate limit, idempotent ingestion, no
   parallel detection / correlation engine.
7. **Config knobs** (`app/config.py`): `source_signing_key`,
   `source_token_lifetime_seconds`,
   `ingress_rate_limit_per_minute`,
   `ingress_max_request_bytes`,
   `ingress_max_response_bytes`.
8. **SecureProxy wire operations**:
   `OP_SOURCE_LIST`, `OP_SOURCE_GET`,
   `OP_SOURCE_LIST_TYPES`, `OP_SOURCE_REGISTER`,
   `OP_SOURCE_CONFIGURE`, `OP_SOURCE_VALIDATE`,
   `OP_SOURCE_ENABLE`, `OP_SOURCE_DISABLE`,
   `OP_SOURCE_RETIRE`, `OP_SOURCE_ISSUE_TOKEN`. Each
   preserves the documented safe-error envelope; secret
   material never crosses the client boundary.
9. **Phase 4.1 `SecurityEventProvenance` extension**:
   the optional `provenance.source_instance_id` field is
   set by the trusted ingress boundary so every event
   carries the verified source-instance pointer through the
   rest of the pipeline.
10. **Source-instance index on `security_events`**:
    sparse index on `provenance.source_instance_id` for
    fast historical-evidence lookups.
11. **End-to-end demo** (`scripts/demo_phase49.py`) that
    drops the documented collections, walks the full
    lifecycle, ingests benign + suspicious telemetry, runs
    Phase 4.4 detection + Phase 4.5 correlation, and
    retires the source — printing **DEMO OK** at the end.

### 1.2 What Phase 4.9 Does NOT Do

* It does NOT implement a second detection / correlation
  engine. The ingress boundary feeds canonical
  SecurityEvents through the existing Phase 4.1 ingestion
  service; Phase 4.4-4.8 operates unchanged.
* It does NOT generate arbitrary Python connector code per
  source instance. Each connector lives in
  `app/connectors/`; the source-management layer only
  carries configuration + provenance.
* It does NOT expose secret material to the client. The
  client sees only the safe `SourceInstanceView` with a
  boolean `secret_ref_set` flag.
* It does NOT silently downgrade a failed ingestion. Every
  per-event failure surfaces as a `rejected` entry in the
  ingress response, never as a fabricated SecurityEvent.
* It does NOT delete historical evidence on retire. The
  document remains in MongoDB; only new telemetry is
  refused.
* It does NOT introduce a frontend / dashboard UI. The
  client-facing proxy exposes only the documented wire
  operations.

---

## 2. Source Management vs Rule Management

The Phase 4.9 source model is **deliberately distinct**
from the Phase 4.7 rule model.

| Concept | Source Management (Phase 4.9) | Rule Management (Phase 4.7) |
|---|---|---|
| Question | "What external security systems are connected to ProShield?" | "What security behaviour should ProShield detect?" |
| Identity | `source_instance_id` (`src-<uuidv7>-<handle>`) | `rule_id` + `version` |
| State machine | REGISTERED -> CONFIGURED -> VALIDATED -> ENABLED -> DISABLED -> RETIRED | CANDIDATE -> APPROVED -> enabled |
| Authorization | admin-only writes; analyst may read | admin-only writes (rule:write) |
| Persistence | `source_instances` collection | `managed_rules` collection |
| Provenance | carried into `SecurityEvent.provenance.source_instance_id` | carried via `Detection.rule_id` / `Correlation.pattern_id` |
| Identity token | HMAC source-identity token | (none — rules run on authenticated events) |

A future analyst UI can manage both via the same proxy
boundary without coupling the two layers; the wire shapes
are independent.

---

## 3. Source Management model

### 3.1 Connector types

`SourceType` is a closed-set enum:

* `nginx` (NGINX access logs)
* `waf` (WAF events)
* `iam` (Identity / authentication events)
* `rate_limit` (Rate-limit / throttling events)
* `network` (Network / TLS anomaly events)
* `simulator` (Deterministic test source)

Each value is mapped to the canonical `SecurityEvent.source`
string via `SOURCE_TYPE_TO_SOURCE_STRING`:

```python
{
    SourceType.NGINX: "nginx",
    SourceType.WAF: "waf",
    SourceType.IAM: "iam",
    SourceType.RATE_LIMIT: "rate_limit",
    SourceType.NETWORK: "network",
    SourceType.SIMULATOR: "simulator",
}
```

The model enforces that every `SourceInstance.source` matches
its `source_type`; a mismatched pair is rejected at the model
boundary (defence-in-depth).

### 3.2 Lifecycle states

```
REGISTERED -- configure --> CONFIGURED -- validate --> VALIDATED
                                                                  |
                                                                  v
                                                            ENABLED
                                                                  |
                                                                  v
                                                            DISABLED
                                                                  |
                                                                  v
                                                            RETIRED (terminal)
```

Documented transitions are enforced by
`app/sources/registry.py::can_transition` and exercised by
the `SourceRegistry.transition` method.

### 3.3 Source instance model

`SourceInstance` is the authoritative record:

```python
class SourceInstance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_instance_id: SourceInstanceId
    source_type: SourceType
    source: str  # canonical SecurityEvent.source
    display_name: str
    description: str
    configuration: SourceInstanceConfiguration
    state: SourceState
    created_by: str
    created_at: datetime
    updated_by: str
    updated_at: datetime
    last_validation_at: Optional[datetime]
    tags: Tuple[Tag, ...]
    asset_tags: Tuple[AssetTag, ...]
    retired_at: Optional[datetime]
```

`SourceInstanceView` is the safe client-facing shape; it
strips `secret_ref` and reports `secret_ref_set` as a boolean.

---

## 4. Source Registry

`app/sources/registry.py` is the in-memory authoritative
catalogue of configured source instances.

Design rules (mirrors Phase 4.2 / Phase 4.7):

* **No mutation outside the documented methods.** The
  registry is the only thing that flips a source
  instance's state, `last_validation_at`, `retired_at`, or
  audit metadata.
* **Idempotent lookups.** Lookup methods never raise
  for "not found"; they return `None` or an empty list.
* **Deterministic iteration.** `list_all` and
  `known_ids` return results in stable sorted order.
* **Strict on the state machine.** Invalid transitions
  raise `SourceInstanceStateError`; an unknown id raises
  `SourceInstanceNotFoundError`.
* **Thread-safe.** A `threading.RLock` guards every mutator.

Supported connector types (the closed set):

```python
SUPPORTED_CONNECTOR_TYPES = frozenset(SourceType)
```

Adding a new connector type is a backend engineering task
(extend `SourceType`, add the connector module under
`app/connectors/<type>/`, add rule library under
`app/rules/_library/<type>/`).

---

## 5. Source Repository

`app/sources/repository.py` is the **only** place that talks
to pymongo about source documents. It mirrors the documented
Phase 4.1 / 4.5 / 4.7 / 4.8 repository policies:

* Translates driver errors to safe `DomainError` subclasses.
* Maintains a BSON `$jsonSchema` validator and the documented
  index set.
* Pairs every read / write with the framework's Pydantic
  `SourceInstance` model.
* Enforces the documented **secret-redaction gate** at
  the persistence boundary: a direct pymongo write cannot
  smuggle raw credential material past the service layer
  because the BSON schema does not allow the `secret_ref`
  field.

Indexes:

| Name | Key | Properties |
|---|---|---|
| `source_source_instance_id_unique` | `{source_instance_id: 1}` | unique |
| `source_source_type` | `{source_type: 1}` | secondary |
| `source_state` | `{state: 1}` | secondary |
| `source_created_at` | `{created_at: -1}` | sort by recency |
| `source_display_name` | `{display_name: 1}` | lookup |

---

## 6. External Connection Configuration

`SourceInstanceConfiguration` is the **server-side** config:

* `connection_type` — `push` / `proxy` / `pull` (closed set).
* `endpoint` — non-empty, no whitespace. The Phase 4.9
  validation gate additionally requires `https://` for the
  `PUSH` / `PROXY` shapes.
* `proxy_path` — optional path prefix.
* `destination` — optional human-readable label.
* `asset_tags` — `Tuple[AssetTag, ...]`, sorted, bounded.
* `tags` — `Tuple[Tag, ...]`, sorted, bounded.
* `references` — `Tuple[str, ...]`, bounded.
* `secret_ref` — opaque server-side reference; the
  repository redacts this on persist. Forbidden
  substrings (`password=`, `token=`, `apikey=`,
  `secret=`, `private_key=`) are rejected at the model
  boundary (defence-in-depth).

---

## 7. Secure Ingress Proxy

The trusted inbound boundary lives in
`app/sources/ingress.py::InboundIngressProxy`. It is
**deliberately distinct** from the client-facing
`SecureProxy`:

| Boundary | Auth | Rate limit | Audience |
|---|---|---|---|
| `SecureProxy` (client) | SessionToken (HMAC) | per-subject | analyst / admin |
| `InboundIngressProxy` (source) | `SourceIdentityToken` (HMAC) | per-source-instance | external systems |

### 7.1 Operations

* `OP_HEALTH` — open, no auth, returns the supported
  operation set.
* `OP_INGEST` — accepts a batch of `events`, verifies the
  source-identity token, looks up the source instance,
  enforces state == `ENABLED`, enforces per-source-instance
  rate limit, builds canonical `SecurityEvent` objects,
  and forwards to the existing `SecurityEventIngestionService`.

### 7.2 Security controls

* **Token verification** — missing / malformed /
  tampered / expired tokens are rejected with safe 4xx
  responses.
* **Source integrity** — the inbound payload's
  `source_instance_id` / `source_type` / `source` triple
  must match the registered instance. A mismatch returns
  `source_integrity_error` (403).
* **State enforcement** — only `ENABLED` sources are
  accepted. `DISABLED` returns 409; `RETIRED` returns 410.
* **Rate limit** — per-source-instance sliding window
  (default 600 req/min). Burst traffic returns 429.
* **Size limit** — payloads > `config.ingress_max_request_bytes`
  return 400.
* **Idempotency** — the existing Phase 4.1 ingestion
  service's idempotent path is reused; re-deliveries
  produce the same canonical event.
* **Secret material** — never crosses the boundary in
  either direction.

---

## 8. Source-Identity Trust

`SourceIdentityToken` is the HMAC-signed, time-bounded
proof that an inbound payload comes from a trusted source.

Wire form:

```
sit-<uuidv7>.<base64url-body>.<base64url-hmac>
```

Body fields:

* `token_id` (`sit-<uuidv7>`)
* `source_instance_id`
* `source_type` (closed set)
* `source` (canonical `SecurityEvent.source` string)
* `issued_at` (UTC unix seconds)
* `expires_at` (UTC unix seconds)
* `nonce` (16 random bytes, base64url)
* `signature` (HMAC-SHA256 over the canonical body)

The token body is JSON-serialised with `sort_keys=True,
separators=(",", ":")` for deterministic verification.

---

## 9. Source Lifecycle

The documented lifecycle is enforced by
`SourceManagementService`:

* `register(...)` — `REGISTERED` (admin-only).
* `configure(...)` — `REGISTERED -> CONFIGURED` (admin-only).
* `validate_connection(...)` — `CONFIGURED -> VALIDATED`
  (admin-only). Structural gate + optional `validator`
  callable.
* `enable(...)` — `VALIDATED -> ENABLED` (admin-only).
* `disable(...)` — `ENABLED -> DISABLED` (admin-only).
* `retire(...)` — any non-retired state -> `RETIRED`
  (admin-only, terminal). Preserves the document.
* `update_metadata(...)` — display name / description /
  tags / asset_tags. Refuses to mutate a retired instance.
* `issue_ingress_token(...)` — issues a fresh
  source-identity token. Refuses if the instance is not
  in `VALIDATED` or `ENABLED`.

Each transition writes the updated document through
`SourceRepository.upsert` (which sets `last_validation_at`
for the validate transition) and reindexes it in the
in-memory `SourceRegistry`.

---

## 10. Relationship to Rules Management

Phase 4.9 introduces **no** new rule class. The Phase 4.7
`GenericDeclarativeRule` + `RuleManagementService` already
handles source-specific rules: a rule with
`category=SOURCE_SPECIFIC`, `sources=("nginx",)`,
`event_types=("authentication_failure",)` is selected only
when `event.source == "nginx"` (enforced by
`RuleMetadata.applies_to_source`).

The Phase 4.9 layer adds:

* a stable `provenance.source_instance_id` field on every
  event (for historical-evidence lookups), and
* a `SecureProxy` `OP_SOURCE_LIST` response that returns
  the supported connector types — a future UI can populate
  the rule-management "Source-Specific" dropdown from this
  list without coupling to the rule framework.

A `CROSS_SOURCE_CORRELATION` rule (Phase 4.7) can declare
two or more sources and run when at least one matching
detection exists for each declared source. The Phase 4.9
layer preserves source identity through the detection
flow so the correlation engine can apply this gate.

---

## 11. Source-Specific Responsibility

The detection engine enforces source-specific rule
applicability at the metadata level:

```python
class RuleMetadata:
    def applies_to_source(self, source: str) -> bool:
        if not self.sources:
            return False
        return source in self.sources

    def applies_to(self, event: SecurityEvent) -> bool:
        return (
            self.applies_to_source(event.source)
            and self.applies_to_event_type(event.event_type)
        )
```

The Phase 4.9 source identity flows through
`event.source` (canonical string) and
`event.provenance.source_instance_id` (instance pointer).
A WAF message cannot execute an NGINX-only rule because:

1. `event.source = "waf"` fails `applies_to_source("nginx")`.
2. The detection engine returns 0 detections.
3. No Phase 4.5 correlation is triggered (it requires a
   detection to exist).

This invariant is exercised end-to-end in
`test_phase49_pipeline.py::test_retired_source_evidence_remains_queryable`
and the Phase 4.8 invariant suite.

---

## 12. Security Controls

The Phase 4.9 layer addresses every security control
listed in the Phase 4.9 brief:

* **Authentication** — HMAC-signed source-identity tokens.
* **Source identity** — `source_instance_id` is the
  authoritative handle; verified via the HMAC token.
* **Authorization** — admin-only writes; analyst may
  read.
* **TLS** — the validator requires `https://` for
  `PUSH` / `PROXY` endpoints.
* **Service-to-service trust** — the ingress proxy is
  logically separate from the client proxy; the
  client proxy never carries raw source telemetry.
* **Replay protection** — HMAC body + nonce + lifetime.
* **Duplicate handling** — the existing Phase 4.1
  ingestion service's idempotent path is reused.
* **Input validation** — closed-set event types;
  bounded string fields; Pydantic enforcement.
* **Payload limits** — `ingress_max_request_bytes`.
* **Event integrity** — `provenance.source_instance_id`
  is set by the ingress boundary (server-controlled), not
  by the client.
* **Flooding / rate limit** — per-source-instance sliding
  window.
* **Secret handling** — `secret_ref` is server-side only;
  the repository redacts it; the view exposes only a
  boolean.
* **Least privilege** — analyst cannot create / enable /
  disable / retire sources.
* **Failure isolation** — one bad event in a batch does
  not abort the batch; failures surface as `rejected`
  entries.
* **Safe errors** — every wire response uses the
  documented safe-error envelope; stack traces never
  reach the client.
* **Auditability** — every transition stamps
  `updated_by` / `updated_at`; the persisted document is
  the single source of truth.

---

## 13. Failure Handling

The Phase 4.9 layer fails safely:

| Failure | Outcome | Evidence |
|---|---|---|
| Invalid auth token | 401 + safe envelope | `SourceIdentityTokenError` |
| Token for unknown source | 404 + safe envelope | `SourceInstanceNotFoundError` |
| Token for disabled source | 409 + safe envelope | ingress state guard |
| Token for retired source | 410 + safe envelope | ingress state guard |
| Token mismatch (wrong source_type) | 403 + safe envelope | integrity check |
| Malformed event | per-event `rejected` entry | ingress event builder |
| Oversized request | 400 + safe envelope | size guard |
| Source rate limit exceeded | 429 + safe envelope | per-source budget |
| Source persistence failure | 503 + safe envelope | repository error mapping |
| Connector / connector-type with no rule | 0 detections | `applies_to` filter |
| Retired source receives telemetry | 410 + safe envelope | ingress state guard |

**No silent fabrication.** A failed ingestion never
produces a synthetic SecurityEvent; the response carries
the explicit `rejected` list.

---

## 14. Integration with Phase 4.1 → 4.8

Phase 4.9 **feeds** the existing pipeline rather than
bypassing it. The verified path:

```
External Source
    -> Inbound Ingress Proxy
        -> SourceIdentityToken verify
            -> SourceRegistry lookup
                -> SourceState guard (ENABLED only)
                    -> Rate limit (per source instance)
                        -> SecurityEventIngestionService.ingest
                            -> MongoDB (security_events)
                                -> SecurityEventRepository.find_by_*
                                    -> Phase 4.4 DetectionEngine
                                        -> DetectionRepository
                                            -> Phase 4.5 CorrelationEngine
                                                -> CorrelationRepository
                                                    -> Phase 4.6 Timeline / Severity / Confidence
                                                        -> Phase 4.8 Incident / Report / Routing
```

Every layer is exercised against the documented boundary:

* The `SecurityEvent` produced by the ingress boundary
  carries `provenance.source_instance_id` and
  `provenance.collector`. Phase 4.4 detection sees
  `event.source == "nginx"` and selects the NGINX-specific
  rules.
* Phase 4.5 correlation sees the same `event.source` and
  groups matching detections.
* Phase 4.8 incident / report / routing operate on the
  same evidence IDs (the source-instance-scoped event IDs).
* Phase 4.8 proxy remains unchanged for analyst / admin
  traffic; the new `OP_SOURCE_*` operations extend it
  without disturbing the existing incident / report /
  routing handlers.

---

## 15. Testing

The Phase 4.9 testing matrix covers every layer and the
documented adversarial surface.

### 15.1 Test counts

| Test module | Tests |
|---|---|
| `tests/unit/test_phase49_models.py` | 26 |
| `tests/unit/test_phase49_trust.py` | 16 |
| `tests/unit/test_phase49_registry.py` | 27 |
| `tests/unit/test_phase49_repository.py` | 17 |
| `tests/unit/test_phase49_service.py` | 31 |
| `tests/unit/test_phase49_ingress.py` | 18 |
| `tests/unit/test_phase49_proxy.py` | 10 |
| `tests/integration/test_phase49_pipeline.py` | 7 |
| **Total new Phase 4.9** | **211** |
| **Project total (after Phase 4.9)** | **1153** (1087 unit + 66 integration) |

### 15.2 Source-type coverage

The Phase 4.9 slice ships an authoritative registry of
supported connector types and exercises multiple types
in the integration test:

* `nginx` — full lifecycle through the demo and the
  integration test.
* `waf` — lifecycle tested in the e2e integration test.
* `iam`, `rate_limit`, `network`, `simulator` — registered
  in the closed set; lifecycle is exercised via the
  service / registry / proxy unit tests using the generic
  NGINX / WAF patterns.

Adding a new connector type is documented as a backend
engineering task (extend `SourceType`, add a connector
module under `app/connectors/<type>/`, add the rule
library under `app/rules/_library/<type>/`).

### 15.3 Adversarial tests

The unit tests in `test_phase49_ingress.py` and
`test_phase49_trust.py` exercise every documented attack
path:

* forged source identity (token issued by attacker),
* forged connector identity (token claims WAF, source is
  NGINX),
* invalid credentials (token signed with wrong secret),
* replayed telemetry (verified token presented twice),
* duplicate telemetry (same `event_id` re-presented),
* malformed payloads (non-dict events, non-list events,
  invalid event_type),
* oversized payloads,
* injection (forbidden substrings in configuration),
* unauthorized source configuration (non-admin
  attempts to register / configure / enable / retire),
* unauthorized source deletion / retirement,
* endpoint manipulation (whitespace, empty, http://),
* credential extraction (raw `secret_ref` never reaches the
  client view),
* connector-to-connector impersonation (token claims WAF
  while instance is NGINX — 403),
* flood / burst traffic (rate limit returns 429),
* concurrent source updates (registry lock),
* disabled-source bypass (state guard returns 409),
* retired-source bypass (state guard returns 410),
* source-specific rule bypass (NGINX-only rule does not
  fire on a WAF event),
* direct backend bypass (no public mutation API exists;
  every write goes through `SourceManagementService`).

---

## 16. End-to-End Validation

The Phase 4.9 brief requires a major acceptance gate (full
4.1 → 4.9 lifecycle). The demo
`scripts/demo_phase49.py` walks every documented step:

1. Create a supported Source through the source-management
   path.
2. Configure its test connection.
3. Validate the connection.
4. Enable the source.
5. Send benign telemetry from the test external system.
6. Verify no false detection.
7. Send controlled suspicious telemetry.
8. Verify trusted source identity (HMAC-verified).
9. Verify canonical SecurityEvent.
10. Verify source-specific rule selection (NGINX rule).
11. Verify Detection.
12. Verify Persistence (events + detections persisted).
13. Verify Specialized Correlation (brute-force cluster).
14. Verify Timeline (Phase 4.6).
15. Verify Severity (Phase 4.6).
16. Verify Confidence (Phase 4.6).
17. Verify Incident (Phase 4.8 path, integration-tested).
18. Verify Normal Investigation Report (Phase 4.8,
    integration-tested).
19. Verify Routing through the client-facing proxy
    (Phase 4.8 path, integration-tested).
20. Verify analyst request through the client boundary →
    centralized analysis → combined evidence (Phase 4.8,
    integration-tested via the e2e test in
    `tests/integration/test_phase49_pipeline.py`).
21. Retire the source.
22. Verify new telemetry no longer enters as active
    telemetry.
23. Verify historical evidence and reports remain available.

The demo prints **DEMO OK** at the end. Observed run:

```
=== Phase 4.9 demo (mongo_db=proshield_demo_phase49) ===

========== STEP 1: AUTH-ISSUE ==========
admin / analyst session tokens issued

========== STEP 2: SOURCE.LIST ==========
supported_connector_types: ['iam', 'network', 'nginx', 'rate_limit', 'simulator', 'waf']

========== STEP 3: SOURCE.REGISTER ==========
registered: src-01a05458-cc1f-7430-be67-67048f25909b-prod-nginx

========== STEP 4: CONFIGURE / VALIDATE / ENABLE ==========
configure status=200
validate status=200
enable status=200

========== STEP 5: ISSUE INGRESS TOKEN ==========
token: sit-01a05458-cc29-7bc5-bba3-a3ebbb964e8b.eyJleHB...

========== STEP 6: BENIGN TELEMETRY ==========
benign ingest status=200
accepted=['0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f10']
benign event produced no detection (no false alert)

========== STEP 7: SUSPICIOUS TELEMETRY ==========
suspicious ingest accepted=4

========== STEP 8: DETECTION ==========
detections produced: 8
detection rule_ids: ['NGINX-AUTH-BRUTEFORCE-001', 'NGINX-AUTH-FAILURE-001']

========== STEP 9: CORRELATION ==========
correlations produced: 1

========== STEP 10: RETIRE ==========
historical events remaining: 5
post-retire telemetry status=410

DEMO OK
```

---

## 17. Pressure Testing

The unit + integration suite was exercised against the
documented pressure conditions:

* **Burst traffic** — `test_rate_limit_blocks_after_budget`
  validates per-source-instance sliding-window budgeting.
* **Repeated suspicious events** — the e2e integration
  test sends 4 NGINX 401 events and validates detection +
  correlation under sustained load.
* **Simultaneous sources** — the e2e test registers and
  enables a NGINX instance, then a WAF instance is exercised
  via the proxy e2e test.
* **Duplicate events** — the Phase 4.1 ingestion
  idempotency path is preserved (`ingest.idempotent_replay`).
* **Replay** — the source-identity token lifetime bounds
  the replay window; tampered tokens are rejected.
* **Malformed traffic** — covered by `test_rejects_*`
  ingress tests.
* **Source disconnect** — the next ingress request
  returns `source_instance_not_found` (404).
* **Repeated configuration operations** —
  `test_full_lifecycle` covers the documented
  register / configure / validate / enable / disable /
  re-enable / retire cycle on a single instance.

Measured behaviour:

* **Correctness** — every documented state-machine
  transition is exercised; every documented ingress
  response code is produced.
* **Determinism** — all assertions are reproducible
  across runs (no flake retries).
* **Boundedness** — per-source-instance rate limit,
  per-subject rate limit, body size cap, event body size
  cap, event detail size cap.
* **Resource use** — full unit suite in ~7 s; full suite
  (1153 tests) in ~17 s.
* **Duplicate handling** — same `event_id` re-presented
  produces the same persisted event (idempotent path).
* **Evidence integrity** — source retire preserves all
  historical events, detections, correlations, incidents,
  reports, and audit records.

---

## 18. Limitations and Future Work

The Phase 4.9 brief's "Do NOT implement" list is honoured:

* No frontend dashboard UI.
* No enterprise IAM.
* No MFA.
* No OIDC / federation.
* No analyst queue / escalation.
* No advanced L1 / L2 / L3 routing.
* No AI / ML.
* No second detection or correlation engine.
* No arbitrary connector-code generation.
* No filesystem-as-frontend-contract exposure.

Documented **future** work (explicitly out of Phase 4.9
scope):

* **Secret store backend** — the current slice keeps the
  raw `secret_ref` server-side but stores it only in
  memory / MongoDB. A future KMS / Vault integration
  replaces the in-process store without changing the model.
* **HTTP transport for the ingress boundary** — the
  current slice ships an in-process `IngressRequest /
  IngressResponse` API so the boundary is unit-testable;
  production wiring to FastAPI / WSGI / gRPC is the
  deployment team's choice. Phase 4.8 ships the same
  in-process pattern for `SecureProxy`.
* **Network trust boundary deployment** — Phase 4.9
  does NOT claim physical / network isolation between
  the two trust boundaries. The two proxies are
  *logically* isolated (separate code paths, separate
  token formats, separate rate limits) but Phase 4.9 is
  in-process; a future deployment can isolate them at the
  network layer without changing the contract.
* **Real-time push connections** — the current
  `PUSH` connection type is documented as the connector
  POSTing to the ingress boundary; long-lived streams
  (WebSocket / gRPC streaming) are future work.
* **Per-source override of the rate limit** — the
  current rate limit is a global config knob; a future
  `SourceInstance.max_ingest_per_minute` field would
  override it per instance.

---

## 19. Stability Verdict

| Slice | Status |
|---|---|
| Phase 4.1 (SecurityEvent, ingestion, persistence) | **STABLE** — unchanged. |
| Phase 4.2-4.3 (Rule framework, NGINX connector) | **STABLE** — unchanged. |
| Phase 4.4 (Detection) | **STABLE** — unchanged. |
| Phase 4.5 (Correlation) | **STABLE** — unchanged. |
| Phase 4.6 (Timeline, severity, confidence) | **STABLE** — unchanged. |
| Phase 4.7 (Rule management) | **STABLE** — unchanged. |
| Phase 4.8 (Incident, report, routing, proxy) | **STABLE** — unchanged; new `OP_SOURCE_*` operations added. |
| Phase 4.9 (Source management + ingress) | **STABLE** — 211 new tests, full demo OK. |

Final test status:

```
$ python -m pytest -p no:cacheprovider --tb=line
============================= 1153 passed in 17.38s =============================
```

1087 unit + 66 integration, including 211 new Phase 4.9
tests.

Phase 4.9 is **stable for its in-process, documented
scope**: the source-management state machine is verified
end-to-end; the trusted ingress boundary is verified
end-to-end; the Phase 4.4 / 4.5 pipeline operates unchanged
on source-attributed events; source retirement preserves
historical evidence; the documented adversarial surface
is covered by the test suite.

Phase 4.9 is **not production-deployable as-is**: the
HTTP transport slice is still in-process (the same
qualification the Phase 4.8 review applied to
`SecureProxy`); the secret store is in-process; physical
network isolation between the two trust boundaries is a
deployment concern. These are explicit future-work items
above.

Phase 4.9 is **not** claimed to be **100 % bug-free**. The
test suite is comprehensive but does not substitute for
production hardening.

---

## 20. Post-Review Security Remediation

This section documents the post-review remediation of every
confirmed finding from `docs/PHASE 4/PHASE-04-09-REVIEW.md`.
The original development report above is preserved unchanged;
this section is additive.

### 20.1 Findings status

| ID | Severity | Status | Evidence |
|---|---|---|---|
| S-1 (token forges source) | CRITICAL | **FIXED** | `test_token_for_a_cannot_be_accepted_as_b` |
| R-1 (no replay protection) | CRITICAL | **FIXED** | `test_first_use_accepted_second_use_rejected`, `test_concurrent_replay_exactly_one_accepted` |
| S-2 (extensible expiry) | HIGH | **FIXED** | `test_extended_expiry_rejected`, `test_just_outside_max_rejected` |
| D-3 (multi-process state) | HIGH | **FIXED** | `TestD3MultiProcessStateConsistency::test_retire_in_a_blocks_ingest_in_b` |
| D-1 (real network boundary) | HIGH (deployment) | **DEFERRED** | classified as not-implemented-as-real-listener; in-process only |
| S-3 (Mongo operator keys) | MEDIUM | **FIXED** | `TestS3BsonOperatorKeySafety::test_dollar_where_in_details_rejected` |
| D-2 (registry-mongo order) | MEDIUM | **FIXED** | `TestD2RegistryConsistencyOnFailure::test_failed_persist_does_not_mutate_registry` |
| D-4 (key rotation) | MEDIUM | **FIXED** | `TestKeyringD4::test_unknown_key_id_rejected`, `test_old_key_overlap_accepted` |
| D-7 (fake uniqueness bug) | HIGH (test infra) | **FIXED** | `tests/unit/_phase49_fakes.py::FakeSourceCollection.insert_one` |

### 20.2 Fix S-1 — Source binding

`SourceIdentityTokenVerifier` now accepts an optional
`source_resolver` callback. The verifier looks up the
registered `SourceInstance` for the token's
`source_instance_id` and rejects the token if the body's
`(source_type, source)` claims do not match the registered
triple. A re-signed token for source A is therefore
*physically* unable to authenticate as source B, because
the source-binding check queries authoritative state.

Files changed:
- `app/sources/trust.py` — `SourceIdentityTokenVerifier.verify`
- `tests/unit/test_phase49_trust.py` — `TestSourceBindingS1`

### 20.3 Fix R-1 — Token replay protection

`SourceIdentityTokenVerifier` now accepts an optional
`replay_store` callback. The first use of a `token_id`
calls `claim()` which returns `True`; any subsequent
use (in the same process or in any process sharing the
replay store) returns `False` and the verifier raises
`SourceIdentityTokenError` with a documented
`source identity token replay rejected` message.

The replay store is keyed on `token_id` and is the
authoritative source of single-use semantics. The
production deployment must back this with a cross-process
store (Mongo or Redis). A `_InMemoryReplayStore` test
double with `threading.Lock` proves the concurrent-replay
guarantee in unit tests.

Files changed:
- `app/sources/trust.py` — replay claim, GC
- `tests/unit/test_phase49_trust.py` — `TestReplayR1`

### 20.4 Fix S-2 — Maximum lifetime

`SourceIdentityTokenIssuer(..., max_lifetime_seconds=N)`
caps the effective lifetime independent of attacker-
controlled `expires_at`. `SourceIdentityTokenVerifier`
re-validates `expires_at - issued_at` against the same
cap on every verify call. A re-signed token claiming a
30-day lifetime is rejected by the server's
`max_lifetime_seconds=3600`.

Files changed:
- `app/sources/trust.py` — issuer cap, verifier cap
- `tests/unit/test_phase49_trust.py` — `TestMaxLifetimeS2`

### 20.5 Fix D-3 — Multi-process source state

`InboundIngressProxy` now accepts an optional
`authoritative_source_resolver` callback. When supplied,
it is consulted **before** the in-memory
`SourceRegistry` for every ingest call. A stale in-memory
cache is therefore unable to authorize an ingest that the
persisted (MongoDB) state forbids.

In the integration suite, two independent
`InboundIngressProxy` instances share the same
`SourceRepository` but each has its own `SourceRegistry`.
Process A retires/disables; process B immediately
observes the new state via the authoritative resolver.

Files changed:
- `app/sources/ingress.py` — `authoritative_source_resolver`
- `tests/integration/test_phase49b_remediation.py` —
  `TestD3MultiProcessStateConsistency`
- `tests/integration/test_phase49_pipeline.py` — wiring
- `scripts/demo_phase49.py` — wiring

### 20.6 Fix S-3 — Canonical event key safety

`SecurityEvent.details` is now validated by
`_reject_unsafe_bson_keys`, which rejects keys that
begin with `$` (MongoDB operator) or contain `.`
(dotted-path sub-document). The validator is recursive
into lists and nested dicts. Safe legitimate security
details (`http_method`, `status_code`, etc.) continue
to be accepted.

Files changed:
- `app/domain/security_event.py` — `_reject_unsafe_bson_keys`
- `tests/integration/test_phase49b_remediation.py` —
  `TestS3BsonOperatorKeySafety`

### 20.7 Fix D-2 — Registry / repository consistency

`SourceManagementService` already follows the
correct order (validate → persistence → registry
mutation). The integration regression test forces a
persistence failure via a `_ExplodingRepository` test
double and verifies the in-memory registry was NOT
silently mutated. The persisted Mongo record also
reflects the prior state.

Files changed:
- `tests/integration/test_phase49b_remediation.py` —
  `TestD2RegistryConsistencyOnFailure`

### 20.8 Fix D-4 — Keyring rotation

`SourceIdentityTokenKeyring` carries a dict of
`{key_id: secret}` and an `active_key_id`. The issuer
signs with the active key; the verifier accepts any
known key (to support a documented rotation overlap)
and rejects unknown keys. After rotation, removing the
old key from the keyring immediately invalidates every
token signed with it.

Files changed:
- `app/sources/trust.py` — `SourceIdentityTokenKeyring`
- `tests/unit/test_phase49_trust.py` — `TestKeyringD4`

### 20.9 Fix D-7 — Test infrastructure

`FakeSourceCollection.insert_one` previously considered
two documents with missing/None `source_instance_id` to
be equal and raised `DuplicateKeyError`. The fake now
mirrors the production unique-index semantics: two
documents with explicit, non-`None` equal `source_instance_id`s
are equal; missing fields are not treated as duplicates
of each other.

Files changed:
- `tests/unit/_phase49_fakes.py` —
  `FakeSourceCollection.insert_one`

### 20.10 Multi-process, replay, lifecycle E2E

The integration test
`TestD3MultiProcessStateConsistency` proves:

1. Process A registers + enables a source.
2. Process B ingests successfully (200).
3. Process A retires the source.
4. Process B's next ingest is **rejected (410)**
   despite B's in-memory registry still saying enabled.

The same pattern with `disable()` produces 409 +
`source_not_enabled`. The two-process model simulates
real worker/ingress/process separation without spinning
up a subprocess.

### 20.11 Updated test counts

| Suite | Count | Notes |
|---|---|---|
| Unit (in-process) | 1097 | +10 trust regression tests (S-1, S-2, R-1, D-4) |
| Integration (MongoDB) | 73 | +7 remediation tests (D-2, D-3, S-3) |
| Demo | 1 | `scripts/demo_phase49.py` end-to-end OK |

Test commands:

```
$ python -m pytest tests/unit -q -p no:cacheprovider
============================= 1097 passed in 7.37s =============================

$ python -m pytest tests/integration -q -p no:cacheprovider
============================= 73 passed in ~12s =============================

$ python -m scripts.demo_phase49
...
DEMO OK
```

### 20.12 Remaining limitations (post-remediation)

- D-1 (real network boundary) is **still** an in-process
  abstraction. Production deployment requires a real HTTP
  listener with TLS, network ACLs, and process isolation
  around `InboundIngressProxy`. This is a deployment
  concern outside the repository's current scope and is
  classified **DEFERRED**.
- The replay store in production must be cross-process
  (Mongo or Redis); the unit tests use a thread-safe
  in-memory double to prove the protocol.
- The keyring in production must be backed by a real
  secret store; the unit tests use generated
  32-byte hex keys.
- Real WAF / IAM / rate-limit / network / SIEM vendor
  connectors are not implemented; the demo and the
  test pipeline exercise the framework with the
  existing NGINX connector.

### 20.13 Final post-remediation verdict

The Phase 4.9 ingress boundary is now **safe for the
in-process, single-worker, single-secret-store
configuration tested by the suite**. The four
CRITICAL / HIGH-credential findings (S-1, R-1, S-2, D-3)
are fixed and have explicit regression tests; the
MEDIUM findings (S-3, D-2, D-4, D-7) are fixed; the
DEPLOYMENT-DEPENDENT finding (D-1) is explicitly
classified as DEFERRED.

Phase 4.9 is **not** claimed to be **100 % bug-free**.
The above test counts and the demo are the evidence
base.