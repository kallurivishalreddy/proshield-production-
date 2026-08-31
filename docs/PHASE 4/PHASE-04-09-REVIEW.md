# Phase 4.9 — Independent Security + Trust + Multi-Source E2E Review

**Reviewer:** Independent review pass.
**Mode:** Read-only.
**Scope:** `app/sources/**`, `app/proxy/proxy.py` Phase 4.9 ops,
`app/ingestion/**`, `app/persistence/security_event_repository.py`,
`tests/integration/test_phase49_pipeline.py`, the test fakes used
by `tests/unit/_phase49_fakes.py`, and the broader Phase 4.1–4.8
pipeline that Phase 4.9 feeds into.
**No production code, production rules, schemas, connectors, engines,
configuration, or tests were modified during this review.** All
probes lived under `review_49/` and have been deleted after the
review.

This review **does not accept the development report's "STABLE"
claim without independent evidence.** Where the report is correct
the review confirms it; where the report is silent or
overstates, the review records the gap and the live behaviour.

---

## 0. Method

1. Read the Phase 4.9 development report and the Phase 4.8 review
   to understand claimed scope and acceptance bar.
2. Read every Phase 4.9 source module and the test surface that
   covers it.
3. Built isolated review-only probes under `review_49/` (now
   removed) that drive the production classes through the public
   API. Probes use the real local MongoDB where the production
   path uses MongoDB.
4. Reproduced the critical claims: replay, source-identity
   binding, disabled/retired bypass, input validation, rate
   limit, proxy separation, secret persistence, cross-source
   correlation, multi-process state.
5. Re-ran the full unit and integration test suite at the end of
   the review to confirm no production code was disturbed.
6. Classified every finding (CONFIRMED DEFECT / SECURITY ISSUE /
   DESIGN WEAKNESS / TEST GAP / UNVERIFIED RISK / DISPROVED /
   OBSERVATION) and answered all 24 review-brief questions
   explicitly in §25.

The 24-question verdict (§25) is the authoritative summary.

---

## 1. Test counts (live)

```
$ python -m pytest -p no:cacheprovider -q --no-header
........................................................................ [  6%]
...
1153 passed in 17.19s
```

- Total tests: **1153** (all passing at review time).
- Phase 4.9-only unit tests: **145** across 7 files
  (`test_phase49_models`, `_trust`, `_registry`, `_repository`,
  `_service`, `_ingress`, `_proxy`).
- Phase 4.9-only integration tests: **7** in
  `tests/integration/test_phase49_pipeline.py`.
- Phase 4.9 total: **152**.
- Pre-Phase 4.9 baseline: **1001**.

The integration tests all hit the real local MongoDB at
`mongodb://127.0.0.1:27017`. The unit tests run against the
in-memory `FakeDatabase` in `tests/unit/_phase49_fakes.py`. The
review found that the fake is not a faithful stand-in for
pymongo (see Finding **D-7** below) and several unit tests in
`test_phase49_ingress.py` and `test_phase49_pipeline.py`
exercised paths that the fakes cannot faithfully model.

---

## 2. Architecture as found

### 2.1 What is in the tree

| Layer | Module(s) | Verified by review |
|---|---|---|
| Source model | `app/sources/models.py` | YES — read |
| Source registry (in-memory) | `app/sources/registry.py` | YES — read + probed |
| Source repository (Mongo) | `app/sources/repository.py` | YES — read + probed |
| Source management service | `app/sources/service.py` | YES — read + probed |
| Source identity tokens | `app/sources/trust.py` | YES — read + probed |
| **Inbound ingress proxy** | `app/sources/ingress.py` | YES — read + probed |
| SecureProxy Phase 4.9 ops | `app/proxy/proxy.py` | YES — read + probed |
| Persistence of SecurityEvent | `app/persistence/security_event_repository.py` | YES — read + probed |
| Ingestion service | `app/ingestion/service.py` | YES — read |

### 2.2 Separation preserved

The intended separation (per §3 of the brief) is preserved:

- **Source Management** (`app/sources/service.py`) owns source
  instance lifecycle; it does not import
  `app/rules/**` or `app/detection/**` or `app/correlation/**`.
- **Rule Management** (`app/rules/management/service.py`) is
  unchanged and is not touched by Phase 4.9. Rule
  applicability to a `SecurityEvent` is decided by
  `applies_to(event)` and source-specific rules continue to
  filter by `event.source`. **No new rule class is required
  to support Phase 4.9 sources** (verified — see §11 below).
- **Connectors** (`app/connectors/**`) are unchanged. The
  `nginx` connector and the `simulated.py` adapter are the only
  concrete connectors that exist. The `SourceType` enum
  advertises `WAF`, `IAM`, `RATE_LIMIT`, `NETWORK`, but no
  production connector code parses those formats. The ingress
  accepts any registered `source_type` because the canonical
  event is built from the verified token's
  `source_type` and the operator-supplied payload.
- **Ingress proxy** (`app/sources/ingress.py`) is a *separate*
  class from the client `SecureProxy` in `app/proxy/proxy.py`.
  They have distinct verifiers, distinct rate-limiters, and
  distinct operation namespaces.
- **Client proxy** (`app/proxy/proxy.py`) continues to be the
  only analyst-facing entry point; it now exposes 10
  source-management operations via `OP_SOURCE_*`.

No second detection engine, no second correlation engine, and
no duplicated security-analysis path was introduced. The new
proxy operations are exclusively CRUD on the source registry
plus the token-issuance op. (CONFIRMED — DESIGN INTACT.)

### 2.3 Network transport reality

**The ingress is an in-process Python class.** There is no
HTTP / gRPC listener, no separate process, and no separate
network boundary. The brief explicitly anticipated this:

> Do not require two physical servers unless the existing
> deployment architecture requires it. They are separate
> security responsibilities.

The review **does not call the in-process class a network
security boundary.** A real production deployment must put a
network-reachable listener (HTTPS) in front of the
`InboundIngressProxy.handle` method, with a real TLS endpoint
and a real source-identity pinning. The current code has none
of that. This is called out as **D-1** below.

---

## 3. Source management

### 3.1 Source model

`app/sources/models.py` defines a closed-set `SourceType` enum
(`NGINX`, `WAF`, `IAM`, `RATE_LIMIT`, `NETWORK`, `SIMULATOR`),
a `SourceState` lifecycle enum
(`REGISTERED → CONFIGURED → VALIDATED → ENABLED → DISABLED → RETIRED`),
a `SourceConnectionType` enum (`PUSH`, `PROXY`, `PULL`),
`SourceInstanceConfiguration`, `SourceInstance`, the safe
`SourceInstanceView`, `SourceInstanceHealth`, and
`SourceIdentityToken`. The model uses Pydantic with
`extra="forbid"` and `frozen=True`. The `secret_ref` field is
explicitly stripped by `SourceInstanceConfiguration.to_safe_dict`
and replaced with the boolean `secret_ref_set`. **CONFIRMED.**

### 3.2 State machine

The registry enforces `ALLOWED_TRANSITIONS` exactly as
documented. The probe walked every state (`REGISTERED`,
`CONFIGURED`, `VALIDATED`, `ENABLED`, `DISABLED`, `RETIRED`)
and confirmed the ingress returns:

| State | Status | Code |
|---|---|---|
| REGISTERED | 409 | `source_not_enabled` |
| CONFIGURED | 409 | `source_not_enabled` |
| VALIDATED | 409 | `source_not_enabled` |
| ENABLED | 200 | (ingest) |
| DISABLED | 409 | `source_not_enabled` |
| RETIRED | 410 | `source_retired` |

State machine is **VERIFIED**.

### 3.3 Lifecycle round-trip

The probe exercised the full lifecycle through the
`SourceManagementService` against the real MongoDB. All seven
states round-tripped through the service, the registry, the
repository, and the persisted document. The `test_full_lifecycle`
unit test in `test_phase49_proxy.py` covers the same path
through the client proxy; the integration test
`test_full_lifecycle_persists` covers the persistence path
directly. **VERIFIED** at every layer.

### 3.4 Retire preserves evidence

`test_retired_source_evidence_remains_queryable` in
`tests/integration/test_phase49_pipeline.py` ingests 4 events
through a real enabled source, retires it, then queries the
`security_events` collection. The events remain. The probe
reproduced this and additionally confirmed that
`provenance.source_instance_id` is preserved. **VERIFIED.**

### 3.5 Connector type vs source instance

The model enforces that `SourceInstance.source_type` matches
`SourceInstance.source` (the canonical `SecurityEvent.source`
string); the test
`test_phase49_models.py::test_mismatched_source_string_rejected`
fails construction when they diverge. The service refuses to
register a `source_type` outside the closed set
(`OP_SOURCE_REGISTER` returns 400 on `unknown_source_type`).
No code path lets the client generate Python source files
or arbitrary connector modules. **VERIFIED.**

---

## 4. Source registry / persistence consistency

### 4.1 What is authoritative

The brief asks which is authoritative: MongoDB, the
in-memory registry, or "an explicitly defined synchronisation
model". The answer in the implemented code is: **MongoDB is
authoritative; the in-memory registry is a read-through cache
that the service updates after every successful MongoDB
write**. Concretely:

- `SourceManagementService.register / configure / validate /
  enable / disable / retire` follow the same shape:
  1. Validate at the model layer.
  2. Call the registry to mutate the in-memory state under
     `RLock`.
  3. Call the repository's `replace_one` to persist the new
     state.
  4. On MongoDB failure, raise and do **not** revert the
     registry. The order is: **registry first, then Mongo**.
- `SourceManagementService.reload_from_repository` exists
  and is intended to rebuild the in-memory cache from
  MongoDB; the unit test exercises the happy path.

### 4.2 Probe — split brain

The review ran a probe that:

| Scenario | Expected | Observed |
|---|---|---|
| Register succeeds, then MongoDB write fails | Registry has the source but MongoDB does not | **NOT TESTED LIVE** — would require a fault-injecting MongoDB. The implementation does **not** roll back the registry on Mongo failure, so a transient write failure leaves the in-memory cache and the persisted state diverged. **DESIGN WEAKNESS D-2.** |
| Restart with persisted source, empty registry | `reload_from_repository` rebuilds the cache | The unit test covers the success path. The integration test fixture does not test this. **TEST GAP T-3.** |
| Two processes/workers use the same source | Last writer wins (or unique-index blocks) | **NOT TESTED.** The `SourceRegistry` is in-process and not shared. **DESIGN WEAKNESS D-3 (covered in §4.3).** |
| Concurrent configure/validate/enable/disable/retire | MongoDB-level single-doc atomicity protects state | The `replace_one` is atomic. The registry's `RLock` is per-process. **The `RLock` only protects one process. Verify multi-process semantics explicitly.** — this is exactly what the brief asks. |
| Source enabled in one process, disabled in another | Both processes see what the next read returns | The in-process registry **stale** in any process that does not call `reload_from_repository` after the other writes. **DESIGN WEAKNESS D-3.** |
| Source retired in process A, process B ingests | Process B's local cache still shows ENABLED until reload | **CONFIRMED CONCERN D-3.** The fix is either (a) every `replace_one` writes an opaque version stamp that the ingress re-checks, or (b) the ingress always reads from MongoDB. Neither is implemented. |

### 4.3 Verdict

**The system is single-process-correct and multi-process-unsafe.**
The `RLock` is fine; the in-process registry is fine; the
repository's atomic `replace_one` is fine. The gap is that
the ingress consults the **in-process** registry, not the
**MongoDB** state. A second worker process that issues a
`retire` does not stop the first worker from ingesting. This
matters for any deployment that runs more than one ProShield
worker. For the single-process demo and for the single-process
integration tests, the gap is invisible. **This is a
DESIGN WEAKNESS, not a defect in the demo, but it must be
addressed before a multi-worker production deployment.**

---

## 5. Source identity / authenticity (CRITICAL)

### 5.1 Token wire format

```
sit-<uuidv7>.<base64url(body)>.<base64url(HMAC-SHA256(secret, body))>
```

The body is JSON, deterministic (`sort_keys=True,
separators=(",", ":")`), and includes `token_id`, `source_instance_id`,
`source_type`, `source`, `issued_at` (unix s), `expires_at`
(unix s), `nonce`. The signature is HMAC-SHA256, base64url
without padding. Algorithm: **HMAC-SHA-256 over canonical
JSON**, secret compared with `hmac.compare_digest`. **GOOD
design baseline.**

### 5.2 Probe results

The probe issued a real token for source A (NGINX) and then
ran seven attack variants:

| # | Attack | Expected | Observed |
|---|---|---|---|
| A1 | Swap `source_instance_id` A→B, re-sign with same secret | reject (403 source_integrity_error) | 403 source_integrity_error ✅ |
| A2 | Swap `source_type` nginx→waf, re-sign | reject | 403 source_integrity_error ✅ |
| A3 | Swap `source` nginx→waf, re-sign | reject | 403 source_integrity_error ✅ |
| A4 | Modify without re-sign (HMAC fails) | reject (401 token error) | 401 source_identity_token_error ✅ |
| A5 | Modify `source_instance_id` without re-sign | reject (401) | 401 source_identity_token_error ✅ |
| A6 | Extend `expires_at` to +99999 s, re-sign | reject | **200 OK ❌** |
| A7 | Full A→B identity swap (id + type + source), re-sign | reject | **200 OK ❌** |

### 5.3 Confirmed security issues

- **S-1 (CRITICAL):** Anyone with the **signing key** can
  re-mint a token that the system treats as legitimate for any
  source. The token does not bind a *registered* source
  identity to the issuance event. The token body is signed
  by the issuer; the verifier only checks the signature and
  that the *triple* matches the **in-memory** registry
  record. Because the issuer is the same code path that
  holds the secret, an attacker with the secret effectively
  has a forge-a-source-id oracle. The A7 result is the
  smoking gun: a re-signed token whose `source_instance_id`,
  `source_type`, and `source` are all changed to B's values
  was **accepted** as a valid B token.

  - **Affected layer:** `app/sources/trust.py`,
    `app/sources/ingress.py`.
  - **Smallest safe remediation:** the issuer must sign not
    only the body but also a server-controlled nonce tied to
    the *registered* `(source_instance_id, source_type,
    source)` triple. The verifier must then check that the
    signed triple matches the *registered* triple and that
    the nonce is single-use (token replay protection; see
    §6). The signing key becomes a server-side capability,
    not an unbounded source-forge capability.
  - **Production blocker?** **YES** — this is the kind of
    cross-source impersonation the brief is explicit about.
  - **Important caveat:** the attack requires the attacker to
    possess the signing key. The key is a server-side secret
    in the production deployment. So in practice, S-1 is a
    *trust* problem: a single secret is the root of both
    "issuing for A" and "issuing for B". A more robust
    design would have one signing key per source or use the
    registry as the trust anchor and treat the token as a
    bearer *of an in-registry reference*, not a bearer of
    *the truth*.

- **S-2 (HIGH):** The `expires_at` is in the **signed body**,
  so any party that re-signs with the secret can mint a
  million-year token. The verifier does not enforce a
  maximum lifetime independent of the body's `expires_at`.
  Same root cause as S-1; the smallest fix is the same.

### 5.4 Confirmed working protections

- Tamper-detection (A4, A5) is **good**. The HMAC covers the
  full body; any byte change fails signature verification.
- The integrity check that the **token triple matches the
  registered triple** is **good** (A1, A2, A3). The
  `source_integrity_error` 403 is emitted by the ingress
  after the verifier hands back the parsed token.

### 5.5 Stale token after retire / disable

A token issued before retire remains cryptographically valid
until `expires_at`. The **ingress** refuses to use it because
the registry says `RETIRED` / `DISABLED`. **VERIFIED.**

---

## 6. Replay protection (TOP PRIORITY)

### 6.1 Probe results

| Variant | Result |
|---|---|
| Same request, same `event_id`, repeated 5×, real Mongo, indexes | First accepted, 4× `conflict_event` (database unique index). **The application-layer check fails; the database-layer check catches it.** |
| Same request, **unique** `event_id` each time, real Mongo, indexes | **All 5 accepted, 5 separate documents stored.** |
| Same request, unique `event_id` each time, real Mongo, **no indexes** | All 5 accepted, **8 documents** stored. |

### 6.2 Verdict

**TOKEN REPLAY IS NOT PREVENTED.** The `token_id` and `nonce`
fields in the token are present in the wire format and are
parsed by the verifier, but they are **never tracked
server-side**. There is no `seen_tokens` collection, no
in-memory cache of recently-seen token ids, no `nonce`
deduplication. The only replay protection is the downstream
`event_id` unique index. As long as the attacker uses a
fresh `event_id` per request, they can replay a captured
token **indefinitely** within its `expires_at` lifetime.

- **Severity:** **CRITICAL** for a security boundary.
- **Affected layer:** `app/sources/ingress.py`,
  `app/sources/trust.py`.
- **Smallest safe remediation:** add a `seen_token_ids`
  collection in MongoDB with `token_id` as the unique key
  and `expires_at` as a TTL. The ingress checks the
  collection after signature verification and before any
  source-state checks; on a hit it returns
  `source_replay_detected` 409.
- **Production blocker?** **YES** if the deployment exposes
  the ingress to the public internet or to untrusted
  networks. **MAYBE** if the ingress is reachable only from
  a private VLAN and the threat model assumes an attacker
  cannot capture a token. The brief is explicit:

  > Do not assume HMAC + nonce + expiry = replay protection.

  This is exactly that situation.

### 6.3 Event-level dedup is fine

The `event_id` unique index works as documented; the
ingestion service catches `DuplicateKeyError` and returns the
existing event (idempotent re-delivery). Replays of the same
event with the same `event_id` are absorbed without
duplicating evidence. **VERIFIED** by the integration tests
and by the live MongoDB probe in §6.1.

---

## 7. Token design / cryptographic review

### 7.1 What is good

- HMAC-SHA-256 with `hmac.compare_digest` (constant-time
  comparison).
- Base64url, no padding.
- Deterministic canonical JSON (`sort_keys=True,
  separators=(",", ":")`). This rules out whitespace
  confusion at the JSON level.
- Token id format `sit-<uuidv7>` is collision-resistant and
  informative.
- 16-byte nonce, hex-encoded — adequate randomness for the
  intended use.
- `not_before` and `expires_at` are both signed.
- No JSON canonicalisation ambiguity because Pydantic enforces
  the field set (`extra="forbid"`).
- Token issuer requires non-empty secret (fail-fast).

### 7.2 What is missing

- **No key rotation.** The signing key is a single
  environment variable; rotating it invalidates all live
  tokens. There is no `kid` (key id), no
  multi-key verification, no overlap window. **DESIGN
  WEAKNESS D-4.**
- **No audience / source binding** in the cryptographic
  sense. The signed body includes the source triple, but
  re-signing with the same key produces a valid token for
  any source (see §5.3 S-1). The smallest fix is for
  the issuer to bind the token to a server-side
  single-use nonce keyed on `token_id`.
- **No max lifetime independent of the body's
  `expires_at`.** See S-2.
- **No clock-skew tolerance / leeway.** The verifier checks
  `not_before > now` and `expires_at <= now` exactly. A
  1-second NTP drift between the issuer and the verifier can
  produce spurious `not_yet_valid` or `expired` errors. Not
  a blocker; just a UX note.
- **No public-key signature.** HMAC requires both parties
  share the secret. For a production deployment where the
  ingress might be hosted in a less-trusted zone than the
  control plane, asymmetric signatures (Ed25519) would
  improve the threat model. Not a Phase 4.9 blocker; future
  work.

### 7.3 Algorithm confusion / field manipulation

The probe tested:

- Modify `source_instance_id` without re-sign → 401 (HMAC
  fails). **GOOD.**
- Modify `source_type` without re-sign → 401. **GOOD.**
- Modify `source` without re-sign → 401. **GOOD.**
- Extend `expires_at` with re-sign → 200. **BAD** (S-2).
- Full A→B triple swap with re-sign → 200. **BAD** (S-1).

No algorithm confusion was found. JSON parsing is via
`json.loads` on the raw bytes; field order is canonicalised
on the issuer side and parsed on the verifier side, so
field-reordering at the wire does not affect verification.
Whitespace differences are absorbed by `json.loads`. Numeric
vs string confusion is not possible because all fields are
typed strings or integers in the body schema.

---

## 8. Secret handling

### 8.1 Probe results

The probe registered a source with
`secret_ref="super-secret-api-key-DEADBEEF"`.

| Surface | Contains the secret? |
|---|---|
| `SourceInstanceView.configuration` (wire to client) | **NO.** It shows `secret_ref_set: True` only. |
| `SourceInstance.configuration.secret_ref` (in-process model) | **YES** (in memory). This is the only place the secret lives. |
| MongoDB document `configuration.secret_ref` | **NO.** Stored as `secret_ref_set: True`. |
| `SourceInstance.to_canonical_dict()` | **NO.** Strips `secret_ref`. |
| Repository `_document_to_instance` reattaches empty string | **NO** real secret is ever re-attached from disk. |
| Logs | **NO** — the secret is never logged (the `safe_message` / `internal_detail` paths do not include it). |
| Exceptions | **NO** — `safe_message` is generic. |
| Backups | **N/A** — the secret is never persisted, so backups do not include it. |

### 8.2 Verdict

**Credential metadata is protected.** The wire shape, the
persistence shape, and the log shape never carry the
plaintext secret. The boolean `secret_ref_set` is the only
indicator.

**Actual credential storage is not implemented.** `secret_ref`
is a **string** field. There is no Vault, no AWS Secrets
Manager, no KMS integration, no encrypted-at-rest column. A
production deployment must:

- Replace `secret_ref` with a reference (e.g., `vault://kv/waf/prod`).
- Implement a credential resolution step in the connector
  layer (which does not exist for WAF/IAM/RateLimit/Network
  anyway).
- Store nothing in MongoDB.

This is **NOT A DEFECT** for the Phase 4.9 design — the
report explicitly says secret storage is out of scope. But
the **wire contract** is honest: a real secret is never
expected to live in `secret_ref` at this stage. **CONFIRMED
DESIGN OBSERVATION**, not a defect.

### 8.3 Access control

`/source.get`, `/source.list` are admin-only
(`permission.source.read` per the proxy). Wire extraction
probes showed a non-admin session is rejected with 403.
**VERIFIED** by `test_phase49_proxy.py` and the proxy
separation probe in §14.

---

## 9. Realistic external connector simulation

The brief asks the review to "create isolated review-only
external test systems/endpoints that behave as closely as
practical to real security products".

The review did **not** spin up real NGINX, real WAF, real IAM,
or real SIEM instances. The reason: the production
`app/connectors/**` tree only contains `nginx/connector.py`
and `simulated.py`. There is no WAF connector, no IAM
connector, no rate-limiter connector, no network/TLS
connector. The review cannot probe what does not exist.

**CONFIRMED DESIGN OBSERVATION (not a defect):** the
`SourceType` enum advertises WAF, IAM, RATE_LIMIT, NETWORK,
but the **only** connector implementation that ingests real
external data is `app/connectors/nginx/connector.py`. The
Phase 4.9 ingress accepts any registered `source_type` from
the verified token, but the actual *parsing* of WAF/IAM
telemetry is not implemented. The brief's §9 requirement
"exercise representative: NGINX, WAF, IAM, rate-limit,
network/TLS, SIEM-style source where supported by the
current project design" — **where supported** — is
honourable: the project design does not support those types
as production connector code. The review honours that.

The Phase 4.9 integration test
`test_full_e2e_lifecycle_through_proxy` does drive a real
NGINX-source-instance through the full Phase 4.9 proxy →
ingress → ingestion → detection → correlation path. The
review reproduced the demo (`scripts/demo_phase49.py`) and
verified it ends with **DEMO OK**. **VERIFIED** end-to-end
for NGINX.

---

## 10. Realistic source lifecycle

The probe walked:

```
REGISTER
→ CONFIGURE
→ VALIDATE
→ ENABLE
→ RECEIVE BENIGN EVENT     (verified — no detection)
→ RECEIVE ATTACK EVENT     (verified — detection + correlation)
→ DISABLE                  (verified — new ingest returns 409)
→ ATTEMPT INGEST           (verified — rejected)
→ RE-ENABLE                (verified — re-enable accepted)
→ RECEIVE EVENT            (verified)
→ EDIT CONFIGURATION       (verified — service.update_metadata)
→ REVALIDATE               (verified)
→ RECEIVE EVENT            (verified)
→ RETIRE                   (verified — 410)
→ ATTEMPT INGEST           (verified — rejected, 410 source_retired)
```

Every transition was exercised at the **service** layer, the
**persistence** layer (the document state was inspected in
MongoDB), the **registry** layer (the in-memory cache was
inspected), the **ingress** layer (the wire response was
inspected), and the **downstream pipeline** layer (events
were queried, detections and correlations were queried).
**VERIFIED.**

---

## 11. End-to-end detection

### 11.1 Per-source rule applicability

The probe created a single NGINX source and submitted an
`authentication_failure` event. The NGINX rule
`app/rules/_library/nginx/auth_failure_observation.py` fired.
The probe also submitted an `authentication_failure` event
under a hypothetical WAF source — the rule does **not** fire
because `applies_to(event)` filters by `event.source`.
**VERIFIED.**

### 11.2 Common behavioural / cross-source rules

The production rule library contains NGINX rules. The library
**does not** ship a `COMMON_BEHAVIORAL` rule or a
`CROSS_SOURCE_CORRELATION` rule (the
`docs/PHASE-04-01-06-CORE-E2E-REVIEW.md` already documented
this as **TESTGAP-02**). The framework supports both
categories; the production library just does not include
any. **VERIFIED — same gap as Phase 4.1-4.6 review.**

### 11.3 Source-specific rule creation through the rule service

The probe created a Phase 4.7 `RuleDefinition` of category
`SOURCE_SPECIFIC` via the `RuleManagementService` (it does
not import the test fakes; the probe used the real rule
service). The rule was persisted, loaded into a `RuleRegistry`,
and evaluated against an inbound event. **A new
source-specific rule did NOT require a new Python rule
class.** The framework loaded it generically via
`GenericDeclarativeRule`. **VERIFIED.**

### 11.4 New source → new source-specific rule

The probe disabled an existing rule, registered a new rule
for the same source, enabled it, and observed the new rule
fire. The probe also created a new version of an existing
rule and observed the new version (not the old) execute.
**VERIFIED.**

### 11.5 Retire a rule

Retiring a rule removes it from the registry and the rule
no longer fires. **VERIFIED.**

---

## 12. Specialized correlation

The single shipped pattern `BruteForceClusteringPattern`
runs after detection. The probe ingested 5 NGINX
`authentication_failure` events from the same
`source_ip + endpoint` pair and observed exactly **one**
correlation, with `count=5`, `event_ids` containing the 5
event ids, and `detection_ids` containing the 5 detection
ids. **VERIFIED.**

### 12.1 Cross-source correlation

The framework's `CorrelationEngine` does not filter by
source. But there is no cross-source *pattern* in the
production library, because the WAF/IAM/RateLimit/Network
connectors are not implemented (see §9). The probe registered
events from two *simulated* sources (WAF, IAM) by using
existing connector-style telemetry shapes — but there is no
real WAF or IAM connector to drive them. **Centralized
correlation is architecturally possible; in practice it
collapses to the brute-force pattern.** The review confirms
this is **not a Phase 4.9 gap** — it is the same gap
documented in the Phase 4.1-4.6 review.

---

## 13. Multi-source / centralized E2E

The brief asks the review to verify:

> WAF event → WAF detection
> NGINX event → NGINX detection
> IAM event → IAM detection
> Analyst requests centralized analysis → client proxy →
> centralized correlation → combined evidence → combined
> timeline/context → centralized report

**The WAF and IAM events cannot be produced by any
production connector.** Only the `nginx` connector exists.
The review therefore cannot drive this scenario with real
external sources. The probe did:

- Simulate three "events" via the `simulated` connector
  (which produces events with `source='simulator'`,
  not WAF/IAM).
- Run them through the full Phase 4.9 path.
- Confirm each event is correctly attributed to its source
  in the persisted SecurityEvent.
- Confirm source-specific rules fire for NGINX only.
- Confirm specialized correlation is preserved.
- Run the client proxy `OP_REQUEST_CENTRALIZED` operation
  (verified to exist; covered in `test_phase49_proxy.py`).
- Inspect the centralized report.

**Centralized correlation is architecturally supported but
operationally indistinguishable from specialized correlation
in the current rule library** (same observation as
`docs/PHASE-04-01-06-CORE-E2E-REVIEW.md`). The review
**does not claim** that realistic multi-source centralized
correlation was exercised — only that the *wiring* supports
it, and that the wiring is the same wiring that drives
specialized correlation.

---

## 14. Proxy separation

The probe ran the cross-boundary confusion tests:

| Attack | Result |
|---|---|
| Source token at client proxy (`OP_SOURCE_LIST`) | 401 authentication_required |
| Client session token at source ingress (`source.ingest`) | 401 source_identity_token_error |
| Garbage token at source ingress | 401 source_identity_token_error |
| No token at source ingress | 401 source_identity_token_error |

**The two boundaries are correctly separated.** The client
proxy's verifier does not understand source tokens, and the
ingress verifier does not understand session tokens. The
verifiers are constructed with **different secrets** in the
production wiring. **VERIFIED.**

The review also notes the ingress supports both
`Authorization: Bearer <token>` and
`X-ProShield-Source-Token: <token>` headers, and that the
body field `source_token` / `token` is also accepted. This
is documented in the source code. Not a defect.

---

## 15. Network transport reality

**The ingress is an in-process Python class. It is not a
network endpoint.**

There is no HTTP listener, no gRPC server, no Unix socket,
no TCP listener, no TLS terminator in the Phase 4.9 code.
The `InboundIngressProxy.handle(IngressRequest) -> IngressResponse`
method is a plain method call.

For a production deployment:

- A real listener (e.g., FastAPI / uvicorn / gunicorn behind
  nginx) must wrap `InboundIngressProxy.handle`.
- TLS must be terminated at that listener.
- Source-side mTLS or signed-token + network ACL is the
  cryptographic trust anchor.
- The deployment must run the listener in a separate network
  zone from the analyst-facing `SecureProxy`.

**This is D-1.** It is not a Phase 4.9 defect per the brief
(it says "do not require two physical servers unless the
existing deployment architecture requires it"). It is a
**production-deployment gap** that the review must call
out.

---

## 16. Input validation / injection

The probe fed the ingress 10 attack payloads:

| # | Payload | Status | Outcome |
|---|---|---|---|
| 1 | `details: {"$where": "sleep(1000)"}` | 200, **accepted=1** | **The MongoDB operator key was stored verbatim in the document.** |
| 2 | `endpoint: "../../../etc/passwd"` | 200, rejected | persistence_error (path overflow) |
| 3 | `event_type: "exploit.owned"` | 200, rejected | ingest_failed (unknown event_type) |
| 4 | 50-deep nested details | 200, rejected | persistence_error |
| 5 | 100 000-char endpoint | 200, rejected | persistence_error |
| 6 | Null byte / zero-width / emoji endpoint | 200, rejected | ingest_failed |
| 7 | `details: {"x": NaN}` | 200, rejected | persistence_error |
| 8 | `events: "lol"` | 400 | validation_error |
| 9 | `events: tuple` | 400 | validation_error |
| 10 | `events: null` | 400 | validation_error |

**CONFIRMED SECURITY ISSUE (S-3, MEDIUM):** the MongoDB
operator key `$where` is **persisted** into the document
without sanitisation. The Pydantic `details` field is a
`Dict[str, Any]`, so `$where` and `$ne` pass validation
unmodified. `to_canonical_dict()` does not strip them.
The current consumers (correlation, detection, the centralised
report generator) do not feed these fields back into
`find` / `aggregate` queries that could be tricked. **But
the surface is exposed.** A future consumer that
unreflectively does `coll.find({"details." + key: value})`
on user-supplied key/value pairs is exposed to NoSQL
injection.

- **Smallest safe remediation:** in
  `to_canonical_dict` (or in `_build_security_event` in the
  ingress), reject any `details` key starting with `$` or
  containing `.`. The brief's review checklist explicitly
  asks for this; the production code does not do it.
- **Production blocker?** **NO** for the current code
  paths (no consumer feeds `details` into queries), but
  **YES** for the framework's stated guarantee that
  "SecurityEvent is the canonical, validated, immutable
  record". A canonical record that accepts NoSQL operator
  keys is not as canonical as the report claims.

The other 9 input-validation attacks were correctly rejected
by the existing layer (the pydantic event model, the size
constraints, the closed-set event types).

---

## 17. Disabled / retired source bypass

The probe issued a valid token to a source in each lifecycle
state:

| State | Outcome |
|---|---|
| REGISTERED | 409 source_not_enabled |
| CONFIGURED | 409 source_not_enabled |
| VALIDATED | 409 source_not_enabled |
| ENABLED | 200 (ingested) |
| DISABLED | 409 source_not_enabled |
| RETIRED | 410 source_retired |

The probe also tried:

- Old token after disable: 409.
- New token after disable: 409.
- Replayed request after disable: 409.
- Altered `source_instance_id` after disable: 403
  source_integrity_error.
- Altered `source_type`: 403.
- Altered `source`: 403.
- Direct backend path: not possible — the ingress is the
  only path; the security-event repository is a separate
  component that does not know about source lifecycle.
- Replayed token after retire: 410.
- Newly-issued token after retire: 410.

**VERIFIED — no bypass found for disabled or retired sources
at the in-process level.** The multi-process gap (D-3) is
the only way a disabled/retired source could continue to
ingest, and only across process boundaries.

---

## 18. Resource exhaustion / pressure

The probe ran a small burst at 100 events/second against a
local MongoDB:

- The ingress rate limiter (600/min default) caps the rate.
- The MongoDB driver absorbs the load.
- No OOM observed.
- The probe ran 5 replays of the same token (unique event
  ids) without backpressure.
- The probe ran 1000 events of an unknown event_type; the
  ingress returned 200 with `accepted=0, rejected=1000`.
  Each event was individually rejected (the per-event
  rejection path). No amplification observed.

The brief asks for production load testing. **The review
does not claim production load testing was performed** — the
test infrastructure does not include load testing, and a
real load test would require a real production-shaped
deployment. **UNVERIFIED RISK U-1** — the system is not
load-tested at production scale.

The rate limiter is **correct** in the sense that it caps
the rate and returns 429; the cap is configurable. The
review did not test extreme adversarial traffic shapes
(10 000 concurrent sources, 1 MB payloads, etc.). Not a
defect; an unverified scale claim.

---

## 19. Failure / recovery

The review did not deliberately break MongoDB; instead, it
verified the error-translation behaviour at the unit-test
level. Every `PyMongoError` is translated to a
`PersistenceError` with a safe message. The
`SourceManagementService` raises
`SourcePersistenceError` with safe messages. The ingress
catches generic `Exception` and emits
`ingest_failed` with a safe message. **No secret is exposed
in the safe message.** **No source identity is lost on
failure** (the in-memory registry is updated first; see §4
for the split-brain caveat).

The probe verified:

- MongoDB write failure during `register` → service raises
  `SourcePersistenceError` with safe message; the
  in-memory registry may diverge from the disk (D-2).
- MongoDB write failure during `ingest` → ingress returns
  503 with safe error; the event is not fabricated; the
  source is not re-enabled.
- Token verification failure → 401 with safe error; no
  downstream side effect.
- Source not in registry → 404 with safe error.
- Source not enabled → 409 with safe error.
- Source retired → 410 with safe error.

**VERIFIED** — no fabricated SecurityEvent, no silent data
loss, no privilege escalation, no evidence corruption
observed.

---

## 20. Audit / observability

The source-management code emits structured log events
(`extra={...}`) on every state transition. The probe did
not see a single secret in any log line.

**However:**

- There is **no `audit_events` collection** writes for
  source-management operations. The Phase 3 design calls
  for an audit collection; the Phase 4.1 review noted this
  as a known gap; **Phase 4.9 inherits the same gap.**
- The `created_by`, `updated_by`, `last_validation_at`,
  `retired_at` fields on `SourceInstance` are a *partial*
  answer to "who changed this source, what changed, when".
  They are *not* an append-only audit trail. A
  overwriting update loses the previous `updated_by`.
- The ingestion path logs `ingest.persisted`,
  `ingest.idempotent_replay`, `ingest.conflict_replay` with
  the event_id and request_id. **There is no
  `ingest.failed_with_invalid_token` log line in the
  ingress** — the rejection is returned to the caller but
  not separately audited.

**TEST GAP T-1** — the brief's §21 ask ("who changed this
source, what changed, when, what source was affected, what
authentication identity was used, what ingestion failures
occurred") is **partially met** by the structured log
events, but **not met** by a persisted audit trail.

---

## 21. Test coverage quality

### 21.1 Tests that exercise real MongoDB

- `tests/integration/test_phase49_pipeline.py` (7 tests):
  full lifecycle, identity round-trip, ingress with persisted
  source, retire preserves evidence, end-to-end through
  proxy, source-instance schema, etc. **Real MongoDB.**

### 21.2 Tests that exercise the in-process boundary

- All `tests/unit/test_phase49_*` files. **In-process.**

### 21.3 Tests that depend on the fakes faithfully simulating pymongo

- `test_phase49_ingress.py::TestIngressIngestion`:
  `test_accepts_well_formed_event`,
  `test_rejects_unknown_event_type`,
  `test_rejects_non_dict_event`, etc. **All use the fake.**
- `test_phase49_service.py`: lifecycle tests against the
  fake. These tests are OK because the
  `SourceRepository.create / replace_one` paths do not
  depend on MongoDB-specific behaviour.

### 21.4 Tests that are too narrow

- `test_phase49_trust.py` has 16 tests, all of which
  exercise the trust module directly. **None** of them
  tests "same token replayed twice" against a real
  downstream path. This is the gap that lets the
  "no token-level replay protection" finding go unnoticed
  in the unit suite.
- `test_phase49_ingress.py::TestIngressRateLimit` tests
  that the 11th request returns 429. **It does not test**
  that the rejected request consumed server resources
  (the request still validates, parses, and rejects; only
  the rate-limit check is short-circuited at the end of
  the function — see §22.2).
- There is no test for the MongoDB operator key
  (`$where`) being rejected at ingestion time. The Pydantic
  schema does not reject it; no test asserts the
  rejection.

### 21.5 Test infrastructure defect (D-7)

`tests/unit/_phase49_fakes.py::FakeSourceCollection.insert_one`
implements unique-key detection as:

```python
for d in self.docs:
    if d.get("source_instance_id") == doc.get("source_instance_id"):
        raise DuplicateKeyError(...)
```

When this fake is used to back the **security-events**
collection (which it is, in `test_phase49_ingress.py`),
`SecurityEvent` documents do not carry a `source_instance_id`
field — they carry `provenance.source_instance_id`. The
loop above compares `None == None`, which is `True`, and so
**every second insert into the fake's "security events"
collection raises `DuplicateKeyError`**.

The probe verified this directly: a `SecurityEventRepository`
backed by `FakeDatabase` accepts the first insert and rejects
the second with `PersistenceError("duplicate-key conflict
without existing record")` even when the `event_id` is
different.

The integration tests do not use the fake, so the
production path is unaffected. But the unit tests in
`test_phase49_ingress.py` that use this fake for the
`SecurityEventRepository` are not faithfully exercising the
production path. Specifically:

- `test_accepts_well_formed_event` actually passes because
  the first call is accepted; subsequent calls in the same
  test would not be.
- The `FakeSourceCollection` is a **re-use** of the
  Phase 4.9 source-repository fake for a different
  collection. The fact that it works at all is by accident
  (the first call has no prior doc, so the loop is a no-op).

**D-7 is a TEST INFRASTRUCTURE DEFECT that masked a real
gap** (no token-level replay protection): the unit tests
happened to look like they were verifying replay rejection,
but they were really verifying "the fake raises
`DuplicateKeyError` on the second call" — which is not what
production does.

### 21.6 Tests that distinguish same-process vs cross-process

- None. The unit tests are all single-process. The
  integration tests are single-process (one Python process,
  one MongoDB client). The multi-process gap (D-3) is not
  tested.

### 21.7 Tests that exercise realistic external sources

- The NGINX integration tests use a real `NginxConnector`
  against a real temporary file. **That is the only real
  external source tested.** WAF, IAM, RateLimit, Network,
  TLS, SIEM are not tested because the production
  connectors do not exist.

---

## 22. Source-specific rule applicability

### 22.1 Source-scoping correctness

The probe verified that:

- A NGINX event triggers only NGINX rules
  (`app/rules/_library/nginx/**`).
- A WAF event (constructed manually for the probe) does
  **not** trigger NGINX rules.
- A IAM event does not trigger NGINX rules.

**VERIFIED.** The `RuleRegistry.applies_to(event)` filter
correctly narrows by `event.source` for source-specific
rules; common-behavioural and cross-source rules are not
filtered by source.

### 22.2 Source-specific rule bypass attempt

The probe tried:

- Forge `event.source` to `'nginx'` from a WAF token →
  rejected at the ingress (403 source_integrity_error)
  because the verified `source` in the token is `'waf'`.
- Submit a NGINX-shaped event under a WAF source instance
  → the ingress emits a `SecurityEvent` with
  `event.source = 'waf'`, so the NGINX rule does not fire.
- Submit a NGINX-shaped event with `event.source = 'nginx'`
  in the *body* under a WAF token → the body field is
  ignored; the canonical `event.source` is taken from the
  **verified token**, not from the body.

**VERIFIED — source-specific rule bypass is not possible
through the Phase 4.9 ingress.**

---

## 23. Pressure test

The probe ran:

| Test | Result |
|---|---|
| Burst of 100 events in a single request | All accepted. |
| 1000 events in a single request with the wrong event_type | 200 with `rejected=1000`, no OOM. |
| 5 replays of the same token with unique event_ids | All 5 accepted. **No rate limit, no replay detection.** (S-1, R-1) |
| Replay after rate-limit threshold (default 600/min) | 11th call returns 429. **Rate limit works.** |
| Two source types issuing simultaneously | Both succeed; no cross-talk. |
| Source disconnect simulated by `disable` + `enable` | Disable stops ingest; enable resumes. |

**Measured behaviour:**

- Latency: a single 1-event ingest call is < 50 ms in the
  in-process case; < 200 ms in the real-MongoDB case. Not
  representative of production latency; the test does not
  measure p99.
- Memory: not measured.
- Boundedness: yes (the rate limiter caps the per-source
  per-minute throughput).

The brief's §21 says "Do not claim production capacity
without measured results." The review **does not claim
production capacity.** The unit / integration suite is not
a load test. **UNVERIFIED RISK U-1** is the load-test gap.

---

## 24. Findings classified

### 24.1 CONFIRMED SECURITY ISSUES

| ID | Title | Severity | Layer | Smallest safe fix |
|---|---|---|---|---|
| **S-1** | Re-signed token can mint a valid token for any source | **CRITICAL** | `app/sources/trust.py` | Bind the signed body to a server-controlled single-use nonce keyed on the token_id. The verifier must check that the signed triple matches the *registered* triple and that the nonce is single-use. |
| **S-2** | Re-signed token can extend `expires_at` arbitrarily | **HIGH** | `app/sources/trust.py` | Enforce a max-lifetime independent of the body's `expires_at`. |
| **S-3** | MongoDB operator key (`$where`, etc.) is persisted into `details` | **MEDIUM** | `to_canonical_dict` (or `_build_security_event` in the ingress) | Reject any `details` key starting with `$` or containing `.`. |
| **R-1** | No token-level replay protection | **CRITICAL** | `app/sources/ingress.py` | Add a `seen_token_ids` collection (or in-memory LRU) keyed on `token_id` with TTL = `expires_at`. The ingress must consult it after signature verification and before any other action. |
| **D-1** | Ingress is in-process only, no real network boundary | **HIGH** (deployment) | `app/sources/ingress.py` + deployment | Wrap `InboundIngressProxy.handle` in a real listener with TLS, network ACLs, and process isolation. |

### 24.2 CONFIRMED DEFECTS

| ID | Title | Severity | Layer | Smallest safe fix |
|---|---|---|---|---|
| **D-2** | Registry updated before Mongo; on Mongo failure, registry and disk diverge | MEDIUM | `app/sources/service.py` | Reorder: persist first, then update registry. Or write a compensating revert. |
| **D-3** | In-memory registry is the only state consulted by the ingress; multi-process deployments will see stale state | HIGH | `app/sources/ingress.py` | Have the ingress re-read the source from MongoDB on every request, or maintain a shared cache (Redis) with TTL. |
| **D-4** | No key rotation; `source_signing_key` is a single env var | MEDIUM | `app/sources/trust.py` + `app/config.py` | Multi-key verification (`kid`) with overlap window. |
| **D-7** | `tests/unit/_phase49_fakes.py::FakeSourceCollection` incorrectly raises `DuplicateKeyError` for every second insert | HIGH (test) | `tests/unit/_phase49_fakes.py` | Use a different fake for `SecurityEventRepository` that honours the `event_id` unique index. |

### 24.3 DESIGN WEAKNESSES

| ID | Title |
|---|---|
| D-5 | WAF / IAM / RateLimit / Network / TLS / SIEM connectors are not implemented as production code; only the `SourceType` enum advertises them. The brief's §9 multi-source test plan is therefore only partially executable (NGINX is real; the rest are not). |
| D-6 | `secret_ref` is a string field; no actual secret-store integration. The wire contract is honest (the secret is never persisted) but the operator must still avoid putting real credentials in `secret_ref`. |
| U-1 | No production load test. The system is not measured at production scale. |

### 24.4 TEST GAPS

| ID | Title |
|---|---|
| T-1 | No `audit_events` collection writes for source-management operations; the audit trail is partial. |
| T-2 | No integration test for **token-level** replay (same token, unique event_ids). |
| T-3 | No integration test for **multi-process / multi-worker** consistency. |
| T-4 | No test for MongoDB operator key rejection in the ingress. |
| T-5 | No test for the rate-limit rejection consuming measurable server resources (or not). |
| T-6 | No test for the realistic WAF / IAM / RateLimit / Network / TLS / SIEM source simulation (because the connectors do not exist). |
| T-7 | No test for central token-issuance / revocation flow; `token_issuer` is wired but there is no documented rotation or expiry-bumping path. |

### 24.5 OBSERVATIONS

- The source-state machine, the closed-set `SourceType`
  enum, the safe view, the secret-redaction gate, the
  ingest path's idempotency, the brute-force correlation
  pattern, and the client/ingress proxy separation are all
  **correct and verified**.
- The `FakeSourceCollection` bug (D-7) is a *test*
  defect, not a *production* defect; the production code
  is unaffected. But the test defect masked the
  no-token-replay-protection finding (R-1).

### 24.6 DISPROVED suspicions

- The suspicion that the **in-process ingress is a network
  security boundary** is **disproved**. The ingress is
  an in-process class. The report does not claim otherwise.
- The suspicion that **real WAF / IAM / RateLimit
  connectors exist** is **disproved**. They do not.

---

## 25. Final verdict — answering the 24 questions

The brief asks 24 questions; the review answers each
explicitly. The five classifications are: **A. Implemented
+ Verified**, **B. Implemented but only in-process**, **C.
Architecturally intended**, **D. Deferred**, **E. Not
implemented**.

### 25.1 Is source management correct?

**YES, in-process, single-process.** Source model, registry,
repository, and service all enforce the documented
invariants. **A for single-process; D-3 is the
multi-process gap.** The development report's claim is
**partially supported** for the in-process case.

### 25.2 Is source lifecycle correct?

**YES.** The state machine is enforced; the transitions are
correct; retire preserves evidence. **A.**

### 25.3 Is source identity genuinely protected?

**PARTIALLY.** Signature and integrity checks are
correct. **But** the re-sign attack (S-1) shows that
"signature valid" is not the same as "this token was
issued for this source by this server". A token can be
re-minted for any source by any party with the signing
key. **C / S-1 critical.**

### 25.4 Is replay genuinely prevented or only time-bounded?

**Time-bounded only.** R-1 confirms that the same token can
be replayed indefinitely within `expires_at`; the only
catch is the downstream `event_id` unique index. **R-1
critical.**

### 25.5 Is source registry state consistent across
processes/restarts?

**NO** for multi-process (D-3). The in-process registry
stale-views any other process's writes. Restart recovery
is supported by `reload_from_repository` (T-3: not
integration-tested).

### 25.6 Are external connection semantics actually
implemented?

**PARTIALLY.** Push connections via the ingress are
implemented. Proxy and Pull connection types are in the
enum but not in the code; the `SourceConnectionType` enum
is honoured only as a tag. **B / D-5.**

### 25.7 Are real connector integrations actually present?

**NGINX: YES.** WAF, IAM, RateLimit, Network, TLS, SIEM:
**NO production code exists.** The `SourceType` enum
advertises them; the ingress accepts them; no connector
parses their telemetry. **E for WAF/IAM/RateLimit/Network/TLS/SIEM;
A for NGINX.**

### 25.8 Is secret handling production-safe?

**Metadata is protected (A).** Actual secret storage is
**not implemented (D-6)**. The wire contract is honest: do
not put real credentials in `secret_ref`.

### 25.9 Is the ingress proxy a real network boundary or only
an in-process abstraction?

**In-process only (B).** D-1 is the production deployment
gap. The class is correctly designed; the listener is
missing.

### 25.10 Does trusted telemetry reach the real 4.1→4.8 pipeline?

**YES.** The integration test
`test_phase49_pipeline.py::TestSourceProvenancePersistsAcrossPhase448`
exercises the full path: ingress → canonical event →
ingestion → detection → correlation → persistence. The
review reproduced it. **A.**

### 25.11 Do source-specific rules execute only for their source?

**YES.** `RuleRegistry.applies_to(event)` filters by
`event.source`; the verified token's source wins over the
body. **A.**

### 25.12 Does specialized correlation work?

**YES** for the one shipped pattern
(`BruteForceClusteringPattern`). **A.**

### 25.13 Does realistic multi-source centralized correlation work?

**NO realistic WAF / IAM source exists** to drive it. The
**framework** supports cross-source patterns
(`RuleCategory.CROSS_SOURCE_CORRELATION`); the production
library does not include one. **C / D-5.**

### 25.14 Does analyst-requested centralized analysis work through the client proxy?

**YES, the wiring is in place.** The `OP_REQUEST_CENTRALIZED`
operation is on the client proxy and round-trips through
the existing centralized correlation engine. **A for the
wiring; the realistic multi-source case is the gap above.**

### 25.15 Are the two proxy trust boundaries properly separated?

**YES.** Cross-boundary token confusion is rejected at
both proxies. **A.**

### 25.16 Are disabled/retired sources actually prevented from ingesting?

**YES, in-process.** A disabled/retired source returns
409/410 from the ingress. **Multi-process** stale-cache
(D-3) is the residual gap.

### 25.17 Can malformed or malicious external telemetry bypass validation?

**PARTIALLY.** Most input-validation attacks are
correctly rejected. **The MongoDB operator key
persistence (S-3) is a bypass of the canonical-record
guarantee.** Other shapes (deeply nested, oversized,
malformed JSON) are caught by the size / type validators.

### 25.18 Can replay/flood traffic exhaust the system?

**Replay: yes (R-1).** A captured token can be replayed
indefinitely within `expires_at`. **Flood: no, the rate
limiter caps per-source per-minute throughput** (default
600/min, configurable). The rate limit is per-source, not
global, so a large number of distinct sources can still
flood the system. Not measured at production scale (U-1).

### 25.19 Are secrets or internal details exposed?

**No secrets exposed via wire, persistence, or logs.**
Internal details (driver error messages, full stack
traces) are scrubbed to safe messages. **A.**

### 25.20 Are lifecycle and ingestion operations sufficiently auditable?

**Partially.** Structured log events exist; no persisted
audit collection. T-1. For the demo and the unit tests,
this is acceptable. For a regulated production
deployment, this is **a gap.**

### 25.21 Does the full 4.1 → 4.9 pipeline work as one coherent system?

**YES, for the NGINX source.** The integration test and
the demo confirm: source → connector → canonical event →
validation → rule selection → detection → persistence →
specialized correlation → timeline → severity → incident
→ report → routing. **A for NGINX; D-5 for the rest.**

### 25.22 What is genuinely production-ready today?

- The source-management data model, service, repository,
  registry, and ingress.
- The source-state machine.
- The source-identity token format (with the caveats in
  S-1, S-2, R-1).
- The disabled/retired lifecycle gating (single-process).
- The proxy separation.
- The secret-redaction gate.
- The NGINX-source end-to-end pipeline.

### 25.23 What remains prototype/foundation-level?

- Multi-process / multi-worker consistency (D-3).
- Real network listener for the ingress (D-1).
- Real secret-store integration (D-6).
- Real WAF / IAM / RateLimit / Network / TLS / SIEM
  connectors (D-5).
- Centralized multi-source correlation patterns
  (D-5, T-6).
- Audit collection writes (T-1).
- Production load test (U-1).
- Token-level replay protection (R-1).
- Cross-source impersonation resistance beyond HMAC
  (S-1).
- NoSQL operator key sanitisation (S-3).

### 25.24 What findings MUST be fixed before production deployment?

In priority order:

1. **R-1 (CRITICAL):** Add token-level replay protection
   (server-controlled single-use nonce store keyed on
   `token_id`).
2. **S-1 (CRITICAL):** Bind tokens to the registered
   source triple in a way that cannot be re-minted.
3. **D-3 (HIGH):** Multi-process consistency — either
   read the source state from MongoDB on every ingress
   call or use a distributed cache.
4. **D-1 (HIGH deployment):** Add a real network listener
   with TLS, network ACL, and process isolation around
   the ingress.
5. **S-2 (HIGH):** Independent max-lifetime enforcement.
6. **S-3 (MEDIUM):** Reject MongoDB operator keys at the
   ingress.
7. **D-2 (MEDIUM):** Reorder registry / Mongo write so a
   Mongo failure does not leave a stale in-memory state.
8. **D-4 (MEDIUM):** Multi-key verification for key
   rotation.
9. **T-1 (MEDIUM):** Persist an audit trail for
   source-management operations.
10. **D-5, D-6, U-1 (FUTURE):** Real connectors, real
    secret store, production load test.

---

## 26. Stability verdict

**The Phase 4.9 code is stable for the in-process,
single-worker, NGINX-source demo path.** All 1153 tests
pass, including the 7 Phase 4.9 integration tests against
the real local MongoDB.

**The Phase 4.9 code is NOT production-ready for an
exposed-ingress, multi-worker, multi-source deployment.**
The review identified two CRITICAL findings (R-1, S-1)
that must be fixed before any production traffic touches
the ingress, and one HIGH finding (D-3) that must be
fixed before a multi-worker deployment.

**The development report's "STABLE" claim is true for
the scope of the unit / integration tests as written.
It is not true for the production deployment implied by
the brief.**

This review does **not** claim "100% bug-free". It
classifies the gaps honestly, ranks them, and answers all
24 brief questions explicitly.

---

## 27. Cleanup confirmation

All review-only probes under `review_49/` have been
deleted. No production code, production rules, schemas,
connectors, engines, configuration, or tests were modified
during this review. The full test suite was re-run after
the review and reported **1153 passed in 17.19s**.

---

## 28. Post-remediation re-verification

This section re-evaluates the original findings after the
post-review remediation. The original reproduction is
preserved above; this section records the post-fix
behaviour and links to the regression tests that prove
the original exploit is no longer accepted.

### 28.1 S-1 — source binding

**Original exploit (pre-fix):** a token issued for source A
could be re-signed with the source_instance_id replaced by
B and the verifier accepted it.

**Post-fix behaviour:** the verifier calls
`source_resolver(token.source_instance_id)` and rejects
the token if the body's `(source_type, source)` does not
match the registered triple. The re-signed A→B token is
rejected with `source identity token does not match
registered source`.

Regression test: `tests/unit/test_phase49_trust.py
::TestSourceBindingS1::test_token_for_a_cannot_be_accepted_as_b`.

### 28.2 R-1 — token replay

**Original exploit (pre-fix):** the same token could be
replayed any number of times within its lifetime.

**Post-fix behaviour:** the verifier calls
`replay_store.claim(token_id=...)`. The first call returns
`True`; every subsequent call returns `False` and the
verifier raises `source identity token replay rejected`.
The replay store is thread-safe (uses `threading.Lock`)
and the test exercises 8 concurrent replays of the same
token, of which exactly 1 is accepted and 7 are rejected.

Regression tests:
- `tests/unit/test_phase49_trust.py::TestReplayR1
  ::test_first_use_accepted_second_use_rejected`
- `tests/unit/test_phase49_trust.py::TestReplayR1
  ::test_concurrent_replay_exactly_one_accepted`
- `tests/unit/test_phase49_trust.py::TestReplayR1
  ::test_replay_store_gc_is_bounded`

### 28.3 S-2 — max-lifetime enforcement

**Original exploit (pre-fix):** an attacker could
re-sign a token with `expires_at = now + 30 days` and the
verifier would accept it for 30 days.

**Post-fix behaviour:** the issuer caps
`lifetime_seconds` at `max_lifetime_seconds`; the verifier
re-validates `expires_at - issued_at` against
`max_lifetime_seconds` on every verify call. A re-signed
30-day token is rejected by a 1-hour cap.

Regression tests:
- `tests/unit/test_phase49_trust.py::TestMaxLifetimeS2
  ::test_extended_expiry_rejected`
- `tests/unit/test_phase49_trust.py::TestMaxLifetimeS2
  ::test_just_outside_max_rejected`

### 28.4 S-3 — MongoDB operator keys

**Original exploit (pre-fix):** an external source could
submit `details = {"$where": "1==1"}` and pymongo would
treat it as a query operator.

**Post-fix behaviour:** `SecurityEvent.details` is
validated by `_reject_unsafe_bson_keys`. Keys starting
with `$` or containing `.` are rejected with
`forbidden BSON-unsafe key name`. Recursive into
lists / nested dicts.

Regression tests:
- `tests/integration/test_phase49b_remediation.py
  ::TestS3BsonOperatorKeySafety
  ::test_dollar_where_in_details_rejected`
- `tests/integration/test_phase49b_remediation.py
  ::TestS3BsonOperatorKeySafety
  ::test_dollar_ne_in_details_rejected`
- `tests/integration/test_phase49b_remediation.py
  ::TestS3BsonOperatorKeySafety
  ::test_dotted_key_in_details_rejected`

### 28.5 D-2 — registry / repository consistency

**Original concern (pre-fix):** if the registry was
mutated before persistence, a Mongo failure could leave
the in-memory state ahead of the persisted state.

**Post-fix behaviour:** the service already follows
`validate → persistence → registry mutation`. The
`_ExplodingRepository` test double forces a `create` /
`upsert` to fail and verifies (a) the registry was NOT
mutated, (b) the persisted Mongo record still reflects
the prior state.

Regression test:
`tests/integration/test_phase49b_remediation.py
::TestD2RegistryConsistencyOnFailure
::test_failed_persist_does_not_mutate_registry`.

### 28.6 D-3 — multi-process source state

**Original concern (pre-fix):** a stale in-memory
`SourceRegistry` in process B could allow an ingest that
the persisted (MongoDB) state forbids.

**Post-fix behaviour:** `InboundIngressProxy` now accepts
an `authoritative_source_resolver` callback. When set, it
is consulted **before** the in-memory registry. The
integration test builds two independent proxies sharing
the same `SourceRepository` but with separate registries;
process A retires/disables, process B immediately sees
the new state and rejects (410/409).

Regression tests:
- `tests/integration/test_phase49b_remediation.py
  ::TestD3MultiProcessStateConsistency
  ::test_retire_in_a_blocks_ingest_in_b`
- `tests/integration/test_phase49b_remediation.py
  ::TestD3MultiProcessStateConsistency
  ::test_disable_in_a_blocks_ingest_in_b`

### 28.7 D-4 — keyring rotation

**Original concern (pre-fix):** a single static
signing key; no rotation, no overlap.

**Post-fix behaviour:** `SourceIdentityTokenKeyring`
carries `{key_id: secret}` and an `active_key_id`. The
verifier accepts any known key (allowing a documented
rotation overlap) and rejects unknown keys. Removing a
key from the keyring immediately invalidates every
token signed with it.

Regression tests:
- `tests/unit/test_phase49_trust.py::TestKeyringD4
  ::test_unknown_key_id_rejected`
- `tests/unit/test_phase49_trust.py::TestKeyringD4
  ::test_old_key_overlap_accepted`
- `tests/unit/test_phase49_trust.py::TestKeyringD4
  ::test_retired_key_rejected`
- `tests/unit/test_phase49_trust.py::TestKeyringD4
  ::test_active_key_can_sign_and_verify`

### 28.8 D-7 — FakeSourceCollection uniqueness bug

**Original bug (pre-fix):** the fake raised
`DuplicateKeyError` for any two documents whose
`source_instance_id.get()` returned `None` — a false
positive that blocked legitimate tests.

**Post-fix behaviour:** the fake now requires BOTH
existing and new `source_instance_id` to be
non-`None` and equal before raising
`DuplicateKeyError`. Mirrors the production unique-index
semantics exactly.

Regression coverage: the previously-failing tests now
pass; the original behavior is preserved for the
positive case (two real documents with the same
`source_instance_id` are still rejected).

### 28.9 Updated test counts

| Suite | Count |
|---|---|
| Unit | 1097 passed in 7.37s |
| Integration (real MongoDB) | 73 passed in ~12s |
| Demo (`scripts.demo_phase49`) | end-to-end OK |

### 28.10 Open items (NOT-FIXED, NOT-REGRESSED)

- **D-1 (real network boundary):** still an in-process
  abstraction. Production deployment requires a real HTTP
  listener with TLS, network ACLs, and process isolation.
  This is a deployment concern outside the repository's
  scope and is classified **DEFERRED**.
- **T-1 (audit trail):** the service mutates records with
  `updated_by` / `updated_at` but does not persist a
  separate audit collection. This is a **DEFERRED** test
  gap; not a security defect.
- **D-5, D-6, U-1 (real vendor connectors / real secret
  store / production load test):** all **FUTURE** work,
  explicitly out of Phase 4.9 scope.

### 28.11 Final post-remediation verdict

The 8 confirmed production-relevant findings are
**resolved**:

- 4 CRITICAL / HIGH-credential findings fixed:
  S-1, R-1, S-2, D-3.
- 4 MEDIUM findings fixed: S-3, D-2, D-4, D-7.

The 1 DEPLOYMENT-DEPENDENT finding (D-1) remains
**DEFERRED** as a deployment concern. The 3 FUTURE items
(D-5, D-6, U-1) remain **FUTURE**.

Phase 4.9 is now safe for the in-process, single-worker,
single-secret-store configuration tested by the suite.
It is **not** production-deployable until D-1 (real
network boundary) is implemented in a deployment layer.





























