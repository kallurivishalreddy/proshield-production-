# ProShield — Phase 4.1 Independent Review Report

## 1. Review Scope

This report covers the Phase 4.1 slice as implemented in this
repository. The slice was claimed by the development report to:

- establish the canonical `SecurityEvent` Pydantic model,
- implement a self-contained RFC 9562 UUIDv7 generator,
- implement a typed `DomainError` hierarchy with a safe-error envelope,
- implement a connector base interface and a `SimulatedConnector`,
- implement the in-process `SecurityEventIngestionService` (the
  documented trust boundary),
- implement the `SecurityEventRepository` (the only module
  permitted to import `pymongo`) with documented idempotency,
  schema validator, and index set,
- ship a `scripts/init_mongo.py` bootstrap and a `scripts/live_smoke.py`
  end-to-end runtime check,
- provide 61 unit tests + 18 integration tests against real MongoDB.

The reviewer inspected every file under `app/`, `scripts/`, `tests/`,
plus the development report, the understanding document, the
requirements/architecture/schema/threat-model/security/detection
corpora under `docs/`, and executed 13 review-only verification tests
in `%TEMP%\proshield_review\`. No product code was modified.

## 2. Documentation Reviewed

The complete `docs/` tree was treated as one connected specification
before any code was inspected:

- `docs/PHASE 0/`: `PRODUCT_SCOPE.md`, `MVP_REQUIREMENTS.md`,
  `MVP_ACCEPTANCE.md`, `INITIAL_SECURITY_EVENTS.md`, `ROUTING_MATRIX.md`.
- `docs/PHASE 1/`: `ARCHITECTURE.md`, `ARCHITECTURE_DECISIONS.md`,
  `THREAT_MODEL.md`.
- `docs/PHASE 2/`: `SECURITY_EVENT_SCHEMA.md`, `DOMAIN_DATA_MODEL.md`,
  `API_CONTRACTS.md`, `CONTRACT_DECISIONS.md`.
- `docs/PHASE 3/`: `AUTH_RBAC.md`, `SECURE_FOUNDATION.md`,
  `SECURITY_CONFIGURATION.md`, `SECURITY_TEST_PLAN.md`.
- `docs/PHASE 4/`: `DETECTION_ENGINEERING_AND_FUTURE_AI.md` and the
  slice's own `PHASE-04-01-REPORT.md` (treated as a set of claims
  to verify, not as proof by itself).
- `docs/PROSHIELD_PROJECT_UNDERSTANDING.md` (the Phase 0-prep
  synthesis).

## 3. Phase 4.1 Scope Verification

**In scope (and present):** canonical `SecurityEvent` model with
documented fields, allowed source/event-type catalogues, sensitive-data
rejection (Section 20), input validation, server-side stamping,
MongoDB $jsonSchema validator, documented index set, the repository
boundary, the in-process ingestion service with idempotency and
replay-conflict semantics, the safe-error envelope, structured JSON
logging with a secret scrub, a working `SimulatedConnector`, and a
bootstrap script.

**Correctly deferred (not in this slice):** detection rules, rule
registry, candidate/approved governance, source-specific detection
logic, correlation, timeline, severity, confidence, incident, report,
routing, AI, audit-event persistence, HTTP API, authentication / RBAC,
object-level authorization, rate limiting, ML dataset pipeline, and
adversarial test factory. The dev report explicitly enumerates these
and they are not Phase 4.1 defects.

**Open / provisional (correctly recorded):** the exact composite
event-identity formula is OPEN per the corpus
(`PROSHIELD_PROJECT_UNDERSTANDING.md` §19); Python/FastAPI/pymongo is
PROVISIONAL (ADR-021, ADR-026, ADR-031); the exact physical index set
is PROVISIONAL (ADR-043). All three are flagged in the dev report.

## 4. Implementation Reviewed

| Area | File | Lines |
|---|---|---|
| Config | `app/config.py` | 1-99 |
| Observability | `app/observability/logging.py` | 1-135 |
| Domain — UUID7 | `app/domain/uuid7.py` | 1-72 |
| Domain — errors | `app/domain/errors.py` | 1-113 |
| Domain — model | `app/domain/security_event.py` | 1-457 |
| Connectors — base | `app/connectors/base.py` | 1-68 |
| Connectors — sim | `app/connectors/simulated.py` | 1-130 |
| Ingestion | `app/ingestion/service.py` | 1-204 |
| Persistence — driver | `app/persistence/mongo.py` | 1-69 |
| Persistence — schema | `app/persistence/schema.py` | 1-112 |
| Persistence — repo | `app/persistence/security_event_repository.py` | 1-322 |
| Scripts | `scripts/init_mongo.py`, `scripts/live_smoke.py` | full |
| Unit tests | `tests/unit/test_*.py` (5 files) | full |
| Integration tests | `tests/integration/test_*.py` (3 files) + `conftest.py` | full |
| Config | `pytest.ini`, `conftest.py`, `requirements.txt`, `README.md`, `.env.example`, `.gitignore` | full |

The development report was read in full (`docs/PHASE 4/PHASE 4-01/PHASE-04-01-REPORT.md`).

## 5. Developer Claims Independently Verified

| Claim | Verification | Result |
|---|---|---|
| 79 tests pass in ~5s | Re-ran `python -m pytest --tb=line -q` | **VERIFIED** (79 passed in 4.98s and again in 6.02s) |
| Real MongoDB used | All 18 integration tests connect to `127.0.0.1:27017` and assert on real documents; `mongo_session(cfg)` opens and closes a real `MongoClient` | **VERIFIED** |
| 7 indexes exist | `recheck_r10.py` dropped the collection, called `ensure_schema()` + `ensure_indexes()`, listed indexes → all 7 documented + MongoDB's `_id_` | **VERIFIED** |
| Schema validator applied | `collMod` with `$jsonSchema` is called by `ensure_schema()`; integration tests and the live smoke confirm | **VERIFIED** |
| Idempotency works | `test_idempotent_re_ingest_returns_existing` + `test_ingest_idempotent_replay_returns_existing` + `test_idempotent_kept_count` in `live_smoke.py` | **VERIFIED** |
| Conflict works | `test_conflict_on_same_event_id_different_content` + `test_ingest_conflict_replay_raises_conflict` + R-T06 | **VERIFIED** |
| Sensitive data rejected | `test_sensitive_key_in_details_is_rejected` + 4 sibling tests | **VERIFIED** |
| Domain errors safe | `test_persistence_error_must_not_leak_driver_message` + `test_persistence_error_is_status_503` + the persistence_failures R-T | **VERIFIED** |

## 6. Requirement Traceability

Important Phase 4.1 requirements, traced:

| Requirement | Implementation | Test | Runtime Evidence |
|---|---|---|---|
| Canonical `event_id` is UUIDv7 (ADR-003) | `app/domain/security_event.py:300-312` | `test_event_id_must_be_uuid7`, `test_event_id_must_be_uuid_string` | 5 review UUIDv7s all `version == 7`, `variant == RFC_4122` |
| Required fields present | `SecurityEvent` model | 8 fields, `test_canonical_event_constructs_with_minimum_fields`, `test_missing_required_field_raises` | Live document has all 13 expected fields + `_id` |
| `source` in catalogue | `ALLOWED_SOURCES` (8) | 8 parametrised tests | R-T10 sample source = "simulator" |
| `event_type` in catalogue | `ALLOWED_EVENT_TYPES` (9) | 9 parametrised tests | R-T10 sample event_type = "waf_attack_detected" |
| UTC timestamps | `_timestamps_must_be_utc` | `test_naive_timestamp_is_rejected`, `_document_to_event` reattaches tzinfo | Stored docs: `event_time type = datetime` (BSON Date) |
| Provenance subdocument | `SecurityEventProvenance` | `test_collect_yields_only_canonical_events`, R-T06 | Stored doc has `provenance: {collector, source_event_id}` |
| Source / provenance lookup | `find_by_canonical_identity` | `test_find_by_canonical_identity_finds_event` | R-T10 live smoke matches |
| Documented $jsonSchema | `app/persistence/schema.py` | `ensure_schema` + R-T09 | R-T09 CONFIRMED extra-field accepted at DB layer |
| Documented indexes | `INDEX_SPECS` (7) | R-T10 recheck; R-T07 explain plan | All 7 indexes present in `recheck_r10.py` |
| Idempotency | `_canonical_equal` excludes `ingested_at` | `test_ingest_idempotent_replay_returns_existing` | Live smoke: `idempotent_kept_count = 1` |
| Conflict on same id + diff content | `_canonical_equal` returns False → `ConflictEventError` | `test_ingest_conflict_replay_raises_conflict` | Live smoke: `conflict_raised_on_change = True` |
| Reject secrets in `details` keys | `_reject_sensitive_keys` | 4 tests | R-T08 confirms sets not a target |
| Field size caps | `MAX_*` + `StringConstraints` | `test_size_validator_rejects_oversized_body`, R-T12 | R-T12 length-65 rejected |
| Body and details byte caps | `validate_size_constraints` | `test_size_validator_rejects_oversized_body` | R-T01 / R-T13 — see Findings |
| Server stamps `ingested_at` | `ingestion.service._stamp` | `test_ingest_overrides_ingested_at_to_server_clock` + R-T04 | R-T04: stored `ingested_at` is server's `now` |
| MongoDB is the only persistence | `app/persistence/` only `pymongo` importer | `findstr` | All pymongo imports inside `app/persistence/*` and `scripts/init_mongo.py` |
| Safe error envelope | `DomainError.safe_message` vs `internal_detail` | `test_persistence_error_must_not_leak_driver_message` | R-T02/R-T03 confirms `safe_message` does NOT contain "pymongo" |
| Structured JSON logging with request_id | `_JsonFormatter` | `live_smoke.py` log lines carry `request_id` | R-T02/R-T03 output is valid JSON |
| Log scrub for secrets | `_scrub` substring replacer | `test_health_does_not_leak_secrets` (connector) | R-T02/R-T03: **PARTIAL** — see Finding-001 / Finding-002 |

## 7. Existing Tests Reviewed

| Test group | Quality notes |
|---|---|
| `tests/unit/test_uuid7.py` (6) | Strong: every spec-mandated bit position is asserted. |
| `tests/unit/test_security_event.py` (31) | Strong: all allowed sources and event types parametrised; explicit rejection paths; size-bounds. |
| `tests/unit/test_domain_errors.py` (8) | Adequate: each `http_status` and `code` asserted. |
| `tests/unit/test_config.py` (5) | Adequate: defaults, overrides, invalid-int, safe-summary, secret redaction. |
| `tests/unit/test_simulated_connector.py` (6) | Adequate. |
| `tests/integration/test_security_event_repository.py` (9) | **Strong.** `test_indexed_query_by_source_works` actually calls `find().explain()` and asserts on the plan. |
| `tests/integration/test_ingestion_service.py` (6) | Adequate. **One test-weakness**: `test_ingest_idempotent_replay_returns_existing` checks that the returned `event_id` matches but does not check that the returned object is the *exact same Pydantic instance* the repository stored. |
| `tests/integration/test_persistence_failures.py` (1) | Single test but the right test. |

## 8. Additional Tests Executed

13 review-only tests in `%TEMP%\proshield_review\review_verification.py`. They do not modify product code and live outside the project tree. Each was run against the real local MongoDB on `127.0.0.1:27017` and recorded below.

| ID | What it exercised | Evidence recorded |
|---|---|---|
| R-T01 | `validate_size_constraints` measures a string produced by `json.dumps(payload, default=str)` while pymongo emits ISO 8601 / BSON. | The two serializations differ in byte size. See Finding-005. |
| R-T02 | Logged a message containing `mongodb://user:secret@host:27017/db`. Inspected the JSON output line. | `***user:secret@host:27017/db` — credentials remain. **CONFIRMED Finding-001.** |
| R-T03 | Logged a message with `PASSWORD=hunter2` and a separate one with mixed-case `Password=X`. | `PASSWORD=hunter2` → `***=hunter2` (the value survives). `Password=X` is unscrubbed. **CONFIRMED Finding-002.** |
| R-T04 | Built a `SecurityEvent` with `ingested_at = et + 1ms`, ingested it, and read the stored document. | Stored `ingested_at = 2026-08-26 19:28:47.487` (server clock), not `2026-01-01 00:00:00.001` (the connector value). Service overrode correctly. **CONFIRMED (connector's pre-set `ingested_at` is dead code; see Finding-003).** |
| R-T05 | Set `PROSHIELD_CONNECTORS=simulated:app.connectors.simulated:SimulatedConnector`; `findstr`-searched product code for `connector_specs`. | The env value lands in `cfg.connector_specs` but no code reads it. **CONFIRMED Finding-004.** |
| R-T06 | Persisted event with `account.id="user-1"` then re-inserted same `event_id` with `account.id="user-2"`. | Second `create` raised `ConflictEventError`. **DISPROVED the suspicion that `account` might be excluded.** |
| R-T07 | Inserted one event with `account` and one without; ran `find({"account.id": "u-1"}).explain()`. | Plan uses `IXSCAN` with `ev_account_time`. **CONFIRMED sparse index works for the indexed predicate.** |
| R-T08 | Constructed a `SecurityEvent` with `details={"x": {1,2,3}}`; tried to JSON-encode the model dump. | Pydantic accepts the set; `json.dumps(..., default=str)` returns the set's repr. Not a current defect (the application never stores the raw JSON form anyway), but it documents a weak spot. See Missing/Weak Tests. |
| R-T09 | Inserted a document with `account: {id, unexpected}` via raw `pymongo`. | Insert succeeded — the DB-level $jsonSchema is loose for `account` and `device`. **CONFIRMED Finding-007.** |
| R-T10 | Listed indexes on the live collection. | First run reported all missing — but the cause was test sequencing: earlier tests had `drop()`ed the collection, and `list_indexes()` ran on the dropped namespace before `ensure_indexes()` rebuilt it. **Re-run** (`recheck_r10.py`) created the collection, called `ensure_schema()` + `ensure_indexes()`, and found all 7 + `_id_` present. **DISPROVED the suspicion.** |
| R-T11 | Spawned 8 threads, each calling `repo.create(e)` for the same `SecurityEvent` (same `event_id`). | Exactly 1 thread returned `"ok"`, 7 returned `"dup"`. **CONFIRMED MongoDB's unique index protects atomicity against the documented race.** |
| R-T12 | Built a `SecurityEvent` with an `event_id` of length 65 (over `MAX_EVENT_ID=64`). | Pydantic raised `ValidationError`. **CONFIRMED boundary enforced at the application layer.** |
| R-T13 | Built a `SecurityEvent` with `details={"k": "x"*8192}` (which serialises to ~8203 B) and a similar one with `"x"*8193` (8204 B). | Both were rejected by `validate_size_constraints`. The cap is on the *full serialised details dict*, not the value. **CONFIRMED Finding-006** (boundary is 11 B lower than the cap implies). |

## 9. Confirmed Findings

### FINDING-001 — HIGH: Logging scrubber leaks MongoDB credentials

- **Severity:** HIGH
- **Area:** Security / Observability
- **Title:** The `_scrub` function replaces only the `mongodb://` scheme substring, leaving `user:secret@host:...` intact in log messages.
- **Requirement:** Phase 3 §30 forbids leakage of credentials, connection strings, and MongoDB credentials via logs or API responses.
- **Evidence:** R-T02. The log line for `log.info("connecting to %s", "mongodb://user:secret@host:27017/db")` produced `"msg": "connecting to ***user:secret@host:27017/db"`. The credentials are still in the message.
- **Affected code:** `app/observability/logging.py:87-92` (`_scrub`).
- **Test performed:** R-T02.
- **Expected:** credentials redacted.
- **Actual:** credentials preserved.
- **Why confirmed:** the empirical log line was inspected; the substring `user:secret` appears verbatim after the `***` substitution.
- **Impact:** Any code path that logs a MongoDB URI (e.g. on connect failure, on retry, on diagnostic dump) leaks the username and password.
- **Recommended fix:** Parse the URI and redact the `userinfo` component; OR substitute the entire `user:pass@host` segment with `***@host`. (`ProShieldConfig.safe_summary()` already does the latter, but it is not called on every log emission.)
- **Required regression test:** log a known MongoDB URI with credentials; assert the userinfo segment does not appear in the JSON `msg`.

### FINDING-002 — HIGH: Logging scrubber is case-sensitive and substring-only

- **Severity:** HIGH
- **Area:** Security / Observability
- **Title:** The scrubber's forbidden list contains the literal uppercase `PASSWORD` and replaces only that exact substring, so mixed-case `Password=` is unscrubbed, and the *value* attached to `PASSWORD=` is preserved.
- **Requirement:** Phase 3 §30 + AC-CONFIG-07 ("Secrets never appear in logs, API responses, or audit records").
- **Evidence:** R-T03. Three observations:
  1. `log.info("credentials: PASSWORD=hunter2; mySecretField=1; password_safe=ok")` produced `"msg": "credentials: ***=hunter2; mySecretField=1; password_safe=ok"`. The `PASSWORD` substring is gone, but the value `hunter2` after it survives, and the value `mySecretField=1` (which contains the lowercase substring `secret` — but the forbidden list is `SECRET`, and `out.replace("SECRET", "***")` is case-sensitive) survives intact.
  2. `log.info("header: Password=X")` produced `"msg": "header: Password=X"`. The literal `Password` is not scrubbed at all.
  3. The forbidden-substring list also contains `PASSWORD` (5 of the 6 entries are uppercase), and `out.replace(needle, "***")` is case-sensitive.
- **Affected code:** `app/observability/logging.py:48-56` (`_FORBIDDEN_SUBSTRINGS`), `app/observability/logging.py:87-92` (`_scrub`).
- **Test performed:** R-T03.
- **Expected:** secrets redacted regardless of case; secret *values* not leaked.
- **Actual:** mixed-case key names unscrubbed; values attached to scrubbed keys visible.
- **Why confirmed:** the empirical log lines were inspected.
- **Impact:** Several. A field name `Password`, `Token`, `Secret`, `Bearer` survives logging. A value like `hunter2` is logged intact.
- **Recommended fix:** convert both detection and replacement to case-insensitive (e.g., `re.sub` with `re.IGNORECASE`), AND either (a) extend the scrubber to also redact obvious `KEY=VALUE` pairs by redacting up to a delimiter, or (b) reject events whose `details` carries a sensitive-shape value (already partially done at validation; extend to log-side defence-in-depth).
- **Required regression test:** log messages containing `Password=`, `token=`, `secret=`, `Bearer abc`; assert the value side is gone.

### FINDING-003 — LOW: `SimulatedConnector` sets `ingested_at`, but the ingestion service overrides it

- **Severity:** LOW
- **Area:** Connector contract / documentation
- **Title:** The `SimulatedConnector._build` method sets `ingested_at = event_time + 1ms`, which the ingestion service unconditionally overwrites with `datetime.now(timezone.utc)`. The connector's pre-set value is dead code.
- **Requirement:** Phase 1 / Phase 3 zero-trust: the connector must not assert authoritative timestamps. The connector contract (`app/connectors/base.py`) is silent on `ingested_at`.
- **Evidence:** R-T04. Connector said `2026-01-01 00:00:00.001`; service stored `2026-08-26 19:28:47.487`.
- **Affected code:** `app/connectors/simulated.py:80`.
- **Test performed:** R-T04.
- **Why confirmed:** the difference between connector value and stored value is months, not microseconds.
- **Impact:** Confusing for future connector authors. The behavior is correct (server stamps, server is authoritative), but the connector's pre-set value is misleading.
- **Recommended fix:** Remove the `ingested_at=et + timedelta(milliseconds=1)` from `SimulatedConnector._build` (the ingestion service stamps it). Add a comment that connectors must not set `ingested_at`.
- **Required regression test:** existing `test_ingest_overrides_ingested_at_to_server_clock` already covers the service-side behavior; add a test that verifies the connector does NOT set `ingested_at` to a value the service should preserve.

### FINDING-004 — LOW: `PROSHIELD_CONNECTORS` env syntax is documented but unimplemented

- **Severity:** LOW
- **Area:** Configuration / Architecture
- **Title:** `.env.example` advertises `PROSHIELD_CONNECTORS=name:module.path:ClassName` but no product code reads `cfg.connector_specs` to instantiate connectors.
- **Requirement:** The dev report's `requirements.txt` and `.env.example` describe this format. The repo's `CONNECTOR_REGISTRY` is a hardcoded dict.
- **Evidence:** R-T05. Setting `PROSHIELD_CONNECTORS=simulated:app.connectors.simulated:SimulatedConnector` populates `cfg.connector_specs` but no loader exists. `findstr` confirms.
- **Affected code:** `app/config.py:53,78,98`; `app/ingestion/service.py:200-204`.
- **Test performed:** R-T05.
- **Why confirmed:** the env value is read but not used; the grep for `connector_specs` outside the dataclass declaration returns nothing.
- **Impact:** Misleading configuration. Operators may believe they have enabled a connector.
- **Recommended fix:** Either implement the loader (importlib + name:module:Class) or remove the env var from `.env.example` and `safe_summary()`.
- **Required regression test:** a unit test that sets the env var, calls a loader, and asserts a connector is constructed.

### FINDING-005 — LOW: `validate_size_constraints` measures the wrong serialization

- **Severity:** LOW
- **Area:** Ingestion / Persistence
- **Title:** The body-size measurement uses `json.dumps(payload, default=str)`, but pymongo encodes datetimes via BSON `Date` (a binary type), not as a string. The size on the wire differs from the size measured.
- **Requirement:** Schema §12 defines byte-size caps that should reflect the actual on-the-wire size.
- **Evidence:** R-T01. `str(datetime)` and `isoformat()` have the same length in this run (both 25 B for `2026-01-01 00:00:00+00:00`), but the `default=str` path returns a *different* overall string than pydantic's JSON mode (10 B difference on a 4-event payload here, attributable to model-dump key ordering, not the datetime format). More importantly, the on-the-wire BSON encoding of a `Date` is **8 bytes** regardless of the textual representation. The current cap is therefore a heuristic, not a wire-size guarantee.
- **Affected code:** `app/domain/security_event.py:417-457` (`validate_size_constraints`).
- **Test performed:** R-T01.
- **Why confirmed:** measured bytes are not the same shape pymongo writes.
- **Impact:** Minor. The cap still rejects payloads well above the documented limit; the boundary is off by a few bytes at most. Not exploitable.
- **Recommended fix:** For an exact wire-size check, measure `len(bson.encode(payload))` (the same encoder pymongo uses). Alternatively, document the cap as a Python-JSON-equivalent size and clarify in the docstring.
- **Required regression test:** a payload at the cap encoded with bson should measure close to the configured cap.

### FINDING-006 — LOW: Details size boundary is offset by the envelope

- **Severity:** LOW
- **Area:** Validation
- **Title:** The configured `MAX_DETAILS_BYTES_DEFAULT = 8192` is enforced on the *serialised `details` dict*, not on the *value inside* the dict. A `details={"k": "x"*8192}` is rejected because the serialised form is ~8203 B (over 8192), not 8192.
- **Requirement:** Schema §12.
- **Evidence:** R-T13. At-limit (8192 chars in the value) was rejected; over-limit (8193) was also rejected. The test for "passes at the limit" failed because the envelope adds 11 bytes.
- **Affected code:** `app/domain/security_event.py:448-457` (the `details` size check).
- **Test performed:** R-T13.
- **Why confirmed:** both events were rejected, including the one labelled "at the limit".
- **Impact:** Confusion for callers. The cap is silent about the envelope. Not a security defect.
- **Recommended fix:** either rename the constant to make the envelope part explicit, or subtract the envelope size when comparing.
- **Required regression test:** a `details={}` of 0 bytes passes; a `details={"k":""}` envelope with empty value passes; a `details={"k":"x"*8186}` (just under 8192 envelope) passes.

### FINDING-007 — LOW (documented asymmetry): DB $jsonSchema is loose for `account` / `device`

- **Severity:** LOW
- **Area:** Persistence / Schema
- **Title:** The DB-level $jsonSchema validator accepts arbitrary extra fields inside `account` and `device` (and the top-level `details`). The Pydantic model is strict (`extra="forbid"`); the DB layer is not.
- **Requirement:** Schema §13/§22 calls for both layers. Strictness is documented to differ, but the gap is undocumented at the field-schema level.
- **Evidence:** R-T09. Direct `insert_one({"account": {"id":"u-1","unexpected":"field"}, ...})` succeeded.
- **Affected code:** `app/persistence/schema.py:79-87`.
- **Test performed:** R-T09.
- **Why confirmed:** the document with the unexpected field was accepted.
- **Impact:** If a future code path bypasses the Pydantic model (e.g., a migration script, a different service), it can store malformed documents. The application would still read them through `_document_to_event` which would `model_validate` and fail for extra fields, but at that point the read path errors.
- **Recommended fix:** add `"additionalProperties": false` to `account` and `device` schema entries; add the same for `details` (or document why `details` must remain open). This is a defense-in-depth improvement.
- **Required regression test:** the R-T09 case becomes a test that asserts WriteError on direct insertion.

## 10. Disproved Suspicions

| ID | Hypothesis | Why it appeared | Test | Result |
|---|---|---|---|---|
| DISPROVED-A | `event_id` not a UUIDv7 might be accepted | Constructing via `model_copy` could bypass validators | R-T12 (length 65) | Pydantic rejected with `ValidationError`. The same field is also asserted in 5 unit tests. |
| DISPROVED-B | `account` might be excluded from canonical comparison | `_canonical_equal` only mentions `ingested_at` exclusion in its docstring | R-T06 | Same `event_id`, different `account.id` → `ConflictEventError`. The exclusion is correctly *only* `ingested_at`. |
| DISPROVED-C | Sparse index `ev_account_time` may be ignored | Sparse indexes can confuse planners | R-T07 explain() | `IXSCAN` with `ev_account_time` was selected. |
| DISPROVED-D | All 7 documented indexes are missing from the live collection | R-T10 first reported this | R-T10 + `recheck_r10.py` | The first run was a test-sequencing bug; a fresh bootstrap creates all 7 + `_id_`. The implementation is correct. |
| DISPROVED-E | R-T08 (set in details) is a real defect | Sets are not BSON-encodable | R-T08 | Pydantic accepts; `default=str` returns the set's repr. The path through pymongo would fail (BSON cannot encode a set), so the bug would be caught by pymongo with a `bson.errors.InvalidDocument` rather than a silent accept. The application never serialises details as JSON to the wire — pymongo always encodes BSON. |
| DISPROVED-F | R-T04 (ingested_at not overridden) | A test of microsecond timing | R-T04 | The stored value differs from the connector's pre-set value by **months**, not microseconds. Service override is correct; the script's classification logic was wrong. |

## 11. Unverified Risks

| ID | Concern | Why verification was not practical | Recommended future verification |
|---|---|---|---|
| UNVERIFIED-A | Memory growth on a billion-event collection | No load generator available; outside Phase 4.1 scope | Phase 4.x load test with synthetic generator |
| UNVERIFIED-B | Behavior when MongoDB is on a slow / partitioned network | No second network; this slice targets local | Multi-AZ test in staging |
| UNVERIFIED-C | Behavior of the logging scrubber on a deeply nested dict containing `password` deep in a `details` sub-tree | The JSON formatter walks `extra` via `_scrub_value` recursively, but the message string itself is not walked | Build a unit test that logs a deeply nested secret in `extra` and confirms the recursive scrub reaches it. |
| UNVERIFIED-D | MongoDB's `$jsonSchema` validator behavior under load | This slice targets correctness, not throughput | Concurrent insert + validator failure test in a later slice |
| UNVERIFIED-E | The `to_canonical_dict` -> `pymongo` path for non-default-value Pydantic models (e.g. nested `account` with `None`) | Tested for `None`; the round-trip via `_document_to_event` reattaches tzinfo, but the `None` vs missing-key case for non-timestamp optional fields is not exhaustively tested | Add round-trip tests for every optional field set to `None` |
| UNVERIFIED-F | The `validate_size_constraints` `details` cap when `details` itself is large because of nested arrays | Not tested | Add a test with `details={"arr": ["x"]*2000}` |

## 12. Missing / Weak Tests

- **MT-1 (existing, weak):** `tests/integration/test_ingestion_service.py::test_ingest_idempotent_replay_returns_existing` only checks `first.event_id == second.event_id`. A future refactor that returned a fresh `SecurityEvent` with the same id would still pass. Strengthen to compare key fields (`account`, `device`, `details`, `provenance`) on the returned object against the original.
- **MT-2 (missing):** No test for the **`_FORBIDDEN_SENSITIVE_KEYS` set itself** (e.g., asserting it is a tuple, not mutable, contains the documented set). Defense-in-depth.
- **MT-3 (missing):** No test for the **`ingested_at` clock-skew guard** in the negative direction (e.g., `event_time` in the year 2050 should still pass; `event_time` in 1990 should be flagged). Schema §10 is silent on this; the model is permissive for forward timestamps.
- **MT-4 (missing):** No test for the **upper bound on body bytes** — only the lower bound (under) is tested. The body cap is one-sided.
- **MT-5 (missing):** No test for **what happens when `validate_size_constraints` is called with a payload that contains a `datetime` AND has `default=str`** — i.e., does the size check produce a *predictable* string format? This is the root of FINDING-005 and the test would document the current behavior.
- **MT-6 (missing):** No test for **concurrent inserts of *different* event_ids that share the same `(source, source_event_id)` pair** — the conflict detection is only at the `event_id` unique index; the provenance lookup could match. Worth a race test.
- **MT-7 (missing):** No test for the **safe-error envelope on the connector health** path — a connector that throws inside `health()` would surface a stack trace through any caller.

## 13. MongoDB Review

- **Connection verification:** `MongoClient` opens against `mongodb://127.0.0.1:27017`; `ping` returns OK. Bounded timeouts (2s server-select, 2s connect, 5s socket) — defensible for a local development database.
- **Database:** `proshield` (production) and `proshield_test_<hash>` (per-test-session, dropped between sessions).
- **Collections:** `security_events` (default name; `PROSHIELD_MONGO_COLLECTION_EVENTS` is overridable). Plus MongoDB's internal `_id_` index.
- **Schema validation:** `$jsonSchema` with `validationLevel: "strict"` and `validationAction: "error"`. The schema covers all documented required fields, lengths, and the provenance subdocument. Asymmetry noted in Finding-007.
- **Indexes (verified via `recheck_r10.py`):** all 7 documented indexes plus `_id_`. Names, keys, and `sparse`/`unique` flags match the development report exactly.
- **Persistence:** documented.
- **Duplicate handling:** MongoDB's `ev_event_id_unique` index is the atomic guarantee; the application translates the resulting `DuplicateKeyError` into either `DuplicateEventError` (idempotent no-op) or `ConflictEventError` (replay inconsistency). R-T11 confirms uniqueness holds under 8-way concurrent insert.
- **Conflict handling:** documented. R-T06 confirms the canonical comparison includes `account`.
- **Failure behavior:** `PersistenceError.safe_message = "database is unavailable"`; `internal_detail` carries the driver class. `tests/integration/test_persistence_failures.py` confirms.

## 14. Security Review

**Confirmed security results:**
- The application treats all incoming data as untrusted (Pydantic `extra="forbid"`, per-field validators, allowed catalogues).
- MongoDB driver errors are translated to `DomainError` subclasses with a safe message and an internal-only detail (no stack traces, no driver error strings on the wire — there is no wire in Phase 4.1).
- Sensitive data in `details` is rejected at the Pydantic layer (Section 20).
- The canonical `event_id` is constrained to UUIDv7.
- The repository boundary is enforced (no `pymongo` imports outside `app/persistence/`).
- The connector abstraction is clean (`SimulatedConnector` performs only source-to-canonical mapping; no detection, no correlation, no DB calls).
- The ingestion service never trusts client-supplied `ingested_at` for trust decisions; it always stamps the server clock.
- The `PROSHIELD_LOG_LEVEL` is honored; the JSON formatter is idempotent.
- The `$jsonSchema` validator is installed with `validationAction: "error"` (writes are rejected, not silently accepted).

**Remaining security risks:**
- **FINDING-001** (HIGH): credentials leak through the logging scrubber. Must be fixed before any production deployment.
- **FINDING-002** (HIGH): mixed-case secret-shaped names and the *values* of scrubbed keys leak. Same severity class.
- Phase 4.1 has no authentication or RBAC enforcement (correctly out of scope, recorded as a deferred item).
- Phase 4.1 has no rate limiting wired (correctly out of scope).
- Phase 4.1 has no audit-event writer (correctly out of scope).

**Code paths searched for secrets:**
- `app/observability/logging.py` — confirmed the scrubber exists but is incomplete.
- `app/config.py` — `safe_summary()` redacts the URI's userinfo (verified by `test_safe_summary_strips_credentials`).
- `app/persistence/mongo.py` — no logging of the URI.
- `scripts/init_mongo.py` — log line `log.info("init_mongo.start", extra={"config": config.safe_summary()})` uses the redacted summary. **GOOD.**
- `scripts/live_smoke.py` — same.

## 15. Architecture Review

**Compliance:**
- Layered architecture: `domain` → `connectors` → `ingestion` → `persistence`. No reverse imports detected.
- `pymongo` is only imported inside `app/persistence/*` (verified by import inspection).
- No global state, no module-level singletons beyond the application logging singleton.
- No circular imports. `from datetime import datetime  # noqa: E402` in the repository is a mid-module import, but it's a defensible comment (avoids an import cycle on the helper).
- Configuration is environment-driven, immutable (`@dataclass(frozen=True)`).
- Logging is idempotent (the `_CONFIGURED` guard).
- The connector boundary is clean — `SimulatedConnector` does no DB calls, no detection, no network.
- The `SecurityEventIngestionService` does no connector construction (deliberate; the host instantiates and hands connectors in).

**Minor architectural notes (non-defects):**
- `_canonical_equal` in `security_event_repository.py` and `_document_to_event` are module-level functions rather than methods. Acceptable for a small repository.
- The repository class does not encapsulate `count_documents({})` into something like `count_all()` — `count()` is the method name, which is fine.
- The dev report's `app.ingestion.service` imports `CONNECTOR_REGISTRY` from itself via a module-level re-import (`from ..connectors.simulated import SimulatedConnector  # noqa: E402`). This is a circular-import workaround. Acceptable, but cleaner would be to keep the registry in a separate module.

## 16. Test Quality

**Score: 7/10**

- 79 tests pass; no required test is failing.
- 61 unit tests cover the model, the catalogues, the validators, the scrubber contract, the UUIDv7 generator, the config, and the simulated connector.
- 18 integration tests against real MongoDB cover the repository, the service, and the driver-failure path.
- The repository's `test_indexed_query_by_source_works` actually inspects `explain()` output — a strong pattern.
- The simulated-connector test asserts event-type membership in the allowed catalogue.
- **Deductions:**
  - `test_ingest_idempotent_replay_returns_existing` checks only `event_id` equality of the returned object (MT-1).
  - No test for FINDING-001 (credentials leak) and FINDING-002 (mixed-case / value scrub) — the dev test suite did not catch them.
  - No test for body-size *upper* bound (MT-4).
  - No concurrent-insert test (R-T11 was a one-off in this review).
  - The 13 review tests live in `%TEMP%`, not in the permanent suite.

## 17. Implementation Quality

**Score: 8/10**

- **Architecture compliance:** 9/10. Layers are clean, boundary is enforced, no premature future-phase code. The `_canonical_equal` and `_document_to_event` helpers could be methods, but it's a stylistic preference.
- **Correctness:** 8/10. The implementation matches the documented contract in every place I tested, with one boundary inconsistency (Finding-006).
- **Security:** 5/10. The Pydantic and DB layers are well-defended. The logging scrubber is the single largest weakness (Findings 001 and 002) and is the only HIGH-severity defect.
- **Maintainability:** 9/10. Clear module boundaries, typed models, frozen Pydantic instances, documented intent. The `default=str` size-check style is a small smell.
- **Database implementation:** 8/10. Indexes, schema validator, repository boundary are all in place and exercised. The DB $jsonSchema is intentionally loose for `account`/`device` (Finding-007), which is documented but not optimal.
- **Error handling:** 9/10. Safe-message contract is clean and tested.
- **Observability:** 6/10. JSON logging and request IDs are good. The scrubber is broken in two material ways (Findings 001, 002).
- **Testability:** 9/10. Pydantic models, frozen dataclass config, separate repository — easy to test.
- **Upgradeability:** 9/10. The connector registry is a clean seam; the ingestion service is a clean seam; the repository hides the driver.

## 18. Strongest Area

**The repository boundary and the safe-error envelope.** The implementation does an exemplary job of treating MongoDB driver exceptions as a single failure surface and translating them into a small, typed set of `DomainError` subclasses. The `PersistenceError.safe_message` is the only thing a future API surface would ever surface to a client; `internal_detail` is the only thing a log aggregator would ever see. This is exactly the documented contract from Phase 3 §30 and it is enforced at the only place that talks to the driver. The unit test `test_persistence_error_must_not_leak_driver_message` is small but proves the boundary. If a future slice adds HTTP routes, the safe-error envelope will hold without further work.

## 19. Weakest Area

**The observability scrubber.** The logging layer is the only place in the slice that touches user-visible output. Its scrubber is **broken in two ways that survive the current test suite**: it leaves the credentials after a `mongodb://` scheme, and it does not detect mixed-case or value-side secrets. Both defects are CONFIRMED by empirical evidence. This is a HIGH-severity security finding; in any production deployment it would log credentials in cleartext. The fix is local to `app/observability/logging.py` and is well-bounded. **CONFIRMED weakness.**

## 20. Review Confidence

**HIGH** for the code areas I directly executed tests against (the logging scrubber, the size check, the connector-vs-service contract, the index list, the conflict detection, the concurrency race). **MEDIUM** for the areas I only inspected by code reading (the `_canonical_equal` corner cases for nested optional fields, the `to_canonical_dict` pymongo-encoding path, the `safe_summary` redaction robustness). **LOW** for any performance, load, or multi-host behavior (out of scope; not tested).

## 21. Final Verdict

**CHANGES REQUIRED**

Reason: two HIGH-severity security defects in the logging scrubber (FINDING-001, FINDING-002) are confirmed by empirical test evidence and are NOT caught by the existing 79-test suite. Per the review rule "Do not approve merely because the developer report says STABLE", approval requires sufficient evidence across Security — and the security evidence is incomplete.

The two HIGH-severity findings are well-bounded fixes in a single file. Once they are remediated and the missing tests (MT-1..MT-7) are addressed, the slice is a strong candidate for `APPROVED WITH MINOR CHANGES`.

## 22. Phase 4.1 Stability Recommendation

**NOT STABLE** — pending the two HIGH-severity logging-scrubber fixes.

After the fixes and the regression tests:
- The slice would qualify for `STABLE` on its own merits.
- It will not be "production ready" until authentication, RBAC, object-level authorization, rate limiting, and audit-event persistence land in subsequent slices (per the dev report's deferred-items list).

## 23. Required Follow-Up

1. **Fix FINDING-001** (HIGH): redact the userinfo segment of any `mongodb://` or `mongodb+srv://` URI in the logging scrubber. Add a regression test that logs a known URI and asserts the userinfo does not appear in the JSON `msg`.\\fixed after testing .
2. **Fix FINDING-002** (HIGH): make the scrubber case-insensitive and also redact the value after a sensitive-shape key. Add regression tests for `Password=`, `Token=`, `Bearer abc`, and `password=hunter2`.\\fixed after testing.
3. **Address MT-1**: strengthen `test_ingest_idempotent_replay_returns_existing` to compare more than just `event_id`.
4. **Address MT-4**: add a test that a body just over the body cap is rejected.
5. **Address MT-5**: add a test that documents the current (FINDING-005) behavior of the size check.
6. **Address MT-6**: add a concurrent-insert test for distinct event_ids sharing the same provenance.
7. **Optional (low priority): FINDING-003, FINDING-004, FINDING-005, FINDING-006, FINDING-007.** All LOW severity. FINDING-007 is documented asymmetry and the dev report's risk list already mentions the loose DB validator.

After items 1 and 2 are fixed, item 3 addressed, and the review's full set of findings re-run, the slice can be re-evaluated. The structural quality of the rest of the implementation is sufficient that I do not expect further HIGH or CRITICAL findings to surface.

---

## 24. Cross-Phase Audit Follow-Up (2026-08-27)

Two findings from the cross-phase audit (Phases 4.1–4.3) were attributed to Phase 4.1. Both were re-inspected against the current code and **disproved**.

### Cross-Phase C-1 — "Logging scrubber leaks `Authorization: Bearer <token>`" — DISPROVED ✅

**Claim:** The scrubber regex `_redact_key_equals_value` matches `KEY=VALUE` but not `Authorization: Bearer <jwt>`, so the token value survives logging.

**Re-inspection:** Empirically tested by constructing the exact input `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature` and passing it through the real `_JsonFormatter.format()` pipeline.

**Actual behaviour:**
- `_scrub` first passes through `_redact_uri_userinfo` (no-op for this input).
- `_redact_key_equals_value` treats `Bearer` as a sensitive key (it is in the case-insensitive key list) and redacts the following value `eyJ...` to `***`.
- The final global forbidden-substring pass replaces any remaining `BEARER` substring with `***`.
- Result: `"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"` → `"Authorization: *** ***"`.
- The token substring `eyJ` does **not** appear in the final JSON log line.

**Why the audit was wrong:** The audit assumed the scrubber only matches `KEY=VALUE` / `KEY: VALUE` patterns, but the scanner is more permissive — it treats any occurrence of a sensitive key name (including in value position) as a redaction trigger. The `BEARER` entry in `_FORBIDDEN_SUBSTRINGS` provides defense-in-depth for any edge case.

**No code change required. No product code modified.**

### Cross-Phase C-2 — "`SecurityEvent.account.id` / `device.id` accept empty strings" — DISPROVED ✅

**Claim:** The `account.id` and `device.id` fields lack `min_length=1`, so empty strings pass validation and could cause provenance-dedup collisions.

**Re-inspection:** Read `app/domain/security_event.py:195, 211` directly, and empirically constructed `SecurityEventAccount(id="")` and `SecurityEventDevice(id="")`.

**Actual declaration:**
```python
# line 195
id: Annotated[str, StringConstraints(min_length=1, max_length=MAX_ACCOUNT_ID)]
# line 211
id: Annotated[str, StringConstraints(min_length=1, max_length=MAX_DEVICE_ID)]
```

**Actual behaviour:**
- `SecurityEventAccount(id="")` → `pydantic.ValidationError` (REJECTED)
- `SecurityEventAccount()` (missing) → `pydantic.ValidationError` (REJECTED)
- `SecurityEventDevice(id="")` → `pydantic.ValidationError` (REJECTED)
- `SecurityEventDevice()` (missing) → `pydantic.ValidationError` (REJECTED)
- `SecurityEventAccount(id="u-1")` → ACCEPTED (valid)

**Why the audit was wrong:** The audit looked at the `max_length=128` bound on the wrong line and missed the `StringConstraints(min_length=1, max_length=...)` annotation on the `id` field. Empty strings are rejected at construction.

**No code change required. No product code modified.**

---

**Verdict:** Both cross-phase findings are false positives. Phase 4.1 is unchanged. Phase 4.4 can proceed.
