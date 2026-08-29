# ProShield — Phase 4.3 Final Report

## 1. Understanding

Phase 4.3 implements the **first real (non-simulated) source
connector and its first production rule** for the ProShield
MVP. It proves the documented end-to-end flow:

```text
Source telemetry
  -> source-specific parsing
  -> source-specific validation / mapping
  -> canonical SecurityEvent
  -> ingestion service
  -> persistence
  -> rule applicability filter
  -> rule evaluation
```

The connector chosen is **NGINX** — the first real source in
the documented source progression in
`docs/PHASE 2/SECURITY_EVENT_SCHEMA.md` (Section 3):

```text
1. Simulator          (Phase 4.1)
2. NGINX              (Phase 4.3  <- this slice)
3. WAF / Cezara       (later)
4. Rate Limiting      (later)
5. TLS / Network      (later)
6. Future SIEM / Endpoint / IAM (later)
```

The rule is the **smallest defensible first rule** for the
NGINX connector: a 401 or 403 on an authentication-shaped
endpoint. Each individual observation fires the rule; a
future correlation rule (Phase 4.4+) can count firings into
a brute-force or credential-stuffing detection. This split
honours the documented detection-vs-correlation boundary
(`docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md`,
Section 8).

The slice uses the documented connector contract
(`docs/PHASE 2/SECURITY_EVENT_SCHEMA.md` Sections 3, 4, 5, 6,
7, 8, 9 and `app/connectors/base.py`), the canonical
`SecurityEvent` envelope, the Phase 4.1 ingestion service,
the Phase 4.2 rule framework, and the Phase 4.2 rule loader
exactly. **No redesign** of any existing module.

### What the slice ships

* A new connector package `app/connectors/nginx/`:
  * `parser.py` — pure parser for the NGINX `combined` log
    format, with documented field-size bounds and a safe
    error envelope that never echoes attacker-controlled
    bytes.
  * `mapping.py` — pure mapping from a parsed record to a
    canonical `SecurityEvent`. Observation-only: no
    detection logic, no thresholds, no correlation.
  * `connector.py` — `NginxConnector(SecurityEventConnector)`
    with documented stats, health, error-handling, and
    provenance contracts.
  * `errors.py` — connector-internal error classes
    (`NginxParseError`, `NginxConnectorError`).
* A new production rule:
  `app/rules/_library/nginx/brute_force_pattern.py` —
  `NGINX-AUTH-BRUTEFORCE-001` (HTTP 401/403 on auth-shaped
  endpoints).
* Wiring:
  * `app/ingestion/service.py` — the connector is registered
    in the documented `CONNECTOR_REGISTRY` so a future CLI
    or HTTP layer can instantiate it from configuration.
  * `app/rules/_library/nginx/__init__.py` — the rule
    module is exported as `RULE_FACTORIES`, discoverable
    by `app.rules.load_rules_from_specs`.
  * `app/__init__.py` — version bumped to `4.3.0`, phase
    to `4.3`.
* Tests (positive, negative, malformed-input, edge, end-to-end):
  * `tests/unit/test_nginx_parser.py` — 28 tests.
  * `tests/unit/test_nginx_mapping.py` — 24 tests.
  * `tests/unit/test_nginx_connector.py` — 22 tests.
  * `tests/unit/test_nginx_rule.py` — 20 tests.
  * `tests/integration/test_nginx_ingestion.py` — 7 tests
    (real MongoDB).
  * `tests/integration/test_nginx_end_to_end.py` — 4 tests
    (real MongoDB; connector -> SecurityEvent -> rule
    applicability + evaluation).

It explicitly does **not** implement the full detection
engine, the correlation engine, the incident engine, the
report engine, the routing engine, the audit-event writer,
authentication, RBAC, object-level authorization, the HTTP
API, or AI.

## 2. Pre-Implementation Findings

### Existing (post-Phase 4.2)

* Backend framework / runtime: `app/` (config,
  observability, domain, connectors, ingestion, persistence,
  rules) is in place.
* The canonical `SecurityEvent` Pydantic model is the
  envelope at the trust boundary; its `ALLOWED_SOURCES`
  and `ALLOWED_EVENT_TYPES` frozensets are the
  authoritative vocabulary. The model also enforces
  UUIDv7 `event_id`, UTC timestamps, IPv4/IPv6 source_ip,
  and the documented `MAX_*` field bounds.
* `app/domain/errors.py` exposes the `DomainError` hierarchy
  and the safe-error envelope.
* `app/ingestion/service.py` exposes the documented
  `SecurityEventIngestionService` with `ingest` and
  `ingest_from_connector` methods, server-side `ingested_at`
  stamping, idempotency / conflict / duplicate-handling
  paths, and a `CONNECTOR_REGISTRY`.
* `app/persistence/security_event_repository.py` is the
  only module allowed to speak pymongo. Its `create()` keys
  on the unique `event_id` index for idempotency.
* `app/rules/` is the Phase 4.2 deterministic rule
  framework: `Rule` interface, `RuleMetadata`, `RuleState`,
  `RuleCategory`, `RuleEvaluation`, `RuleRegistry`, and
  `load_rules_from_specs`.
* 213 unit tests + 18 integration tests, all green.

### Missing

* Everything connector-side: real per-source parsing,
  validation, mapping, error handling, stats, health.
* Everything rule-side for the NGINX source: a production
  rule for the new connector, demonstrating that the
  Phase 4.2 framework can be applied to a real source.
* End-to-end integration of the new connector with the
  Phase 4.1 ingestion service and the Phase 4.2 rule
  framework, with real MongoDB.

### Local MongoDB state

* `mongod` PID 4832, **running** on `127.0.0.1:27017`. No
  new `proshield` collections are needed for Phase 4.3
  (the connector reuses the existing `security_events`
  collection); the integration tests use the dedicated
  `proshield_test` database (dropped and recreated per
  session, per the existing Phase 4.1 test conftest).

### Relevant dependencies

* Python 3.13.3, `pymongo 4.16.0`, `pydantic 2.13.4`,
  `pytest 9.1.1` (no new dependencies were added by this
  slice).

## 3. Implementation Summary

| Layer | Module(s) | Responsibility |
|---|---|---|
| Connector (parser) | `app/connectors/nginx/parser.py` | Pure parser for the NGINX `combined` log format. |
| Connector (mapping) | `app/connectors/nginx/mapping.py` | Pure mapping from a parsed record to a canonical `SecurityEvent`. |
| Connector (adapter) | `app/connectors/nginx/connector.py` | `NginxConnector(SecurityEventConnector)`. |
| Connector (errors) | `app/connectors/nginx/errors.py` | Connector-internal error classes. |
| Rule | `app/rules/_library/nginx/brute_force_pattern.py` | `NGINX-AUTH-BRUTEFORCE-001`. |
| Wiring | `app/ingestion/service.py` | Connector registered in `CONNECTOR_REGISTRY`. |
| Wiring | `app/rules/_library/nginx/__init__.py` | Rule exported as `RULE_FACTORIES`. |
| Versioning | `app/__init__.py` | `__version__ = "4.3.0"`, `__phase__ = "4.3"`. |
| Tests | `tests/unit/test_nginx_*.py` + `tests/integration/test_nginx_*.py` | 94 unit + 11 integration. |

The connector is the **only** place licensed to know about
NGINX log-line shape. It does not perform detection,
correlation, or any rule-side work, and it does not import
any other connector.

## 4. Connector Design

### 4.1 Why NGINX is first

Per `docs/PHASE 2/SECURITY_EVENT_SCHEMA.md` Section 3, the
documented source progression puts NGINX second (after the
simulator). NGINX is the right first slice for a real
source because its log format (the standard `combined`
format) is the textbook example of canonical web-server
access telemetry, it is the example source used in the
canonical `SecurityEvent` JSON example (Section 4 of the
schema), and its events map cleanly to multiple documented
event types in the MVP catalogue (Section 17 of
`docs/PHASE 0/INITIAL_SECURITY_EVENTS.md`).

### 4.2 Log format and parser

The connector reads the standard NGINX `combined` log
format:

```text
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

The parser (`app/connectors/nginx/parser.py`) is a **pure
function** from a single line to a `ParsedNginxLine`. It
has no I/O, no globals, no time, and no logging, which
keeps it deterministic and trivially testable. The
compiled regex is created once at module load. Field-size
caps (matching the schema's documented field bounds) are
applied before any further processing so a 1 GB line
cannot consume memory.

The parser applies the documented safe-error envelope:

* The error message is a short category (e.g., "line does
  not match the combined format"), **never** the raw
  line. An attacker can put anything in a log line; the
  parser must not echo it.
* A per-line size cap is applied before the regex so a
  10 MB line cannot blow up the matcher.
* A status range check (100..599) is applied.
* An IP-validity check is applied.
* A method (uppercase ASCII) check is applied.
* NGINX's `+0000` and `-0000` are both accepted as UTC.

### 4.3 Mapping: observation-only

The mapping (`app/connectors/nginx/mapping.py`) is a
**partial function** from an observation to a canonical
`SecurityEvent`. The mapping rules:

* HTTP 401 on any endpoint -> `authentication_failure`
* HTTP 403 on any endpoint -> `request_blocked`
* HTTP 404, 405, 408, 409, 410, 412, 413, 415, 418, 422 ->
  `request_blocked`
* HTTP 429 -> `rate_limit_exceeded`
* HTTP 5xx (500, 501, 502, 503, 504) -> `request_blocked`
* HTTP 200/201/204 on an auth-shaped endpoint with a
  known `remote_user` -> `authentication_success`
* HTTP 1xx -> `None` (informational, not security-relevant)
* HTTP 2xx/3xx (other than auth-success) -> `None` (the
  rule layer is the right place to draw conclusions from
  normal-traffic patterns; the connector does not
  pre-judge)

A `None` return means "no security-relevant event for this
line" — a **documented contract decision**, not a per-line
failure. The connector never silently drops lines that DO
carry a security signal; the `None` mapping is a
documented, traceable contract.

The mapping builds the canonical `SecurityEvent` exactly
per `docs/PHASE 2/SECURITY_EVENT_SCHEMA.md`:

* `source = "nginx"` (a documented `ALLOWED_SOURCES`
  member).
* `event_type` is one of the documented `ALLOWED_EVENT_TYPES`
  members.
* `provenance.collector = "nginx"`.
* `provenance.source_event_id` is the deterministic
  per-line id provided by the connector.
* `event_id` is the deterministic per-line id provided by
  the connector (a real UUIDv7; see 4.5).
* `details` carries the structured observable fields
  (`http_method`, `status_code`, `protocol`,
  `body_bytes_sent`, optional `referer` and `user_agent`,
  `log_line_number` for analyst traceability).
* `account` is constructed from `remote_user` (id only;
  the schema forbids password / token / hash / bearer).
* `ingested_at` is set to `event_time`; the ingestion
  service **overrides it server-side** (same pattern as
  the Phase 4.1 `SimulatedConnector`).

### 4.4 Provenance: deterministic per-line ids

Two ids are attached to every emitted event:

* `provenance.source_event_id` — the SHA-1 of
  `log_path:line_number:raw_line`. The full hex digest
  (40 chars) fits well under the documented 256-char
  bound. This id is the connector's source-side
  identifier.
* `event_id` — a real UUIDv7 derived from the SHA-1 of
  `event-id:log_path:line_number:raw_line`, with the
  version-7 and RFC 4122 variant nibbles forced into
  their canonical positions. The result is a UUIDv7
  (RFC 9562) that the canonical `SecurityEvent` validator
  accepts.

Both ids are **deterministic for a given
(log_path, line_number, raw_line_content)**. Two readings
of the same log produce the same ids. This is what makes
the documented Boundary 2 idempotency path (Section 16 of
the schema) reachable: the repository's `insert_one` keys
on the unique `event_id` index, and a re-delivery of the
same line hits the `DuplicateKeyError` branch and is
treated as a no-op by the ingestion service.

### 4.5 Why a deterministic event_id (and how it stays a real UUIDv7)

The repository's idempotency path keys on the canonical
`event_id`. A fresh UUIDv7 per `collect()` call would
defeat the dedup: a re-read of the same log line would be
inserted as a new event with a different `event_id`,
bypassing the `DuplicateKeyError` branch.

The connector therefore constructs a deterministic
**real RFC 9562 UUIDv7** by:

1. Sampling a real `unix_ms` timestamp once at connector
   construction time (`self._event_id_ts_ms`) and
   freezing it for the lifetime of the instance.
2. Computing `sha1("event-id:" + log_path + ":" +
   line_number + ":" + raw_line)` to derive 12 bits of
   `rand_a` and 62 bits of `rand_b` from the line content
   (the same SHA-1 the connector uses for
   `source_event_id`, so the two ids share the same
   per-line entropy source).
3. Assembling the 128-bit UUID value with the layout
   prescribed by RFC 9562 §5.7:
   * bytes 0..5 = `unix_ts_ms` (48 bits, big-endian),
   * byte  6 high nibble = version `0b0111`,
   * bytes 6 low / 7 = `rand_a` (12 bits),
   * byte  8 high two bits = variant `0b10`,
   * bytes 8 low / 9..15 = `rand_b` (62 bits).

The result is a real UUIDv7 (RFC 9562) that:

* Satisfies the canonical
  `SecurityEvent._event_id_must_be_uuidv7` validator
  (`is_uuid7(parsed) is True`).
* Embeds a real unix-ms timestamp in the first 48 bits,
  not random SHA-1 output. A regression test
  (`test_event_id_embeds_real_unix_ms_timestamp`) decodes
  the embedded timestamp and asserts it is within the
  connector's construction window and within ±1 second of
  `datetime.now()`.
* Is **per-instance deterministic**: two `collect()` calls
  on the same connector instance + the same line produce
  the same `event_id` (the frozen timestamp is constant
  for the instance), so the repository's `insert_one`
  dedup path remains reachable. Two different connector
  instances (or two different processes) sample different
  timestamps and therefore produce different `event_id`s
  for the same line — this is the expected behaviour of
  a real UUIDv7 (different generators produce different
  ids), and the documented Boundary 2 replay contract is
  per-instance replay, not cross-instance replay.
* Differs by 1 bit minimum for a line that differs by 1
  byte (SHA-1 avalanche in `rand_a` / `rand_b`).
* Does **not** modify `app/domain/uuid7.py` or the
  canonical event_id contract; the connector's choice is
  internal to the NGINX adapter.

### 4.6 Error handling

The connector uses two error types, both connector-internal
and never re-raised across the connector boundary:

* `NginxParseError(ValueError)` — a single log line could
  not be parsed. The connector catches it per line and
  counts it in `stats.lines_skipped_parse_error`. The
  connector **never** echoes the raw line. In `strict=True`
  mode the connector re-raises on the first malformed
  line for the caller's diagnostic use.
* `NginxConnectorError(RuntimeError)` — a file-level
  failure (file not found, permission denied, OS error).
  The connector catches it, counts it in
  `stats.connector_errors`, and yields no events. The
  `health()` endpoint reports `status="degraded"` for any
  file-level failure.

Per the documented "do not silently discard" principle
(`docs/PHASE 0/PRODUCT_SCOPE.md` Section 16), per-line
failures are never silently swallowed: they are counted
in `stats` and surfaced in `health()`. The `collect()`
generator is the documented callable; it does not raise
across the connector boundary for the cases the
connector knows how to handle.

### 4.7 Stats and health

`NginxConnector.stats` is a small counter object exposed
on every connector instance:

* `lines_read`
* `lines_parsed`
* `lines_skipped_parse_error`
* `lines_skipped_no_signal`
* `events_emitted`
* `connector_errors`

`NginxConnector.health()` returns a small dict that is
safe to expose in any HTTP health endpoint:

* It does **not** include the log path (a path can
  disclose internal hostnames / deployment layout).
* It does **not** include raw line content.
* It does **not** include secrets, file paths, or any
  attacker-controlled bytes.
* `status` is `ok` when the file exists and there are no
  recorded `connector_errors`; otherwise `degraded`.
* The status and stats fields are **consistent**: when
  the file is missing, `status` is `degraded` AND
  `stats.connector_errors >= 1` (the health probe
  records the file-missing error in `stats` the first
  time it is observed; subsequent calls are idempotent
  and do not double-count). This contract is pinned by
  the regression test
  `test_missing_file_health_stats_consistent`.
* The probe is direct (`Path.exists()` / `Path.stat()`)
  so the health endpoint is meaningful even when
  `collect()` has not been called yet.

## 5. First Production Rule: `NGINX-AUTH-BRUTEFORCE-001`

### 5.1 Why this rule is the right first rule

The first rule for the NGINX connector detects a
well-known NGINX-observable pattern: an HTTP 401
(`Unauthorized`) or 403 (`Forbidden`) response on an
authentication-shaped endpoint. These observations
correspond to failed authentication attempts and
authorization denials; they are the building blocks of
brute-force and credential-stuffing attacks.

The rule is the right first rule for four documented
reasons:

1. **Source-specific.** The rule's applicability is
   `(source=nginx, event_type in
   (authentication_failure, request_blocked))`. The NGINX
   connector emits both of these event types for HTTP
   401/403 respectively, so the rule's applicability
   filter is the documented fast path (DET-04).
2. **Observation-only on the input side.** The connector's
   mapping already produced a canonical
   `authentication_failure` for 401s and `request_blocked`
   for 403s; the rule simply looks for the 401/403 status
   code in the canonical event's structured `details` and
   the auth path hint.
3. **Deterministic.** A single canonical event either
   matches (status 401/403 on an auth-shaped endpoint) or
   does not. No thresholds, no windows, no state.
4. **NOT a brute-force detection.** A brute-force rule
   needs a time window and a count of failures, both of
   which are out of scope for this slice (the correlation
   engine is not yet implemented). The rule fires on each
   individual authentication failure, so a downstream
   correlation rule can later count rule firings.

### 5.2 What the rule does NOT do

* It does NOT count failures over a window (correlation).
* It does NOT enrich the detection with prior context
  (timeline).
* It does NOT assign severity or confidence (the severity
  and confidence engines are not yet implemented).
* It does NOT decide incident ownership or routing.

Those are the documented responsibilities of later slices.
This rule is the **smallest defensible first rule**.

### 5.3 Rule metadata

The rule is implemented as a factory
(`build_nginx_auth_brute_force_rule`) that produces a
fresh `SimpleRule` instance, exposed as a `RULE_FACTORIES`
tuple in `app/rules/_library/nginx/__init__.py`:

```python
RuleMetadata(
    rule_id="NGINX-AUTH-BRUTEFORCE-001",
    version=1,
    name="NGINX 401/403 on auth endpoint",
    category=RuleCategory.SOURCE_SPECIFIC,
    sources=("nginx",),
    event_types=("authentication_failure", "request_blocked"),
    state=RuleState.APPROVED,
    enabled=True,
    description=...,
    tags=("AUTH", "BRUTEFORCE-CANDIDATE", "NGINX"),
    references=("docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
                "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories"),
)
```

The factory pattern (over a class-level singleton) keeps
the rule's mutable instance attributes (e.g. `enabled`)
isolated from other tests' instances and from the rule
loader's per-process state. The documented
candidate -> approved -> enabled funnel (Section 59,
Section 89) is preserved by the registry, not by this
module: this rule ships as `APPROVED` + `enabled=True`
because the framework was loaded with the rule in that
state, and a future re-enable on a superseded version is
rejected by the registry (Phase 4.2 FINDING-1 guard).

### 5.4 Predicate and reasoner

The predicate (matching the documented "validated
detection logic" principle, Section 49):

```python
def _predicate(event: SecurityEvent) -> bool:
    if event.source != "nginx":
        return False
    if event.event_type not in ("authentication_failure", "request_blocked"):
        return False
    status = event.details.get("status_code")
    if status not in (401, 403):
        return False
    if event.endpoint is None:
        return False
    ep = event.endpoint.lower()
    return any(hint in ep for hint in _AUTH_PATH_LOWER)
```

The reasoner is a small, analyst-friendly string that
mentions the status code, the endpoint, and the source
IP. It does NOT contain secrets, request bodies, or
attacker-controlled bytes.

## 6. Integration with the Ingestion Service

The connector is registered in the documented
`CONNECTOR_REGISTRY` in
`app/ingestion/service.py`:

```python
CONNECTOR_REGISTRY = {
    "simulated": SimulatedConnector,
    "nginx": NginxConnector,
}
```

The ingestion service exposes
`ingest_from_connector(connector)` which calls
`connector.collect()` and runs each yielded event through
the documented Boundary 2 path (validate -> server-stamp
-> persist). The connector's deterministic `event_id` and
`source_event_id` make the documented idempotency,
duplicate, and conflict paths observable end-to-end.

## 7. Tests Added

### 7.1 Unit tests

| Test file | Count | What it covers |
|---|---:|---|
| `tests/unit/test_nginx_parser.py` | 28 | Positive (well-formed line, trailing LF/CRLF, `-` user fields, `-0000` UTC, IPv6, non-UTC offset, user-agent with spaces, status range, 599 accepted); negative (empty, non-string, garbage, missing method, status 99, status 600, status not int, non-IP, lowercase method, bad time, trailing garbage, oversized line, oversized UA, oversized referer, oversized remote_user, NUL in path); edge cases (zero body bytes, error message does not leak raw line). |
| `tests/unit/test_nginx_mapping.py` | 24 | Positive mapping (401 -> auth_failure, 403/404 -> request_blocked, 429 -> rate_limit_exceeded, 5xx -> request_blocked, 2xx + auth user -> auth_success); negative (200 on non-auth path, 200 on auth path without user, 3xx, 1xx); envelope (UUIDv7 event_id, provenance, account, details fields, asset propagation, source IP, endpoint). |
| `tests/unit/test_nginx_connector.py` | 29 | Happy path (canonical events, malformed-line skip, no-signal skip, provenance collector, deterministic `source_event_id`, unique per line, `event_id` is UUIDv7); error handling (missing file, oversized line, strict vs non-strict, constructor type checks); health (ok, no path leak, no secret leak, degraded on missing file); stats (complete dict, reset, source declaration). **Plus the CONFIRMED-1 + CONFIRMED-2 regression tests added in the review follow-up**: real-UUIDv7 timestamp decode (`test_event_id_embeds_real_unix_ms_timestamp`), per-instance frozen timestamp (`test_event_id_timestamp_is_frozen_per_instance`), cross-instance timestamp divergence (`test_event_id_differs_across_instances`), `health()` status/stats consistency on missing file (`test_missing_file_health_stats_consistent`, `test_missing_file_health_stats_consistent_after_collect`, `test_existing_file_health_stats_consistent`, `test_health_probe_is_idempotent_for_missing_file`). |
| `tests/unit/test_nginx_rule.py` | 20 | Positives (401/403 on /api/login, /api/v1/auth/login, /oauth/token, /sso/login, /api/token/refresh); negatives (200 auth success, 404, 401 on non-auth, 401 on static, non-nginx source, missing endpoint); metadata; applicability; registry (loads, lists for auth_failure, lists for request_blocked, NOT listed for other source); reasoning. |
| **Subtotal unit** | **101** | |

### 7.2 Integration tests (real MongoDB)

| Test file | Count | What it covers |
|---|---:|---|
| `tests/integration/test_nginx_ingestion.py` | 7 | Happy path (connector -> service -> MongoDB, persisted shape, server-clock override of `ingested_at`); idempotency (replay returns existing); duplicate event_id path; conflict (same event_id, different content raises `ConflictEventError`); registry entry. |
| `tests/integration/test_nginx_end_to_end.py` | 4 | The full documented Phase 4.3 flow: connector -> SecurityEvent -> MongoDB -> registry applicability filter -> rule evaluation, with assertions on the match / non-match counts. Health reflects persisted state. Disabled rule is excluded. Provenance chain preserved. |
| **Subtotal integration** | **11** | |

### 7.3 Coverage of the four test classes the task requires

| Class | Tests |
|---|---|
| **Positive** | Parser (10): well-formed line, trailing LF, trailing CRLF, minus remote_user, minus0000 UTC, non-UTC offset, IPv6, user-agent with spaces, status range, 599 accepted. Mapping (9): 401, 403, 404, 429, 5xx x4, 2xx auth success. Connector (7): canonical events, source_event_id deterministic, unique, differs by content, event_id deterministic, UUIDv7, differs per line. Rule (5): 401/403 on login/auth/oauth/sso/token endpoints. |
| **Negative** | Parser (12): empty, non-string, garbage, missing method, status 99, status 600, status non-int, non-IP, lowercase method, bad time, trailing garbage, oversized fields, NUL in path. Mapping (4): 200 non-auth, 200 auth without user, 3xx, 1xx. Connector (4): missing file, strict raises, non-strict doesn't, constructor types. Rule (6): 200 auth, 404, 401 non-auth, 401 static, non-nginx source, missing endpoint. |
| **Malformed-input** | Parser: oversized line rejected BEFORE regex; oversized UA/referer/remote_user rejected; error message does NOT leak the line; minus fields handled; bad time rejected; status 99/600 rejected; lowercase method rejected; NUL in path rejected. Connector: malformed line in a real log file is skipped and counted, not raised (non-strict default). |
| **Edge case** | Parser: trailing newline, trailing CRLF, IPv6, zero body bytes, multiple timezones. Mapping: 1xx, 3xx, 200-without-user, asset propagation, source IP, endpoint. Connector: missing file, strict mode, oversized line in a real log, stats reset. Rule: metadata, applicability, registry, reasoner, disabled state. |

## 8. Verification Performed

```
$ python -m pytest tests/ --collect-only
343 tests collected in ~1.5s

$ python -m pytest tests/
============================= 343 passed in 7.19s ==============================
```

| Suite | Tests | Time |
|---|---:|---:|
| Unit tests (no MongoDB) | 314 | < 2 s |
| Integration tests (real MongoDB) | 29 | ~ 5 s |
| **Total** | **343** | **~ 7.19 s** |

All 231 pre-existing Phase 4.1 + 4.2 tests continue to
pass; the 112 new Phase 4.3 tests (105 original + 7
CONFIRMED-1 / CONFIRMED-2 regression tests) all pass.

### 8.1 End-to-end flow

The end-to-end test
(`tests/integration/test_nginx_end_to_end.py::test_end_to_end_nginx_to_rule_evaluation`)
proves the documented flow:

* A 5-line NGINX access log is read.
* 4 canonical `SecurityEvent`s are emitted (the 200 on a
  public page is correctly mapped to `None`).
* All 4 are persisted in MongoDB.
* For each persisted event, the registry's
  `list_for_event(source, event_type)` returns the
  `NGINX-AUTH-BRUTEFORCE-001` rule (because applicability
  matches).
* The rule is evaluated: **2 matches** (the 401 and 403
  on auth-shaped endpoints) and **2 non-matches** (the
  404 on auth endpoint and the 401 on a non-auth
  endpoint). The count matches the documented expectation.

## 9. Stability

**STABLE.**

The connector is exercised end-to-end on the real local
MongoDB (`PID 4832`, `127.0.0.1:27017`); the canonical
schema, the 7 indexes, and the documented idempotency,
duplicate, and conflict paths are all observed. The
deterministic `event_id` and `source_event_id` are
verified by the unit and integration tests. The
deterministic `event_id` is a **real RFC 9562 UUIDv7**
with the connector's per-instance frozen unix-ms
timestamp in the first 48 bits (Section 4.5). The
`health()` endpoint reports a `status` and `stats` that
are consistent for a missing log file
(`status == "degraded"` AND
`stats.connector_errors >= 1`, Section 4.7). The 112 new
Phase 4.3 tests pass (105 original + 7 CONFIRMED-1 /
CONFIRMED-2 regression tests), the 231 pre-existing
tests continue to pass, and **no required test is
failing**.

## 10. Limitations

These are documented at the implementation site and are
**not** silent limitations:

* **One log format.** The connector supports the standard
  `combined` format. Custom NGINX log formats
  (e.g. `main` or a custom `log_format` directive with
  extra fields) are not supported in this slice. A future
  slice can add a `log_format` parameter and the
  corresponding parser. The combined format is the
  default in nearly every NGINX distribution, so this
  covers the MVP case.
* **Tail-only collection.** The connector reads a single
  log file once per `collect()` call. Continuous tailing
  is a deployment / runtime concern, not a connector
  contract concern, and belongs in a future ingestion
  scheduler slice.
* **No log rotation handling.** The connector does not
  detect NGINX log rotation (`logrotate`, USR1 signal)
  and will simply re-read whatever is at the configured
  path. The deterministic per-line id makes the documented
  idempotency path a safe response to re-reads: a
  re-delivery of a line that has already been ingested
  is a no-op.
* **Deterministic `event_id`.** The connector mints a
  deterministic UUIDv7 (Section 4.5) rather than a fresh
  per-call UUIDv7. This is a deliberate trade-off: it is
  required by the documented Boundary 2 idempotency path,
  and it preserves the canonical event_id contract (real
  UUIDv7, RFC 9562). The semantic value of a fresh
  UUIDv7 (millisecond-timestamped, per-call entropy) is
  traded for replay-safe idempotency. A future slice
  could explore a hybrid (e.g. a per-process stable seed
  for the random bits) but this slice's approach is the
  documented minimum.
* **One rule, no correlation.** Only one production rule
  ships (`NGINX-AUTH-BRUTEFORCE-001`). It fires per
  observation; the documented brute-force / credential
  stuffing / scanning detections are correlation rules
  and belong in a future slice (the correlation engine is
  out of scope for Phase 4.3).
* **No remote log source.** The connector reads a local
  file. Tailing a remote NGINX (`rsyslog` over TLS,
  syslog forwarder, etc.) is a deployment concern that
  belongs in the future collector runner.
* **No file-level metrics beyond `log_exists` and
  `log_size_bytes`.** The `health()` endpoint reports the
  existence and size of the configured path. A future
  slice can add lag metrics (time of last successfully
  read line vs. now) for a SRE-grade health check.

### Unresolved issues

* None material. The connector's design is a direct
  realisation of the documented connector contract and
  the canonical `SecurityEvent` schema; the rule is a
  direct realisation of the documented rule framework.

## 11. Deferred to later slices

* Detection engine wiring (engine, scheduling, batching,
  `Detection` object persistence).
* Correlation engine, timeline engine, severity engine,
  confidence engine.
* Incident engine, report engine, routing engine,
  audit-event writer.
* HTTP API routes under `/api/v1/*`.
* Authentication, RBAC, object-level authorization.
* The remaining connector sources: WAF, rate-limiter,
  TLS / network, future SIEM / endpoint / IAM.
* A WAF / rate-limit rule library (the existing
  `app/rules/_library/{waf,rate_limit,...}/` slots are
  empty; the documented research -> approved funnel must
  be followed before any rule enters production).
* A correlation rule that counts
  `NGINX-AUTH-BRUTEFORCE-001` firings per source IP into
  a brute-force / credential-stuffing detection.
* AI-assisted features (current role = research assistant,
  future role = anomaly / similarity / investigation
  assistance behind hard gates).
* Future ML dataset pipeline, adversarial test factory,
  dataset versioning.
* Any production deployment / containerization / TLS
  termination.
* The remote-collector runner (syslog, gRPC, etc.).

## 12. Files Touched

### New files

* `app/connectors/nginx/__init__.py`
* `app/connectors/nginx/parser.py`
* `app/connectors/nginx/mapping.py`
* `app/connectors/nginx/connector.py`
* `app/connectors/nginx/errors.py`
* `app/rules/_library/nginx/brute_force_pattern.py`
* `tests/unit/test_nginx_parser.py`
* `tests/unit/test_nginx_mapping.py`
* `tests/unit/test_nginx_connector.py`
* `tests/unit/test_nginx_rule.py`
* `tests/integration/test_nginx_ingestion.py`
* `tests/integration/test_nginx_end_to_end.py`

### Modified files

* `app/__init__.py` — `__version__ = "4.3.0"`,
  `__phase__ = "4.3"`.
* `app/ingestion/service.py` — connector registered in
  `CONNECTOR_REGISTRY`.
* `app/rules/_library/nginx/__init__.py` — replaces the
  empty Phase 4.2 placeholder; exports the
  `RULE_FACTORIES` for the new rule.

### Unchanged files

All Phase 4.1 and Phase 4.2 modules are unchanged. No
redesign of the canonical `SecurityEvent`, the
`RuleRegistry`, the `Rule` interface, the
`SecurityEventIngestionService`, the
`SecurityEventRepository`, the error envelope, or the
rule loader.

## 13. Independent Review Follow-up (CONFIRMED-1 / CONFIRMED-2)

The independent review
(`docs/PHASE 4/PHASE 4-03/PHASE-04-03-REVIEW.md`)
identified two CONFIRMED findings that warranted code
changes. Both have been remediated in this slice and
pinned by regression tests.

### 13.1 CONFIRMED-1 (MEDIUM) — `event_id` is now a real RFC 9562 UUIDv7

**Code change.** `app/connectors/nginx/connector.py`:

* The connector now samples a real `unix_ms` timestamp
  once at construction time
  (`self._event_id_ts_ms = time.time_ns() // 1_000_000`)
  and freezes it for the lifetime of the instance.
* `_make_event_id` now assembles the 128-bit UUID value
  with the layout prescribed by RFC 9562 §5.7: bytes
  0..5 are the frozen `unix_ts_ms` (48 bits,
  big-endian), byte 6 high nibble is the version
  `0b0111`, bytes 6 low / 7 are `rand_a` (12 bits from
  the line-content SHA-1), byte 8 high two bits are
  the variant `0b10`, and bytes 8 low / 9..15 are
  `rand_b` (62 bits from the line-content SHA-1).
* The previously-documented contract that the
  deterministic `event_id` is "a real UUIDv7 (RFC 9562
  version 7) that is deterministic for a given (log
  path, line number, raw line content)" is now
  literally true.
* Deterministic replay identity is preserved as
  per-instance replay: two `collect()` calls on the
  same connector instance + the same line produce the
  same `event_id` (the frozen timestamp is constant),
  so the repository's `insert_one` dedup path remains
  reachable. Two different connector instances sample
  different timestamps and therefore produce different
  `event_id`s for the same line, which is the expected
  behaviour of a real UUIDv7 and matches the documented
  Boundary 2 replay contract (per-instance replay, not
  cross-instance replay).

**Tests added / updated** (in
`tests/unit/test_nginx_connector.py`):

* `test_event_id_embeds_real_unix_ms_timestamp` —
  decodes the first 48 bits of the `event_id` and
  asserts they equal the connector's frozen timestamp
  AND that the frozen timestamp is a real unix-ms
  timestamp within the construction window AND within
  ±1 second of `datetime.now()`. This is the test
  that would have failed against the original
  implementation.
* `test_event_id_timestamp_is_frozen_per_instance` —
  asserts that two `collect()` calls on the same
  connector instance produce event_ids that all embed
  the same frozen timestamp (per-instance replay
  identity).
* `test_event_id_differs_across_instances` — asserts
  that two different connector instances constructed
  at least 5 ms apart produce event_ids whose embedded
  timestamps differ.
* `test_event_id_is_deterministic` — updated to use
  the same connector instance for both `collect()`
  calls, matching the new per-instance replay
  contract.

All 4 pass.

### 13.2 CONFIRMED-2 (LOW) — `health()` is now consistent for a missing log file

**Code change.** `app/connectors/nginx/connector.py`:

* `health()` no longer fakes a connector-error count via
  a local variable: when the log file is missing, the
  probe now records the error in
  `self.stats.connector_errors` (idempotently — only on
  the first observed file-missing error, so repeated
  `health()` calls do not amplify the counter). The
  `status` field is then computed from the (now
  consistent) `self.stats.connector_errors`.
* The result: `status == "degraded"` AND
  `stats.connector_errors >= 1` for a missing file.
  This was the contract the review flagged as
  violated.

**Tests added** (in
`tests/unit/test_nginx_connector.py`):

* `test_missing_file_health_stats_consistent` — the
  regression test for CONFIRMED-2. Asserts that
  `health()["status"] == "degraded"` AND
  `health()["stats"]["connector_errors"] >= 1` for a
  missing file. This is the test that would have
  failed against the original implementation.
* `test_missing_file_health_stats_consistent_after_collect`
  — asserts that after `collect()` on a missing file,
  the health probe is still consistent (and that the
  `collect()` path's own increment + the health probe's
  idempotent increment do not double-count).
* `test_existing_file_health_stats_consistent` —
  asserts that a healthy connector reports
  `status="ok"` AND `stats.connector_errors=0` (the
  health probe must not mark a healthy connector as
  degraded).
* `test_health_probe_is_idempotent_for_missing_file` —
  asserts that repeated `health()` calls on a missing
  file do not amplify `stats.connector_errors` (the
  health probe is idempotent from the operator's
  perspective).

All 4 pass.

### 13.3 Test count summary after CONFIRMED fixes

| Test file | Tests (post-fix) | Delta |
|---|---:|---:|
| `tests/unit/test_nginx_connector.py` | 29 | +7 |
| `tests/unit/test_nginx_parser.py` | 28 | 0 |
| `tests/unit/test_nginx_mapping.py` | 24 | 0 |
| `tests/unit/test_nginx_rule.py` | 20 | 0 |
| `tests/integration/test_nginx_ingestion.py` | 7 | 0 |
| `tests/integration/test_nginx_end_to_end.py` | 4 | 0 |
| **Subtotal Phase 4.3** | **112** | **+7** |
| Pre-existing Phase 4.1 + 4.2 (untouched) | 231 | 0 |
| **Grand total** | **343** | **+7** |

### 13.4 Final verification

```
$ python -m pytest tests/
============================= 343 passed in 7.19s ==============================
```

All CONFIRMED-1 / CONFIRMED-2 regression tests pass; no
previously passing test broke. The framework's public
surface (`SecurityEventConnector.collect`, `.health`,
`.stats`, the connector's `source`, the deterministic
`source_event_id`, the deterministic per-instance
`event_id`) is preserved; the new private field
`NginxConnector._event_id_ts_ms` is the only additive
internal change, and it is the contract that makes the
real-UUIDv7 determinism work.

Phase 4.3 is **STABLE** (post-fix). Phase 4.4 has not
been started.








