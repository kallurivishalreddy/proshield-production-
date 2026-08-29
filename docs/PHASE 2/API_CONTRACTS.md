# ProShield — API Contracts

## 1. Purpose

This document defines the HTTP/JSON API contract for the ProShield MVP.

The API exposes controlled access to:

- security-event ingestion
- incidents
- detections
- evidence/timeline information
- reports
- routing recommendations
- rules
- routing policies
- audit information
- authenticated administrative/user operations

The API is derived from:

- `PRODUCT_SCOPE.md`
- `MVP_REQUIREMENTS.md`
- `ROUTING_MATRIX.md`
- `MVP_ACCEPTANCE.md`
- `ARCHITECTURE.md`
- `THREAT_MODEL.md`
- `ARCHITECTURE_DECISIONS.md`
- `SECURITY_EVENT_SCHEMA.md`
- `DOMAIN_DATA_MODEL.md`

The API is a transport boundary.

The API must not redefine the domain model.

---

# 2. API Principles

The ProShield API must be:

- authenticated
- authorization-aware
- versioned
- JSON-based
- explicit
- deterministic where the domain logic is deterministic
- auditable for security-sensitive operations
- safe against untrusted input
- independent of frontend implementation details

The backend remains the security authority.

Clients must not be trusted to provide authoritative:

- severity
- confidence
- incident ownership
- routing decisions
- audit actor identity
- final classification
- final response decisions

---

# 3. API Base Convention

The initial API is versioned under:

```text
/api/v1
```

Example:

```text
GET /api/v1/incidents
```

The version exists to make future incompatible contract changes explicit.

A backwards-incompatible API change must use a new version.

---

# 4. Content Type

Requests containing JSON must use:

```text
Content-Type: application/json
```

Responses use:

```text
Content-Type: application/json
```

Unless an endpoint explicitly documents another representation.

---

# 5. Authentication

Protected endpoints require authenticated access.

Conceptual mechanism:

```text
Authorization: Bearer <access-token>
```

The exact token technology is a secure-foundation decision.

The API must validate:

- token authenticity
- token validity
- expiration where applicable
- caller identity
- caller authorization

The API must reject malformed or missing authentication.

---

# 6. Roles

The initial MVP defines at least two logical roles.

## Security Analyst

May:

- view authorized incidents
- inspect evidence
- inspect reports
- inspect routing
- update authorized incident workflow state
- perform authorized human overrides

## Security Admin / Security Lead

May additionally:

- manage rules
- manage routing policies
- manage protected configuration
- inspect audit history
- perform authorized administrative actions

The backend must enforce permissions server-side.

---

# 7. Authorization Principle

Authentication answers:

> Who are you?

Authorization answers:

> What are you allowed to do?

Every protected endpoint must perform authorization independently of the
frontend.

Changing an ID in a URL or request body must not grant access to another
object.

---

# 8. Common API Response Rules

Successful responses must use predictable JSON structures.

Errors must use the common error model defined later in this document.

The API should avoid exposing:

- database implementation details
- internal exception traces
- credentials
- tokens
- private keys
- sensitive configuration
- unnecessary internal storage identifiers

---

# 9. Common Error Contract

All API errors should use a common structure:

```json
{
  "error": {
    "code": "incident_not_found",
    "message": "The requested incident was not found.",
    "request_id": "0198c2a1-8b10-7a2e-91e1-3e5b5d4c9a21"
  }
}
```

## Required Error Fields

### `code`

Stable machine-readable error identifier.

Examples:

- `unauthorized`
- `forbidden`
- `invalid_request`
- `validation_failed`
- `not_found`
- `conflict`
- `rate_limited`
- `internal_error`

### `message`

Human-readable explanation.

It must not expose sensitive internal details.

### `request_id`

Correlation identifier for troubleshooting and audit.

---

# 10. HTTP Status Convention

Initial status usage:

| Status | Meaning |
|---|---|
| 200 | Successful request |
| 201 | Resource created |
| 202 | Accepted for asynchronous processing |
| 204 | Successful request with no response body |
| 400 | Invalid request |
| 401 | Authentication required/invalid |
| 403 | Authenticated but unauthorized |
| 404 | Resource not found or intentionally hidden |
| 409 | State/conflict violation |
| 422 | Validation failure |
| 429 | Rate limited |
| 500 | Unexpected server failure |
| 503 | Required dependency unavailable |

The implementation must not leak internal exception details through 500
responses.

---

# 11. Request IDs

Each API request should have a request/correlation ID.

The server may accept a client-provided request ID if valid and safe, but
must not trust it as a security identity.

If no valid request ID is supplied, the server generates one.

The request ID should appear:

- in logs
- in error responses
- in relevant audit/diagnostic context

---

# 12. Event Ingestion API

## Endpoint

```text
POST /api/v1/events
```

## Purpose

Accept a canonical `SecurityEvent` from an authorized source.

This endpoint is intended for:

- simulator
- NGINX adapter
- WAF adapter
- rate-limit adapter
- future real collectors

## Authentication

Required.

The exact source-authentication mechanism is defined in the secure
foundation phase.

## Request

The request body follows the canonical SecurityEvent contract.

Example:

```json
{
  "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
  "event_time": "2026-08-26T03:15:42.123Z",
  "source": "nginx",
  "event_type": "request_blocked",
  "source_ip": "192.0.2.10",
  "destination": "app.example.internal",
  "endpoint": "/api/login",
  "asset": "web-api-01",
  "details": {
    "http_method": "POST",
    "status_code": 403
  },
  "provenance": {
    "collector": "nginx-adapter",
    "source_event_id": "nginx-998877"
  }
}
```

## Server-owned Fields

The server controls:

- `ingested_at`
- authoritative source identity
- audit actor/source identity
- processing state

The caller must not be allowed to forge those values.

## Success

For synchronous acceptance:

```text
201 Created
```

Example:

```json
{
  "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
  "status": "accepted"
}
```

If ingestion becomes asynchronous:

```text
202 Accepted
```

may be used.

---

# 13. Event Duplicate Handling

Repeated submission of the same event must follow the deduplication policy.

The API must not create uncontrolled duplicate SecurityEvents.

A duplicate may return:

```text
200 OK
```

or:

```text
409 Conflict
```

depending on the final idempotency contract.

The final implementation must document the chosen behavior.

---

# 14. Event Query API

## Endpoint

```text
GET /api/v1/events
```

## Purpose

Provide authorized access to security events for investigation and
administration.

## Query Parameters

Initial logical filters may include:

```text
source
event_type
asset
account
source_ip
from
to
limit
offset
```

The exact filter catalogue will follow actual MVP UI/query needs.

## Authorization

Event visibility is role-controlled.

Not every authenticated user must have access to all events.

## Response

```json
{
  "items": [
    {
      "event_id": "0198...",
      "event_time": "2026-08-26T03:15:42.123Z",
      "source": "nginx",
      "event_type": "request_blocked"
    }
  ],
  "limit": 50,
  "offset": 0
}
```

Raw sensitive details must not be exposed unless the caller is authorized.

---

# 15. Event Detail API

## Endpoint

```text
GET /api/v1/events/{event_id}
```

## Purpose

Retrieve one SecurityEvent for authorized investigation.

The response must use the canonical event representation or an explicitly
authorized projection of it.

---

# 16. Detection API

## Endpoint

```text
GET /api/v1/detections
```

## Purpose

List authorized detection results for investigation.

Possible filters:

```text
rule_id
incident_id
category
from
to
limit
offset
```

## Detection Detail

```text
GET /api/v1/detections/{detection_id}
```

The response must contain or reference:

- detection identity
- rule ID
- rule version
- category
- detection time
- supporting event references
- reasoning
- severity/confidence contribution

---

# 17. Incident List API

## Endpoint

```text
GET /api/v1/incidents
```

## Purpose

List incidents available to the authenticated user.

Possible filters:

```text
status
severity
category
team
queue
required_skill
from
to
limit
offset
```

The final filter list should be implemented only when required by the MVP
UI/workflow.

## Response

```json
{
  "items": [
    {
      "incident_id": "0198...",
      "category": "web_attack",
      "severity": "HIGH",
      "confidence": "HIGH",
      "status": "OPEN",
      "created_at": "2026-08-26T03:20:00Z"
    }
  ],
  "limit": 50,
  "offset": 0
}
```

---

# 18. Incident Detail API

## Endpoint

```text
GET /api/v1/incidents/{incident_id}
```

## Purpose

Return the complete authorized investigation view.

The response should include or reference:

- incident identity
- category
- severity
- confidence
- status
- timestamps
- affected assets
- supporting event references
- detection references
- correlation references
- timeline
- evidence
- report
- routing recommendation
- audit summary where authorized

---

# 19. Incident Creation

Incident creation is normally a server-side result of detection/correlation
processing.

Therefore clients should NOT normally create authoritative incidents
directly.

Preferred flow:

```text
SecurityEvent
→ Detection
→ Correlation
→ Incident Manager
→ Incident
```

If administrative/manual incident creation is required later, it must use a
separate explicitly authorized endpoint.

---

# 20. Incident Status Update

## Endpoint

```text
PATCH /api/v1/incidents/{incident_id}
```

## Purpose

Allow authorized human workflow updates.

Possible fields:

```json
{
  "status": "INVESTIGATING"
}
```

or other explicitly permitted human-controlled fields.

## Restrictions

The caller must not use this endpoint to bypass automated security logic.

The backend must validate:

- actor authorization
- valid state transition
- allowed fields
- audit requirements

---

# 21. Severity Override

Severity is normally a ProShield-derived value.

Authorized human override:

```text
PATCH /api/v1/incidents/{incident_id}/severity
```

Request:

```json
{
  "severity": "CRITICAL",
  "reason": "Business impact is higher than the initial automated estimate."
}
```

The system must preserve:

- previous severity
- new severity
- actor
- timestamp
- reason

This action must create an AuditEvent.

---

# 22. Classification Override

If authorized, a human may change the preliminary incident category.

Conceptual endpoint:

```text
PATCH /api/v1/incidents/{incident_id}/classification
```

Request:

```json
{
  "category": "web_attack",
  "reason": "Manual investigation confirmed the attack category."
}
```

This must be auditable.

---

# 23. Timeline API

## Endpoint

```text
GET /api/v1/incidents/{incident_id}/timeline
```

## Purpose

Return the evidence-backed chronological timeline.

Each item should expose:

- timeline ID
- timestamp
- source reference
- detection/correlation reference where applicable
- description
- evidence relationship

Timeline entries must not be presented as raw observations unless backed
by the corresponding SecurityEvent.

---

# 24. Evidence API

## Endpoint

```text
GET /api/v1/incidents/{incident_id}/evidence
```

## Purpose

Return the evidence supporting the incident.

Evidence may include references to:

- SecurityEvents
- Detections
- Correlations
- other authorized artifacts

The endpoint must enforce authorization.

---

# 25. Report API

## Endpoint

```text
GET /api/v1/incidents/{incident_id}/report
```

## Purpose

Retrieve the current early investigation report.

The response should distinguish:

```text
observed_facts
derived_conclusions
recommendations
```

Example:

```json
{
  "report_id": "0198...",
  "incident_id": "0198...",
  "observed_facts": [],
  "derived_conclusions": [],
  "recommendations": [],
  "generated_at": "2026-08-26T03:40:00Z"
}
```

The report must never silently convert unavailable information into
fabricated facts.

---

# 26. Report Regeneration

## Endpoint

```text
POST /api/v1/incidents/{incident_id}/report/regenerate
```

## Purpose

Request regeneration when incident state/evidence changes or an
authorized user explicitly requests a fresh report.

The regenerated report must be based on current authoritative incident
data.

The action should be auditable.

If report generation becomes asynchronous, the endpoint may return:

```text
202 Accepted
```

with a report-generation operation identifier.

---

# 27. Routing Recommendation API

## Endpoint

```text
GET /api/v1/incidents/{incident_id}/routing
```

## Purpose

Retrieve the current ProShield routing recommendation.

The response should include:

- recommended level
- required skill
- team
- queue
- severity used
- complexity
- confidence
- affected technology where applicable
- reason
- routing policy ID/version
- recommendation timestamp

---

# 28. Routing Override

## Endpoint

```text
PATCH /api/v1/incidents/{incident_id}/routing
```

## Request

```json
{
  "level": "L3",
  "skill": "Incident Response",
  "team": "Security Incident Response",
  "queue": "IR-L3",
  "reason": "Complex multi-layer activity requires expert investigation."
}
```

## Rules

- only authorized users may override routing
- original recommendation must remain preserved
- override must be auditable
- the backend validates all fields
- clients cannot fabricate organizational information

---

# 29. Rule List API

## Endpoint

```text
GET /api/v1/rules
```

## Purpose

List available detection rules to authorized users.

Possible fields:

- rule ID
- version
- name
- enabled
- category
- updated_at

---

# 30. Rule Detail API

## Endpoint

```text
GET /api/v1/rules/{rule_id}
```

## Purpose

Return a specific rule and its current version where authorized.

---

# 31. Rule Creation

## Endpoint

```text
POST /api/v1/rules
```

## Authorization

Security Admin / Security Lead only.

## Request

Conceptually:

```json
{
  "name": "Repeated Rate Limit Abuse",
  "enabled": true,
  "definition": {
    "match": {
      "event_type": "rate_limit_exceeded"
    }
  }
}
```

The exact rule DSL is defined separately.

## Requirements

- validate rule definition
- reject executable code
- assign server-side rule ID
- assign version
- audit creation

---

# 32. Rule Update

## Endpoint

```text
PUT /api/v1/rules/{rule_id}
```

The implementation should create a new Rule version rather than silently
mutating the history of the previous version.

The previous version remains auditable.

---

# 33. Rule Enable/Disable

## Endpoint

```text
PATCH /api/v1/rules/{rule_id}/status
```

Request:

```json
{
  "enabled": false,
  "reason": "Temporarily disabled during controlled rule review."
}
```

This is a privileged security action and must be audited.

---

# 34. Routing Policy API

## List

```text
GET /api/v1/routing-policies
```

## Detail

```text
GET /api/v1/routing-policies/{policy_id}
```

## Create

```text
POST /api/v1/routing-policies
```

## Update

```text
PUT /api/v1/routing-policies/{policy_id}
```

All routing-policy management is privileged and versioned.

---

# 35. Audit API

## Endpoint

```text
GET /api/v1/audit-events
```

## Purpose

Provide authorized administrators/security leads access to audit history.

Possible filters:

```text
actor
action
object_type
object_id
from
to
limit
offset
```

Audit records must be protected from unauthorized modification.

The API should generally be read-only for audit history.

---

# 36. Health API

## Endpoint

```text
GET /api/v1/health
```

## Purpose

Provide operational health.

A health response may expose:

```json
{
  "status": "ok",
  "dependencies": {
    "database": "ok",
    "event_processing": "ok"
  }
}
```

Health endpoints must not expose:

- credentials
- connection strings
- secrets
- sensitive security data

---

# 37. Metrics / Operational Status

A separate operational endpoint may provide authorized health/metrics
information.

It should not expose security evidence to unauthenticated users.

Exact metrics exposure will depend on the deployment architecture.

---

# 38. Pagination

List endpoints should use bounded pagination.

Initial model:

```text
limit
offset
```

Example:

```text
GET /api/v1/incidents?limit=50&offset=100
```

Rules:

- `limit` must have a maximum
- `offset` must not be negative
- large unbounded queries are prohibited

Cursor-based pagination may be introduced later if event volume makes
offset pagination inefficient.

---

# 39. Filtering

Filters must be explicitly supported per endpoint.

Clients must not be able to construct arbitrary database queries through
query parameters.

Example:

Correct:

```text
GET /api/v1/incidents?severity=HIGH
```

Incorrect:

```text
GET /api/v1/incidents?raw_query={"$where":"..."}
```

No raw database query syntax is exposed through the API.

---

# 40. Sorting

Sortable fields must be explicitly allowlisted.

Example:

```text
sort=created_at
order=desc
```

The backend must reject arbitrary field expressions.

Default sorting for incidents, detections, and events should favor recent
activity where appropriate.

---

# 41. Input Validation

All request inputs must be validated.

Validation includes:

- type
- length
- enum values
- range
- nested structure
- allowed fields
- authorization context

The backend must not rely on frontend validation.

---

# 42. Unknown Request Fields

Strict request schemas should reject unknown fields unless the contract
explicitly defines an extension area.

This prevents accidental client/server contract drift.

---

# 43. Idempotency

State-changing endpoints that may be retried must consider duplicate
requests.

Where necessary, support:

```text
Idempotency-Key
```

for operations such as:

- event ingestion
- rule creation where applicable
- configuration operations
- response actions in future

The exact required endpoint set will be finalized based on workflow risk.

The core design principle is:

> Retries must not silently create unintended duplicate state.

---

# 44. Concurrency

The API must be safe under concurrent requests.

Examples:

- two analysts attempting the same incident state transition
- repeated event submission
- concurrent rule updates
- simultaneous routing overrides

The backend must detect conflicts where required rather than silently
losing a change.

---

# 45. Security-Sensitive Fields

Clients must never be allowed to choose authoritative values for:

- audit actor identity
- organization identity
- final severity without authorized override
- system-generated timestamps
- rule version
- routing policy version
- internal database identifiers
- internal processing status

The server derives or validates these values.

---

# 46. Error Safety

Errors must not expose:

- stack traces
- database queries
- credentials
- connection strings
- secret configuration
- internal file paths

For debugging, use:

```text
request_id
```

to correlate the user-facing error with protected server logs.

---

# 47. API Audit Requirements

The following API actions must generate AuditEvents where applicable:

- rule creation
- rule modification
- rule enable/disable
- routing-policy changes
- incident status changes
- severity override
- classification override
- routing override
- administrative configuration changes
- security-sensitive response actions

Read-only operations may be audited according to the security policy.

---

# 48. Internal vs External API

The same semantic contracts should be reusable internally, but internal
service communication does not automatically inherit external trust.

Internal endpoints must still have:

- authentication where required
- authorization
- schema validation
- bounded payloads
- versioning
- observability

The architecture may later separate public API and internal service APIs
physically, but the contract principles remain the same.

---

# 49. API Version Evolution

A change is backward-compatible when it does not alter the meaning of
existing fields or valid client behavior.

Examples of potentially breaking changes:

- removing a field
- changing a field type
- changing enum meaning
- changing authentication requirements
- changing error semantics
- changing state-transition behavior

Breaking changes require a new API version.

---

# 50. Initial Endpoint Summary

The initial MVP API surface is:

```text
EVENTS
POST   /api/v1/events
GET    /api/v1/events
GET    /api/v1/events/{event_id}

DETECTIONS
GET    /api/v1/detections
GET    /api/v1/detections/{detection_id}

INCIDENTS
GET    /api/v1/incidents
GET    /api/v1/incidents/{incident_id}
PATCH  /api/v1/incidents/{incident_id}
PATCH  /api/v1/incidents/{incident_id}/severity
PATCH  /api/v1/incidents/{incident_id}/classification

TIMELINE / EVIDENCE / REPORT
GET    /api/v1/incidents/{incident_id}/timeline
GET    /api/v1/incidents/{incident_id}/evidence
GET    /api/v1/incidents/{incident_id}/report
POST   /api/v1/incidents/{incident_id}/report/regenerate

ROUTING
GET    /api/v1/incidents/{incident_id}/routing
PATCH  /api/v1/incidents/{incident_id}/routing

RULES
GET    /api/v1/rules
GET    /api/v1/rules/{rule_id}
POST   /api/v1/rules
PUT    /api/v1/rules/{rule_id}
PATCH  /api/v1/rules/{rule_id}/status

ROUTING POLICIES
GET    /api/v1/routing-policies
GET    /api/v1/routing-policies/{policy_id}
POST   /api/v1/routing-policies
PUT    /api/v1/routing-policies/{policy_id}

AUDIT
GET    /api/v1/audit-events

OPERATIONS
GET    /api/v1/health
```

Not every endpoint must be implemented immediately.

The implementation phase should create only the endpoints required by the
current MVP slice.

---

# 51. API Acceptance Criteria

The API contract is considered correct when:

### API-01

Protected endpoints require authentication.

### API-02

Authorization is enforced server-side.

### API-03

Client input cannot determine authoritative security decisions.

### API-04

All request bodies use explicit validation schemas.

### API-05

Security-event ingestion follows the canonical SecurityEvent contract.

### API-06

Incident access is authorization-controlled.

### API-07

Severity and routing overrides are restricted to authorized actors.

### API-08

Rule and routing-policy changes are privileged, versioned, and audited.

### API-09

Errors use the common error structure.

### API-10

Sensitive implementation details are not exposed in API errors.

### API-11

List endpoints use bounded pagination.

### API-12

Filters and sorting are allowlisted.

### API-13

State-changing operations consider duplicate/retry behavior.

### API-14

Security-sensitive actions create appropriate audit records.

### API-15

The API version is explicit.

### API-16

The API contract remains consistent with the logical domain model.

---

# 52. What This Contract Does Not Decide

This document intentionally does not fully lock:

- token technology
- exact authorization implementation
- exact database queries
- exact MongoDB index definitions
- exact message-broker transport
- exact internal service RPC protocol
- exact UI routes
- exact deployment topology

Those are separate implementation/security/deployment decisions.

---

# 53. Final API Principle

The ProShield API should provide a clean boundary:

```text
UNTRUSTED CLIENT / SOURCE
        ↓
AUTHENTICATION
        ↓
AUTHORIZATION
        ↓
VALIDATION
        ↓
DOMAIN SERVICE
        ↓
AUTHORITATIVE SECURITY STATE
```

The core principle is:

> **The client asks ProShield to perform an operation; the client does not
> get to decide what the security state should be.**

The backend remains the authority for:

- evidence
- detections
- severity
- incidents
- routing
- audit
- security configuration
- response permissions