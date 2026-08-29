# ProShield — Contract Decisions

## 1. Purpose

This document records the major technical decisions made for the ProShield
Phase 2 contracts and data model.

The purpose is to prevent future developers or AI agents from silently
changing important contract behavior during implementation.

The following documents define the detailed contracts:

- `SECURITY_EVENT_SCHEMA.md`
- `DOMAIN_DATA_MODEL.md`
- `API_CONTRACTS.md`

This document records the decisions behind those contracts.

A future change must not silently replace an accepted decision.

If a decision needs to change, the change must document:

1. Existing decision
2. New evidence or requirement
3. Problem with the existing decision
4. Alternatives considered
5. New decision
6. Security impact
7. Data impact
8. API/contract impact
9. Migration impact
10. Test impact

---

# 2. Decision Status

Each decision uses one of the following statuses.

### ACCEPTED

The decision is approved for the MVP and should be followed.

### PROVISIONAL

The decision is appropriate for the MVP but may be revisited when new
evidence or production requirements justify it.

### DEFERRED

The decision is intentionally postponed until a later phase.

### SUPERSEDED

A newer decision has replaced the previous decision.

---

# 3. ADR-001 — MongoDB Is the Primary Database

**Status:** ACCEPTED

## Decision

MongoDB is the primary persistence layer for the ProShield MVP.

## Reason

MongoDB was selected because ProShield security events are naturally
document-oriented and may contain source-specific structured metadata that
varies across:

- NGINX
- WAF
- rate limiting
- TLS/network systems
- future SIEM
- endpoint
- IAM

MongoDB provides:

- straightforward document inspection
- flexible structured metadata
- natural JSON-like storage
- practical local development
- suitable event-oriented storage
- simple extension for new event types

The product also benefits from being able to inspect security documents
directly during development and investigation.

## Important Constraint

MongoDB flexibility must not become unvalidated arbitrary storage.

Core domain objects remain structured.

Major domain objects use separate collections and references where
appropriate.

## Initial Logical Collections

```text
security_events
rules
detections
correlations
timeline_events
incidents
reports
routing_policies
routing_recommendations
audit_events
```

## Revisit When

Consider another storage strategy only if actual MVP/production evidence
demonstrates that MongoDB no longer satisfies:

- consistency
- performance
- security
- query requirements
- operational requirements
- cost requirements

---

# 4. ADR-002 — MongoDB-Native Document Strategy

**Status:** ACCEPTED

## Decision

Use a MongoDB-native document model rather than forcing a relational
schema onto MongoDB.

Major domain objects are represented in separate collections.

References use stable IDs.

Small data that naturally belongs together may be embedded.

## Example

```text
Incident
├── incident_id
├── severity
├── confidence
├── status
├── event_ids
├── detection_ids
├── timeline_event_ids
└── routing_recommendation_id
```

## Reason

This provides:

- readable documents
- clear domain boundaries
- flexible event metadata
- controlled references
- manageable document sizes

## Constraint

Do not create:

- one giant Incident document containing everything
- thousands of tiny collections with no real lifecycle/query need

---

# 5. ADR-003 — JSON Is the Canonical Wire Representation

**Status:** ACCEPTED

## Decision

JSON is the canonical representation for:

- APIs
- canonical security-event exchange
- internal message payloads where applicable
- test fixtures

## Reason

JSON is:

- readable
- easy to inspect
- widely supported
- suitable for frontend/backend communication
- appropriate for collector integration
- easy to test

## Constraint

The domain model is authoritative.

JSON is a representation of the domain model, not the domain model itself.

---

# 6. ADR-004 — Timestamp Representation

**Status:** ACCEPTED

## Decision

All API and canonical event timestamps use UTC RFC 3339 / ISO 8601
serialization.

Example:

```text
2026-08-26T03:15:42.123Z
```

## Reason

Security correlation and timelines require unambiguous time.

The system must distinguish:

```text
event_time
=
when the event occurred

ingested_at
=
when ProShield received it
```

## Constraint

Do not silently mix:

- local timestamps
- epoch seconds
- epoch milliseconds
- timezone-naive timestamps

inside one canonical contract.

---

# 7. ADR-005 — UUIDv7 for Internal Entity IDs

**Status:** ACCEPTED

## Decision

Use UUIDv7 for authoritative internal IDs.

Applies conceptually to:

- SecurityEvent
- Detection
- Correlation
- TimelineEvent
- Incident
- Report
- RoutingPolicy
- RoutingRecommendation
- AuditEvent

Rules:

- generated server-side
- immutable
- unique
- not client-authoritative
- suitable for distributed generation

## Reason

UUIDv7 provides:

- global uniqueness
- non-sequential public identifiers
- useful time ordering
- distributed generation capability

## Human-Readable IDs

If the UI later needs readable references, add separate display IDs.

Example:

```text
INC-20260826-000123
DET-20260826-000456
```

These must not replace UUIDv7 as the authoritative internal identifier.

---

# 8. ADR-006 — Canonical SecurityEvent Is Source-Independent

**Status:** ACCEPTED

## Decision

Every collector converts source-specific telemetry into the canonical
`SecurityEvent`.

Architecture:

```text
Source
→ Collector / Adapter
→ Canonical SecurityEvent
→ ProShield Core
```

## Reason

The detection/correlation engine must not be rewritten for every new
collector.

## Constraint

Source-specific parsing belongs in the collector layer.

Source-specific detection logic does not belong in the core engine.

---

# 9. ADR-007 — SecurityEvent Represents Observation Only

**Status:** ACCEPTED

## Decision

A `SecurityEvent` represents observed security activity.

It must not automatically contain or imply:

- confirmed attack
- final severity
- incident classification
- routing decision
- analyst assignment
- human conclusion
- AI interpretation

## Reason

This preserves the critical distinction between:

```text
Observed
vs
Derived
vs
Recommended
vs
Human Decision
```

---

# 10. ADR-008 — Evidence Must Remain Traceable

**Status:** ACCEPTED

## Decision

Every important ProShield conclusion must be traceable through the domain
chain:

```text
SecurityEvent
→ Detection
→ Correlation
→ Timeline
→ Incident
→ Report
→ Routing
```

## Reason

ProShield is a security-triage product.

Analysts must be able to understand why a result exists.

The system must not create unexplained security conclusions.

---

# 11. ADR-009 — Detection Is Separate From Incident

**Status:** ACCEPTED

## Decision

A Detection is not automatically a separate Incident.

Detections become part of incidents when correlation/incident logic
determines that they belong to the same investigation unit.

## Reason

One real security activity may produce multiple detections.

Creating one incident per detection would recreate alert fatigue.

---

# 12. ADR-010 — Detection Rules Are Versioned Configuration

**Status:** ACCEPTED

## Decision

Rules are:

- configurable
- versioned
- deterministic
- explainable
- testable
- auditable

Every Detection must preserve the Rule ID and Rule version responsible for
its creation.

## Reason

A historical incident must remain explainable even after a rule changes.

Example:

```text
WEB-RATE-001
Version 3
```

must remain distinguishable from:

```text
WEB-RATE-001
Version 4
```

---

# 13. ADR-011 — Declarative YAML Rule Authoring

**Status:** ACCEPTED

## Decision

Rule authoring uses a constrained declarative YAML representation.

Rules are validated into a strongly typed internal representation before
execution.

Example:

```yaml
id: WEB-RATE-001
version: 1
name: Repeated Rate Limit Abuse
enabled: true

match:
  event_type: rate_limit_exceeded

window:
  duration: 60s

condition:
  count:
    operator: gte
    value: 5

classification:
  category: rate_limit_abuse
  severity: MEDIUM
  confidence: HIGH
```

## Reason

YAML is:

- human-readable
- version-control friendly
- easy to review
- suitable for explicit configuration

## Security Constraint

Rules must never allow arbitrary executable code.

Do not implement the rule engine using:

```text
eval()
exec()
user-supplied Python
user-supplied JavaScript
```

or equivalent arbitrary execution mechanisms.

---

# 14. ADR-012 — Rule Changes Are Privileged and Audited

**Status:** ACCEPTED

## Decision

Rule creation, modification, enable/disable, and deletion/retirement are
privileged security operations.

Every important change must be auditable.

## Reason

Rules determine detection behavior.

Rule tampering can directly create detection blind spots.

---

# 15. ADR-013 — Severity and Confidence Are Separate

**Status:** ACCEPTED

## Decision

Severity and confidence remain distinct domain values.

Severity:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Confidence indicates evidence strength.

## Example

```text
Severity: HIGH
Confidence: MEDIUM
```

is valid.

## Reason

Impact and certainty are different properties.

Combining them into one opaque score would reduce explainability.

---

# 16. ADR-014 — Severity Is Preliminary

**Status:** ACCEPTED

## Decision

ProShield severity is a preliminary triage assessment.

Authorized humans may override it.

## Reason

ProShield prepares the investigation.

Human analysts retain final judgment.

## Requirement

Severity overrides must be auditable.

---

# 17. ADR-015 — Routing Is Deterministic for the MVP

**Status:** ACCEPTED

## Decision

The MVP routing engine is deterministic and explainable.

Given identical:

- incident inputs
- routing policy
- policy version

the same routing recommendation should be produced.

## Reason

Deterministic routing is:

- testable
- explainable
- auditable
- predictable

---

# 18. ADR-016 — Routing Targets Level/Skill/Team/Queue

**Status:** ACCEPTED

## Decision

The MVP routes to:

- analyst level
- required skill
- team
- queue

It does not assign an individual analyst without an authorized
organizational data source.

## Reason

The system does not inherently know:

- current analyst availability
- workload
- shift
- specialization

Pretending it does would create fabricated routing.

---

# 19. ADR-017 — Routing Is Not Severity-Only

**Status:** ACCEPTED

## Decision

Routing considers more than severity.

Inputs may include:

- severity
- complexity
- category
- skill
- affected technology
- affected asset
- business criticality
- confidence
- investigation depth

## Reason

Severity alone causes:

- unnecessary escalation
- skill mismatch
- inefficient analyst allocation

---

# 20. ADR-018 — Routing Policy Is Versioned Configuration

**Status:** ACCEPTED

## Decision

Routing policies are protected configuration and are versioned where
needed.

A RoutingRecommendation records the policy/version used to produce it.

## Reason

Historical routing must remain explainable even after policy changes.

---

# 21. ADR-019 — Human Overrides Remain Distinct

**Status:** ACCEPTED

## Decision

When a human overrides a ProShield recommendation, the system preserves:

- original recommendation
- human decision
- actor
- timestamp
- reason when supplied

## Reason

The system must distinguish:

```text
System Recommendation
```

from:

```text
Human Decision
```

This protects accountability.

---

# 22. ADR-020 — AuditEvent Is Separate From SecurityEvent

**Status:** ACCEPTED

## Decision

`SecurityEvent` and `AuditEvent` are separate domain concepts.

### SecurityEvent

Observed activity from the monitored environment.

### AuditEvent

An action performed inside ProShield or by an authorized actor.

## Reason

They have different:

- trust models
- purposes
- retention expectations
- security semantics

---

# 23. ADR-021 — API Uses Explicit Versioning

**Status:** ACCEPTED

## Decision

The initial public API uses:

```text
/api/v1
```

Breaking contract changes require a new API version.

## Reason

ProShield needs stable contracts for:

- frontend
- collectors
- integrations
- future clients

---

# 24. ADR-022 — Backend Is the Security Authority

**Status:** ACCEPTED

## Decision

The backend is authoritative for:

- authentication
- authorization
- evidence
- detections
- severity
- incidents
- routing
- audit identity
- configuration
- response authorization

The client is not trusted to define security state.

## Reason

Frontend validation and display are not security controls.

---

# 25. ADR-023 — API Uses JSON

**Status:** ACCEPTED

## Decision

API requests/responses use JSON unless an endpoint explicitly requires
another representation.

## Reason

JSON is readable, testable, and compatible with the chosen domain model.

---

# 26. ADR-024 — Internal Messages Use Versioned JSON Envelopes

**Status:** ACCEPTED

## Decision

Internal asynchronous or integration messages use a versioned JSON
envelope.

Conceptual structure:

```json
{
  "message_id": "0198...",
  "message_type": "security_event",
  "schema_version": "1.0",
  "occurred_at": "2026-08-26T03:15:42.123Z",
  "source": "nginx",
  "payload": {}
}
```

## Reason

The message contract needs:

- explicit type
- versioning
- identity
- provenance
- transport independence

The transport itself remains a separate decision.

---

# 27. ADR-025 — At-Least-Once + Idempotent Processing

**Status:** ACCEPTED

## Decision

The architecture assumes that internal/event delivery may be
at-least-once.

Consumers must handle duplicate delivery safely.

## Reason

Designing around at-least-once plus idempotent processing is more robust
than assuming perfect exactly-once delivery.

Important messages have unique `message_id` values.

---

# 28. ADR-026 — Message Transport Is Not Yet Locked

**Status:** PROVISIONAL

## Decision

The message format is defined, but the transport is not yet permanently
chosen.

Possible transport mechanisms:

- HTTP
- lightweight internal queue
- message broker

## Reason

The correct transport depends on:

- event volume
- latency
- deployment
- reliability
- operational complexity

We will not introduce Kafka/RabbitMQ/etc. solely because they are common
in large systems.

---

# 29. ADR-027 — MVP Retention Is Configurable

**Status:** ACCEPTED

## Decision

Retention periods are configurable by data class.

Initial operational targets:

```text
Security Events       → 90 days
Detections            → 180 days
Correlations          → 180 days
Incidents             → 1 year
Reports               → 1 year
Audit Events          → 1 year
Rule history          → system life unless archived
Routing policy history→ system life unless archived
```

## Important Note

These are MVP operational defaults.

They are NOT claims of legal or regulatory compliance.

Deployments may configure different retention periods based on:

- customer requirements
- business requirements
- contracts
- regulations
- storage constraints
- investigation needs

---

# 30. ADR-028 — Security Evidence Requires Controlled Deletion

**Status:** ACCEPTED

## Decision

Security evidence and audit history must not be arbitrarily deleted by
normal application operations.

Lifecycle should be:

```text
Active
→ Retained
→ Archived where appropriate
→ Controlled Purge
```

Purge must follow configured retention policy and appropriate authorization.

## Reason

Evidence and audit records have security and accountability value.

---

# 31. ADR-029 — MongoDB Uses Structured Collections + References

**Status:** ACCEPTED

## Decision

MongoDB major collections are separate logical domains.

Initial collections:

```text
security_events
rules
detections
correlations
timeline_events
incidents
reports
routing_policies
routing_recommendations
audit_events
```

Major objects reference other objects by stable IDs.

Small data that naturally belongs together may be embedded.

## Reason

This provides readable MongoDB documents without creating one giant
aggregate.

---

# 32. ADR-030 — MongoDB Schema Must Still Be Strict

**Status:** ACCEPTED

## Decision

Choosing MongoDB does not mean arbitrary documents are accepted.

The implementation must provide:

- validation
- bounded fields
- allowed types
- stable contracts
- unique indexes
- appropriate references
- controlled update paths

## Reason

Document flexibility must not weaken security or data integrity.

---

# 33. ADR-031 — MongoDB Transactions Are Used Where Supported and Needed

**Status:** PROVISIONAL

## Decision

Where a business operation requires atomic changes across multiple
MongoDB documents, use MongoDB transactions when the deployment topology
supports them.

Do not artificially split a consistency-critical operation into multiple
unprotected writes.

## Reason

Some ProShield operations may require related state changes to remain
consistent.

## Important Constraint

The deployment must be configured with a MongoDB topology that supports the
required transaction guarantees.

If the MVP runs in a topology without those guarantees, the affected
workflow must explicitly document the resulting consistency model.

---

# 34. ADR-032 — MongoDB Storage Is Not the Domain Model

**Status:** ACCEPTED

## Decision

The logical domain model remains independent of MongoDB-specific details.

MongoDB implements persistence for:

- SecurityEvent
- Detection
- Correlation
- Timeline
- Incident
- Report
- Routing
- Audit
- configuration

The domain meaning must not depend on MongoDB-specific behavior.

## Reason

This keeps the application maintainable and allows future storage changes
if requirements ever justify them.

---

# 35. ADR-033 — API Pagination Is Bounded

**Status:** ACCEPTED

## Decision

List endpoints use bounded pagination.

Initial approach:

```text
limit
offset
```

`limit` must have a server-enforced maximum.

## Reason

Unbounded list queries can cause:

- excessive memory use
- expensive queries
- API abuse
- slow analyst UI

Cursor-based pagination may be introduced later if actual event scale
requires it.

---

# 36. ADR-034 — API Filters and Sorting Are Allowlisted

**Status:** ACCEPTED

## Decision

Clients may use only explicitly supported:

- filters
- sort fields
- sort directions

Raw database query syntax is never exposed.

## Example

Allowed:

```text
?severity=HIGH
```

Not allowed:

```text
?raw_query={"$where":"..."}
```

## Reason

Database query construction must remain server-controlled.

---

# 37. ADR-035 — Idempotency Is Required for Risky Retries

**Status:** ACCEPTED

## Decision

State-changing endpoints that may be retried must consider idempotency.

Where required, support:

```text
Idempotency-Key
```

## Reason

Retries must not silently create duplicate security state.

Particularly important for:

- event ingestion
- administrative operations
- future response actions

---

# 38. ADR-036 — SecurityEvents and AuditEvents Are Append-Oriented

**Status:** ACCEPTED

## Decision

Security evidence and audit history should be treated as primarily
append-oriented data.

Normal application operations should not arbitrarily mutate historical
evidence.

If correction is required, the change should be handled through an
auditable mechanism.

## Reason

Historical integrity is essential for investigation and accountability.

---

# 39. ADR-037 — Unknown Is a Valid Security State

**Status:** ACCEPTED

## Decision

ProShield must support:

- unknown event classification
- unknown incident classification
- uncertain confidence
- unresolved specialist routing

## Reason

The system must not invent certainty when evidence is incomplete.

Unknown does not mean:

```text
malicious
```

and should not automatically become:

```text
confirmed attack
```

---

# 40. ADR-038 — AI Is Not on the Critical MVP Path

**Status:** ACCEPTED

## Decision

AI is not required for:

- ingestion
- validation
- normalization
- detection
- correlation
- timeline
- severity
- confidence
- incident creation
- report baseline
- routing
- audit

## Reason

The rule-based foundation must be independently validated first.

Future AI can enhance the system without becoming a single point of
failure.

---

# 41. ADR-039 — No Autonomous High-Impact Response in MVP

**Status:** ACCEPTED

## Decision

The initial response model is:

```text
Detect
→ Report
→ Recommend
→ Human Approval
→ Response
```

No unrestricted destructive autonomous response is part of the MVP.

## Reason

The MVP's primary value is triage intelligence, not autonomous destructive
response.

---

# 42. ADR-040 — Real Collectors Are Added After Core Validation

**Status:** ACCEPTED

## Decision

The simulator validates the deterministic core first.

Real collectors are then integrated progressively:

```text
Simulator
→ NGINX
→ WAF / Cezara
→ Rate Limiting
→ TLS / Network
→ SIEM
→ Endpoint
→ IAM
```

At least one real collector must work through the same canonical pipeline
before production MVP validation is considered complete.

---

# 43. ADR-041 — Contract Changes Require Explicit Review

**Status:** ACCEPTED

## Decision

The following are considered protected contracts:

- SecurityEvent schema
- Domain model
- API contract
- rule schema
- routing policy
- message envelope
- retention behavior
- state-transition semantics

A breaking change requires:

1. contract change proposal
2. impact analysis
3. security review
4. implementation update
5. regression tests
6. documentation update

## Reason

Contract drift is especially dangerous when multiple AI/development agents
work on the same project.

---

# 44. ADR-042 — Implementation Must Follow the Contracts

**Status:** ACCEPTED

## Decision

Implementation agents must not silently:

- add authoritative fields
- change ID meaning
- change state semantics
- change severity semantics
- change routing logic
- change event meaning
- weaken validation
- expose new privileged API fields

without an explicit contract decision.

## Reason

The contracts are the source of truth for implementation.

---

# 45. ADR-043 — Exact Physical Indexes Remain Query-Driven

**Status:** PROVISIONAL

## Decision

MongoDB indexes should be based on actual API/query patterns rather than
being created indiscriminately.

Likely candidates include:

- SecurityEvent timestamp
- source
- event_type
- source_ip where useful
- incident status
- incident severity
- incident created_at
- detection rule
- audit object
- audit actor

Exact indexes are finalized after API/query implementation.

## Reason

Unnecessary indexes increase:

- storage
- write cost
- operational complexity

---

# 46. ADR-044 — Retention Is Configuration, Not Hard-Coded Business Logic

**Status:** ACCEPTED

## Decision

Retention values must be configurable.

They must not be buried as irreversible constants throughout the application.

## Reason

Different deployments may have different:

- legal requirements
- customer requirements
- storage budgets
- investigation requirements

---

# 47. ADR-045 — Unresolved Decisions Remain Explicitly Marked

**Status:** ACCEPTED

## Decision

The following remain intentionally open until requirements justify them:

- exact message transport
- exact deployment platform
- exact cloud provider
- exact production network topology
- final retention implementation mechanism
- exact MongoDB indexing strategy
- exact API pagination evolution beyond the MVP
- future AI model selection
- future response platform integration

## Reason

Unresolved decisions are safer when explicitly visible than when
implicitly invented by an implementation agent.

---

# 48. Phase 2 Contract Decision Summary

The current Phase 2 decisions are:

| Area | Decision | Status |
|---|---|---|
| Primary database | MongoDB | ACCEPTED |
| MongoDB modeling | Structured collections + references | ACCEPTED |
| Canonical wire format | JSON | ACCEPTED |
| Timestamp format | UTC RFC 3339 / ISO 8601 | ACCEPTED |
| Internal entity IDs | UUIDv7 | ACCEPTED |
| Human-readable IDs | Separate display IDs | ACCEPTED |
| SecurityEvent | Observation only | ACCEPTED |
| Detection | Separate from Incident | ACCEPTED |
| Rules | Versioned, deterministic, auditable | ACCEPTED |
| Rule authoring | Declarative YAML DSL | ACCEPTED |
| Arbitrary rule code | Not permitted | ACCEPTED |
| Severity | LOW/MEDIUM/HIGH/CRITICAL | ACCEPTED |
| Confidence | Separate from severity | ACCEPTED |
| Routing | Level/skill/team/queue | ACCEPTED |
| Routing | Deterministic | ACCEPTED |
| Routing | Severity is not sole input | ACCEPTED |
| AuditEvent | Separate from SecurityEvent | ACCEPTED |
| API | `/api/v1` | ACCEPTED |
| API representation | JSON | ACCEPTED |
| API pagination | Bounded limit/offset | ACCEPTED |
| API filtering | Allowlisted | ACCEPTED |
| Message envelope | Versioned JSON | ACCEPTED |
| Message delivery | At-least-once + idempotent | ACCEPTED |
| Message transport | Not yet locked | PROVISIONAL |
| Retention | Configurable by data class | ACCEPTED |
| Security-event retention | 90-day MVP default | ACCEPTED |
| Incident retention | 1-year MVP default | ACCEPTED |
| Audit retention | 1-year MVP default | ACCEPTED |
| High-impact autonomous response | Excluded from MVP | ACCEPTED |
| AI critical path | Excluded from MVP | ACCEPTED |
| Real collectors | Added incrementally | ACCEPTED |
| MongoDB transactions | Use when required and supported | PROVISIONAL |
| MongoDB indexes | Query-driven | PROVISIONAL |

---

# 49. Phase 2 Completion Principle

Phase 2 is complete when the ProShield contracts are sufficiently explicit
that implementation can begin without an agent having to guess:

- what a SecurityEvent means
- what an Incident means
- what data objects exist
- how they relate
- what APIs accept
- what APIs return
- how IDs work
- how timestamps work
- how rules are represented
- how routing is represented
- how messages are represented
- how persistence is organized
- how retention works
- which decisions are fixed
- which decisions are still open

The implementation phase must build **to these contracts**, not redefine
them while coding.