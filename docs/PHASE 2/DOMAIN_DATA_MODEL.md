# ProShield — Domain Data Model

## 1. Purpose

This document defines the logical domain model for the ProShield MVP.

`PRODUCT_SCOPE.md` defines what ProShield is.

`MVP_REQUIREMENTS.md` defines what the MVP must do.

`ARCHITECTURE.md` defines how the system is structured.

`SECURITY_EVENT_SCHEMA.md` defines the canonical security-event contract.

This document defines the major domain objects, their responsibilities,
their relationships, and the distinction between observed data, derived
security intelligence, recommendations, and human decisions.

The model is designed for MongoDB persistence, but this document remains a
logical domain model rather than a physical database-schema document.

---

## 2. Core Domain Principle

ProShield must preserve the following distinction:

```text
OBSERVED
SecurityEvent
        ↓
DERIVED SECURITY INTELLIGENCE
Detection
Correlation
Timeline
Severity
Confidence
        ↓
INVESTIGATION
Incident
Report
        ↓
RECOMMENDATION
RoutingRecommendation
        ↓
HUMAN DECISION
Analyst / Admin Action
        ↓
ACCOUNTABILITY
AuditEvent
```

The system must never silently treat a derived conclusion as raw evidence
or a system recommendation as a human decision.

---

## 3. Domain Object Groups

### Observed Data

- `SecurityEvent`

### Security Intelligence

- `Rule`
- `Detection`
- `Correlation`
- `TimelineEvent`
- `Severity`
- `Confidence`

### Investigation

- `Evidence`
- `Incident`
- `Report`

### Routing

- `RoutingPolicy`
- `RoutingRecommendation`

### Accountability

- `AuditEvent`

---

## 4. SecurityEvent

## Purpose

`SecurityEvent` represents an observed security-related event received from
a security source.

Examples:

- WAF detection
- blocked request
- rate-limit violation
- suspicious request
- authentication failure
- authentication success
- TLS anomaly
- network anomaly

A SecurityEvent is an observation.

It is not:

- a confirmed attack
- a detection
- an incident
- a severity decision
- a routing decision
- a human conclusion
- an AI interpretation

## Authoritative Schema

The detailed SecurityEvent contract is defined in:

`SECURITY_EVENT_SCHEMA.md`

## Key Conceptual Fields

- `event_id`
- `event_time`
- `ingested_at`
- `source`
- `event_type`
- `source_ip` when available
- `destination` when available
- `endpoint` when applicable
- `asset` when known
- `account` when known
- `device` when known
- `details`
- `provenance`

## Relationships

```text
SecurityEvent
   ├── may trigger → Detection
   ├── may participate in → Correlation
   └── may appear in → TimelineEvent
```

---

## 5. Rule

## Purpose

A `Rule` defines a deterministic security condition that ProShield knows
how to evaluate.

Rules are security-sensitive configuration.

## Conceptual Fields

A Rule should support:

- `rule_id`
- `version`
- `name`
- `enabled`
- `description`
- `conditions`
- `window`
- `classification`
- severity contribution where applicable
- confidence contribution where applicable
- configuration metadata
- audit information

The exact rule DSL is defined separately in the Phase 2 contract work.

## Relationships

```text
Rule
   ↓
evaluates SecurityEvent(s)
   ↓
may create Detection
```

One Rule version may produce many Detection objects.

---

## 6. Detection

## Purpose

A `Detection` represents the result of a Rule identifying a defined
security condition.

A Detection is derived from one or more SecurityEvents.

It means:

> A configured security condition was observed.

It does not automatically mean:

> A confirmed attack occurred.

## Conceptual Fields

A Detection should contain or reference:

- `detection_id`
- `rule_id`
- `rule_version`
- `detected_at`
- detection category
- supporting event references
- rule reasoning
- severity contribution
- confidence contribution
- detection status where required

## Relationships

```text
SecurityEvent(s)
      ↓
Detection
      ↑
Rule
```

A single SecurityEvent may contribute to multiple legitimate detections.

---

## 7. Correlation

## Purpose

A `Correlation` represents an explicit relationship between multiple
events and/or detections.

Correlation exists because one real security activity may generate many
separate security events.

## Conceptual Fields

A Correlation should support:

- `correlation_id`
- participating event references
- participating detection references
- correlation factors
- correlation window
- correlation reasoning
- confidence/strength
- creation timestamp

Possible correlation factors include:

- source
- destination
- endpoint
- account
- device
- asset
- event type
- repeated behavior
- attack pattern
- related security controls
- time relationship

## Relationships

```text
SecurityEvent(s)
        +
Detection(s)
        ↓
Correlation
```

Correlation must remain explainable.

---

## 8. TimelineEvent

## Purpose

A `TimelineEvent` is an item in an incident's chronological investigation
timeline.

A TimelineEvent is not necessarily a new raw security event.

It may represent:

- an observed SecurityEvent
- a Detection
- a Correlation-derived activity
- another explicitly derived investigation step

## Conceptual Fields

- `timeline_event_id`
- `incident_id`
- timestamp
- source event reference when applicable
- detection reference when applicable
- correlation reference when applicable
- description
- evidence references

## Critical Rule

Every TimelineEvent must trace to:

1. an observed SecurityEvent, or
2. an explicitly derived ProShield result.

No fabricated activity may appear as observed evidence.

---

## 9. Evidence

## Purpose

`Evidence` is the logical concept representing the supporting material
behind an incident or derived conclusion.

Evidence may be represented through references rather than always requiring
a standalone physical MongoDB document.

Possible evidence sources:

- SecurityEvents
- Detections
- Correlations
- TimelineEvents
- source metadata
- explicitly supported artifacts

## Evidence Principle

Every important ProShield conclusion should be traceable to supporting
evidence.

```text
Evidence
   ↑
SecurityEvent
Detection
Correlation
TimelineEvent
   ↓
Incident
Report
RoutingRecommendation
```

Evidence must never be fabricated.

---

## 10. Severity

## Purpose

Severity is a preliminary triage assessment used to prioritize an
incident.

Initial values:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Severity is a derived property.

It is not normally a raw SecurityEvent fact.

## Possible Inputs

- triggered rule
- number of related events
- correlation strength
- affected asset
- business criticality
- attack category
- confidence
- potential impact

## Human Authority

Severity is preliminary.

An authorized human analyst may later change it.

Any change must be auditable.

---

## 11. Confidence

## Purpose

Confidence represents how strongly the available evidence supports the
current detection/correlation conclusion.

Confidence must remain separate from severity.

Example:

```text
Severity: HIGH
Confidence: MEDIUM
```

is valid.

## Possible Inputs

- rule certainty
- evidence strength
- correlation strength
- consistency of observed signals
- completeness of available evidence

Confidence must be derived from actual information.

It must not be fabricated merely to make the incident look more certain.

---

## 12. Incident

## Purpose

`Incident` is the central ProShield investigation object.

An Incident represents a contextualized investigation unit created from
relevant detections and correlated activity.

The goal is to transform:

```text
many fragmented observations
```

into:

```text
one investigation-ready case
```

## Conceptual Fields

An Incident should support:

- `incident_id`
- category
- severity
- confidence
- status
- created_at
- updated_at
- event references
- detection references
- correlation references
- timeline references
- evidence references
- affected assets
- source information
- report references
- routing recommendation references

## Initial States

```text
OPEN
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE
```

State transitions must be controlled and auditable.

## Relationships

```text
SecurityEvent(s)
      ↓
Detection(s)
      ↓
Correlation
      ↓
TimelineEvent(s)
      ↓
Incident
```

---

## 13. Incident Category

## Purpose

Incident category identifies the type of security activity represented by
an Incident when the available evidence supports a classification.

Initial categories may include:

- web attack
- rate-limit abuse
- suspicious authentication activity
- multi-control correlated activity
- network/TLS anomaly

The catalogue may grow as additional rules and collectors are introduced.

## Unknown Classification

If the evidence does not support a reliable category:

- preserve uncertainty
- do not invent a category
- allow human investigation

Unknown classification is a valid outcome.

---

## 14. Report

## Purpose

`Report` represents the early investigation report generated from an
Incident.

It is intended to reduce repetitive analyst preparation work.

## Conceptual Content

A Report may include:

- incident summary
- observed facts
- derived conclusions
- attack timeline
- supporting evidence
- severity
- confidence
- classification
- affected assets
- correlation reasoning
- recommended investigation steps
- routing information

## Required Separation

The Report must distinguish:

```text
OBSERVED FACTS
DERIVED CONCLUSIONS
RECOMMENDATIONS
```

The report must never present speculation as observed evidence.

## Relationship

```text
Incident
   ↓
Report
```

A report may be regenerated when incident information changes.

If historical report versions are retained, each version must remain
traceable.

---

## 15. RoutingPolicy

## Purpose

`RoutingPolicy` defines the deterministic policy used to determine the
appropriate investigation destination.

RoutingPolicy is security-sensitive configuration.

## Conceptual Inputs

- severity
- complexity
- incident category
- required security skill
- affected technology
- affected asset
- business criticality
- confidence
- investigation depth

## Conceptual Identity

A policy must have:

- `policy_id`
- `version`
- enabled/disabled state
- policy definition
- metadata
- audit history

## Relationship

```text
RoutingPolicy
       ↓
RoutingRecommendation
       ↑
Incident
```

---

## 16. RoutingRecommendation

## Purpose

`RoutingRecommendation` represents ProShield's recommendation for where
and at what level an Incident should be investigated.

## Conceptual Fields

- `routing_recommendation_id`
- `incident_id`
- recommended analyst level
- required skill/category
- recommended team
- recommended queue
- severity used
- complexity used
- confidence used
- affected technology where relevant
- reason
- policy ID
- policy version
- timestamp

## Important Principle

A RoutingRecommendation is a system recommendation.

It is not an assignment to an individual analyst.

The MVP initially routes to:

- analyst level
- skill
- team
- queue

Individual analyst assignment requires authorized organizational data.

---

## 17. Human Decision / Override

Human decisions are distinct from system recommendations.

An authorized analyst or administrator may:

- change severity
- change classification
- change routing
- change incident status
- close/reclassify the incident
- make response decisions

When a human overrides a ProShield recommendation, the model must preserve:

- original recommendation
- human decision
- actor
- timestamp
- reason when provided

The system must never silently replace the automated recommendation.

---

## 18. AuditEvent

## Purpose

`AuditEvent` is the accountability record for actions performed inside
ProShield.

AuditEvent is different from SecurityEvent.

### SecurityEvent

Means:

> Something security-related was observed in the monitored environment.

### AuditEvent

Means:

> Something happened inside ProShield or was performed by a user/service.

## Examples

- event ingestion
- validation result
- rule creation
- rule modification
- detection creation
- incident creation
- severity change
- routing decision
- routing override
- analyst action
- administrative action
- configuration change
- response action

## Conceptual Fields

- `audit_event_id`
- timestamp
- actor/service identity
- action
- object type
- object ID
- result
- relevant context
- source information where applicable

Secrets must never be stored in an AuditEvent.

---

## 19. Relationship Between SecurityEvent and AuditEvent

These two objects must remain separate.

```text
SecurityEvent
=
Evidence from the monitored environment

AuditEvent
=
Accountability record for ProShield activity
```

Example:

```text
SecurityEvent:
"WAF blocked suspicious request."

AuditEvent:
"Rule WEB-WAF-001 version 3 created Detection DET-123."
```

They answer different questions and serve different trust purposes.

---

## 20. Core Relationship Map

```text
                         ┌───────────────┐
                         │ SecurityEvent │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │   Detection   │
                         └───────┬───────┘
                                 ▲
                                 │
                         ┌───────┴───────┐
                         │     Rule      │
                         └───────────────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │  Correlation  │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │ TimelineEvent │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │    Incident   │
                         └───┬─────┬─────┘
                             │     │
                 ┌───────────┘     └─────────────┐
                 ▼                               ▼
          ┌────────────┐                  ┌──────────────────┐
          │   Report   │                  │ RoutingPolicy    │
          └────────────┘                  └────────┬─────────┘
                                                    │
                                                    ▼
                                          ┌────────────────────┐
                                          │RoutingRecommendation│
                                          └────────────────────┘
```

`Evidence` provides traceability across the chain.

`AuditEvent` records important actions taken across the entire model.

---

## 21. Core Relationships

### SecurityEvent → Detection

One SecurityEvent may contribute to:

- zero detections
- one detection
- multiple detections

depending on which rules match.

---

### Rule → Detection

One Rule version may produce many Detection objects.

Each Detection records the exact Rule version used.

---

### Detection → Correlation

Multiple detections may participate in one Correlation.

A Detection may participate in more than one correlation where the
configured domain logic permits it.

---

### SecurityEvent → TimelineEvent

A TimelineEvent may directly reference a SecurityEvent.

---

### Correlation → TimelineEvent

A TimelineEvent may represent a correlation-derived activity.

---

### Incident → SecurityEvent

An Incident may reference many supporting SecurityEvents.

The complete event payload should not be duplicated unnecessarily into the
Incident document.

---

### Incident → Detection

An Incident may reference multiple Detections.

---

### Incident → Correlation

An Incident may reference one or more Correlations that explain the
relationship between supporting activity.

---

### Incident → TimelineEvent

An Incident contains or references multiple TimelineEvents.

---

### Incident → Report

An Incident may have a current Report and, if report versioning is
implemented, historical versions.

---

### Incident → RoutingRecommendation

An Incident may have a current RoutingRecommendation and historical
recommendations if policy or incident state changes.

---

### RoutingPolicy → RoutingRecommendation

A RoutingRecommendation records the RoutingPolicy version that produced it.

---

## 22. Data Ownership

Each domain object has a primary conceptual owner.

| Domain Object | Primary Responsibility |
|---|---|
| SecurityEvent | Event ingestion/source layer |
| Rule | Rule management |
| Detection | Detection engine |
| Correlation | Correlation engine |
| TimelineEvent | Timeline/incident context |
| Incident | Incident manager |
| Report | Report generator |
| RoutingPolicy | Routing policy management |
| RoutingRecommendation | Routing engine |
| AuditEvent | Audit subsystem |

A component should not silently mutate another component's domain object
without an explicit contract.

---

## 23. Observed vs Derived vs Human-Controlled Data

This distinction is mandatory.

### Observed

- SecurityEvent values
- source-provided metadata
- source timestamps
- provenance

### Derived

- Detection
- Correlation
- Timeline relationships
- Severity
- Confidence
- Incident category
- RoutingRecommendation

### Human-Controlled

- final severity override
- final classification
- routing override
- incident status decision
- final response decision
- incident closure

This distinction must remain visible in the domain model, persistence
model, API responses, and UI where appropriate.

---

## 24. Duplication Principle

ProShield should prefer references to authoritative domain objects instead
of copying entire objects unnecessarily.

Examples:

### Incident

Reference supporting event IDs instead of copying full event documents.

### Detection

Reference the Rule and Rule version rather than duplicating the entire
Rule definition.

### RoutingRecommendation

Reference the RoutingPolicy and policy version rather than duplicating the
entire policy.

### Report

Derive from authoritative Incident and Evidence information.

This reduces inconsistency and simplifies updates.

---

## 25. MongoDB Document Strategy

MongoDB is the primary persistence layer.

Major logical domains should use separate collections rather than one giant
document.

Initial logical collections:

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

Major domain objects are referenced by stable IDs.

Small data that naturally belongs inside an object may be embedded.

For example, a RoutingRecommendation can contain:

- recommended level
- required skill
- team
- queue
- reason

while still referencing the RoutingPolicy version that produced it.

The model should avoid both extremes:

### Avoid

One giant Incident document containing every event, rule, audit record,
and report.

### Also avoid

Splitting every small field into a separate collection without a real
query or lifecycle reason.

The goal is a readable MongoDB-native document model with clear references
between major domain objects.

---

## 26. MongoDB Consistency Requirements

MongoDB's flexibility must not weaken domain integrity.

The implementation should enforce where practical:

- unique identifiers
- valid references
- valid states/enums
- required fields
- schema validation
- controlled update paths

Critical multi-document state changes should use MongoDB transactions
when the production deployment topology supports them.

If a deployment cannot provide the required transaction guarantees, the
workflow must explicitly document the consistency model rather than
pretending atomicity exists.

---

## 27. Identity Requirements

Every major domain object requires a stable identity.

Initial internal identifiers:

- `event_id`
- `rule_id`
- `detection_id`
- `correlation_id`
- `timeline_event_id`
- `incident_id`
- `report_id`
- `routing_policy_id`
- `routing_recommendation_id`
- `audit_event_id`

Internal IDs use UUIDv7.

Human-readable display/reference IDs may be added separately.

Internal IDs are authoritative.

---

## 28. Time Model

Domain objects may need different timestamps.

Examples:

### SecurityEvent

- `event_time`
- `ingested_at`

### Detection

- `detected_at`

### Correlation

- `created_at`

### Incident

- `created_at`
- `updated_at`

### Report

- `generated_at`

### RoutingRecommendation

- `created_at`

### AuditEvent

- `timestamp`

All system-generated timestamps use UTC.

---

## 29. State Model

The initial Incident state model is:

```text
OPEN
  ↓
INVESTIGATING
  ↓
CONTAINED
  ↓
RESOLVED
```

Alternative outcome:

```text
INVESTIGATING
  ↓
FALSE_POSITIVE
```

The exact transition matrix will be finalized in the workflow/API
contracts.

All important state changes must be auditable.

---

## 30. Retention Model

Retention applies differently to different domain objects.

Initial MVP targets:

```text
SecurityEvent:
90 days default

Detection:
180 days default

Correlation:
180 days default

TimelineEvent:
Retention aligned with related Incident where practical

Incident:
1 year default

Report:
1 year default

AuditEvent:
1 year default

Rule history:
retain for the life of the system unless explicitly archived

Routing policy history:
retain for the life of the system unless explicitly archived
```

These are operational MVP defaults, not legal or regulatory requirements.

A deployment may configure longer or shorter retention according to
business, customer, contractual, regulatory, and storage requirements.

---

## 31. Security Requirements

Every domain object containing sensitive information must enforce:

- authentication
- authorization
- least privilege
- integrity protection
- auditability
- appropriate retention
- safe serialization

The UI is not a security boundary.

The backend must enforce authorization.

---

## 32. Unknown / Uncertain Data

The model must support unknown values.

Examples:

- unknown source IP
- unknown destination
- unknown account
- unknown asset
- unknown category
- unknown specialist skill
- unknown routing target

Unknown must not become a fabricated value.

---

## 33. Extensibility

The model should support future:

- real collectors
- SIEM integrations
- endpoint integrations
- IAM integrations
- AI-assisted investigation
- richer routing
- analyst skill matrices
- controlled response

Future capabilities should extend the existing domain model rather than
change the meaning of core observed evidence.

---

## 34. Domain Validation Requirements

### SecurityEvent

Must be:

- valid
- source-attributable
- bounded
- traceable

### Rule

Must be:

- valid
- authorized
- versioned
- testable

### Detection

Must reference:

- valid evidence
- known Rule version

### Correlation

Must reference:

- actual participating evidence
- explainable correlation factors

### TimelineEvent

Must reference:

- observed evidence or explicitly derived results

### Incident

Must contain:

- sufficient evidence and context for investigation

### Report

Must separate:

- facts
- conclusions
- recommendations

### RoutingRecommendation

Must use:

- authorized inputs
- explainable policy

### AuditEvent

Must identify:

- actor/service
- action
- affected object

without exposing secrets.

---

## 35. Query and Access Principles

The domain model must support analyst workflows such as:

- list incidents
- filter incidents
- open incident
- inspect evidence
- inspect timeline
- inspect detections
- inspect report
- inspect routing
- change authorized incident state
- provide authorized human override

Administrators additionally require:

- rule management
- routing policy management
- configuration management
- audit-history access

The API contract will define the exact operations.

---

## 36. Domain Model Acceptance Criteria

The domain model is considered complete when:

### DM-01

Every required MVP concept has a clear domain representation.

### DM-02

Observed evidence is clearly separated from derived intelligence.

### DM-03

Incident is the central investigation object.

### DM-04

Detections are traceable to Rules and SecurityEvents.

### DM-05

Correlations are explainable.

### DM-06

Timeline entries are evidence-backed.

### DM-07

Severity and confidence are separate.

### DM-08

RoutingRecommendation is separate from human decision.

### DM-09

Rules and RoutingPolicies are represented as protected configuration.

### DM-10

AuditEvent is separate from SecurityEvent.

### DM-11

Major relationships are traceable without unnecessary document
duplication.

### DM-12

The model remains compatible with future collectors.

### DM-13

The model is suitable for MongoDB document storage without becoming a
single giant aggregate.

### DM-14

Important data changes remain auditable.

---

## 37. Explicitly Not Finalized Here

This document intentionally does not finalize:

- exact MongoDB collection validators
- exact MongoDB indexes
- exact API request/response JSON
- exact pagination contracts
- exact rule DSL syntax
- exact message payload schemas
- exact UI structures
- exact retention implementation jobs

Those belong to the remaining Phase 2 contract and implementation design.

---

## 38. Final Domain Principle

ProShield's domain model must preserve this chain:

```text
OBSERVED
SecurityEvent
        ↓
DERIVED
Detection
Correlation
Timeline
Severity
Confidence
        ↓
INVESTIGATION
Incident
Report
        ↓
RECOMMENDATION
RoutingRecommendation
        ↓
HUMAN DECISION
Analyst / Admin
        ↓
ACCOUNTABILITY
AuditEvent
```

The fundamental rule is:

> ProShield must always preserve the difference between what was observed,
> what the system derived, what it recommended, and what a human decided.

That separation is fundamental to the product's:

- explainability
- security
- evidence integrity
- auditability
- maintainability
- future AI integration