# ProShield — Architecture

## 1. Purpose

This document defines the technical architecture of the first ProShield
MVP.

`PRODUCT_SCOPE.md` defines what ProShield is.

`MVP_REQUIREMENTS.md` defines what the MVP must do.

`INITIAL_SECURITY_EVENTS.md` defines the initial simulated event sources
and test scenarios.

`ROUTING_MATRIX.md` defines how incidents are routed.

`MVP_ACCEPTANCE.md` defines how the complete MVP will be validated.

This document defines how those requirements are implemented as a
coherent system.

The architecture must prioritize:

- security
- correctness
- reliability
- explainability
- testability
- maintainability
- reasonable scalability
- cost efficiency

The architecture must remain simple enough for the first production MVP
while leaving a clear path for future real collectors, broader
integrations, and AI-assisted investigation.

---

# 2. Architectural Goal

The central architectural goal is to reliably transform fragmented
security telemetry into one contextualized, evidence-backed,
analyst-ready incident.

The target flow is:

Security Sources
→ Collectors
→ Event Validation
→ Event Normalization
→ Detection
→ Correlation
→ Timeline
→ Severity + Confidence
→ Incident
→ Early Report
→ Routing
→ Human Analyst

The architecture must preserve the traceability of evidence through this
entire flow.

---

# 3. Core Architectural Principles

## 3.1 Source Independence

The core ProShield engine must not depend on one specific security product.

NGINX, WAF/Cezara, rate-limiting systems, TLS/network systems, SIEM,
endpoint-security systems, IAM systems, and the simulator are all sources
of telemetry.

Each source should integrate through an adapter/collector boundary.

Correct:

Source
→ Source Adapter
→ Canonical SecurityEvent
→ ProShield Core

Incorrect:

Source
→ Source-specific detection logic embedded throughout ProShield

---

## 3.2 Canonical Event Model

All downstream processing must operate on a canonical `SecurityEvent`
representation.

The collector layer is responsible for converting source-specific
telemetry into that representation.

This allows:

- the simulator to use the same processing pipeline as real collectors
- NGINX to use the same processing pipeline as WAF
- future SIEM integration without rewriting the core engine

---

## 3.3 Deterministic Core

The first MVP detection pipeline is deterministic and rule-based.

The following capabilities must not depend on AI:

- validation
- normalization
- detection
- correlation
- timeline construction
- severity
- confidence
- incident creation
- routing

AI is a future enhancement and must not become a critical dependency for
the core security pipeline.

---

## 3.4 Evidence Traceability

Every important derived result must be traceable to its supporting
evidence.

The basic chain is:

SecurityEvent
→ Detection
→ Correlation
→ Timeline
→ Severity / Confidence
→ Incident
→ Report
→ Routing

A downstream component must be able to identify which upstream events and
rules produced its result.

---

## 3.5 Explainability

Security decisions must be understandable.

Important decisions must identify:

- what happened
- which rule or logic triggered
- what evidence was used
- how related events were correlated
- why severity was selected
- why routing was selected

The MVP must avoid opaque security decisions.

---

## 3.6 Human-in-the-Loop

ProShield prepares the investigation.

It does not replace the human analyst.

The architecture must therefore make it easy for a human to:

- inspect evidence
- inspect the timeline
- review severity
- review confidence
- review routing
- override recommendations
- investigate
- close or reclassify the incident

---

## 3.7 Fail Safely

A failure in one component must not silently destroy the integrity of the
security workflow.

The architecture must prefer:

- explicit failure
- preserved evidence
- visible telemetry gaps
- recoverable state
- deterministic fallback

over:

- silent data loss
- false success
- fabricated results

---

# 4. High-Level System Architecture

The logical architecture is:

```text
                         EXTERNAL SECURITY SOURCES
                  ┌────────────┬────────────┬────────────┐
                  │            │            │            │
              Simulator      NGINX      WAF/Cezara   Other Sources
                  │            │            │
                  └────────────┴────────────┴────────────┘
                                   │
                                   ▼
                          COLLECTOR / ADAPTER
                                   │
                                   ▼
                           EVENT INGESTION
                                   │
                                   ▼
                          EVENT VALIDATION
                                   │
                                   ▼
                         EVENT NORMALIZATION
                                   │
                                   ▼
                            RULE ENGINE
                                   │
                                   ▼
                         CORRELATION ENGINE
                                   │
                                   ▼
                           TIMELINE ENGINE
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ SEVERITY + CONFIDENCE ENGINE   │
                  └─────────────────────────────────┘
                                   │
                                   ▼
                           INCIDENT MANAGER
                              /           \
                             /             \
                            ▼               ▼
                    REPORT GENERATOR   ROUTING ENGINE
                            │               │
                            └───────┬───────┘
                                    ▼
                             ANALYST INTERFACE
                                    │
                                    ▼
                              HUMAN ANALYST
```

Cross-cutting security and operational controls apply across the system:

```text
Authentication
Authorization
Audit
Event Integrity
Rule Integrity
Configuration Security
Secrets Management
Observability
Failure Handling
Rate Limiting / Abuse Protection
```

---

# 5. Architectural Layers

ProShield is divided into logical layers.

## Layer 1 — Source Integration

Responsible for receiving or reading telemetry from external sources.

Examples:

- simulated event generator
- NGINX
- WAF/Cezara
- rate-limiting system
- TLS/network source
- future SIEM
- future endpoint security
- future IAM

This layer is source-specific.

---

## Layer 2 — Ingestion

Responsible for receiving source events into ProShield.

Responsibilities:

- receive events
- identify source
- assign/preserve event identity
- perform basic ingestion protection
- perform duplicate handling where defined
- pass events to validation

This layer should not perform deep security reasoning.

---

## Layer 3 — Validation

Responsible for determining whether an incoming event is structurally
acceptable.

Responsibilities:

- schema validation
- required-field validation
- timestamp validation
- type validation
- supported-event validation
- malformed-input handling

Invalid data must not silently enter the trusted detection pipeline.

---

## Layer 4 — Normalization

Converts source-specific data into the canonical `SecurityEvent`.

Responsibilities:

- field mapping
- type normalization
- timestamp normalization
- source/provenance preservation
- normalized metadata

Normalization is transformation, not security reasoning.

---

## Layer 5 — Detection

The rule engine evaluates normalized events and determines whether defined
security conditions have occurred.

Responsibilities:

- execute rules
- maintain rule identity/version
- produce detections
- attach evidence
- provide deterministic reasoning
- record rule execution/audit information

The rule engine must not directly bypass the incident-management layer.

---

## Layer 6 — Correlation

The correlation engine determines whether detections/events are related.

Possible correlation factors:

- timestamp
- source
- destination
- endpoint
- account
- device
- asset
- event type
- repeated behavior
- attack pattern
- related security-control activity

The correlation engine must preserve the evidence supporting the
relationship.

---

## Layer 7 — Timeline

The timeline engine constructs a chronological representation of the
investigation activity.

Responsibilities:

- order evidence chronologically
- represent derived correlation relationships
- preserve event identity
- identify gaps where appropriate
- prevent fabricated activity

Every timeline entry must trace to evidence or an explicitly derived
result.

---

## Layer 8 — Severity and Confidence

This layer determines the preliminary triage assessment.

Severity:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Confidence is represented separately from severity.

The component should explain:

- major contributing factors
- evidence strength
- correlation strength
- affected asset
- business criticality
- attack category
- potential impact

Severity and confidence remain preliminary assessments.

---

## Layer 9 — Incident Management

The incident manager creates and maintains the contextualized
investigation case.

Responsibilities:

- create incidents
- associate detections
- associate events
- maintain timeline reference
- store severity/confidence
- maintain incident state
- manage status transitions
- preserve audit history

Initial states:

- OPEN
- INVESTIGATING
- CONTAINED
- RESOLVED
- FALSE_POSITIVE

---

## Layer 10 — Report Generation

The report generator produces the early investigation report.

The report must distinguish:

OBSERVED FACTS

from:

DERIVED CONCLUSIONS

from:

RECOMMENDATIONS

The report should be generated from incident data and supporting evidence,
not from invented narrative.

---

## Layer 11 — Routing

The routing engine determines:

- analyst level
- required skill/category
- team
- queue
- routing reason

The MVP does not assume individual analyst availability.

The routing engine is deterministic and explainable.

The routing decision is stored and audited.

---

## Layer 12 — Human Interface

The analyst-facing interface presents:

- incidents
- severity
- confidence
- evidence
- timeline
- reports
- routing recommendation
- incident status
- audit history
- human override controls

The interface is the investigation workspace.

It is not the source of truth for security decisions.

Security decisions must remain enforced by the backend.

---

# 6. Event Lifecycle

A security event follows this lifecycle:

```text
SOURCE
  ↓
RECEIVED
  ↓
VALIDATED
  ↓
NORMALIZED
  ↓
DETECTION EVALUATION
  ↓
CORRELATION
  ↓
TIMELINE / INCIDENT CONTEXT
```

An event may not trigger a detection.

An event may remain useful as evidence even when no rule is triggered.

An event may also become associated with an existing incident.

---

# 7. Detection Lifecycle

A detection follows:

```text
Normalized Event(s)
        ↓
Rule Evaluation
        ↓
Rule Match?
   ┌────┴────┐
   │         │
  NO        YES
   │         │
   │         ▼
   │     Detection
   │         │
   │         ▼
   │     Evidence
   │         │
   └─────────┴──────► Correlation
```

A detection must preserve:

- rule ID
- rule version
- triggering evidence
- category
- timestamp
- severity/confidence contribution where applicable

---

# 8. Correlation Lifecycle

Correlation takes one or more events/detections and determines whether they
represent related activity.

Conceptually:

```text
Event A ─────┐
             │
Event B ─────┼──► Correlation Evaluation
             │
Event C ─────┘
                    ↓
              Related Activity
                    ↓
              Incident Context
```

Correlation must:

- use defined factors
- preserve evidence
- avoid arbitrary grouping
- remain deterministic for the same input/policy
- be auditable

---

# 9. Incident Lifecycle

The incident lifecycle is:

```text
Detection / Correlated Activity
            ↓
        Incident Created
            ↓
            OPEN
            ↓
      INVESTIGATING
            ↓
      ┌─────┴─────┐
      ↓           ↓
   CONTAINED    FALSE_POSITIVE
      ↓
   RESOLVED
```

The exact state transition policy will be finalized during the contracts
and workflow design phase.

---

# 10. Collector Architecture

Collectors are adapters.

The collector's responsibility is to convert source-specific telemetry
into canonical ProShield security events.

Example:

```text
NGINX
  ↓
NGINX Collector
  ↓
Canonical SecurityEvent
  ↓
ProShield Core
```

Another example:

```text
WAF
  ↓
WAF Collector
  ↓
Canonical SecurityEvent
  ↓
ProShield Core
```

The source collector must not contain core incident-detection logic that
belongs in the shared rule/correlation system.

---

# 11. Simulated Event Architecture

The first source is simulated canonical events.

The simulator exists to test the core pipeline under controlled conditions.

Correct:

```text
Scenario Generator
        ↓
Canonical SecurityEvent
        ↓
ProShield Core
```

Incorrect:

```text
Scenario Generator
        ↓
Direct Incident Creation
```

The simulator must behave like a real source.

It must not bypass:

- validation
- normalization
- detection
- correlation
- severity
- incident creation
- routing

This ensures simulation results remain representative of later real
collector integrations.

---

# 12. Real Collector Progression

The planned integration order is:

1. Simulated canonical events
2. NGINX
3. WAF / Cezara
4. Rate limiting
5. TLS / network
6. SIEM
7. Endpoint security
8. IAM

The first MVP proof must not depend on having every collector.

At least one real collector should eventually pass through the same core
pipeline before the production MVP is declared validated.

---

# 13. API Boundary

The application/API layer sits between external users or administrative
clients and ProShield internal services.

Conceptually:

```text
Client / Analyst UI
        ↓
     API Layer
        ↓
Authentication
        ↓
Authorization
        ↓
Application Services
        ↓
Core ProShield Components
```

The API must not trust security-sensitive decisions supplied by clients.

Examples:

- client cannot choose its own incident severity
- client cannot claim an arbitrary routing decision
- client cannot submit a forged audit actor
- client cannot bypass authorization by changing an incident ID

The backend remains the authority.

---

# 14. Authentication and Authorization Boundary

Authentication identifies the caller.

Authorization determines what the caller is allowed to do.

These must remain separate concepts.

The architecture must eventually support role-based access appropriate
to the MVP, such as:

- Security Analyst
- Security Admin / Security Lead

Sensitive operations must require explicit authorization.

Examples:

- modifying rules
- changing routing policies
- changing configuration
- administrative incident actions
- security-sensitive response actions

---

# 15. Data Storage Responsibilities

The architecture requires durable storage for important security state.

At minimum, the logical data domains are:

- security events
- detections
- incidents
- timeline information
- reports or report references
- rules and rule versions
- routing policies/configuration
- audit records

Not every logical object must become a separate physical database table or
collection.

The final storage technology and exact schema will be determined in
Phase 2.

Storage design must support:

- traceability
- querying
- auditability
- retention policy
- appropriate integrity protection
- reasonable MVP performance

---

# 16. Event Integrity

Security events are evidence.

The architecture must protect them from unauthorized manipulation.

Controls may include, depending on the final design:

- source authentication
- event identity
- provenance
- integrity metadata
- replay detection
- append-oriented storage behavior
- authorization controls
- audit logging

The exact mechanism will be finalized during the secure architecture and
data-model phases.

---

# 17. Rule Management Architecture

Rules are security-sensitive configuration.

The rule system must support:

- unique rule identity
- rule version
- enabled/disabled state
- defined conditions
- deterministic execution
- ownership/authorization
- audit history
- testing

A rule change must be distinguishable from normal runtime event
processing.

Unauthorized users must not be able to change detection behavior.

---

# 18. Routing Policy Architecture

Routing policies are also security-sensitive configuration.

The routing subsystem must be able to evaluate:

- severity
- complexity
- incident category
- required skill
- affected technology
- affected asset
- business criticality
- confidence
- investigation depth

The routing output must contain the explanation supporting the decision.

Routing policy changes must be authorized and auditable.

---

# 19. Audit Architecture

Audit records provide accountability for security decisions.

The audit system must capture important actions such as:

- event ingestion
- validation results
- rule execution
- detection creation
- correlation
- severity decisions
- incident creation
- report generation
- routing decisions
- rule modifications
- configuration changes
- analyst actions
- administrative actions
- response actions

Audit records must themselves be protected from unauthorized modification.

---

# 20. Observability Architecture

ProShield must be able to distinguish:

- security events
- application logs
- security audit events
- operational health information

Operational logs must not become a substitute for the audit system.

Observability should support:

- service health
- ingestion failures
- processing failures
- queue/backlog visibility when applicable
- latency
- throughput
- dependency health
- security telemetry gaps
- critical errors

Secrets and sensitive security data must not be casually exposed in
operational logs.

---

# 21. Failure Handling

Failures must be handled explicitly.

Examples:

### Collector failure

The system should identify telemetry loss or collector unavailability.

### Validation failure

The event must not enter the trusted pipeline.

### Normalization failure

The event should be rejected/quarantined or otherwise handled according
to the defined policy.

### Rule engine failure

The system must not falsely claim detection succeeded.

### Correlation failure

Existing evidence must remain preserved.

### Report generation failure

The underlying incident must remain available.

### Routing failure

The incident must remain available and the routing failure must be visible.

### Storage failure

The system must not falsely confirm persistence when persistence did not
occur.

---

# 22. Fail-Safe Processing Principle

Where possible, the architecture should separate:

CORE SECURITY STATE

from:

OPTIONAL OBSERVABILITY / ENHANCEMENT

For example, a failure to generate an optional enriched summary must not
destroy the underlying incident and evidence.

Likewise, future AI functionality must not become a single point of failure
for deterministic detection.

---

# 23. Processing Model

The exact processing model will be finalized after evaluating:

- expected MVP event volume
- latency requirements
- reliability requirements
- operational complexity
- deployment environment
- failure recovery needs

The MVP should prefer the simplest processing architecture that satisfies
the requirements.

Do not introduce Kafka, RabbitMQ, multiple worker clusters, or other
infrastructure merely because they are common at large scale.

If asynchronous processing is required, it should be introduced around
clear boundaries such as ingestion and detection processing.

---

# 24. Synchronous vs Asynchronous Responsibilities

The architecture should distinguish operations that require immediate
responses from work that can safely happen asynchronously.

Potentially synchronous:

- API authentication
- permission checks
- direct incident retrieval
- analyst updates
- configuration operations

Potentially asynchronous:

- high-volume event processing
- detection evaluation
- correlation
- timeline updates
- report generation
- integrations

The final implementation decision must be based on the actual MVP
performance and reliability requirements rather than assumed scale.

---

# 25. Source Provenance

Every event must retain enough provenance to answer:

- Where did this event come from?
- Which collector produced it?
- When was it received?
- What was the source event identity?
- What transformation occurred?

Provenance is essential for:

- evidence review
- debugging
- audit
- incident investigation
- future connector troubleshooting

---

# 26. Evidence Chain

ProShield should preserve a logical evidence chain:

```text
Source Event
    ↓
Canonical SecurityEvent
    ↓
Detection
    ↓
Correlation
    ↓
Timeline Entry
    ↓
Incident
    ↓
Report
    ↓
Routing Decision
```

Each downstream object should be able to reference the upstream evidence
needed to explain its existence.

---

# 27. Security-Critical Components

The following components require particularly strong security controls:

- event ingestion
- authentication
- authorization
- rule management
- incident management
- routing management
- audit storage
- secrets management
- response controls

A compromise of these components could directly affect security decisions.

---

# 28. Trust Boundaries

The architecture must explicitly recognize these trust boundaries.

### Boundary 1 — External Source → ProShield

External security sources cannot automatically be trusted.

Events must be validated and, where appropriate, authenticated.

### Boundary 2 — Collector → Core Engine

Only normalized and validated events should enter the trusted processing
pipeline.

### Boundary 3 — Core Engine → Storage

Security state written to storage must be protected against unauthorized
modification.

### Boundary 4 — Client → API

Clients are untrusted inputs.

Authentication and authorization are mandatory before protected operations.

### Boundary 5 — Admin/User → Configuration

Configuration changes are privileged operations.

### Boundary 6 — ProShield → Response Target

Any future response action crosses a high-risk control boundary and must
require explicit authorization and safety checks.

---

# 29. Security Zones

Conceptually, ProShield can be viewed as:

```text
UNTRUSTED
External Security Sources / Clients
        ↓
INGESTION ZONE
Collectors / Validation
        ↓
TRUSTED PROCESSING
Normalization / Rules / Correlation /
Timeline / Severity / Incident
        ↓
PROTECTED STATE
Storage / Audit / Rules / Configuration
        ↓
AUTHORIZED HUMAN ACCESS
Analyst / Admin
        ↓
CONTROLLED RESPONSE
```

The exact network and deployment boundaries will be defined during the
secure-foundation phase.

---

# 30. Scalability Strategy

ProShield should scale by separating source integration from core
processing.

Additional collectors should not require rewriting the detection engine.

Additional rules should not require rewriting collectors.

Additional routing policies should not require rewriting correlation.

The intended scaling direction is:

```text
More Sources
    ↓
More Canonical Events
    ↓
Same Core Pipeline
```

and:

```text
More Rules
    ↓
Same Event Contract
    ↓
Same Detection Interface
```

---

# 31. MVP Scaling Philosophy

The MVP should be designed for realistic startup-scale workloads, not
internet-scale SIEM volumes.

The architecture should be capable of evolving toward:

- larger event volume
- additional collectors
- more rules
- more incidents
- more users
- more teams

without requiring a complete rewrite.

However, infrastructure should be introduced only when requirements
justify it.

---

# 32. Availability Strategy

Availability requirements should reflect the fact that ProShield is a
security operations system.

The architecture should minimize single points of failure that would:

- silently lose telemetry
- destroy incidents
- invalidate audit information
- falsely report processing success

The final availability architecture depends on the intended production
deployment and workload.

The MVP must at minimum expose meaningful health and failure states.

---

# 33. Data Retention and Evidence Lifecycle

The architecture must eventually define retention policies for:

- raw security events
- normalized events
- detections
- incidents
- timelines
- audit records
- reports

Different data types may require different retention periods.

Retention policy is a production concern and must not be invented during
implementation without an explicit requirement.

The exact retention values will be decided during the data-model and
deployment phases.

---

# 34. Configuration Architecture

Configuration should be separated from source code where appropriate.

Configuration may include:

- enabled collectors
- event-source settings
- rules
- rule thresholds
- routing policies
- severity policy
- business-criticality mappings
- operational limits

Security-sensitive configuration must be protected and changes must be
audited.

---

# 35. Dependency Boundaries

A component should depend only on the interfaces it actually needs.

Examples:

- the rule engine should depend on the canonical event contract, not on
  NGINX internals
- routing should depend on incident information, not raw source log
  formats
- the report generator should depend on incident/evidence data, not on
  collector implementation details

This reduces coupling and makes future integrations easier.

---

# 36. Testing Architecture

Each architectural layer must be testable independently.

Examples:

### Collector tests

Verify source → canonical event conversion.

### Validation tests

Verify valid/invalid event behavior.

### Normalization tests

Verify canonical conversion.

### Rule tests

Verify rule trigger/non-trigger behavior.

### Correlation tests

Verify related/unrelated event grouping.

### Timeline tests

Verify chronological and evidence-backed output.

### Severity tests

Verify deterministic severity logic.

### Incident tests

Verify creation and state transitions.

### Report tests

Verify report completeness and fact/conclusion/recommendation separation.

### Routing tests

Verify routing matrix behavior.

### Security tests

Verify unauthorized actions are blocked.

### End-to-end tests

Verify:

Event
→ Detection
→ Incident
→ Report
→ Routing

---

# 37. Test Data Strategy

The simulator and deterministic event scenarios defined in
`INITIAL_SECURITY_EVENTS.md` are the primary source of repeatable test
data during early development.

Tests should include:

- normal cases
- edge cases
- invalid events
- duplicate events
- correlated events
- unrelated events
- unknown patterns
- failure scenarios
- security abuse scenarios

Real production data must not be required for the core MVP tests.

---

# 38. Deployment Architecture Boundary

This architecture document describes the logical application architecture.

It does not yet lock:

- cloud provider
- container platform
- database technology
- orchestration platform
- exact network topology
- CI/CD provider

Those decisions will be made through explicit architecture decisions and
deployment requirements.

The goal is to avoid choosing infrastructure merely because it is popular.

---

# 39. Future AI Architecture

AI is not part of the deterministic critical path.

Future architecture may introduce:

```text
Deterministic Pipeline
        ↓
AI Investigation Layer
        ↓
Deeper Correlation
        ↓
Investigation Assistance
        ↓
Human Analyst
```

AI may assist with:

- investigation
- deeper correlation
- contextual reasoning
- report enhancement
- recommendations

AI must not become a single dependency whose failure stops:

- event ingestion
- deterministic detection
- incident creation
- audit
- human access to existing evidence

---

# 40. Future Response Architecture

Response actions are outside the initial autonomous scope.

Future controlled response may be introduced as:

```text
Incident
  ↓
Recommendation
  ↓
Human Approval
  ↓
Authorized Response
  ↓
Audit
```

The response subsystem must remain isolated from the core detection logic
so that a detection cannot accidentally execute an unrestricted
destructive action.

---

# 41. Architecture Boundaries for the MVP

The first MVP architecture must include:

- source adapters
- ingestion
- validation
- normalization
- deterministic rule engine
- correlation
- timeline
- severity/confidence
- incident management
- report generation
- routing
- audit
- authentication
- authorization
- security controls
- observability
- fail-safe handling

The first MVP architecture does not require:

- AI investigation
- autonomous SOC behavior
- complete SIEM functionality
- individual analyst workload scheduling
- unrestricted automated response
- every possible security collector
- internet-scale infrastructure

---

# 42. Component Responsibilities Summary

| Component | Primary Responsibility | Must Not Own |
|---|---|---|
| Collector | Source-specific ingestion/adaptation | Core detection logic |
| Ingestion | Receive and identify events | Security conclusions |
| Validation | Verify event structure | Correlation decisions |
| Normalizer | Convert source formats | Detection reasoning |
| Rule Engine | Evaluate deterministic rules | Human decisions |
| Correlation | Relate evidence | Invent evidence |
| Timeline | Build chronological evidence view | New unsupported events |
| Severity/Confidence | Preliminary assessment | Final human judgment |
| Incident Manager | Investigation case lifecycle | Source-specific parsing |
| Report Generator | Prepare investigation summary | Fabricated evidence |
| Routing Engine | Recommend level/skill/team/queue | Individual availability assumptions |
| Audit | Preserve accountability | Normal runtime state |
| Analyst UI | Present/manage authorized workflow | Backend authorization |
| Response Module | Controlled future response | Unrestricted autonomous actions |

---

# 43. Architecture Quality Requirements

A proposed implementation must be rejected or reconsidered if it:

- tightly couples the core engine to one security product
- requires AI for deterministic detection
- makes security decisions without traceable evidence
- hides important failures
- mixes authentication and authorization logic carelessly
- allows clients to dictate trusted security decisions
- makes rule changes unauditable
- makes routing decisions unauditable
- creates unnecessary infrastructure without a requirement
- prevents independent testing of core components

---

# 44. Architecture Review Questions

Before implementation of a major component, answer:

1. What problem does this component solve?
2. Why is it required?
3. What inputs does it receive?
4. What outputs does it produce?
5. Who can access it?
6. What can an attacker abuse?
7. How is it protected?
8. How does it fail?
9. How is it tested?
10. How does it scale?
11. How does it integrate with the rest of ProShield?

These questions are part of the ProShield engineering discipline.

---

# 45. Architecture Completion Criteria

Phase 1 architecture is complete when:

- all major components are identified
- responsibilities are clear
- event lifecycle is defined
- trust boundaries are defined
- core data flow is documented
- collector boundaries are clear
- deterministic processing is defined
- failure behavior is understood
- security-critical components are identified
- the initial threat model exists
- unresolved architecture decisions are explicitly recorded
- no major component depends on undocumented assumptions

Architecture does not need to predict every future requirement.

It must provide a safe, understandable foundation for the MVP.

---

# 46. Final Architecture Principle

ProShield architecture should be:

SIMPLE ENOUGH TO BUILD
+
SECURE ENOUGH TO TRUST
+
MODULAR ENOUGH TO EXTEND
+
EXPLAINABLE ENOUGH TO AUDIT
+
TESTABLE ENOUGH TO PROVE

The core architectural rule is:

SOURCE-SPECIFIC TELEMETRY
→ CANONICAL SECURITY EVENTS
→ DETERMINISTIC SECURITY INTELLIGENCE
→ CONTEXTUALIZED INCIDENT
→ EXPLAINABLE ROUTING
→ HUMAN INVESTIGATION

Everything else exists to support that pipeline without compromising its
security, evidence integrity, reliability, or explainability.