# ProShield — MVP Requirements

## 1. Purpose of This Document

This document defines the functional, security, reliability, and
operational requirements for the first ProShield MVP.

`PRODUCT_SCOPE.md` defines what ProShield is and why it exists.

This document defines what the MVP must actually do.

These requirements are the baseline for:

- architecture
- API contracts
- data-model design
- implementation
- testing
- security review
- MVP acceptance

An implementation must satisfy these requirements before the MVP can be
considered complete.

Requirements are written to be testable and explainable.

---

# 2. MVP Objective

The ProShield MVP must demonstrate that deterministic automation can
reduce repetitive first-stage security investigation work.

The MVP must transform:

Security Event
→ Detection
→ Correlation
→ Attack Timeline
→ Preliminary Severity
→ Incident
→ Early Investigation Report
→ Analyst Routing
→ Human Analyst

The MVP must work without an AI investigation engine.

AI is not a dependency for the MVP's core functionality.

---

# 3. Functional Requirements

## FR-01 — Security Event Ingestion

ProShield must accept security events from supported event sources.

The first MVP validation source is simulated canonical security events.

Later collectors must use adapters that convert source-specific events into
the canonical ProShield `SecurityEvent` format.

The core detection and correlation pipeline must not depend on one
specific external security product.

### Acceptance

Given a valid canonical security event:

- ProShield accepts it.
- ProShield assigns or preserves an event identity.
- ProShield records its arrival.
- The event becomes available to the detection pipeline.

---

## FR-02 — Event Validation

Every incoming event must be validated before being processed.

Invalid events must not be treated as valid security evidence.

Validation must detect at minimum:

- missing required fields
- invalid field types
- invalid timestamps
- unsupported event types
- malformed source information
- malformed structured metadata

### Acceptance

Given an invalid event:

- ProShield rejects or quarantines it according to the defined ingestion
  behavior.
- It does not enter the normal detection pipeline.
- The failure is auditable.

---

## FR-03 — Event Normalization

ProShield must normalize source-specific event formats into one canonical
`SecurityEvent` representation.

Normalization must preserve important source information.

Normalization must not invent security facts.

The original source identity and relevant source metadata must remain
traceable.

### Acceptance

Given two different source formats describing equivalent security activity:

- both can be normalized into the canonical event structure.
- the normalized output contains the information required by detection
  and correlation.
- source provenance remains available.

---

## FR-04 — Event Deduplication

ProShield must identify duplicate events where the source provides enough
information to do so.

Duplicate handling must not silently discard genuinely separate events.

The deduplication strategy must be deterministic and auditable.

### Acceptance

Given the same event received repeatedly within the defined duplicate
window:

- ProShield does not create uncontrolled duplicate detections/incidents.
- the duplicate decision is traceable.

The exact deduplication mechanism will be defined during architecture and
data-model phases.

---

## FR-05 — Configurable Detection Rules

The MVP must contain a deterministic rule engine.

Rules must be:

- configurable
- versioned
- explainable
- testable
- auditable

A rule evaluates one or more normalized events and determines whether a
defined security condition has occurred.

The rule result must preserve:

- rule identity
- rule version
- rule outcome
- relevant evidence
- relevant event IDs
- detection category
- severity/confidence contribution where applicable

### Acceptance

Given an event set that satisfies a rule:

- the rule triggers deterministically.
- the resulting detection identifies the rule.
- the evidence supporting the rule is available.

Given an event set that does not satisfy the rule:

- the rule does not trigger.

---

## FR-06 — Detection Explainability

Every detection must explain why it occurred.

A detection must be traceable to:

- observed events
- rule conditions
- thresholds
- time windows
- correlation conditions where applicable

ProShield must not produce an unexplained "high risk" result.

---

## FR-07 — Event Correlation

ProShield must determine whether multiple events are related.

Correlation may consider:

- timestamp
- source
- destination
- endpoint
- account
- device
- event type
- repeated behavior
- attack pattern
- related security-control activity

The correlation result must preserve the evidence supporting the relationship.

### Acceptance

Given multiple related events:

- ProShield can group them into a coherent activity set.
- the relationship is explainable.
- unrelated events are not automatically merged.

---

## FR-08 — Incident Creation

ProShield must create a contextualized incident from relevant detected and
correlated activity.

An incident should be created when the configured detection/correlation
conditions indicate that the activity should be investigated as one case.

An incident must have a unique incident ID.

An incident must contain, where available:

- incident ID
- category
- severity
- confidence
- evidence
- related event IDs
- timeline
- affected assets
- source information
- timestamps
- status
- routing recommendation
- required skill/category
- analyst level
- team/queue
- recommended response
- audit history

---

## FR-09 — Incident Deduplication / Correlation Continuity

Repeated events belonging to an already-open incident should not create
unnecessary duplicate incidents.

The system must be able to associate new relevant evidence with an
existing incident when the correlation rules determine that the activity
is part of the same investigation.

The exact incident grouping strategy will be finalized during architecture.

---

## FR-10 — Attack Timeline

Every incident must have an evidence-backed chronological timeline.

Timeline entries must trace to:

1. an observed security event, or
2. an explicitly derived rule/correlation result.

The timeline must preserve chronological ordering.

No timeline event may be fabricated.

### Acceptance

Given a known sequence of simulated events:

- the incident timeline reproduces the sequence in the correct order.
- each timeline entry can be traced back to its evidence.

---

## FR-11 — Preliminary Severity

ProShield must calculate a preliminary incident severity.

Initial levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Severity may consider:

- triggered rule
- number of related events
- correlation strength
- affected asset
- business criticality
- attack category
- confidence
- potential impact

The severity decision must be explainable.

Severity is a preliminary triage assessment, not final human judgment.

---

## FR-12 — Confidence

ProShield must represent confidence separately from severity.

Confidence describes how strongly the available evidence supports the
detection/correlation conclusion.

A high-severity incident may still have lower confidence.

A low-severity incident may have high confidence.

The implementation must not collapse severity and confidence into one
unexplained score.

---

## FR-13 — Incident Classification

ProShield must assign an understandable incident category when the
available evidence supports one.

Examples may include:

- web attack
- rate-limit abuse
- suspicious authentication activity
- multi-control correlated activity
- network/TLS anomaly

The final category catalogue will be defined during rule and data-model
design.

If the system cannot confidently classify the incident, it must preserve
the uncertainty rather than invent a category.

---

## FR-14 — Early Investigation Report

The early incident report is a core MVP feature.

The report must reduce the analyst's initial manual workload.

Where available, it must include:

- what happened
- when it happened
- detection trigger
- related events
- attack timeline
- affected asset
- source information
- relevant security controls
- severity
- confidence
- correlation reasoning
- evidence
- incident classification
- recommended next investigation steps
- recommended analyst level
- required expertise

The report must explicitly distinguish:

OBSERVED FACTS

from

DERIVED CONCLUSIONS

from

RECOMMENDATIONS.

---

## FR-15 — Analyst Routing

ProShield must recommend where an incident should be investigated.

The MVP routing target is:

- analyst level
- skill category
- team
- queue

The MVP must not assume individual analyst availability or workload unless
an authorized data source exists.

Routing must consider more than severity.

Possible inputs:

- severity
- complexity
- incident category
- required security expertise
- affected technology
- affected asset
- business criticality
- confidence

### Example baseline

LOW + SIMPLE
→ L1

MEDIUM + STANDARD
→ L1

HIGH
→ L2

CRITICAL + COMPLEX
→ L3

The routing engine must also account for skill mismatch.

For example:

MEDIUM
+ IAM expertise required
+ current L1 capability does not include IAM
→ route to an IAM-capable team/level.

---

## FR-16 — Routing Explainability

Every routing recommendation must explain:

- recommended level
- required skill/category
- recommended team/queue
- reason for the decision
- severity
- complexity
- confidence
- supporting evidence where applicable

Routing must be auditable.

---

## FR-17 — Human Investigation Handoff

An analyst must be able to begin investigation from the generated incident.

The incident view must provide enough information to answer:

- What happened?
- When?
- Why was it detected?
- Which events support it?
- What assets are affected?
- What is the timeline?
- How severe is it?
- How confident is the system?
- Why was it routed here?
- What should the analyst investigate next?

---

## FR-18 — Incident Status

Incidents must support at least:

- OPEN
- INVESTIGATING
- CONTAINED
- RESOLVED
- FALSE_POSITIVE

Status transitions must be auditable.

The MVP must not automatically close incidents without an explicitly
defined workflow rule.

---

## FR-19 — Audit Trail

ProShield must maintain an auditable history for important actions.

At minimum, audit records must cover:

- event ingestion
- validation decisions
- normalization
- rule execution
- detection
- correlation
- severity decision
- incident creation
- report generation
- routing decision
- rule changes
- configuration changes
- response actions
- analyst actions

Audit records must not contain sensitive credentials or secrets.

---

## FR-20 — Recommended Response

The MVP response flow is:

Detect
→ Report
→ Recommend
→ Human Approval
→ Response

Initial response capabilities must remain controlled.

ProShield must not automatically perform unrestricted destructive actions.

---

# 4. Initial Detection Scope

The first MVP should use a small number of deterministic rule families.

The exact thresholds and conditions will be finalized during the rule-design
phase.

Initial categories should include:

1. Rate-limit abuse
2. Repeated suspicious requests
3. WAF attack-pattern detection
4. Multi-control correlated activity
5. Suspicious activity against sensitive endpoints
6. TLS/network security anomaly
7. Other clearly defined event patterns required by the first test cases

The MVP must prioritize a small, reliable rule set over a large catalogue
of weak rules.

---

# 5. Initial Security Event Scope

The first event source is simulated canonical security events.

The simulation must represent observations, not invented attack stories.

Example event concepts:

- WAF detection
- rate-limit exceeded
- suspicious request
- blocked request
- authentication/security-control event
- TLS/network anomaly

The canonical event contract will be defined separately during the
contracts/data-model phase.

---

# 6. Security Requirements

ProShield is a security-critical system.

The MVP must protect:

- event ingestion
- APIs
- rules
- incidents
- routing
- storage
- audit records
- secrets
- response capabilities

The system must address, at minimum:

- authentication
- authorization
- input validation
- API abuse
- event integrity
- replay considerations
- event flooding
- rule integrity
- rule authorization
- incident integrity
- audit integrity
- secrets management
- least privilege
- secure configuration
- dependency security
- failure handling
- availability

Specific controls and implementation details belong to the architecture and
secure-foundation phases.

---

# 7. Fail-Safe Requirements

If a dependency fails:

- security events must not be silently discarded
- successful processing must not be falsely reported
- incidents should be preserved where possible
- operators should know when telemetry is unavailable
- deterministic fallback behavior should be used where possible

A failure in a future AI component must never disable the deterministic
security pipeline.

---

# 8. AI Boundary

AI is outside the initial detection foundation.

The following MVP functions must work without AI:

- event validation
- normalization
- rule execution
- detection
- correlation
- timeline construction
- severity
- incident creation
- early report
- analyst routing
- audit

AI may be introduced later for:

- deeper investigation
- advanced correlation
- contextual reasoning
- investigation assistance
- report enhancement
- investigation recommendations

AI must enhance the deterministic pipeline rather than replace it.

---

# 9. Non-Functional Requirements

## NFR-01 — Explainability

Important decisions must be explainable from evidence and deterministic
logic.

---

## NFR-02 — Auditability

Important system actions and configuration changes must be traceable.

---

## NFR-03 — Reliability

A failure in one optional component must not silently invalidate security
processing.

---

## NFR-04 — Security

Security controls must be applied to ProShield itself, not only to the
event sources it monitors.

---

## NFR-05 — Testability

Every major detection, correlation, severity, routing, and failure path
must be testable with deterministic inputs.

---

## NFR-06 — Maintainability

Rules, connectors, correlation logic, severity logic, and routing logic
should remain modular enough to change without rewriting the entire
system.

---

## NFR-07 — Scalability

The MVP architecture should allow additional collectors and rules to be
added without redesigning the core processing pipeline.

Do not over-engineer for massive scale before validating the product.

---

## NFR-08 — Evidence Integrity

Security evidence must remain traceable from:

source event
→ normalized event
→ detection
→ correlation
→ timeline
→ incident
→ report
→ routing

---

# 10. Required MVP User Outcomes

At the end of the MVP, a security analyst should be able to receive an
incident and understand:

1. What happened?
2. Why was it detected?
3. Which events support the detection?
4. Are multiple events related?
5. What is the attack timeline?
6. What asset is affected?
7. What is the preliminary severity?
8. How confident is ProShield?
9. What incident category is likely?
10. What expertise is required?
11. Why was the incident routed to this level/team?
12. What should the analyst investigate next?

If an analyst still has to reconstruct the entire incident manually from
raw alerts, the core MVP has not solved the intended problem.

---

# 11. MVP Acceptance Criteria

The MVP is functionally successful when it can demonstrate all of the
following:

### AC-01 — Ingestion

Receive valid canonical security events.

### AC-02 — Validation

Reject or quarantine invalid events.

### AC-03 — Normalization

Convert source events into the canonical format.

### AC-04 — Detection

Trigger the correct rule for defined simulated security scenarios.

### AC-05 — Correlation

Combine related events into a coherent activity set without incorrectly
merging unrelated events.

### AC-06 — Timeline

Produce an evidence-backed chronological attack timeline.

### AC-07 — Severity

Produce an explainable preliminary severity.

### AC-08 — Confidence

Produce a separate confidence assessment.

### AC-09 — Incident

Create one contextualized incident from appropriately correlated activity.

### AC-10 — Report

Generate an analyst-ready early investigation report.

### AC-11 — Routing

Recommend the appropriate analyst level, skill, team, or queue.

### AC-12 — Audit

Preserve the history of important detection and decision-making steps.

### AC-13 — Human Handoff

Allow a human analyst to begin investigation immediately from the incident.

### AC-14 — Safe Failure

Demonstrate safe behavior when a dependency or optional component fails.

### AC-15 — Security

Demonstrate that unauthorized users cannot manipulate important security
decisions, evidence, rules, incidents, or routing.

---

# 12. MVP Success Metrics

The MVP must be evaluated using both technical and operational metrics.

## Technical

- detection accuracy
- false-positive rate
- correlation accuracy
- timeline accuracy
- severity accuracy
- routing accuracy
- processing latency
- throughput
- failure behavior

## Operational

- initial triage time saved
- reduction in manual correlation
- reduction in manual timeline creation
- reduction in manual initial report preparation
- analyst usefulness/acceptance
- time from raw event/alert to analyst-ready incident

## Primary Product Metric

The primary product question is:

**How much repetitive first-stage analyst work does ProShield remove without
reducing security quality?**

---

# 13. Explicit MVP Exclusions

The following are outside the first MVP unless the scope is deliberately
reopened:

- AI-first detection
- autonomous SOC behavior
- complete SIEM functionality
- complete SIEM integration
- individual analyst workload scheduling
- unrestricted automated response
- destructive autonomous actions
- every possible security integration
- every possible attack pattern
- advanced ML-based detection
- autonomous final incident judgment

---

# 14. Requirement Change Control

Once Phase 0 is approved, these requirements become the MVP baseline.

A new feature or requirement should not be added casually during
implementation.

Any scope change should identify:

- what requirement changes
- why the change is needed
- impact on architecture
- impact on security
- impact on timeline
- impact on testing
- whether an existing requirement becomes obsolete

The goal is to prevent uncontrolled scope growth.

---

# 15. Source of Truth

Requirement hierarchy:

1. `PRODUCT_SCOPE.md`
2. `MVP_REQUIREMENTS.md`
3. later architecture/contracts/security documents
4. phase-specific implementation plans

If a later implementation choice conflicts with an MVP requirement,
the conflict must be identified and resolved explicitly rather than
silently changing the requirement.

---

# 16. Definition of MVP Completion

ProShield's first MVP is complete only when the following complete loop works
reliably:

Security Events
→ Validation
→ Normalization
→ Detection
→ Correlation
→ Evidence-backed Timeline
→ Preliminary Severity + Confidence
→ Contextualized Incident
→ Early Investigation Report
→ Explainable Skill/Level/Team Routing
→ Human Analyst

The system must preserve evidence, maintain auditability, fail safely, and
protect ProShield itself from unauthorized manipulation.

Only after this rule-based MVP is validated should the product expand into
real-world collector integrations and AI-assisted investigation.