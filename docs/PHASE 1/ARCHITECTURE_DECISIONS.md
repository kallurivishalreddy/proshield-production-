# ProShield — Architecture Decisions

## 1. Purpose

This document records major architectural decisions made for ProShield.

The purpose is to preserve the reasoning behind important technical
choices so that future developers, reviewers, or AI agents do not
unintentionally reverse a decision without understanding why it was made.

This document is not a list of implementation details.

It records decisions that affect:

- system architecture
- security
- reliability
- data flow
- scalability
- maintainability
- integration strategy
- MVP boundaries

A future change should not silently replace a decision.

If a decision needs to change, the change must be documented with:

- the original decision
- the reason for reconsideration
- alternatives considered
- impact
- new decision
- migration implications

---

# 2. Decision Status

Each decision uses one of these statuses:

### ACCEPTED

The decision is approved and should be followed.

### PROVISIONAL

The decision is appropriate for the current MVP but may be revisited when
new evidence appears.

### DEFERRED

A decision is intentionally postponed until a later phase.

### SUPERSEDED

A newer decision replaced the original decision.

---

# 3. ADR-001 — Rule-Based MVP Before AI

**Status:** ACCEPTED

## Decision

The first ProShield MVP uses deterministic, rule-based detection.

AI is not required for:

- event validation
- normalization
- detection
- correlation
- timeline construction
- severity
- confidence
- incident creation
- report generation
- routing

## Reason

The MVP must first prove that deterministic automation can reduce
repetitive first-stage analyst work.

A rule-based foundation provides:

- explainability
- deterministic testing
- auditability
- predictable behavior
- easier debugging
- measurable baseline performance

It also allows the business value of ProShield to be evaluated before
introducing the additional complexity and uncertainty of AI.

## Alternatives Considered

### AI-first detection

Rejected for MVP.

Reason:

- difficult to validate deterministically
- harder to establish evidence attribution
- introduces model dependency
- harder to measure the true baseline value of automation

### AI + rules from day one

Deferred.

The architecture should allow later AI integration without making AI a
dependency of the deterministic pipeline.

## Revisit When

After the rule-based MVP has been validated and its metrics have been
measured.

---

# 4. ADR-002 — Source-Independent Core Engine

**Status:** ACCEPTED

## Decision

The core ProShield detection and incident-processing engine remains
independent of any specific security product.

External sources integrate through adapters/collectors.

Architecture:

```text
Source
→ Source Adapter
→ Canonical SecurityEvent
→ ProShield Core
```

## Reason

ProShield must eventually support multiple security sources.

If the core engine depends directly on NGINX, WAF, or another vendor,
every new integration would require changes throughout the system.

Source isolation improves:

- maintainability
- testability
- extensibility
- integration speed

## Alternatives Considered

### Source-specific detection logic

Rejected.

This would create tight coupling and make future integrations expensive.

### Build one large generic collector framework first

Rejected for MVP.

The core product value should be validated before building infrastructure
for every possible source.

## Revisit When

Only if actual integration requirements prove that the adapter boundary is
insufficient.

---

# 5. ADR-003 — Simulated Events Before Real Collectors

**Status:** ACCEPTED

## Decision

The initial core pipeline will be validated using simulated canonical
security events.

Real collectors are added incrementally afterward.

Planned progression:

1. Simulated canonical events
2. NGINX
3. WAF / Cezara
4. Rate limiting
5. TLS / network
6. SIEM
7. Endpoint
8. IAM

## Reason

The core product must be validated independently of external integration
complexity.

Simulation provides:

- deterministic input
- repeatable scenarios
- controlled relationships
- fast development
- regression testing

## Important Constraint

The simulator must not bypass the real ProShield pipeline.

Correct:

```text
Simulator
→ Canonical SecurityEvent
→ Validation
→ Detection
→ Correlation
→ Incident
→ Report
→ Routing
```

Incorrect:

```text
Simulator
→ Direct Incident Creation
```

## Alternatives Considered

### Start immediately with NGINX/WAF

Deferred, not rejected.

Real collectors are required for stronger MVP validation, but they should
not be allowed to hide core detection problems.

## Revisit When

After the core detection pipeline is stable enough to begin real
integration.

---

# 6. ADR-004 — Canonical SecurityEvent

**Status:** ACCEPTED

## Decision

All downstream ProShield processing operates on a canonical
`SecurityEvent`.

Collectors convert source-specific telemetry into this representation.

## Reason

This creates a stable contract between:

- collectors
- validation
- normalization
- detection
- correlation
- timeline
- incident management

It allows new sources to be added without rewriting the core engine.

## Alternatives Considered

### Keep source-specific objects throughout the system

Rejected.

Would increase coupling and make multi-source correlation difficult.

---

# 7. ADR-005 — Evidence-Backed Security Decisions

**Status:** ACCEPTED

## Decision

Every important derived result must be traceable to observed evidence
or an explicitly derived result.

The evidence chain is:

```text
SecurityEvent
→ Detection
→ Correlation
→ Timeline
→ Severity / Confidence
→ Incident
→ Report
→ Routing
```

## Reason

ProShield is a security-operations system.

Security analysts must be able to understand why a decision was made.

This also prevents fabricated security narratives.

## Required Principle

The system must distinguish:

```text
Observed Facts
Derived Conclusions
Recommendations
```

These must not be presented as the same type of information.

---

# 8. ADR-006 — Human-in-the-Loop

**Status:** ACCEPTED

## Decision

ProShield recommends and prepares.

Human analysts retain final authority.

The system does not replace human investigation.

## Reason

The MVP is intended to reduce repetitive first-stage work, not remove
human judgment.

Humans retain responsibility for:

- final judgment
- deeper investigation
- high-impact decisions
- complex response
- incident closure

## Alternatives Considered

### Fully autonomous SOC

Rejected for MVP.

Reason:

- excessive risk
- difficult validation
- unnecessary scope
- conflicts with the product's intended role

---

# 9. ADR-007 — Routing Target Is Level/Skill/Team/Queue

**Status:** ACCEPTED

## Decision

The MVP routes incidents to:

- analyst level
- required skill/category
- team
- queue

It does not assign individual analysts unless authorized data exists.

## Reason

The MVP does not automatically know:

- analyst availability
- workload
- shifts
- individual specialization

Pretending otherwise would create false routing decisions.

## Routing Principle

```text
Severity
+
Complexity
+
Required Skill
+
Technology
+
Business Criticality
+
Confidence
→
Routing Recommendation
```

Severity alone must not determine routing.

## Alternatives Considered

### Route only by severity

Rejected.

This creates unnecessary escalation and skill mismatch.

### Assign individual analysts immediately

Deferred until an authorized analyst/organizational data source exists.

---

# 10. ADR-008 — Deterministic Routing for MVP

**Status:** ACCEPTED

## Decision

Routing is deterministic and explainable during the MVP.

Given the same:

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

## Alternatives Considered

### AI-based routing

Deferred to future versions.

---

# 11. ADR-009 — Preliminary Severity and Confidence Are Separate

**Status:** ACCEPTED

## Decision

Severity and confidence are separate values.

Severity:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Confidence represents how strongly the available evidence supports the
assessment.

## Reason

A high-impact incident can have uncertain evidence.

Example:

```text
Severity: HIGH
Confidence: MEDIUM
```

This is meaningfully different from:

```text
Severity: HIGH
Confidence: HIGH
```

Combining them into one opaque score would reduce explainability.

---

# 12. ADR-010 — Incident Is the Main Product Output

**Status:** ACCEPTED

## Decision

A raw detection is not the primary ProShield user output.

The primary output is a contextualized incident.

## Reason

The business problem is fragmented analyst workflow.

The product must transform:

```text
Many disconnected events
→ One investigation-ready case
```

The incident contains:

- evidence
- timeline
- severity
- confidence
- classification
- report
- routing recommendation

---

# 13. ADR-011 — Detection Does Not Automatically Equal Incident

**Status:** ACCEPTED

## Decision

A detection is not automatically a separate incident.

The incident manager uses detection and correlation results to determine
whether activity should become a contextualized investigation unit.

## Reason

One attack can produce many alerts.

Creating one incident per alert would reproduce the alert-fatigue problem
ProShield is intended to reduce.

## Required Behavior

Related detections should be associated with one incident where the
configured correlation logic determines they belong together.

---

# 14. ADR-012 — Core Processing Must Preserve Provenance

**Status:** ACCEPTED

## Decision

Event provenance must survive processing.

The system must be able to answer:

- where an event originated
- which collector handled it
- when it was received
- what source identity it had
- what transformations occurred

## Reason

Provenance is required for:

- evidence review
- debugging
- audit
- incident investigation
- connector troubleshooting

---

# 15. ADR-013 — Security Rules Are Configuration, Not Hard-Coded Business Logic

**Status:** ACCEPTED

## Decision

Detection rules are treated as configurable, versioned, testable, and
auditable security configuration.

## Reason

The rule catalogue will evolve.

Rules should be changeable without rewriting the entire application.

## Required Rule Properties

A rule should support:

- unique ID
- version
- enabled/disabled state
- conditions
- evidence reference
- detection category
- severity/confidence contribution where applicable
- audit history

## Security Requirement

Only authorized users/services may change rules.

---

# 16. ADR-014 — Routing Policies Are Protected Configuration

**Status:** ACCEPTED

## Decision

Routing policies are treated as security-sensitive configuration.

Changes must be:

- authorized
- validated
- versioned where appropriate
- auditable

## Reason

Routing manipulation can cause:

- skill mismatch
- delayed response
- unnecessary escalation

Routing must therefore not be treated as ordinary UI preferences.

---

# 17. ADR-015 — No Unrestricted Autonomous Response in MVP

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

The MVP does not permit unrestricted destructive response actions.

## Examples Outside MVP Autonomous Scope

- account deletion
- mass session revocation
- broad firewall modification
- destructive infrastructure operations

## Reason

The product must first prove detection, triage, reporting, and routing
before introducing high-impact automation.

---

# 18. ADR-016 — ProShield Is Security-Critical

**Status:** ACCEPTED

## Decision

ProShield itself is treated as a security-critical system.

## Reason

Compromise of ProShield could affect security decisions.

An attacker could attempt to:

- inject fake events
- suppress events
- manipulate rules
- manipulate incidents
- manipulate severity
- manipulate routing
- tamper with evidence
- abuse response

Therefore ProShield must protect:

- ingestion
- APIs
- rules
- incidents
- routing
- storage
- audit
- secrets
- response controls

---

# 19. ADR-017 — Fail-Safe Over Silent Failure

**Status:** ACCEPTED

## Decision

When a dependency fails, ProShield must fail visibly and preserve
security state wherever possible.

Preferred behavior:

```text
Explicit Failure
+
Preserved Evidence
+
Operator Visibility
+
Recoverable State
```

instead of:

```text
Silent Data Loss
or
False Success
```

## Reason

A security platform that silently loses telemetry is dangerous.

---

# 20. ADR-018 — Optional Observability Must Not Corrupt Core Security State

**Status:** ACCEPTED

## Decision

Optional observability/enrichment failures must not unnecessarily reverse
or destroy already committed core security state.

For example, failure to generate a non-critical enrichment should not cause
a valid incident to disappear.

## Reason

Core security state and optional observability have different reliability
requirements.

The business/security result should remain authoritative.

---

# 21. ADR-019 — Preserve Auditability of Human Overrides

**Status:** ACCEPTED

## Decision

When a human overrides a ProShield recommendation, the system preserves:

- original recommendation
- human decision
- actor
- timestamp
- reason when provided

## Reason

The system must preserve the difference between:

```text
Machine Recommendation
```

and:

```text
Human Decision
```

This is essential for accountability and future analysis.

---

# 22. ADR-020 — MVP Architecture Favors Simplicity

**Status:** PROVISIONAL

## Decision

The MVP should use the simplest architecture that satisfies:

- security
- correctness
- reliability
- expected workload
- testability
- maintainability

The project must not introduce infrastructure merely because it is common
in large enterprise systems.

Examples of infrastructure that require justification:

- Kafka
- RabbitMQ
- Kubernetes
- multiple service clusters
- complex event-processing frameworks

## Reason

Premature infrastructure complexity increases:

- development time
- operational burden
- failure modes
- deployment complexity
- cost

## Important Constraint

Simplicity must not compromise security or required reliability.

## Revisit When

Actual event volume, latency, deployment, or reliability requirements prove
that additional infrastructure is necessary.

---

# 23. ADR-021 — Processing Model Is Not Prematurely Locked

**Status:** PROVISIONAL

## Decision

The exact synchronous/asynchronous processing architecture is not fully
locked in Phase 1.

The decision will be based on:

- expected event volume
- latency requirements
- reliability requirements
- deployment environment
- failure recovery requirements
- operational complexity

## Reason

Choosing a queue or distributed processing system before requirements are
known would be premature.

## Direction

The system may use asynchronous processing around:

- ingestion
- detection
- correlation
- report generation

if requirements justify it.

---

# 24. ADR-022 — Simulated Events Must Use the Real Pipeline

**Status:** ACCEPTED

## Decision

Simulated events are test inputs, not a separate execution path.

They must pass through:

```text
Simulator
→ Event Validation
→ Normalization
→ Detection
→ Correlation
→ Timeline
→ Severity
→ Incident
→ Report
→ Routing
```

## Reason

Otherwise the MVP could demonstrate a fake workflow that does not represent
the real product architecture.

The simulator must therefore behave like a real source.

---

# 25. ADR-023 — Real Collectors Are Added Incrementally

**Status:** ACCEPTED

## Decision

Real collectors are introduced incrementally after the core pipeline is
stable.

Preferred order:

1. NGINX
2. WAF / Cezara
3. Rate limiting
4. TLS / network
5. SIEM
6. Endpoint
7. IAM

## Reason

This allows ProShield to validate the core intelligence before dealing
with every external integration.

At least one real collector should eventually be validated end-to-end for
the production MVP.

---

# 26. ADR-024 — AI Is a Future Enhancement Layer

**Status:** ACCEPTED

## Decision

Future AI functionality sits above the deterministic foundation.

Conceptually:

```text
Security Events
→ Deterministic Detection
→ Correlation
→ AI-Assisted Investigation
→ Incident
→ Report
→ Routing
→ Human
```

AI may assist with:

- deeper investigation
- advanced correlation
- contextual reasoning
- report enhancement
- recommendations

AI must never become a single point of failure for deterministic security
processing.

---

# 27. ADR-025 — No Individual Analyst Assignment Without Authorized Data

**Status:** ACCEPTED

## Decision

The MVP does not assign incidents to individual analysts unless an
authorized source provides:

- skills
- availability
- workload
- shifts
- specialization
- escalation information

## Reason

Without authoritative data, individual assignment would be fabricated.

The MVP instead routes to:

- level
- skill
- team
- queue

---

# 28. ADR-026 — Evidence, Conclusions, and Recommendations Remain Separate

**Status:** ACCEPTED

## Decision

ProShield output must distinguish:

```text
OBSERVED FACTS
```

from:

```text
DERIVED CONCLUSIONS
```

from:

```text
RECOMMENDATIONS
```

## Reason

This is fundamental to trustworthy incident triage.

An inference must not be presented as if it were direct evidence.

---

# 29. ADR-027 — Human Analysts Retain Final Authority

**Status:** ACCEPTED

## Decision

ProShield provides preliminary assessments and recommendations.

Human analysts retain authority over:

- final classification
- final severity
- investigation depth
- response
- closure
- false-positive determination

## Reason

ProShield exists to accelerate human investigation, not replace it.

---

# 30. ADR-028 — Technology Choices Must Follow Requirements

**Status:** ACCEPTED

## Decision

No programming language, database, message broker, cloud provider, or
framework is locked merely because it is familiar or popular.

Technology choices must be justified by:

- functional requirements
- security requirements
- reliability
- expected scale
- cost
- developer productivity
- deployment constraints
- maintainability

## Reason

The architecture should serve ProShield rather than forcing ProShield into
a predetermined technology stack.

---

# 31. ADR-029 — Major Decisions Must Be Revisited With Evidence

**Status:** ACCEPTED

## Decision

An architectural decision may be changed when new evidence demonstrates
that the current decision no longer satisfies the requirements.

A decision must NOT be changed merely because:

- another technology is fashionable
- an AI agent prefers it
- a developer is more familiar with another option
- the system could theoretically support a much larger scale

A change should identify:

1. Original decision
2. New evidence
3. Problem with the current decision
4. Alternatives considered
5. New decision
6. Migration impact
7. Security impact
8. Testing impact

---

# 32. Architecture Decision Change Process

When a decision is challenged:

```text
Existing Decision
      ↓
New Requirement / Evidence
      ↓
Impact Analysis
      ↓
Alternatives
      ↓
Security Review
      ↓
Decision
      ↓
Documentation Update
      ↓
Implementation
      ↓
Regression Testing
```

No major architectural change should be silently introduced during
implementation.

---

# 33. Decision Review Triggers

Architecture decisions should be reconsidered when:

- a new production requirement appears
- expected volume changes significantly
- security testing exposes a weakness
- deployment constraints change
- a real collector introduces a new trust boundary
- an integration requires a different processing model
- MVP validation reveals a major usability or reliability problem
- cost becomes materially higher than expected

---

# 34. Decisions Intentionally Deferred

The following are intentionally not fully locked yet:

- final database/storage technology
- exact message-broker technology, if any
- exact asynchronous-processing implementation
- cloud provider
- deployment platform
- exact production network topology
- final retention periods
- final real-collector implementation details
- future AI model selection

These decisions will be made when their requirements are sufficiently
clear.

---

# 35. Decision Ownership

Major ProShield architectural decisions should be reviewed as engineering
decisions, not delegated blindly to an implementation model.

AI agents may propose alternatives.

They must not silently redefine the product architecture.

Any major proposal should be checked against:

- PRODUCT_SCOPE.md
- MVP_REQUIREMENTS.md
- ARCHITECTURE.md
- THREAT_MODEL.md
- ROUTING_MATRIX.md
- MVP_ACCEPTANCE.md
- this decision log

---

# 36. Final Architecture Decision Principle

ProShield should follow this principle:

BUILD THE SIMPLEST ARCHITECTURE THAT CAN SAFELY PROVE THE PRODUCT.

Do not sacrifice:

- security
- evidence integrity
- explainability
- reliability
- testability

for simplicity.

Do not sacrifice simplicity:

- maintainability
- cost efficiency
- development speed

for theoretical scale that the MVP does not require.

The architecture should evolve from evidence, requirements, testing, and
real product validation.