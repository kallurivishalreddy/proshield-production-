# ProShield — MVP Acceptance Criteria

## 1. Purpose

This document defines how the first ProShield MVP will be evaluated.

`PRODUCT_SCOPE.md` defines what ProShield is.

`MVP_REQUIREMENTS.md` defines what the MVP must do.

`INITIAL_SECURITY_EVENTS.md` defines the initial simulated security
events used to test the pipeline.

`ROUTING_MATRIX.md` defines how incidents are routed.

This document defines the final question:

> **How do we prove that ProShield actually works and provides meaningful
> first-layer incident-triage value?**

The MVP must satisfy the acceptance criteria in this document before it
can be considered validated.

---

## 2. Core MVP Proof

The primary proof loop is:

Security Events
→ Validation
→ Normalization
→ Detection
→ Correlation
→ Attack Timeline
→ Preliminary Severity + Confidence
→ Incident
→ Early Investigation Report
→ Skill / Level / Team Routing
→ Human Analyst

The MVP must demonstrate this complete path using controlled simulated
security events.

---

## 3. Acceptance Philosophy

Acceptance is based on:

- correctness
- evidence preservation
- explainability
- deterministic behavior
- security
- reliability
- useful routing
- analyst usefulness
- measurable reduction in repetitive first-stage work

A visually impressive interface is not sufficient.

A high detection count is not sufficient.

A successful MVP must demonstrate that ProShield produces useful,
evidence-backed, analyst-ready incidents.

---

# 4. Acceptance Levels

Each acceptance test should be classified as:

### PASS

The required behavior works correctly and the expected evidence is
available.

### FAIL

The required behavior does not work or produces an incorrect result.

### BLOCKED

The test cannot be executed because a required dependency is unavailable.
A blocked test must not be falsely reported as passed.

---

# 5. End-to-End Acceptance Test

## AC-E2E-01 — Complete Incident-Triage Pipeline

### Given

A controlled set of simulated canonical security events representing a
known security scenario.

### When

The events are submitted to ProShield.

### Then

ProShield must:

1. accept valid events
2. validate them
3. normalize them
4. evaluate detection rules
5. generate the correct detection
6. correlate related events
7. construct an evidence-backed timeline
8. determine preliminary severity
9. determine confidence
10. create a contextualized incident
11. generate an early investigation report
12. determine required skill/category
13. recommend analyst level
14. recommend team/queue
15. preserve the audit history

### PASS condition

The complete chain works without fabricated evidence and the resulting
incident is ready for human investigation.

---

# 6. Event Ingestion Acceptance

## AC-ING-01 — Valid Event

Given a valid canonical `SecurityEvent`:

Expected:

- event accepted
- event identity preserved
- event timestamp preserved
- event source preserved
- event becomes available to the detection pipeline
- audit entry exists where required

PASS if all required properties are preserved.

---

## AC-ING-02 — Invalid Event

Given an invalid event:

Examples:

- missing required field
- invalid timestamp
- invalid type
- unsupported structure

Expected:

- event rejected or quarantined according to the defined ingestion policy
- event does not enter the normal detection pipeline
- failure is auditable

PASS if invalid input cannot silently become valid security evidence.

---

## AC-ING-03 — Duplicate Event

Submit the same event repeatedly within the configured duplicate-handling
window.

Expected:

- uncontrolled duplicate processing does not occur
- deduplication decision is deterministic
- handling is auditable

---

# 7. Normalization Acceptance

## AC-NORM-01 — Canonical Conversion

Provide equivalent security activity using two different source-style
event structures.

Expected:

- both are converted to the canonical `SecurityEvent`
- relevant source information is preserved
- detection/correlation can operate on the normalized result

PASS if the core engine does not need source-specific logic.

---

# 8. Detection Acceptance

## AC-DET-01 — Rule Trigger

Provide events that clearly satisfy a configured detection rule.

Expected:

- rule triggers
- detection is created
- rule ID/version is recorded
- supporting event IDs are preserved
- detection category is recorded
- severity/confidence contribution is available where configured

---

## AC-DET-02 — Rule Non-Trigger

Provide events that do not satisfy the rule.

Expected:

- rule does not trigger
- no false detection is created from that rule

---

## AC-DET-03 — Rule Explainability

For every triggered detection, ProShield must be able to answer:

- Which rule triggered?
- Which events supported it?
- Which threshold/condition was satisfied?
- What time window was used?
- What evidence was considered?

PASS only when the detection can be explained from actual evidence.

---

# 9. Initial Detection Scenario Acceptance

The MVP should prove a small set of deterministic scenarios.

## AC-SCENARIO-01 — WAF Attack

Input:

- WAF detection
- related blocked request

Expected:

- detection
- correlation
- timeline
- incident
- report
- routing

---

## AC-SCENARIO-02 — Rate-Limit Abuse

Input:

- repeated requests from same source
- rate-limit exceeded
- related blocked requests

Expected:

- repeated activity recognized
- related events correlated
- coherent incident created
- explainable severity
- routing recommendation

---

## AC-SCENARIO-03 — WAF + NGINX Correlation

Input:

- WAF detection
- NGINX request activity
- same source
- same target
- related time window

Expected:

- events correlated
- evidence preserved
- one coherent incident where appropriate

---

## AC-SCENARIO-04 — Multi-Control Correlation

Input:

- suspicious request
- WAF event
- rate-limit event
- blocked request

Expected:

- multiple controls contribute to one investigation context
- timeline shows all supporting evidence
- correlation reasoning is explainable

---

## AC-SCENARIO-05 — Authentication Activity

Input:

- repeated authentication failures
- successful authentication
- subsequent suspicious activity

Expected:

- sequence can be correlated when rules support it
- report distinguishes observations from conclusions
- severity/confidence remains explainable

---

## AC-SCENARIO-06 — TLS / Network Activity

Input:

- TLS anomaly
- network anomaly
- same relevant asset/destination

Expected:

- related activity can be correlated
- timeline created
- appropriate category/skill recommendation

---

## AC-SCENARIO-07 — Complex Multi-Layer Activity

Input:

- multiple event types
- multiple security controls
- multiple affected technologies or assets
- strong temporal/correlation relationships

Expected:

- a coherent investigation context
- more complex timeline
- higher complexity classification
- appropriate analyst level
- explainable routing

---

# 10. Correlation Acceptance

## AC-CORR-01 — Related Events

Given events sharing valid correlation factors:

- source
- destination
- endpoint
- account
- asset
- timestamp
- repeated behavior
- event type

Expected:

- related events grouped appropriately

---

## AC-CORR-02 — Unrelated Events

Provide events that are intentionally unrelated.

Expected:

- they are not incorrectly merged solely because they arrived close
  together

---

## AC-CORR-03 — Evidence Preservation

For every correlation result:

- related event IDs are preserved
- correlation reason is available
- the relationship can be explained

---

# 11. Timeline Acceptance

## AC-TIME-01 — Chronological Timeline

Given events occurring in a known order:

Expected:

- timeline displays the correct chronological sequence
- timestamps are preserved
- each timeline entry points to evidence

---

## AC-TIME-02 — No Fabricated Events

If no evidence exists for an activity:

Expected:

- ProShield does not invent a timeline step
- it may identify an uncertainty or gap
- the gap is distinguishable from an observed event

---

# 12. Severity Acceptance

## AC-SEV-01 — Severity Levels

The system must support:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

## AC-SEV-02 — Explainable Severity

Every severity decision must identify the major factors contributing to it.

Possible factors:

- triggered rule
- event count
- correlation strength
- affected asset
- business criticality
- category
- confidence
- potential impact

---

## AC-SEV-03 — Preliminary Nature

The system must clearly treat severity as a preliminary triage assessment.

A human analyst must be able to change it.

---

# 13. Confidence Acceptance

## AC-CONF-01 — Separate Confidence

Confidence must be represented separately from severity.

Example:

HIGH severity + MEDIUM confidence

is valid and must remain distinguishable from:

HIGH severity + HIGH confidence.

---

## AC-CONF-02 — Evidence-Based Confidence

Confidence must be based on actual evidence and configured logic.

The system must not invent confidence values.

---

# 14. Incident Acceptance

## AC-INC-01 — Incident Creation

Given a detection/correlation result that meets incident-creation criteria:

Expected:

- unique incident ID
- incident category
- severity
- confidence
- evidence
- related events
- timeline
- affected assets
- timestamps
- routing recommendation
- status

---

## AC-INC-02 — Incident Deduplication

If additional evidence belongs to an existing open incident:

Expected:

- evidence can be attached to the existing case
- unnecessary duplicate incidents are avoided

---

## AC-INC-03 — Unknown Activity

If activity does not match a known rule:

Expected:

- evidence is preserved
- no fictional attack conclusion is created
- uncertainty is represented
- human review remains possible

---

# 15. Early Report Acceptance

## AC-REPORT-01 — Report Completeness

The early investigation report must provide, when available:

- what happened
- when it happened
- detection trigger
- related events
- timeline
- affected assets
- sources
- severity
- confidence
- correlation reasoning
- evidence
- classification
- recommended investigation steps
- recommended analyst level
- required skill

---

## AC-REPORT-02 — Fact/Conclusion/Recommendation Separation

The report must distinguish:

OBSERVED FACTS

from:

DERIVED CONCLUSIONS

from:

RECOMMENDATIONS

---

## AC-REPORT-03 — No Fabricated Evidence

If information is unavailable:

- the report must say it is unavailable/unknown
- it must not invent a value
- it must not present speculation as evidence

---

# 16. Routing Acceptance

## AC-ROUTE-01 — Basic Routing

LOW + SIMPLE:

→ L1

MEDIUM + STANDARD:

→ L1

HIGH:

→ L2

CRITICAL + COMPLEX:

→ L3

---

## AC-ROUTE-02 — Skill Override

If an incident requires a skill that the default level/team does not
support:

Expected:

- route to an appropriate skill-capable team/level

---

## AC-ROUTE-03 — Technology-Aware Routing

Example:

WAF + web attack

→ Web/WAF security skill

TLS/network anomaly

→ Network/TLS security skill

IAM anomaly

→ IAM/Authentication skill

---

## AC-ROUTE-04 — Criticality-Aware Routing

The same security pattern may produce different routing when affected
asset criticality legitimately differs.

Business criticality must come from an authorized source.

---

## AC-ROUTE-05 — Human Override

An authorized human must be able to override the routing recommendation.

The system must retain:

- original recommendation
- override
- actor
- timestamp
- reason when provided

---

# 17. Audit Acceptance

## AC-AUDIT-01 — Core Decision Audit

The audit trail must preserve:

- ingestion
- rule execution
- detection
- correlation
- severity
- incident creation
- report generation
- routing

---

## AC-AUDIT-02 — Configuration Audit

The audit trail must preserve important:

- rule changes
- configuration changes
- routing-policy changes

---

## AC-AUDIT-03 — Human Action Audit

The audit trail must preserve relevant:

- analyst actions
- administrator actions
- routing overrides
- response actions

---

# 18. Security Acceptance

ProShield is itself a security-critical system.

The MVP must demonstrate protection against at least the following
categories:

### AC-SEC-01 — Unauthorized Access

Unauthorized users cannot access protected APIs or administrative functions.

### AC-SEC-02 — Unauthorized Rule Modification

Users without permission cannot modify detection rules.

### AC-SEC-03 — Event Injection

Unauthorized or malformed sources cannot freely inject trusted security
events.

### AC-SEC-04 — Event Tampering

Stored evidence cannot be modified by unauthorized users without detection
or audit visibility.

### AC-SEC-05 — Routing Manipulation

Unauthorized users cannot manipulate routing decisions.

### AC-SEC-06 — Audit Tampering

Unauthorized users cannot silently modify or delete security audit history.

### AC-SEC-07 — Event Flooding

The ingestion path has protection appropriate to the MVP against uncontrolled
event flooding or abuse.

### AC-SEC-08 — Secret Protection

Secrets, credentials, private keys, and sensitive authentication material
must not be exposed through normal event/report/audit output.

---

# 19. Fail-Safe Acceptance

## AC-FAIL-01 — Collector Failure

If a collector/source becomes unavailable:

Expected:

- ProShield does not falsely report normal processing
- telemetry gap is visible
- already received events remain preserved

---

## AC-FAIL-02 — Rule Engine Failure

If rule processing temporarily fails:

Expected:

- the system does not silently discard events
- failure is observable
- recovery can continue processing safely

---

## AC-FAIL-03 — Report Failure

If report generation fails:

Expected:

- the underlying incident remains available
- report failure is visible
- evidence is not lost

---

## AC-FAIL-04 — Routing Failure

If routing evaluation fails:

Expected:

- incident remains available
- routing failure is visible
- the system does not fabricate a successful routing decision

---

## AC-FAIL-05 — Future AI Failure

If AI functionality is introduced later and fails:

Expected:

- deterministic detection still works
- incidents can still be created
- AI failure does not disable the core security pipeline

---

# 20. Real Collector Acceptance

Although simulated events are the first validation source, the production
MVP should prove that at least one real security source can eventually pass
through the same canonical pipeline.

The preferred first real source is NGINX.

The real collector must:

1. receive/read source telemetry
2. convert it into canonical `SecurityEvent`
3. preserve source provenance
4. send it through the same normalization/detection/correlation pipeline
5. produce the same classes of downstream outputs as simulated events

The core pipeline must not contain NGINX-specific business logic.

Additional collectors can then be added incrementally.

---

# 21. Analyst-Usefulness Acceptance

Technical correctness alone is not enough.

A representative security analyst should be able to use a generated
incident and answer:

1. What happened?
2. Why was it detected?
3. Which events support it?
4. Are the events related?
5. What is the attack timeline?
6. Which asset is affected?
7. What is the preliminary severity?
8. How confident is ProShield?
9. What category is likely?
10. What skill is required?
11. Why was it routed here?
12. What should I investigate next?

If the analyst still has to reconstruct the entire incident manually from
raw events, the core product objective has not been achieved.

---

# 22. MVP Success Metrics

The MVP should be measured against a baseline manual process.

Measure at minimum:

### Analyst Work

- initial triage time
- manual correlation time
- manual timeline-construction time
- manual initial report-preparation time

### Security Quality

- detection accuracy
- false-positive rate
- correlation accuracy
- timeline accuracy
- severity accuracy
- routing accuracy

### System Performance

- processing latency
- throughput
- failure behavior
- event-processing reliability

### Human Usefulness

- analyst usefulness/acceptance
- whether analysts can begin investigation faster
- time from raw event/alert to analyst-ready incident

---

# 23. Primary MVP Success Definition

ProShield's MVP is successful only when it can reliably demonstrate:

```text
Fragmented Security Events
        ↓
Correct Detection
        ↓
Correct Correlation
        ↓
Evidence-Backed Timeline
        ↓
Explainable Severity + Confidence
        ↓
Contextualized Incident
        ↓
Useful Early Investigation Report
        ↓
Appropriate Skill / Level / Team Routing
        ↓
Human Analyst
```

And the most important business question is:

> **How much initial analyst work does ProShield remove without reducing
> security quality?**

The MVP must demonstrate measurable improvement against the chosen manual
baseline.

---

# 24. Final MVP Gate

The ProShield MVP can be declared complete only when:

- all mandatory functional acceptance criteria pass
- security acceptance criteria pass
- core failure scenarios are tested
- the complete simulated-event pipeline works end-to-end
- at least one real collector works through the same canonical pipeline
- generated incidents preserve evidence
- reports distinguish facts, conclusions, and recommendations
- routing is deterministic and explainable
- human override works
- audit history is preserved
- no critical unresolved security issue remains
- performance is adequate for the intended MVP workload
- representative analysts find the output useful
- the documented business metrics show meaningful reduction in first-stage
  analyst effort

---

# 25. Definition of MVP Completion

The first ProShield MVP is complete when a human security analyst can take
an incident generated by ProShield and start meaningful investigation
without manually reconstructing the initial incident from a fragmented pile
of raw alerts.

The product must prove:

FRAGMENTED EVENTS
→ CONTEXTUALIZED INCIDENT
→ EVIDENCE-BACKED TIMELINE
→ PRELIMINARY SEVERITY
→ EARLY REPORT
→ EXPLAINABLE ROUTING
→ HUMAN INVESTIGATION

while maintaining:

- security
- evidence integrity
- auditability
- reliability
- explainability
- safe failure

Only after this foundation is validated should ProShield expand into
broader collectors, advanced response capabilities, and AI-assisted
investigation.