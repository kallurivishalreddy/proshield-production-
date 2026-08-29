# ProShield — Product Scope

## 1. What Is ProShield?

**ProShield turns fragmented security events into one evidence-backed,
analyst-ready incident and recommends the appropriate investigation skill,
analyst level, team, or queue.**

ProShield is a security-operations intelligence and first-layer
incident-triage platform.

Its purpose is to help security teams handle the repetitive work that
happens at the beginning of an incident investigation.

Modern security environments generate large numbers of alerts and security
events from systems such as WAFs, NGINX, rate-limiting systems,
network/security controls, and eventually SIEM, endpoint, and IAM systems.

These events are often fragmented.

One system may report a blocked request.
Another may report rate-limit violations.
Another may report suspicious network activity.

A security analyst may have to manually look at all of these events,
determine whether they are related, reconstruct what happened, build a
timeline, decide the preliminary severity, prepare an initial incident
summary, and determine which analyst or team should investigate.

ProShield is designed to automate this **first layer of work**.

ProShield does not replace the security controls that generate the events
and does not replace human security analysts.

Instead, ProShield sits above those systems and turns fragmented security
telemetry into one contextualized incident that a human analyst can
immediately begin investigating.

---

## 2. The Core Problem

The main problem ProShield solves is excessive manual first-stage
security triage.

A security analyst may need to:

- inspect individual alerts
- determine whether alerts are related
- identify suspicious behavior
- correlate events from different systems
- reconstruct an attack sequence
- build an attack timeline
- collect supporting evidence
- determine preliminary severity
- classify the incident
- prepare an initial report
- determine what security skill is required
- determine what analyst level or team should investigate

This work consumes analyst time.

It can also cause:

- alert fatigue
- duplicated investigation work
- slow initial response
- incorrect prioritization
- unnecessary escalation
- senior analysts spending time on simple incidents
- complex incidents being assigned to analysts who do not have the
  required expertise

ProShield's purpose is to reduce this repetitive first-stage workload
without removing human judgment.

---

## 3. ProShield's Core Value

The core value of ProShield is not simply collecting logs or displaying
alerts.

The core transformation is:

Security Events
→ Detection
→ Correlation
→ Attack Timeline
→ Preliminary Severity
→ Early Incident Report
→ Appropriate Analyst Routing
→ Human Investigation

The output should be a prepared investigation starting point rather than a
collection of disconnected alerts.

### Detection vs Incident

A **detection** is an observed rule match or security finding produced from
security events.

An **incident** is a contextualized investigation case created when one or
more relevant detections/events are sufficiently related to form a single
investigation unit.

Not every detection must become a separate incident.

---

## 4. What ProShield Is

ProShield is:

- a first-layer incident-triage platform
- a security-operations intelligence system
- a security-event correlation system
- an evidence-backed attack-timeline builder
- a preliminary severity/confidence system
- an early incident-report generator
- an analyst skill/level/team/queue routing system
- an auditable security workflow

---

## 5. What ProShield Is NOT

ProShield is not:

- a SIEM replacement
- a firewall
- a WAF
- an endpoint-security product
- an IAM system
- a complete cybersecurity platform
- an autonomous SOC
- a replacement for security analysts
- an AI system that automatically understands every attack
- an unrestricted autonomous response system

ProShield sits above existing security controls and uses their events as
inputs.

---

## 6. Who Uses ProShield?

### Security Analyst

The primary user of ProShield.

The analyst receives an incident that has already been:

- detected
- correlated
- organized
- given a preliminary severity
- supported with evidence
- placed on a timeline
- assigned a recommended investigation skill/level/team

The analyst then performs the deeper investigation and makes the final
decision.

### Security Admin / Security Lead

The administrative user can review:

- incidents
- detections
- rules
- routing decisions
- audit history
- system status
- configuration

The admin is responsible for oversight and controlled configuration.

### Security Event Sources

These are systems that generate security telemetry.

Examples include:

- simulated security events
- NGINX
- WAF / Cezara
- rate-limiting controls
- TLS/network security controls
- future SIEM integrations
- future endpoint integrations
- future IAM integrations

These systems are sources of evidence. They are not part of ProShield
itself.

---

## 7. The First ProShield MVP

The first MVP is deliberately rule-based.

The MVP must prove that deterministic automation can meaningfully reduce
the repetitive manual work involved in the first stage of security
investigation.

The MVP pipeline is:

Security Event
→ Event Validation
→ Event Normalization
→ Detection Rule
→ Correlation
→ Attack Timeline
→ Severity + Confidence
→ Incident
→ Early Incident Report
→ Analyst Routing
→ Human Analyst

The MVP must work without AI.

AI is a future enhancement and must not be required for the core detection
pipeline to function.

### MVP Philosophy

Build the smallest reliable implementation that can prove the product's
core value.

Prefer:

- deterministic behavior
- explainable decisions
- testable components
- auditable results
- simple architecture
- clear evidence

Avoid adding sophisticated features that do not directly improve
first-stage incident triage.

---

## 8. Initial Security Sources

ProShield should not begin by building every possible security collector.

The first proof of the product should use simulated canonical security
events.

This allows the core pipeline to be validated before integrating with
real systems.

The planned source progression is:

1. Simulated canonical security events
2. NGINX
3. WAF / Cezara
4. Rate-limiting events
5. TLS / network security events
6. Future SIEM integration
7. Future endpoint-security integration
8. Future IAM integration

Real collectors must act as adapters.

A collector converts source-specific telemetry into the common ProShield
`SecurityEvent` format.

The core detection and correlation engine must not depend on one specific
security product.

---

## 9. Core Product Flow

A typical ProShield workflow is:

1. A security system produces an event.
2. ProShield receives the event.
3. ProShield validates the event.
4. ProShield converts it into the canonical `SecurityEvent` format.
5. Detection rules evaluate the event.
6. Related events are correlated.
7. A chronological attack timeline is created.
8. Preliminary severity and confidence are calculated.
9. A contextualized incident is created.
10. ProShield creates an early investigation report.
11. ProShield determines the required security skill/category.
12. ProShield recommends an analyst level/team/queue.
13. A human analyst begins the investigation.

---

## 10. The Main Product Output

The main ProShield output is **not a raw alert**.

The main output is a **contextualized incident**.

An incident should contain, when available:

- incident ID
- incident category
- severity
- confidence
- evidence
- related events
- attack timeline
- affected assets
- source information
- timestamps
- incident status
- routing recommendation
- required skill/category
- recommended analyst level
- recommended team/queue
- recommended response
- audit history

### Severity Meaning

ProShield's severity and confidence are **preliminary triage assessments**.

They are not final determinations of what happened or how the incident
must ultimately be handled.

A human analyst retains authority to:

- change severity
- change classification
- change routing
- continue investigation
- close the incident
- declare a false positive

---

## 11. Evidence Principle

ProShield must never invent security evidence.

Every timeline item must trace back to:

1. an observed security event, or
2. an explicitly derived rule/correlation result.

The system must distinguish:

**OBSERVED FACTS**

from

**DERIVED CONCLUSIONS**

from

**RECOMMENDATIONS**

For example:

Observed fact:
"Three WAF alerts were generated from source IP X within five minutes."

Derived conclusion:
"The events are correlated based on source, time window, and target."

Recommendation:
"Route to an L2 web-security analyst."

The recommendation must never be presented as if it were an observed fact.

---

## 12. Analyst Routing

Routing is a core ProShield function.

The goal is:

RIGHT INCIDENT
→ RIGHT SKILL
→ RIGHT ANALYST LEVEL / TEAM
→ RIGHT TIME

The MVP should **not** attempt to decide exactly which individual analyst
is available or should receive the case unless an authorized data source
provides that information.

The initial MVP routes to:

- analyst level
- skill category
- team
- queue

Routing should consider more than severity.

Possible routing inputs include:

- severity
- incident complexity
- incident category
- required security expertise
- affected technology
- affected asset
- business criticality
- confidence

Example:

LOW + SIMPLE
→ L1

MEDIUM + STANDARD
→ L1

HIGH
→ L2

CRITICAL + COMPLEX
→ L3

However, severity alone is not sufficient.

For example:

MEDIUM
+ IAM expertise required
+ current L1 capability does not include IAM
→ IAM-capable team / appropriate level

The routing decision must be explainable and auditable.

---

## 13. Human-in-the-Loop Principle

ProShield does not replace human security analysts.

ProShield performs repetitive first-stage work so that humans can start
the real investigation faster.

Humans retain responsibility for:

- final judgment
- deeper investigation
- high-impact decisions
- complex response
- incident closure

The goal is:

**MAKE ANALYSTS FASTER**

not

**REMOVE ANALYSTS.**

---

## 14. Response Boundary

The initial ProShield response model is:

Detect
→ Report
→ Recommend
→ Human Approval
→ Response

ProShield must not initially perform unrestricted destructive actions.

Examples of actions that are outside the initial autonomous scope:

- account deletion
- mass session revocation
- broad firewall modification
- destructive infrastructure changes

Controlled and low-risk response capabilities may be introduced later
after the detection and investigation pipeline has been validated.

---

## 15. ProShield's Own Security

ProShield itself is security-critical.

If ProShield is compromised, an attacker could potentially:

- inject fake security events
- suppress real events
- manipulate severity
- manipulate routing
- change detection rules
- tamper with evidence
- create alert floods
- abuse response capabilities
- manipulate security decisions

Therefore ProShield must protect:

- event ingestion
- APIs
- internal services
- rules
- incidents
- routing
- storage
- audit logs
- secrets
- response actions

Security architecture and threat modeling must begin before implementation
rather than being added at the end.

---

## 16. Safe Failure Principle

ProShield must fail safely.

When a dependency fails:

- security events must not be silently discarded
- the system must not falsely report successful processing
- incidents should be preserved where possible
- operators should be informed of telemetry gaps
- deterministic fallback behavior should be retained where possible

Future AI failures must never disable the deterministic security pipeline.

---

## 17. AI Strategy

AI is **not part of the first detection foundation**.

The initial MVP must prove the rule-based system first.

Only after the rule-based MVP is validated should AI be introduced for:

- deeper investigation
- advanced correlation
- contextual reasoning
- investigation assistance
- severity assistance
- confidence assessment
- incident summarization
- investigation recommendations

AI should enhance the deterministic security pipeline rather than replace
it.

---

## 18. MVP Success

ProShield is successful only if it demonstrates meaningful reduction in
repetitive first-stage analyst work without reducing security quality.

Measure:

- initial triage time
- manual correlation time
- timeline-construction time
- initial report-preparation time
- routing accuracy
- detection accuracy
- false-positive rate
- processing latency
- throughput
- failure behavior
- analyst usefulness/acceptance

### Primary Business Metric

**How much initial analyst work does ProShield remove without reducing
security quality?**

This is more important than simply counting how many alerts ProShield
can detect.

---

## 19. MVP Boundary

The first ProShield MVP must prove:

Security Events
→ Detection
→ Correlation
→ Attack Timeline
→ Preliminary Severity
→ Incident
→ Early Investigation Report
→ Skill / Level / Team Routing
→ Human Analyst

The MVP does not need to prove:

- complete SIEM replacement
- complete SOC automation
- autonomous incident response
- AI investigation
- every possible security attack
- every possible security integration

---

## 20. Long-Term Direction

The long-term ProShield vision is:

Existing Security Controls
→ Security Events
→ ProShield
→ Detection
→ Correlation
→ Attack Timeline
→ Severity
→ AI-Assisted Investigation
→ Evidence-Based Incident Report
→ Skill / Complexity / Severity Routing
→ Appropriate L1 / L2 / L3 Analyst/Team
→ Controlled Response
→ Audit / Continuous Improvement

The product should expand only after the rule-based MVP proves its value.

---

## 21. Core Product Principle

Build the smallest ProShield that can prove a meaningful reduction in the
repetitive first-stage work of security analysts.

Do not build a giant cybersecurity platform before proving the core idea.

The first proof must be:

FRAGMENTED SECURITY EVENTS
→ CORRELATED INCIDENT
→ ATTACK TIMELINE
→ PRELIMINARY SEVERITY
→ EARLY INVESTIGATION REPORT
→ APPROPRIATE SKILL / LEVEL ROUTING
→ HUMAN ANALYST