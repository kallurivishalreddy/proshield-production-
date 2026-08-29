# ProShield — Routing Matrix

## 1. Purpose

This document defines how ProShield recommends the appropriate
investigation destination for an incident.

The purpose of routing is to send:

RIGHT INCIDENT
→ RIGHT SKILL
→ RIGHT ANALYST LEVEL
→ RIGHT TEAM / QUEUE
→ AT THE RIGHT TIME

Routing exists to reduce:

- incorrect assignment
- unnecessary senior escalation
- skill mismatch
- investigation delay
- wasted analyst time

Routing is a CORE ProShield MVP capability.

---

## 2. What Routing Does

ProShield does not decide which individual human must investigate an
incident.

Instead, the MVP produces an explainable routing recommendation based on
the information available in the incident.

The MVP routing target is:

- analyst level
- required skill/category
- team
- queue

Example:

```text
Recommended Level: L2
Required Skill: Web Security
Recommended Team: Application Security
Queue: Web-Security-L2

Reason:
High-confidence correlated WAF and NGINX activity affecting a
production web endpoint requires deeper web-security investigation.
```

---

## 3. What Routing Does NOT Assume

The MVP must not assume that ProShield knows:

- individual analyst availability
- current analyst workload
- shift schedules
- individual skill matrices
- who is currently on call

unless an authorized source explicitly provides that information.

Therefore the initial MVP does not assign an incident to a specific person.

Future versions may use authorized analyst/organizational data to support
individual assignment.

---

## 4. Routing Inputs

Routing should consider more than severity.

Primary inputs:

1. Severity
2. Incident complexity
3. Incident category
4. Required security skill
5. Affected technology
6. Affected asset
7. Business criticality
8. Confidence
9. Investigation depth required

The routing engine should use only information actually available from the
incident and authorized configuration.

It must not invent missing analyst or organizational information.

---

## 5. Severity Levels

Initial severity levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Severity is a preliminary triage assessment.

It is not the final analyst judgment.

A human analyst may later change the severity.

---

## 6. Analyst Levels

The MVP uses three investigation levels.

### L1 — Initial / Standard Investigation

Typical characteristics:

- simple or well-understood pattern
- lower complexity
- limited investigation depth
- standard security skill requirement

Typical routing:

```text
LOW + SIMPLE
→ L1

MEDIUM + STANDARD
→ L1
```

L1 must still receive enough evidence and context to begin investigation.

---

### L2 — Advanced Investigation

Typical characteristics:

- HIGH severity
- moderate or high complexity
- specialized security expertise
- multiple related events
- investigation requiring deeper technical analysis

Typical routing:

```text
HIGH
→ L2

MEDIUM
+ specialized skill required
+ L1 lacks that skill
→ appropriate L2-capable team
```

---

### L3 — Expert / Incident Response

Typical characteristics:

- CRITICAL severity
- highly complex incidents
- multi-layer attack activity
- significant business impact
- advanced investigation requirements

Typical routing:

```text
CRITICAL + COMPLEX
→ L3 / Incident Response
```

---

## 7. Base Routing Matrix

The following is the initial baseline.

| Severity | Complexity | Base Level |
|---|---|---|
| LOW | SIMPLE | L1 |
| LOW | STANDARD | L1 |
| LOW | COMPLEX | L2 if specialist expertise is required |
| MEDIUM | SIMPLE | L1 |
| MEDIUM | STANDARD | L1 |
| MEDIUM | COMPLEX | L2 |
| HIGH | SIMPLE | L2 |
| HIGH | STANDARD | L2 |
| HIGH | COMPLEX | L2 / L3 depending on impact and investigation requirements |
| CRITICAL | SIMPLE | L3 if business impact warrants escalation |
| CRITICAL | STANDARD | L3 |
| CRITICAL | COMPLEX | L3 |

This matrix is a starting policy, not an absolute rule.

Routing must consider skill, technology, criticality, confidence, and
complexity in addition to severity.

---

## 8. Skill-Based Overrides

Severity alone must never be the only routing factor.

Example:

```text
MEDIUM
+
IAM expertise required
+
L1 capability does not include IAM
→ IAM-capable team / appropriate level
```

Another example:

```text
HIGH
+
well-understood web-security pattern
+
known affected technology
+
strong evidence
→ L2 Web Security may be sufficient
```

Another example:

```text
HIGH
+
multiple technologies
+
uncertain correlation
+
complex investigation
→ L3 / Incident Response may be recommended
```

---

## 9. Required Skill Categories

The initial MVP should support a small, clear skill taxonomy.

Suggested categories:

- Web Security
- Network Security
- IAM / Authentication
- Application Security
- WAF / Edge Security
- TLS / Cryptography
- Incident Response
- Security Operations / General Triage

New skill categories may be added when a real MVP scenario requires them.

Do not create dozens of categories before they are useful.

---

## 10. Affected Technology

Routing should consider which technology is involved.

### NGINX / Web Traffic

Possible routing:

- Skill: Web Security / Application Security
- Level: L1 or L2 depending on severity and complexity

### WAF

Possible routing:

- Skill: WAF / Edge Security
- Level: L1 for simple known patterns
- Level: L2 for complex or high-risk patterns

### TLS / Network

Possible routing:

- Skill: Network Security / TLS
- Level based on severity, complexity, and confidence

### Authentication / IAM

Possible routing:

- Skill: IAM / Authentication
- Level based on severity and investigation complexity

---

## 11. Business Criticality

The affected asset may change routing.

Example:

```text
MEDIUM
+
simple web event
+
low-criticality development asset
→ L1 Web Security
```

versus:

```text
MEDIUM
+
same event pattern
+
critical production asset
→ potentially L2 or a higher-priority security queue
```

depending on configured policy.

Business criticality must come from an authorized source.

ProShield must not invent the importance of an asset.

---

## 12. Confidence

Confidence should influence routing.

### High confidence

A known rule triggered with strong supporting evidence.

Possible result:

Normal severity-based routing.

### Low confidence

Weak correlation or incomplete evidence.

Possible result:

Route for additional investigation rather than automatically escalating
to the highest level.

Confidence must not override severity blindly.

It is one input to the routing decision.

---

## 13. Complexity

Complexity is different from severity.

A LOW-severity incident can still be complex.

A HIGH-severity incident can be technically simple.

Possible complexity factors:

- number of related events
- number of affected assets
- number of security controls involved
- number of technologies involved
- number of timeline stages
- correlation uncertainty
- investigation depth required

The complexity assessment must be explainable.

---

## 14. Routing Decision Output

Every routing recommendation should contain:

- recommended analyst level
- required skill/category
- recommended team
- recommended queue
- severity
- complexity
- confidence
- affected technology
- reason for routing
- evidence supporting the decision when applicable

Example:

```text
Recommended Level: L2
Required Skill: Web Security
Team: Application Security
Queue: Web-Security-L2

Severity: HIGH
Complexity: STANDARD
Confidence: HIGH

Reason:
A high-confidence WAF detection is correlated with repeated NGINX
requests from the same source against the same production endpoint.
The incident requires deeper web-security investigation but does not
currently require L3 incident response.
```

---

## 15. Routing Must Be Explainable

ProShield must never produce:

```text
Route to L2
```

without explaining why.

A valid routing decision should be understandable to a human reviewer.

The explanation should describe:

- what the incident is
- why its severity matters
- why its complexity matters
- what expertise is required
- why the selected level/team is appropriate

Routing reasoning must use evidence and configured policy.

---

## 16. Routing Must Be Auditable

Every routing decision must be auditable.

Record:

- incident ID
- routing decision
- recommended level
- required skill
- team/queue
- policy/rule version
- inputs used
- timestamp
- final decision if changed later
- analyst/admin action if applicable

If a human changes the routing recommendation, that change must also be
auditable.

The system must preserve the difference between:

- ProShield's automated recommendation
- human override
- final disposition

---

## 17. Human Override

ProShield provides a recommendation.

An authorized human analyst or security administrator may override the
recommendation.

Example:

```text
ProShield recommendation:
L2 Web Security

Human decision:
Escalate to L3 Incident Response
```

The system must preserve:

- original recommendation
- human override
- reason, when provided
- timestamp
- authorized actor

ProShield must never silently replace its automated recommendation with a
human decision.

---

## 18. Unknown / Uncertain Cases

If ProShield does not have enough evidence to determine the correct
specialization:

- do not invent a skill
- do not pretend certainty
- route to a reasonable general security investigation level/team/queue
- clearly state that specialist routing could not be determined
- preserve the evidence needed for human decision

Example:

```text
Recommended Level: L2
Skill: Security Operations / General Triage
Team: Security Operations
Queue: General-L2

Reason:
The incident is HIGH severity, but the current evidence does not
reliably identify a specialized investigation category.
Additional human investigation is required.
```

---

## 19. Routing Examples

### Example A — Low Web Event

```text
Severity: LOW
Complexity: SIMPLE
Technology: NGINX
Confidence: HIGH
Skill: Web Security

→ L1
→ Web Security Queue
```

### Example B — Medium IAM Incident

```text
Severity: MEDIUM
Complexity: STANDARD
Technology: IAM
Confidence: HIGH

L1 does not have IAM capability.

→ L2
→ IAM Security Queue
```

### Example C — High WAF Incident

```text
Severity: HIGH
Complexity: STANDARD
Technology: WAF + NGINX
Confidence: HIGH

→ L2
→ Application/Web Security Queue
```

### Example D — Critical Multi-Layer Incident

```text
Severity: CRITICAL
Complexity: COMPLEX
Technology: WAF + NGINX + Network
Confidence: HIGH

→ L3
→ Incident Response Queue
```

### Example E — Unknown Pattern

```text
Severity: HIGH
Complexity: UNKNOWN
Confidence: LOW

Specialist category cannot be determined reliably.

→ L2
→ Security Operations / General Triage Queue

Reason:
Additional investigation is required before specialist routing can
be determined.
```

---

## 20. MVP Routing Boundaries

The MVP routing engine must:

- be deterministic
- be explainable
- be configurable
- be testable
- be auditable
- route to level/skill/team/queue
- avoid unsupported assumptions
- support human override

The MVP routing engine must NOT:

- choose individual analysts using fabricated availability
- infer workload without an authorized source
- silently change routing
- use opaque AI reasoning
- require an AI model to make the routing decision
- route only from severity without considering other available inputs

AI-assisted routing is future scope.

---

## 21. Routing Acceptance Criteria

Routing is considered correct when:

### AC-01 — Basic low-severity routing

A LOW + SIMPLE incident is routed to L1 unless skill requirements require
otherwise.

### AC-02 — High-severity routing

A HIGH incident is routed to L2 by default.

### AC-03 — Critical routing

A CRITICAL + COMPLEX incident is routed to L3.

### AC-04 — Skill mismatch

A skill mismatch causes routing to an appropriate skill-capable
level/team/queue.

### AC-05 — Severity is not the only factor

The same severity can produce different routing when complexity, skill,
technology, criticality, or confidence differs.

### AC-06 — Explainable recommendation

Every routing recommendation contains a human-readable reason.

### AC-07 — Auditable decision

The routing decision and its inputs are recorded.

### AC-08 — Human override

An authorized human can override the recommendation.

### AC-09 — Unknown behavior

Insufficient evidence does not cause fabricated specialist routing.

### AC-10 — Determinism

The same incident inputs and routing policy version produce the same
routing recommendation.

### AC-11 — Evidence traceability

The routing reason can be traced to the incident's severity, complexity,
skills, technology, or other actual available inputs.

### AC-12 — No false organizational assumptions

The system does not claim analyst availability, workload, or individual
assignment when that information does not exist.

---

## 22. Future Extensions

Future versions may integrate:

- analyst skill matrices
- availability
- shift information
- current workload
- specialization
- escalation policies
- individual assignment
- AI-assisted routing

These are not required for the first MVP.

Any future integration must use authorized organizational data.

---

## 23. Core Routing Principle

ProShield should not ask:

> "Who is the most senior analyst?"

It should ask:

> "What level, expertise, team, and investigation depth does this incident
> actually require?"

The goal is:

RIGHT INCIDENT
→ RIGHT SKILL
→ RIGHT LEVEL
→ RIGHT TEAM / QUEUE
→ RIGHT TIME

without unnecessary escalation or skill mismatch.

Routing is successful when a capable human receives the right incident
with enough context to begin the appropriate level of investigation
without ProShield pretending to know information it does not actually
have.