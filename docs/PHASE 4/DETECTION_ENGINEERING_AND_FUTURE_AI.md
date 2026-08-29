# ProShield — Detection Engineering, Adversarial Testing, and Future AI

## 1. Purpose

This document defines the long-term detection-engineering strategy for
ProShield.

It connects three major capabilities:

1. Deterministic backend detection
2. Continuous threat research and adversarial testing
3. Future AI-assisted detection and investigation

The purpose is to ensure that ProShield does not simply contain a static
collection of security rules.

Instead, the system should continuously improve through:

```text
Research
→ Understand Behavior
→ Identify Defender-Visible Signals
→ Map to Security Connectors
→ Create Safe Test Scenario
→ Run Through ProShield
→ Measure Result
→ Investigate Failure
→ Improve Rule
→ Regression Test
→ Version Rule
→ Add Validated Knowledge
```

This document is a long-term engineering specification.

It must be preserved and reviewed before making major changes to the
detection architecture.

---

# 2. Core Principle

ProShield must not attempt to detect attacks by matching only attack names.

The system detects **observable security behavior**.

The fundamental model is:

```text
Threat Behavior
      ↓
Observable Signals
      ↓
Security Telemetry
      ↓
ProShield Detection
```

The attacker performs an action.

The security environment produces telemetry.

ProShield analyzes the telemetry.

Therefore:

> ProShield does not need to reproduce every attack internally. It needs
> to understand the observable behavior produced by attacks and determine
> whether that behavior can be detected reliably.

---

# 3. The Difference Between an Attack and a Detection Rule

An attack technique and a detection rule are not the same thing.

One attack behavior may produce multiple observable patterns.

One observable pattern may apply to multiple attack techniques.

Therefore:

```text
1 Attack
≠
1 Rule
```

and:

```text
1 Rule
may detect behavior relevant to
multiple attack techniques
```

The rule catalogue must therefore be organized around **observable
behavior and detection opportunities**, not simply attack-name count.

---

# 4. Connector Responsibility

A security connector is a source adapter.

Its primary responsibility is:

```text
Source telemetry
→ Source-specific parsing
→ Validation/mapping
→ Canonical SecurityEvent
```

Examples:

```text
WAF
→ WAF Connector
→ SecurityEvent

NGINX
→ NGINX Connector
→ SecurityEvent

IAM
→ IAM Connector
→ SecurityEvent

Rate Limiter
→ Rate-Limit Connector
→ SecurityEvent
```

A connector should understand the format and semantics of its source.

A connector must NOT become the entire ProShield detection engine.

---

# 5. Security Product Rules vs ProShield Rules

Security controls such as WAF, NGINX, IAM, and rate limiters may already
have their own rules.

Their responsibilities are different from ProShield's rules.

## Source Security Control

Example:

```text
WAF rule
→ inspect request
→ block request
→ generate WAF event
```

Its question is:

> Should this security control allow, block, or flag the activity?

## ProShield

Example:

```text
WAF event
+
NGINX event
+
rate-limit event
→ ProShield correlation
→ detection
```

Its question is:

> Do these observations together represent a meaningful security
> behavior that requires investigation?

ProShield must not simply duplicate every source product's detection
engine.

---

# 6. Canonical Event Boundary

All connectors must produce the canonical:

```text
SecurityEvent
```

The core pipeline begins only after the source-specific event has crossed
this boundary.

The architectural path is:

```text
Source
  ↓
Connector
  ↓
Canonical SecurityEvent
  ↓
Validation / Normalization
  ↓
ProShield Detection Engine
```

This keeps the detection engine independent of individual vendors.

---

# 7. Why the Core Engine Must Not Be Connector-Specific

Bad architecture:

```text
WAF code
  ↓
calls NGINX detection
  ↓
calls IAM detection
  ↓
creates incident
```

This creates tightly coupled components.

Better architecture:

```text
WAF Connector
     ↓
SecurityEvent
     ↓
WAF-relevant rules
     ↓
Detection
     ↓
shared correlation layer
```

Similarly:

```text
NGINX Connector
     ↓
SecurityEvent
     ↓
NGINX-relevant rules
     ↓
Detection
```

All detection results enter a common system.

---

# 8. Rule Categories

ProShield should support three major rule categories.

## 8.1 Source-Specific Rules

Rules that depend primarily on telemetry from one source.

Examples:

```text
WAF rule
NGINX rule
IAM rule
Rate-limit rule
TLS rule
```

These rules understand source-specific semantics.

---

## 8.2 Source-Independent Behavioral Rules

Rules based on normalized event properties rather than one vendor.

Example:

```text
Repeated authentication failures
+
same source
+
defined time window
```

The source may vary because the event has already been normalized.

---

## 8.3 Cross-Source Correlation Rules

Rules that intentionally combine evidence from multiple connectors.

Example:

```text
WAF detection
+
NGINX request burst
+
rate-limit violation
+
same source
+
same target
+
defined time window
```

These rules are particularly important to ProShield because they allow the
platform to identify behavior that is distributed across multiple security
controls.

---

# 9. Rule Organization

Rules should remain physically separated for maintainability.

Conceptual structure:

```text
backend/
├── rules/
│   ├── common/
│   ├── waf/
│   ├── nginx/
│   ├── iam/
│   ├── rate_limit/
│   ├── network/
│   └── correlation/
```

Rules should not be placed into one enormous file.

Each rule should have:

- unique ID
- version
- purpose
- applicable sources
- applicable event types
- conditions
- thresholds/windows where applicable
- evidence requirements
- category
- severity contribution where applicable
- confidence contribution where applicable
- false-positive considerations
- test references

---

# 10. Rule Registry

Although rule implementations are separated, ProShield should have one
authoritative rule registry.

Conceptually:

```text
Rule Registry
├── WAF-001
├── NGINX-001
├── IAM-001
├── RATE-001
├── CORR-WEB-001
└── ...
```

The registry provides:

- rule discovery
- enabled/disabled state
- metadata
- version lookup
- execution selection

The registry should not contain all rule implementation logic.

It is the authoritative inventory of available rules.

---

# 11. Rule Metadata for Efficient Execution

Rules should identify what they need before the engine evaluates them.

Example:

```yaml
id: WAF-001
version: 1
sources:
  - waf
event_types:
  - waf_attack_detected
```

A correlation rule might declare:

```yaml
id: CORR-WEB-001
version: 1

required_sources:
  - waf
  - nginx
  - rate_limiter
```

This allows the engine to avoid evaluating irrelevant rules.

---

# 12. Rule Selection Pipeline

The efficient runtime flow should be:

```text
SecurityEvent
      ↓
Identify source
      ↓
Identify event type
      ↓
Select applicable rules
      ↓
Run relevant rules
      ↓
Create detections
```

The engine should NOT do:

```text
Every event
  ↓
Every rule
```

when metadata allows safe filtering.

This reduces:

- CPU usage
- latency
- unnecessary rule evaluation
- complexity
- accidental rule/source mismatches

---

# 13. Detection Signals

A rule should produce a structured detection signal.

Conceptually:

```text
Detection
├── detection_id
├── rule_id
├── rule_version
├── category
├── timestamp
├── evidence_refs
├── severity_contribution
├── confidence_contribution
└── reasoning
```

The detection becomes an input to later correlation and incident logic.

---

# 14. Correlation Engine

The correlation engine is responsible for combining relevant evidence.

It should not require connector A to directly call connector B.

Instead:

```text
Connector A
    ↓
Detection A
    │
Connector B
    ↓
Detection B
    │
Connector C
    ↓
Detection C
    │
    └──────────────┐
                   ↓
            Correlation Engine
                   ↓
             Correlation Rule
                   ↓
          Correlated Detection
```

This keeps connectors independent.

---

# 15. Correlation Inputs

Correlation may use:

- source
- destination
- endpoint
- account
- device
- asset
- source IP
- event type
- detection category
- timestamps
- time windows
- repeated behavior
- related controls
- sequence
- rule relationships

Only actual available information may be used.

---

# 16. Correlation Must Be Selective

Not every event should be correlated with every other event.

A correlation rule should explicitly define what evidence it needs.

Example:

```yaml
id: CORR-WEB-001

required_sources:
  - waf
  - nginx

conditions:
  same_source: true
  same_target: true

window:
  seconds: 120
```

This allows the engine to focus on relevant evidence.

---

# 17. Example Cross-Connector Detection

Suppose the environment produces:

```text
WAF:
blocked suspicious request
```

```text
NGINX:
repeated requests from same source
```

```text
Rate Limiter:
request threshold exceeded
```

ProShield may correlate:

```text
WAF
+
NGINX
+
Rate Limiter
+
same source
+
same target
+
same time window
```

into:

```text
High-confidence correlated web-abuse activity
```

This is more valuable than simply forwarding three independent alerts.

---

# 18. Why We Do Not Create One Rule Per Attack

A large attack catalogue does not mean a large one-to-one rule catalogue.

Example:

```text
Attack Behaviors:
Brute Force
Password Spraying
Credential Stuffing
Account Takeover
```

These can share observable signals.

Possible signals:

```text
repeated authentication failures
source repetition
account spread
unusual success after repeated failures
```

One or more rules may detect these signals.

Therefore:

```text
Threat Corpus
```

and:

```text
Rule Corpus
```

are different datasets.

The Threat Corpus is broader.

The Rule Corpus contains validated detection opportunities.

---

# 19. Threat Behavior Corpus

ProShield should eventually maintain a large research corpus.

A threat-behavior record should capture:

- behavior name
- source/reference
- technique ID when applicable
- behavior description
- observable defender signals
- affected technologies
- relevant connectors
- likely false positives
- candidate correlation patterns
- safe simulation design
- ProShield rule candidates
- testing status
- validation status
- version/history

The goal is not simply:

```text
1000 attack names
```

The goal is:

```text
1000+ researched behaviors/scenarios
→ detection opportunities
→ validated rules/tests where justified
```

---

# 20. Research Sources

The research corpus may use:

- MITRE ATT&CK
- NIST
- CISA
- CVE/NVD
- vendor advisories
- CERT advisories
- security research papers
- government security guidance
- verified incident reports
- relevant Indian cybersecurity advisories

Research sources must be recorded.

The source is not automatically assumed to be correct merely because an AI
model summarized it.

---

# 21. AI-Assisted Threat Research

A local AI model such as Nemotron may assist with:

- reading large security references
- extracting behaviors
- grouping similar behaviors
- identifying potential telemetry
- generating candidate test scenarios
- generating negative cases
- identifying possible false positives
- suggesting candidate rules
- generating rule variations

AI outputs must be treated as candidate analysis.

They are not automatically trusted security decisions.

---

# 22. Research Verification

The safe research process is:

```text
Authoritative Source
        ↓
AI-assisted analysis
        ↓
Candidate behavior
        ↓
Human verification
        ↓
Safe scenario
        ↓
Test
        ↓
Validated result
```

Do not allow an AI-generated claim to become a production rule without
verification.

---

# 23. Safe Simulation Strategy

Initial testing should primarily use controlled synthetic events.

Example:

```text
authentication_failure
authentication_failure
authentication_failure
authentication_success
suspicious_request
```

The objective is to represent observable behavior.

The simulator must pass events through the real ProShield pipeline.

It must NOT directly create the expected Detection or Incident.

---

# 24. Isolated Real-Lab Testing

Where appropriate and authorized, ProShield may later be tested with
controlled security activity in an isolated laboratory.

Conceptually:

```text
Controlled Test Environment
        ↓
Authorized security test activity
        ↓
Test system
        ↓
Telemetry
        ↓
Connector
        ↓
ProShield
```

The laboratory must be:

- owned or explicitly authorized
- isolated from unintended systems
- non-production
- reproducible
- monitored
- safely resettable

No unauthorized third-party systems may be used.

---

# 25. Simulation and Real-Lab Testing Are Complementary

Synthetic tests answer:

> Does ProShield behave correctly when given known telemetry?

Real-lab testing answers:

> Does the actual controlled activity produce the telemetry we expected?

Both are useful.

The intended testing program uses both rather than depending entirely on
one.

---

# 26. Adversarial Detection Testing

Once baseline rules are stable, test controlled variations.

Examples of safe variations include:

- timing differences
- event frequency
- event ordering
- source variation
- target variation
- sequence variation
- combinations of behaviors
- legitimate activity mixed with suspicious activity

The objective is to determine whether ProShield detects only one exact
pattern or whether the detection logic remains useful when behavior changes.

---

# 27. Positive Testing

A positive test represents behavior the rule is designed to detect.

Example:

```text
Expected:
Detection created
```

The test should verify:

- correct rule
- correct evidence
- correct category
- appropriate severity contribution
- appropriate confidence
- correct incident/routing behavior where applicable

---

# 28. Negative Testing

A negative test represents legitimate or unrelated behavior.

Expected:

```text
No detection
```

Negative testing is required to control false positives.

A rule that detects everything is not a good rule.

---

# 29. Edge-Case Testing

Test unusual but legitimate or ambiguous conditions.

Examples:

- threshold exactly reached
- threshold just below
- threshold just above
- delayed event
- out-of-order event
- duplicate event
- missing optional field
- incomplete telemetry
- multiple sources
- conflicting signals

---

# 30. False Positive Analysis

When a rule triggers incorrectly:

```text
False Positive
     ↓
Investigate why
     ↓
Identify missing context
     ↓
Improve conditions/correlation
     ↓
Add regression case
     ↓
Re-test
```

False positives must be measured, not merely ignored.

---

# 31. False Negative Analysis

When ProShield fails to detect behavior it should detect:

```text
False Negative
      ↓
Identify missing signal
      ↓
Identify weak rule
      ↓
Identify telemetry gap
      ↓
Improve rule/correlation
      ↓
Create regression test
      ↓
Re-test
```

A missed detection can indicate:

- poor rule logic
- insufficient telemetry
- incorrect normalization
- incorrect correlation
- insufficient coverage

The root cause must be determined before changing a rule.

---

# 32. Rule Improvement Loop

Every important rule should follow:

```text
Research
   ↓
Candidate Rule
   ↓
Positive Tests
   ↓
Negative Tests
   ↓
Edge Cases
   ↓
Real-Lab Validation where appropriate
   ↓
False Positive / False Negative Analysis
   ↓
Rule Revision
   ↓
Regression Tests
   ↓
Version Freeze
```

A rule should not be considered mature because it passed one example.

---

# 33. Rule Versioning

Every meaningful rule change creates a new version.

Example:

```text
AUTH-001 v1
      ↓
false positive discovered
      ↓
AUTH-001 v2
```

Historical detections must preserve the rule version used.

This allows ProShield to answer:

> Which exact detection logic produced this result?

---

# 34. Rule Quality Record

Each mature rule should maintain a record containing:

```text
Rule ID
Version
Purpose
Behavior detected
Required sources
Required event types
Conditions
Correlation logic
Expected positives
Expected negatives
Known false positives
Known limitations
Test coverage
Real-lab validation status
Metrics
Last review
```

---

# 35. Detection Coverage

ProShield should measure more than rule count.

Useful metrics include:

- behavior coverage
- telemetry coverage
- detection coverage
- true positives
- false positives
- false negatives
- unknown cases
- rule execution latency
- correlation success
- analyst usefulness

A large rule count with poor precision is not success.

---

# 36. Dataset Creation

The detection-testing program can create a valuable security dataset.

But raw logs alone are not sufficient.

Useful training/evaluation data should preserve:

```text
Event sequence
+
Telemetry source
+
Known/unknown behavior
+
Rule applied
+
ProShield result
+
Expected result
+
Human/validated label
+
False-positive/false-negative status
+
Relevant context
```

---

# 37. Dataset Labels

Possible labels include:

```text
TRUE_POSITIVE
FALSE_POSITIVE
TRUE_NEGATIVE
FALSE_NEGATIVE
UNKNOWN
INSUFFICIENT_EVIDENCE
```

The exact label set may evolve.

Labels must represent validated outcomes, not guesses from the model that
generated the test.

---

# 38. Dataset Quality Requirements

A future AI dataset must be:

- validated
- deduplicated
- versioned
- traceable to source/test scenario
- balanced enough for the intended task
- labeled
- protected
- free from unintended secrets
- reproducible

More data does not automatically mean better data.

---

# 39. Future AI Role

AI should initially be treated as an enhancement layer.

Potential future uses:

- anomaly detection
- pattern discovery
- behavior similarity
- advanced correlation
- investigation assistance
- report enrichment
- recommendation generation
- alert prioritization

The deterministic rule engine remains the baseline.

---

# 40. AI Must Not Replace the Deterministic Baseline

The core MVP architecture remains:

```text
SecurityEvent
→ Rules
→ Correlation
→ Incident
→ Report
→ Routing
```

Future AI operates alongside or after deterministic detection.

Example:

```text
Security Events
        ↓
Deterministic Rules
        ↓
Known Detections
        ↓
AI Investigation Layer
        ↓
Additional Insight
        ↓
Human Analyst
```

AI failure must not disable:

- ingestion
- deterministic rules
- correlation
- incident creation
- audit
- access to evidence

---

# 41. AI Evaluation Requirement

Do not introduce an AI detector simply because a dataset exists.

The AI system must be compared against the deterministic baseline.

Measure:

- precision
- recall
- false-positive rate
- false-negative rate
- latency
- explainability
- analyst usefulness
- operational cost

AI must demonstrate meaningful improvement on a defined problem.

If it does not outperform or materially improve the baseline, it should not
be placed on the critical detection path.

---

# 42. AI Training Data Separation

Separate:

```text
Training Data
Validation Data
Test Data
```

Do not repeatedly tune the model against the final test set.

The final evaluation dataset must remain protected from continuous tuning.

---

# 43. Data Leakage Prevention

Future AI training/evaluation must avoid:

- duplicated records across train/test
- accidental future information
- labels generated from the same model being evaluated
- secrets
- production credentials
- customer-sensitive data
- test contamination

---

# 44. AI Model Versioning

Future models must preserve:

- model identity
- model version
- configuration
- dataset version
- evaluation results
- deployment date
- known limitations

A historical AI-assisted result must be traceable to the model/version
used.

---

# 45. AI Explainability

AI output should identify:

- evidence used
- relevant detections
- relevant events
- uncertainty
- recommendation vs observation

AI-generated claims must not silently become authoritative evidence.

---

# 46. Human Oversight of AI

The AI layer remains subject to human review.

For high-impact recommendations:

```text
AI output
   ↓
Human review
   ↓
Accepted / rejected / modified
```

Human decisions must remain auditable.

---

# 47. Unknown-Behavior Testing

ProShield should maintain a dedicated category for activity that does not
match current known rules.

Expected workflow:

```text
Unknown behavior
      ↓
Preserve evidence
      ↓
Anomaly / suspicious classification where justified
      ↓
Human investigation
      ↓
Research
      ↓
Candidate rule
      ↓
Testing
      ↓
New rule version
```

Unknown does not mean confirmed malicious.

---

# 48. Zero-Day Boundary

ProShield must not claim that it can detect every future zero-day.

A zero-day may exploit previously unknown vulnerabilities.

What ProShield can test is:

- behavior-level resilience
- anomalous sequences
- deviations from normal behavior
- unexpected combinations of known signals
- unknown patterns
- telemetry gaps

The honest claim is:

> ProShield can be evaluated for resilience against previously unseen
> behavioral variations.

Not:

> ProShield detects every zero-day.

---

# 49. Pre-Readiness Testing

The future objective is to improve detection before new attack variations
become widespread.

The process is:

```text
Known behavior
      ↓
Generate controlled variations
      ↓
Run isolated tests
      ↓
Measure current coverage
      ↓
Identify blind spots
      ↓
Improve rules
      ↓
Regression test
```

This is a readiness mechanism, not a guarantee of future attack detection.

---

# 50. Test Factory Architecture

The long-term testing system should automate repetitive work.

Conceptually:

```text
Threat Corpus
      ↓
Scenario Generator
      ↓
Synthetic Event Generator
      ↓
Optional Controlled Lab
      ↓
ProShield Test Runner
      ↓
Expected vs Actual
      ↓
Metrics
      ↓
Regression Dataset
```

AI may assist with generating candidate variations, but the test runner
must remain deterministic and auditable.

---

# 51. Example Complete Test Lifecycle

Suppose research identifies:

```text
Repeated authentication abuse
```

The lifecycle becomes:

```text
1. Research behavior
2. Understand attack concept
3. Identify defender-visible signals
4. Identify IAM/NGINX/WAF telemetry
5. Create safe synthetic scenario
6. Define expected telemetry
7. Create candidate ProShield rule
8. Run positive tests
9. Run negative tests
10. Run edge cases
11. Run controlled lab validation where appropriate
12. Inspect actual logs
13. Compare actual vs expected
14. Identify false positives/negatives
15. Improve rule
16. Add regression cases
17. Freeze new rule version
18. Record metrics
19. Add validated result to corpus
```

---

# 52. Connector-Test Relationship

Each connector should have its own integration tests.

Example:

```text
NGINX
→ NGINX Connector Tests
→ canonical SecurityEvent
```

The rule tests then operate on canonical events.

This means a failure can be classified correctly.

For example:

```text
NGINX log parsed incorrectly
```

is a connector problem.

While:

```text
Correct SecurityEvent
but rule failed to detect behavior
```

is a detection-engine problem.

This separation makes debugging much faster.

---

# 53. Detection-Test Separation

Testing must distinguish:

### Connector Failure

Telemetry was not represented correctly.

### Normalization Failure

The event was mapped incorrectly.

### Detection Failure

The rule did not recognize the behavior.

### Correlation Failure

Related detections were not connected.

### Incident Failure

The correct detection did not become the correct investigation case.

### Routing Failure

The incident was routed incorrectly.

### Presentation Failure

The backend was correct but the UI showed incorrect/stale information.

This separation prevents teams from fixing the wrong component.

---

# 54. Efficiency Principles

The detection engine should be efficient through:

- source/event-type rule filtering
- bounded rule complexity
- bounded correlation windows
- indexed event access
- targeted correlation
- avoiding unnecessary duplicate processing
- caching immutable rule metadata where useful
- asynchronous processing where required
- idempotent event handling

Do not sacrifice correctness merely for speed.

---

# 55. Performance Measurement

Measure:

- event ingestion latency
- rule-evaluation latency
- correlation latency
- incident-creation latency
- report-generation latency
- queue/backlog where applicable
- throughput
- resource usage

Performance should be measured against realistic MVP workload rather than
arbitrary enterprise-scale targets.

---

# 56. Security of the Testing System

The testing environment is itself sensitive.

Protect:

- test infrastructure
- generated telemetry
- research corpus
- credentials
- attack-simulation tooling
- result datasets

Testing must remain isolated from production unless explicitly authorized.

---

# 57. Safety Boundary

All controlled attack simulation must remain:

- authorized
- isolated
- non-production
- reproducible
- logged
- resettable

Never use public or third-party infrastructure as an uncontrolled test
target.

The purpose is detection engineering, not unauthorized exploitation.

---

# 58. Research-to-Rule Governance

A research finding must not automatically become a production rule.

Required flow:

```text
Research Finding
      ↓
Candidate Behavior
      ↓
Telemetry Analysis
      ↓
Candidate Rule
      ↓
Testing
      ↓
Human Review
      ↓
Rule Approval
      ↓
Versioned Production Rule
```

---

# 59. Rule Approval States

Rules may conceptually have:

```text
DRAFT
TESTING
REVIEW
APPROVED
ENABLED
DISABLED
RETIRED
```

Only approved/enabled rules should participate in production detection.

---

# 60. Continuous Improvement Loop

The long-term ProShield improvement cycle is:

```text
                     RESEARCH
                        ↓
                  Threat Corpus
                        ↓
                Candidate Behavior
                        ↓
                 Safe Test Scenario
                        ↓
                 ProShield Testing
                        ↓
              ┌─────────┴─────────┐
              ↓                   ↓
          PASS / GOOD          FAILURE
              ↓                   ↓
        Rule Approved       Investigation
                                  ↓
                            Rule Improvement
                                  ↓
                            Regression Test
                                  ↓
                            New Rule Version
                                  ↓
                              Approved
```

This loop should continue throughout the product lifecycle.

---

# 61. What "Better Detection" Means

A better rule is not necessarily a rule that detects more activity.

A better rule should aim for:

```text
High useful detection
+
Low unnecessary noise
+
Strong evidence
+
Explainable reasoning
+
Acceptable latency
```

Increasing alert volume without improving analyst usefulness is not
progress.

---

# 62. Rule-Base Growth Principle

Do not optimize for:

```text
Number of rules
```

Optimize for:

```text
Useful detection coverage
+
precision
+
recall
+
correlation quality
+
analyst value
```

A smaller high-quality rule base is better than a huge noisy catalogue.

---

# 63. Threat-Corpus Growth Principle

Research breadth and production rule count must remain separate.

Example:

```text
1000 researched behaviors
        ↓
400 relevant behaviors
        ↓
200 observable in available telemetry
        ↓
120 useful detection opportunities
        ↓
60 validated rule families
        ↓
35 production-quality rules
```

These numbers are illustrative only.

The actual result must come from research and testing.

---

# 64. Future AI Dataset Lifecycle

When enough validated data exists:

```text
Validated Security Data
        ↓
Cleaning
        ↓
Deduplication
        ↓
Labeling
        ↓
Train / Validation / Test split
        ↓
Model experiment
        ↓
Baseline comparison
        ↓
Safety evaluation
        ↓
Human review
        ↓
Controlled deployment
```

The AI dataset must not be built merely from whatever logs happen to
exist.

---

# 65. Rule Engine as Baseline

Before AI deployment, the deterministic rule engine remains the baseline.

Every AI experiment should answer:

> Does the AI provide measurable improvement over ProShield's existing
> deterministic behavior?

If not, the AI should remain experimental rather than becoming production
critical infrastructure.

---

# 66. Future Hybrid Detection Architecture

The intended future architecture is:

```text
                 Security Events
                        ↓
                Canonical Pipeline
                        ↓
             Deterministic Rules
                        ↓
              Known Detections
                        ↓
              Correlation Engine
                        ↓
            ┌───────────┴───────────┐
            ↓                       ↓
      Known Behavior          AI Assistance
                               / Anomaly
                              / Similarity
                             / Investigation
            └───────────┬───────────┘
                        ↓
                    Incident
                        ↓
                 Human Analyst
```

AI adds intelligence.

It does not replace the trusted deterministic foundation.

---

# 67. Future AI Safety Requirements

Before AI enters a production security path, it must have:

- versioned model
- versioned dataset
- evaluation results
- clear limitations
- evidence references
- uncertainty handling
- human oversight
- rollback strategy
- monitoring
- failure isolation

AI failure must degrade gracefully.

---

# 68. Acceptance Criteria for Detection Engineering

The detection-engineering architecture is considered healthy when:

### DET-01

Connectors produce canonical SecurityEvents.

### DET-02

Rules are separated by source/purpose.

### DET-03

Rules contain explicit applicability metadata.

### DET-04

The rule engine does not evaluate irrelevant rules unnecessarily.

### DET-05

Correlation is handled centrally rather than by connector-to-connector
coupling.

### DET-06

Cross-source detection is supported.

### DET-07

Every Detection references its rule/version.

### DET-08

Every Detection references supporting evidence.

### DET-09

Positive tests exist.

### DET-10

Negative tests exist.

### DET-11

Edge-case tests exist.

### DET-12

False positives are measured.

### DET-13

False negatives are investigated.

### DET-14

Important rule improvements create new rule versions.

### DET-15

Research findings are verified before becoming production rules.

### DET-16

Safe simulation is supported.

### DET-17

Controlled real-lab testing is supported where appropriate.

### DET-18

Unknown behavior remains possible.

### DET-19

The deterministic engine does not depend on AI.

### DET-20

Future AI can consume validated datasets without replacing the baseline.

---

# 69. What Must Never Happen

ProShield must not become:

```text
One giant rule file
```

or:

```text
Every attack = one rule
```

or:

```text
Every event = every rule
```

or:

```text
Connector A directly calls Connector B logic
```

or:

```text
AI says malicious
→ system automatically trusts it
```

or:

```text
Large number of rules
→ assumed to mean good detection
```

or:

```text
Raw logs
→ automatically treated as labeled AI training data
```

---

# 70. Final Architecture Principle

The long-term ProShield detection strategy is:

```text
CONNECTORS
→ collect and normalize telemetry

RULES
→ detect known observable behaviors

CORRELATION
→ combine evidence across relevant controls

INCIDENT ENGINE
→ turn meaningful activity into investigation cases

TESTING
→ continuously challenge detection quality

RESEARCH
→ continuously discover new behaviors

AI
→ eventually assist with broader pattern discovery and investigation
```

The most important principle is:

> **ProShield should continuously learn from validated security research
> and testing without making its core security decisions dependent on an
> opaque model.**

The ultimate goal is not:

> "Have the most rules."

The ultimate goal is:

> **Detect more useful security behavior, with less noise, stronger
> evidence, better correlation, and better analyst routing — and keep
> improving that capability as new evidence becomes available.**

## 71. Backend-First Product Architecture

ProShield is fundamentally a backend security-intelligence platform.

The frontend dashboard, analyst interface, and administrator/operator
interface are supporting interfaces for:

- viewing security state
- investigating incidents
- reviewing evidence
- reviewing reports
- reviewing routing
- managing authorized configuration
- evaluating the behavior of the backend

The frontend is NOT the core product.

The backend is responsible for:

- receiving security telemetry
- validating events
- normalizing events
- executing detection rules
- correlating security signals
- constructing investigation timelines
- calculating preliminary severity
- calculating confidence
- creating incidents
- generating reports
- generating routing recommendations
- maintaining audit history
- protecting all security decisions
- exposing controlled APIs

The frontend must never become the source of truth for these decisions.

---

## 72. Product Core vs Evaluation Interface

The product should be thought of as:

```text
PROSHIELD CORE
────────────────────────────────────

Security Sources
      ↓
Connectors
      ↓
Canonical SecurityEvents
      ↓
Detection Engine
      ↓
Correlation Engine
      ↓
Timeline
      ↓
Severity + Confidence
      ↓
Incident
      ↓
Report
      ↓
Routing
      ↓
Audit


EVALUATION / OPERATIONS INTERFACE
────────────────────────────────────

Frontend Dashboard
        ↓
Reads backend state
        ↓
Displays evidence
        ↓
Displays incidents
        ↓
Displays recommendations
        ↓
Allows authorized human actions
```

The interface exists to operate and evaluate ProShield.

It does not implement the core security intelligence.

---

## 73. Backend as the Source of Truth

The backend is authoritative for:

- SecurityEvents
- Detections
- Correlations
- Timelines
- Incident state
- Severity
- Confidence
- Reports
- Routing recommendations
- Rules
- Routing policies
- Audit history
- Authorization
- Configuration

The frontend may display these values.

It must not create authoritative versions of them.

For example:

```text
Frontend:
"Severity = HIGH"

Backend:
"Current severity = MEDIUM"
```

The backend remains authoritative.

The frontend must display the backend result.

---

## 74. Frontend Security Boundary

The frontend is untrusted.

Never rely on:

- hidden buttons
- disabled controls
- frontend route protection
- frontend role variables
- frontend state
- frontend validation

for security.

Example:

```text
Frontend hides:
[Edit Rule]

Attacker manually calls:
PUT /api/v1/rules/...

Backend:
authorization check
→ DENY
```

Security must always be enforced server-side.

---

## 75. Full Backend Layer Model

The backend is logically divided into:

```text
1. API Layer
2. Authentication / Authorization
3. Application Services
4. Security Processing Core
5. Connectors
6. Rule System
7. Correlation System
8. Incident / Report / Routing Services
9. Repository / Persistence Layer
10. MongoDB
11. Audit / Observability
12. Configuration / Secrets
```

These boundaries exist to keep the backend maintainable and testable.

---

## 76. API Layer

The API layer is the external boundary of ProShield.

Responsibilities:

- receive HTTP requests
- authenticate callers
- authorize operations
- validate requests
- serialize responses
- enforce pagination limits
- enforce filter/sort restrictions
- enforce request size limits
- apply rate limiting
- return safe errors
- generate/carry request IDs

The API layer should NOT contain:

- WAF detection logic
- NGINX detection logic
- correlation logic
- incident reasoning
- routing reasoning

Those belong in backend services.

---

## 77. Authentication and Authorization Layer

This layer determines:

```text
WHO is calling?
        ↓
WHAT are they allowed to do?
```

It protects:

- APIs
- incidents
- evidence
- rules
- routing policies
- configuration
- audit
- administrative functions

It must enforce:

- authentication
- RBAC
- object-level authorization
- service identity
- least privilege

---

## 78. Application Service Layer

Application services coordinate business workflows.

Examples:

```text
EventIngestionService
IncidentService
ReportService
RoutingService
RuleManagementService
AuditService
ConfigurationService
```

A service should coordinate domain operations.

Example:

```text
API
 ↓
IncidentService
 ↓
Incident domain operation
 ↓
Repository
 ↓
MongoDB
```

API endpoints should not contain large amounts of database or business
logic.

---

## 79. Security Processing Core

The security processing core is the heart of ProShield.

It contains:

```text
Event Validation
      ↓
Normalization
      ↓
Rule Selection
      ↓
Rule Evaluation
      ↓
Detection
      ↓
Correlation
      ↓
Timeline Construction
      ↓
Severity / Confidence
      ↓
Incident Creation / Update
```

This core must be:

- deterministic for deterministic rules
- testable
- source-independent
- explainable
- evidence-backed

---

## 80. Connector Architecture

A connector converts source-specific telemetry into canonical
`SecurityEvent` objects.

Initial connectors may include:

```text
Simulator
WAF / Cezara
NGINX
IAM
Rate Limiter
TLS / Network
Future SIEM
Future Endpoint
```

Each connector is responsible for:

- source-specific ingestion
- source parsing
- source validation
- source authentication where required
- normalization
- provenance preservation
- creation of canonical SecurityEvents

---

## 81. Connector Responsibility Boundary

A connector asks:

> "What did this source observe?"

A ProShield detection rule asks:

> "Does this observed behavior represent a security condition we should
> detect?"

A correlation rule asks:

> "Are these signals related?"

An incident service asks:

> "Should this activity become an investigation case?"

A routing engine asks:

> "What investigation destination is appropriate?"

These responsibilities must not be mixed.

---

## 82. Source Security Controls vs ProShield

External security controls may already have their own security rules.

Examples:

```text
WAF
NGINX
IAM
Rate Limiter
```

Their rules may:

- block traffic
- allow traffic
- rate-limit traffic
- flag authentication activity
- generate alerts
- generate logs

ProShield does not need to duplicate every one of their rules.

Instead:

```text
Security Control
      ↓
Telemetry / Alert
      ↓
Connector
      ↓
SecurityEvent
      ↓
ProShield Detection / Correlation
```

This separation is a core architectural principle.

---

## 83. Rule Architecture

ProShield rules are separate from connectors.

Rules are organized by purpose/source.

Conceptual structure:

```text
rules/
├── common/
├── waf/
├── nginx/
├── iam/
├── rate_limit/
├── network/
└── correlation/
```

The exact filesystem may evolve, but the logical separation must remain.

---

## 84. Common Rules

Common rules operate on normalized fields that are independent of one
specific vendor.

Example:

```text
5 authentication failures
from the same source
within a defined time window
```

The rule can operate regardless of which supported authentication source
produced the canonical event.

Common rules should not contain vendor-specific parsing logic.

---

## 85. Source-Specific Rules

Source-specific rules operate on telemetry that has meaningful semantics
for one source category.

Examples:

```text
WAF rule
NGINX rule
IAM rule
Rate-limit rule
TLS rule
```

Example:

```text
WAF Connector
      ↓
SecurityEvent
      ↓
WAF Rule
      ↓
Detection
```

The same principle applies to the other source categories.

---

## 86. Correlation Rules

Correlation rules intentionally combine signals.

Example:

```text
WAF Detection
+
NGINX abnormal request volume
+
Rate-Limit violation
+
same source
+
same target
+
same time window
```

This may produce:

```text
High-confidence correlated web-abuse activity
```

Correlation rules live separately from source-specific rules.

---

## 87. Rules Must Not Directly Call Other Connector Rules

DO NOT build:

```text
WAF rule
 ↓
calls NGINX rule
 ↓
calls IAM rule
```

This creates tight coupling.

Instead:

```text
WAF
 ↓
Detection

NGINX
 ↓
Detection

IAM
 ↓
Detection

      ↓

Shared Correlation Engine
      ↓
Correlation Rule
```

The shared correlation layer is responsible for combining signals.

---

## 88. Rule Registry

The backend maintains one authoritative Rule Registry.

The registry answers:

> "Which rules are approved and available to the runtime engine?"

Conceptually:

```text
RULE_REGISTRY
├── WAF-001
├── WAF-002
├── NGINX-001
├── IAM-001
├── RATE-001
├── CORR-WEB-001
└── ...
```

Registry metadata should include:

- rule ID
- version
- source/category
- applicable event types
- rule type
- status
- enabled/disabled state

The registry does not duplicate all rule implementation logic.

---

## 89. Candidate Rules vs Production Rules

Experimental rules must be separated from approved rules.

Conceptually:

```text
rules/
├── waf/
│   ├── candidate/
│   ├── approved/
│   └── tests/
│
├── nginx/
│   ├── candidate/
│   ├── approved/
│   └── tests/
│
├── iam/
│   ├── candidate/
│   ├── approved/
│   └── tests/
│
└── correlation/
    ├── candidate/
    ├── approved/
    └── tests/
```

The exact filesystem structure is an implementation detail.

The mandatory principle is:

```text
Candidate
→ Testing
→ Review
→ Approved
→ Registry
→ Enabled
```

Experimental rules must not silently enter production execution.

---

## 90. Rule Execution Filtering

The engine must not unnecessarily evaluate every rule against every
event.

Each rule should provide applicability metadata.

Example:

```yaml
id: WAF-001
sources:
  - waf

event_types:
  - waf_attack_detected
```

When a WAF event arrives:

```text
WAF event
   ↓
source/event-type filtering
   ↓
WAF-compatible rules
   ↓
rule evaluation
```

This improves:

- performance
- latency
- correctness
- maintainability

---

## 91. Correlation Execution Filtering

Correlation rules should also declare required signals.

Example:

```yaml
id: CORR-WEB-001

required_sources:
  - waf
  - nginx
  - rate_limiter

window:
  seconds: 120
```

The correlation engine should evaluate the rule only when its required
signals are available or when the configured correlation state indicates
that evaluation is appropriate.

---

## 92. Detection Engine

The Detection Engine receives canonical SecurityEvents.

Its basic process is:

```text
SecurityEvent
      ↓
Rule applicability
      ↓
Rule evaluation
      ↓
Rule matched?
   ┌────┴────┐
   │         │
 NO        YES
   │         │
ignore       ↓
          Detection
```

A Detection must retain:

- detection ID
- rule ID
- rule version
- timestamp
- category
- evidence references
- reasoning
- severity/confidence contribution

---

## 93. Correlation Engine

The Correlation Engine receives:

- SecurityEvents
- Detections
- relevant metadata

It determines whether defined signals are related.

The engine should support factors such as:

- source
- source IP
- destination
- endpoint
- account
- device
- asset
- time window
- sequence
- event type
- detection type
- repeated behavior

Correlation must preserve the evidence that established the relationship.

---

## 94. Timeline Engine

The Timeline Engine converts evidence and derived activity into an ordered
investigation timeline.

It must support:

```text
observed event
detection
correlation
derived activity
```

Every timeline entry must remain traceable.

A timeline must never invent activity merely to create a more complete
story.

---

## 95. Severity and Confidence Engine

Severity and confidence are derived independently.

Example:

```text
Severity = HIGH
Confidence = MEDIUM
```

The engine may consider:

- attack category
- evidence strength
- number of signals
- correlation strength
- affected asset
- business criticality
- potential impact
- investigation complexity

The exact policy is governed by the relevant rules/policies.

---

## 96. Incident Engine

The Incident Engine transforms meaningful detection/correlation results
into investigation cases.

Conceptually:

```text
Detections
   +
Correlations
   +
Evidence
   ↓
Incident
```

An Incident may contain references to:

- SecurityEvents
- Detections
- Correlations
- TimelineEvents
- Evidence
- Report
- RoutingRecommendation

The Incident is the central investigation object.

---

## 97. Report Engine

The Report Engine generates the analyst-ready early investigation report.

The report must clearly separate:

```text
Observed Facts
Derived Conclusions
Recommendations
```

The report is generated from authoritative incident/evidence state.

The frontend does not author the authoritative report.

---

## 98. Routing Engine

The Routing Engine consumes the Incident and RoutingPolicy.

It produces:

```text
Analyst Level
+
Required Skill
+
Team
+
Queue
+
Reason
```

The routing engine does not invent analyst workload or availability.

It uses only authorized information.

---

## 99. Audit Service

The Audit Service records important system and human actions.

Examples:

- rule creation
- rule update
- rule enable/disable
- routing policy update
- severity override
- classification override
- routing override
- incident state changes
- privileged configuration changes
- administrative actions

Audit history remains separate from SecurityEvents.

---

## 100. Repository Layer

All persistent data access should be centralized through repository/data
access components.

Example:

```text
IncidentService
      ↓
IncidentRepository
      ↓
MongoDB
```

Avoid scattered database queries throughout the application.

Repositories provide:

- read operations
- write operations
- controlled updates
- query logic
- persistence mapping
- index-aware access

---

## 101. MongoDB Collections

Initial logical collections:

```text
security_events
detections
correlations
timeline_events
incidents
reports
rules
routing_policies
routing_recommendations
audit_events
```

Each collection represents a meaningful domain or lifecycle boundary.

MongoDB should not contain one giant document representing the entire
ProShield system.

---

## 102. MongoDB References

Major domain objects should reference each other by stable IDs where
appropriate.

Example:

```text
Incident
├── event_ids
├── detection_ids
├── correlation_ids
├── timeline_event_ids
└── routing_recommendation_id
```

This prevents unnecessary duplication of authoritative evidence.

---

## 103. MongoDB Embedding

Small information that naturally belongs to one object may be embedded.

For example, a RoutingRecommendation may contain:

```text
level
skill
team
queue
reason
```

while still referencing:

```text
routing_policy_id
routing_policy_version
```

Use embedding where it improves clarity and lifecycle management.

Do not embed entire unrelated domain objects unnecessarily.

---

## 104. Backend Models

Backend domain models should represent:

- SecurityEvent
- Rule
- Detection
- Correlation
- TimelineEvent
- Incident
- Report
- RoutingPolicy
- RoutingRecommendation
- AuditEvent

They should remain separate from:

```text
HTTP request models
MongoDB persistence models
frontend models
```

when that separation is useful.

---

## 105. Configuration Layer

The configuration layer controls:

- MongoDB connection
- authentication
- authorization
- CORS
- request limits
- event limits
- rate limits
- retention
- collector settings
- rule settings
- routing settings
- environment behavior

Configuration must be validated before becoming active.

---

## 106. Security Layer

The security layer contains:

- authentication
- authorization
- RBAC
- token/session verification
- security middleware
- secret access
- security policy enforcement

Security checks must be centralized enough to remain consistent.

---

## 107. Observability

Operational observability must support:

- service health
- event ingestion rate
- processing latency
- error rate
- collector health
- rule evaluation failures
- correlation failures
- dependency health
- backlog where applicable
- security telemetry gaps

Operational logs do not replace AuditEvents.

---

## 108. Failure Isolation

Backend components must fail safely.

Examples:

```text
Connector failure
→ connector telemetry gap is visible
→ other connectors continue when possible
```

```text
Rule failure
→ rule failure is isolated/logged
→ unrelated rules continue
```

```text
Report failure
→ incident remains available
```

```text
Routing failure
→ incident remains available
→ routing failure visible
```

```text
AI failure
→ deterministic detection remains operational
```

---

## 109. Backend Test Architecture

Testing must mirror backend boundaries.

```text
Connector Tests
       ↓
SecurityEvent Tests

Rule Tests
       ↓
Detection Tests

Correlation Tests
       ↓
Correlation Tests

Incident Tests
       ↓
Incident Workflow Tests

Routing Tests
       ↓
Routing Tests

Integration Tests
       ↓
Full Backend Pipeline
```

This allows failures to be isolated to the correct component.

---

## 110. Connector-Independent Testing

Each connector must first be tested independently.

Example:

```text
WAF Connector
     ↓
WAF SecurityEvent
     ↓
WAF Rules
     ↓
Expected Detection
```

This test should not require NGINX or IAM.

Likewise:

```text
NGINX Connector
     ↓
NGINX SecurityEvent
     ↓
NGINX Rules
```

This isolates integration failures from detection failures.

---

## 111. Cross-Connector Testing

Only after connector-specific detection works should cross-connector
correlation be tested.

Example:

```text
WAF Detection
+
NGINX Detection
+
Rate-Limit Detection
        ↓
Correlation Engine
        ↓
Correlation Rule
        ↓
Expected correlated activity
```

This creates a clean test hierarchy:

```text
Source correctness
→ Detection correctness
→ Correlation correctness
→ Incident correctness
→ Routing correctness
```

---

## 112. End-to-End Backend Test

The complete backend flow is:

```text
Security Source
      ↓
Connector
      ↓
Canonical SecurityEvent
      ↓
Relevant Rules
      ↓
Detection
      ↓
Correlation
      ↓
Timeline
      ↓
Severity + Confidence
      ↓
Incident
      ↓
Report
      ↓
Routing
      ↓
Audit
```

An end-to-end test should verify the complete chain using controlled
events.

---

## 113. Rule Development and Testing Loop

The development loop is:

```text
Research
  ↓
Understand behavior
  ↓
Identify observable signals
  ↓
Map to connector/source
  ↓
Create candidate rule
  ↓
Positive tests
  ↓
Negative tests
  ↓
Edge cases
  ↓
Controlled lab validation where appropriate
  ↓
False-positive / false-negative analysis
  ↓
Improve
  ↓
Regression tests
  ↓
Approve
  ↓
Registry
```

This is the primary mechanism by which the ProShield detection catalogue
improves.

---

## 114. Frontend's Role in Evaluation

The dashboard/operator panel is primarily used for:

- visual validation
- incident investigation
- evidence inspection
- report inspection
- routing inspection
- rule administration where authorized
- system-health visibility

The dashboard should not contain hidden detection logic that is absent
from the backend.

If the backend API says:

```text
Severity = HIGH
```

the frontend displays it.

It does not calculate its own different severity.

---

## 115. Operator Panel as Backend Evaluation Tool

The operator/admin interface should be considered a **window into the
backend**, not the backend itself.

It should allow a reviewer to observe:

```text
Events
Detections
Correlations
Incidents
Timelines
Reports
Routing
Rules
Audit
System Health
```

This makes the dashboard valuable for evaluating whether the backend
actually behaves correctly.

---

## 116. Backend-First Development Priority

Development effort should prioritize:

```text
1. Security foundation
2. Data/contracts
3. Connectors
4. Event ingestion
5. Detection engine
6. Rule system
7. Correlation
8. Incident management
9. Report generation
10. Routing
11. Audit/observability
12. Frontend
```

The frontend is intentionally not the majority of the engineering effort.

---

## 117. Why Backend-First Is Important

ProShield's core value is not:

```text
A dashboard showing alerts
```

Its core value is:

```text
Fragmented telemetry
      ↓
contextualized security intelligence
      ↓
investigation-ready incident
      ↓
correct routing
```

Therefore backend correctness has priority over visual complexity.

---

## 118. Backend Upgradeability

The architecture must make these changes relatively isolated:

### New connector

Add:

```text
connector
+
mapping
+
tests
```

without rewriting the core detection engine.

### New source-specific rule

Add:

```text
rule
+
tests
+
registry entry
```

without rewriting the connector.

### New correlation rule

Add:

```text
correlation rule
+
tests
```

without rewriting source connectors.

### New report field

Update report contract/service without changing detection logic.

### New routing policy

Update routing policy without rewriting event collection.

---

## 119. Backend Debugging Principle

When a detection test fails, determine WHICH layer failed.

Possible categories:

```text
Connector failure
Normalization failure
Validation failure
Rule-selection failure
Rule-evaluation failure
Correlation failure
Timeline failure
Severity failure
Incident failure
Report failure
Routing failure
Persistence failure
API failure
Frontend presentation failure
```

Do not immediately change the rule when the real problem is the connector.

Do not change the frontend when the backend response is wrong.

Do not change the backend when the backend is correct but the UI state is
stale.

---

## 120. Backend Observability for Debugging

The backend should make it possible to trace:

```text
event_id
    ↓
detection_id
    ↓
correlation_id
    ↓
incident_id
    ↓
report_id
    ↓
routing_recommendation_id
```

This allows engineers to reconstruct why a result exists.

Request IDs should also connect API requests to backend diagnostics.

---

## 121. Backend Performance Strategy

The MVP backend should be efficient through:

- applicable-rule filtering
- bounded rule complexity
- bounded correlation windows
- indexed MongoDB queries
- targeted correlation
- bounded payloads
- controlled concurrency
- idempotent processing
- asynchronous processing where justified

Do not introduce Kafka, RabbitMQ, Kubernetes, or distributed infrastructure
merely for theoretical scale.

Infrastructure must follow actual requirements.

---

## 122. Backend Security Strategy

Every backend layer must follow:

```text
Authenticate
→ Authorize
→ Validate
→ Process
→ Persist
→ Audit
```

No layer may bypass these controls simply because a request originated from
another internal component.

---

## 123. Future Real Source Integration

When NGINX/WAF/IAM/network/SIEM connectors are added, each must satisfy:

```text
Source
 ↓
Authenticated Connector
 ↓
Validated Source Data
 ↓
Canonical SecurityEvent
 ↓
Existing ProShield Pipeline
```

A new source should not create a second detection architecture.

It joins the existing one.

---

## 124. Future AI Boundary

Future AI should enter through an isolated backend service.

Conceptually:

```text
Canonical Events
      ↓
Deterministic Detection
      ↓
Validated Data
      ↓
AI Assistance Service
      ↓
Additional Insight
      ↓
Human Analyst
```

AI may assist with:

- anomaly detection
- pattern discovery
- correlation suggestions
- investigation
- report enrichment
- alert prioritization

AI must not bypass:

- authentication
- authorization
- evidence integrity
- audit
- deterministic baseline detection

---

## 125. AI Must Not Become the Detection Authority Automatically

The initial production rule remains:

```text
Rules = deterministic baseline
AI = additional intelligence
Human = final judgment
```

An AI result must not automatically become:

```text
confirmed attack
```

without the appropriate evidence and workflow.

---

## 126. Future Training Dataset

The ProShield testing system can eventually produce a valuable labeled
dataset.

A useful record may contain:

```text
Event sequence
Source
Telemetry type
Known behavior
Rule used
ProShield result
Expected result
Human/validated label
False-positive status
False-negative status
Context
```

Raw logs alone are not sufficient.

---

## 127. Future AI Evaluation

AI should be introduced only after a sufficiently validated dataset exists.

The AI system must be compared against the deterministic baseline.

Measure:

- precision
- recall
- false-positive rate
- false-negative rate
- latency
- explainability
- analyst usefulness
- operational cost

If AI does not materially improve a defined task, it should remain
experimental rather than replacing the deterministic baseline.

---

## 128. Zero-Day / Unknown Behavior Boundary

ProShield must not claim:

```text
Detects every future zero-day
```

Instead, ProShield should evaluate:

- unknown behavior
- behavioral variations
- unusual sequences
- deviations from known patterns
- combinations not represented in current rules

Unknown activity should remain distinguishable from confirmed malicious
activity.

---

## 129. Pre-Readiness Detection Testing

Future readiness testing should:

```text
Known behavior
      ↓
Controlled variation
      ↓
Isolated testing
      ↓
Existing ProShield rules
      ↓
Find blind spots
      ↓
Improve rules
      ↓
Regression
```

This helps prepare ProShield for variations of known behavior.

It does not guarantee detection of future unknown attacks.

---

## 130. Backend Architecture Quality Rule

A backend design should be reconsidered if it causes:

- connector-to-connector coupling
- one giant rule file
- one giant incident document
- direct database access from every API endpoint
- frontend-owned security logic
- AI-dependent core detection
- untestable detection logic
- unversioned rules
- untraceable evidence
- hidden failures
- uncontrolled rule execution
- unnecessary infrastructure complexity

---

## 131. Final Backend Architecture

The complete ProShield backend should be understood as:

```text
                   SECURITY SOURCES
                         ↓
                  ┌──────────────┐
                  │  CONNECTORS  │
                  └──────┬───────┘
                         ↓
                 CANONICAL EVENTS
                         ↓
                 VALIDATION / MAP
                         ↓
                  RULE SELECTION
                         ↓
                 RULE EVALUATION
                         ↓
                    DETECTIONS
                         ↓
                CORRELATION ENGINE
                         ↓
                      TIMELINE
                         ↓
                SEVERITY / CONFIDENCE
                         ↓
                     INCIDENT
                         ↓
                      REPORT
                         ↓
                     ROUTING
                         ↓
                       AUDIT
                         ↓
                     MONGODB
```

Across the entire architecture:

```text
Authentication
Authorization
RBAC
Secrets
Configuration
Input validation
Rate limiting
Observability
Failure handling
Security testing
```

The frontend/operator dashboard sits outside the core intelligence path:

```text
                         PROSHIELD BACKEND
                               ↓
                         Authoritative APIs
                               ↓
                     FRONTEND / OPERATOR PANEL
```

The frontend displays and operates the backend.

It does not define the backend's security truth.

---

## 132. Final Backend Engineering Principle

ProShield should be built as:

```text
MODULAR
+
BACKEND-FIRST
+
SOURCE-INDEPENDENT
+
RULE-DRIVEN
+
CORRELATION-CAPABLE
+
EVIDENCE-TRACEABLE
+
TESTABLE
+
UPGRADABLE
```

The central engineering rule is:

> A new security source should require a connector, mapping, and tests —
> not a rewrite of the ProShield detection architecture.

The central detection rule is:

> A new threat behavior should first become a tested, evidence-backed
> candidate rule — not immediately become production logic.

The central product rule is:

> The backend is the product core; the frontend is the interface for using,
> observing, and evaluating that core.