# ProShield — Initial Security Events

## 1. Purpose

This document defines the initial simulated security events used to
develop and validate the first ProShield MVP.

These events are synthetic test inputs.

They are NOT real incidents, real customer data, or real attack evidence.

Their purpose is to provide realistic, deterministic inputs for testing:

Security Event
→ Validation
→ Normalization
→ Detection
→ Correlation
→ Timeline
→ Severity
→ Incident
→ Report
→ Analyst Routing

The first MVP must prove the core processing pipeline before real
security-product collectors are introduced.

---

# 2. Why Simulated Events Come First

ProShield must prove its core intelligence pipeline before spending time
integrating every external security source.

A simulated event source gives us:

- deterministic test cases
- repeatable attack scenarios
- controlled timestamps
- controlled relationships between events
- predictable expected results
- fast development
- easy regression testing

The core ProShield engine must treat these events exactly as it would treat
events later received from real security products.

---

# 3. Canonical SecurityEvent Principle

All simulated events must use the same conceptual canonical
`SecurityEvent` structure that future collectors will produce.

The simulated source must NOT create a special event format that only the
simulation engine understands.

Future collectors such as:

- NGINX
- WAF / Cezara
- rate limiting
- TLS/network security systems
- SIEM
- endpoint security
- IAM

must eventually convert their source-specific data into the same canonical
event model.

The core engine must therefore remain independent of any particular vendor
or source.

---

# 4. SecurityEvent Goals

A canonical security event should provide enough information for ProShield
to:

- identify the event
- understand when it occurred
- identify the source
- identify the relevant asset or target
- identify the source/client when available
- identify the event category/type
- preserve useful security metadata
- correlate it with other events
- trace a detection back to the original evidence

Events should contain observed information.

They should not contain invented conclusions such as:

"Attacker compromised the server."

That would be a derived conclusion, not a raw event.

---

# 5. Conceptual Event Fields

The final technical schema will be defined during the contracts/data-model
phase.

At the conceptual level, the canonical event should support:

- `event_id`
- `timestamp`
- `source`
- `event_type`
- `source_ip` when available
- `destination` or target when available
- `endpoint` when applicable
- `asset` when known
- `account` or identity when known
- source severity when provided by the originating system
- structured metadata/details
- source/provenance information

Additional fields may be introduced during the data-model phase if required.

The final schema must remain minimal enough for the MVP while supporting
detection, correlation, timeline construction, and auditability.

---

# 6. Initial Event Sources

The first source is:

**SIMULATED**

The simulated source represents events that could later come from:

1. NGINX
2. WAF / Cezara
3. Rate-limiting controls
4. TLS/network security controls

Future sources may include:

5. SIEM
6. Endpoint security
7. IAM

The simulator must therefore use source identifiers that can realistically
map to those future systems.

---

# 7. Initial Event Categories

The first MVP should use a small, controlled event catalogue.

The initial categories are:

1. Web application security events
2. Rate-limiting events
3. WAF detection events
4. Authentication/security-control events
5. TLS/network security events
6. Generic security-control events

The purpose is not to simulate every possible cyberattack.

The purpose is to provide enough realistic security telemetry to prove
ProShield's correlation and triage capabilities.

---

# 8. Event Type Catalogue

The following initial event types should be supported.

## 8.1 `waf_attack_detected`

Represents a WAF detecting a suspicious or blocked request pattern.

Example observed information:

- source IP
- destination host
- HTTP endpoint
- request method
- WAF rule identifier
- timestamp
- source product
- action taken

This event says that the WAF detected a security pattern.

It does not by itself prove that a successful attack occurred.

---

## 8.2 `request_blocked`

Represents a security control blocking a request.

Possible context:

- source IP
- endpoint
- HTTP method
- reason
- security-control source
- timestamp

This may later correlate with WAF or rate-limit activity.

---

## 8.3 `rate_limit_exceeded`

Represents a rate-limiting control detecting traffic above its configured
threshold.

Possible context:

- source IP
- endpoint
- threshold
- observed request count
- time window
- timestamp
- affected service

This event represents an observation from a rate-limiting control.

---

## 8.4 `suspicious_request`

Represents a security control identifying a request as suspicious based on
its configured criteria.

Possible context:

- source IP
- endpoint
- request metadata
- detection reason
- security-control source
- timestamp

This must not be treated as proof of a successful compromise.

---

## 8.5 `authentication_failure`

Represents a failed authentication attempt observed by a security control
or authentication service.

Possible context:

- source IP
- username/account identifier when available
- authentication service
- timestamp
- reason category

The event should never contain plaintext passwords or authentication
secrets.

---

## 8.6 `authentication_success`

Represents a successful authentication event.

Possible context:

- source IP
- account/user identifier
- authentication method
- timestamp
- service

This can be correlated with preceding failed attempts or other activity.

---

## 8.7 `tls_anomaly`

Represents a detected TLS/network-security anomaly.

Possible context:

- source
- destination
- connection metadata
- TLS-related observation
- timestamp
- affected asset

The simulator should record the observation, not assert an attack
conclusion.

---

## 8.8 `network_anomaly`

Represents a network security control identifying unusual network behavior.

Possible context:

- source
- destination
- protocol
- port
- asset
- observation
- timestamp

---

## 8.9 `security_control_alert`

Generic event type for a security control that produces a security finding
that does not yet fit a more specific event category.

This supports future collectors without forcing them to invent a new core
schema immediately.

---

# 9. Initial Simulated Scenarios

Individual events are useful, but ProShield's main value is correlation.

Therefore the simulator must support repeatable multi-event scenarios.

---

## Scenario S1 — Simple WAF Attack

Example sequence:

1. `waf_attack_detected`
2. additional related `request_blocked`

Expected result:

- detection created
- related events correlated
- timeline created
- preliminary severity calculated
- incident created
- early report generated
- routing recommendation produced

This proves the basic pipeline.

---

## Scenario S2 — Repeated Rate-Limit Abuse

Example sequence:

1. multiple requests from the same source
2. `rate_limit_exceeded`
3. additional related `request_blocked`

Correlation factors:

- same source
- same target/endpoint
- short time window
- repeated behavior

Expected result:

- one coherent detection/incident rather than many disconnected alerts
- evidence-backed timeline
- explainable severity
- routing recommendation

---

## Scenario S3 — WAF + NGINX Correlation

Example sequence:

1. `waf_attack_detected`
2. `request_blocked`
3. another related event from the same source
4. repeated access to the same endpoint

Expected result:

- events grouped by correlation
- one incident where appropriate
- timeline containing every supporting event
- report explains why the events were considered related

---

## Scenario S4 — Multi-Control Correlation

Example:

1. suspicious request
2. WAF detection
3. rate-limit threshold exceeded
4. repeated blocked requests

The purpose is to prove that ProShield can correlate multiple security
controls into one investigation unit.

This is an important MVP demonstration because the core product value is
turning fragmented events into one contextualized incident.

---

## Scenario S5 — Authentication Suspicious Activity

Example:

1. several `authentication_failure` events
2. successful authentication from the same source
3. additional suspicious activity

Expected result:

- events are correlated according to configured rules
- the report clearly separates observed activity from conclusions
- severity/confidence is explainable
- routing reflects the required expertise

---

## Scenario S6 — TLS / Network Anomaly

Example:

1. `tls_anomaly`
2. related `network_anomaly`
3. another event affecting the same destination/asset

Expected result:

- related events can be correlated
- timeline is created
- security category and routing are explainable

---

## Scenario S7 — Mixed/Complex Activity

This scenario combines several event categories affecting the same asset
within a defined time window.

Example:

WAF
+
NGINX
+
rate limiting
+
network event

Purpose:

- stress correlation
- produce a more complex timeline
- exercise severity/complexity logic
- demonstrate higher-level routing

---

# 10. Unknown / Unmatched Event Scenario

ProShield must also support events that do not match a known detection rule.

Example:

A new event type arrives that is valid and normalized but does not match
any current rule.

Expected behavior:

- preserve the event
- do not invent an attack
- do not fabricate a timeline
- do not claim a known incident category without evidence
- optionally classify the activity as unclassified/suspicious according to
  the defined MVP behavior
- make the event available for human review

This scenario is important because ProShield must be safe when its rules do
not understand something.

---

# 11. Evidence and Provenance

Every simulated event must have identifiable provenance.

At minimum, ProShield should know:

- which simulated source produced it
- which scenario generated it
- when it was generated
- its unique event identity

This information is for testing and auditability.

Production source adapters will later replace the simulator without changing
the canonical event model.

---

# 12. Event Relationships

The simulator should support relationships that allow the correlation
engine to reason about:

- same source
- same destination
- same endpoint
- same asset
- same user/account
- same event category
- repeated behavior
- time-window relationships
- known event sequences

These relationships should be explicit enough for deterministic testing.

---

# 13. Event Quality Rules

A simulated event must:

- be structurally valid
- contain a valid timestamp
- contain a unique event ID
- identify its source
- contain an appropriate event type
- preserve source information
- avoid fabricated conclusions
- avoid secrets
- remain deterministic when used in tests

---

# 14. Sensitive Data Rules

Simulated security events must never contain:

- real passwords
- private keys
- API keys
- production credentials
- customer secrets
- real personal data
- real security-system credentials

All identities, addresses, hostnames, and examples must be synthetic.

---

# 15. Rule Development Principle

The simulator is not the detection engine.

It provides inputs to the detection engine.

Correct architecture:

Simulated Source
→ Canonical SecurityEvent
→ Rule Engine

Incorrect architecture:

Simulator
→ directly creates "incident"

The incident must be produced by the same detection/correlation pipeline
that real collectors will eventually use.

---

# 16. Testability Requirement

Every initial scenario must be reproducible.

A test must be able to specify:

- scenario
- event sequence
- timestamps
- source
- expected detection
- expected correlation
- expected timeline
- expected severity range
- expected incident category
- expected routing result

This allows ProShield to measure accuracy and regression behavior without
depending on real external security systems.

---

# 17. Initial MVP Event Catalogue Summary

| Event Type | Primary Source Concept | Main Use |
|---|---|---|
| `waf_attack_detected` | WAF | Web attack detection |
| `request_blocked` | WAF/NGINX/security control | Correlation |
| `rate_limit_exceeded` | Rate limiter | Abuse/repetition detection |
| `suspicious_request` | WAF/security control | Rule input |
| `authentication_failure` | IAM/auth service | Authentication correlation |
| `authentication_success` | IAM/auth service | Sequence correlation |
| `tls_anomaly` | TLS/network security | Network correlation |
| `network_anomaly` | Network security | Network correlation |
| `security_control_alert` | Generic source | Future extensibility |

This catalogue is intentionally small.

New event types should be added only when a concrete MVP rule, collector, or
acceptance scenario requires them.

---

# 18. Phase 0 Boundary

This document defines the initial event concepts and simulated scenarios.

It does NOT finalize:

- the exact database schema
- exact API request/response models
- message-bus contracts
- final event-storage technology
- final rule-expression language
- collector implementation
- deployment architecture

Those belong to later architecture and contract phases.

---

# 19. Definition of Success

The initial simulated event system is successful when ProShield can
reproducibly demonstrate:

Simulated Security Event
→ Canonical SecurityEvent
→ Detection
→ Correlation
→ Evidence-backed Timeline
→ Severity + Confidence
→ Incident
→ Early Report
→ Explainable Routing

using the same core pipeline that will later accept real collector data.

The simulation must prove the product's core intelligence without becoming
a separate implementation path.