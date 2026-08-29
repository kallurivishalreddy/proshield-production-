# ProShield — Security Test Plan

## 1. Purpose

This document defines how the ProShield secure foundation will be tested
before the project proceeds to the detection and incident-intelligence
phases.

The purpose is not simply to confirm that features work.

The purpose is to actively try to break the security assumptions established
in:

- `THREAT_MODEL.md`
- `SECURE_FOUNDATION.md`
- `AUTH_RBAC.md`
- `SECURITY_CONFIGURATION.md`
- `API_CONTRACTS.md`

Phase 3 is accepted only when ProShield demonstrates that its security
boundaries resist the defined attack and abuse cases.

The testing philosophy is:

```text
EXPECTED BEHAVIOR
        +
ADVERSARIAL TESTING
        +
NEGATIVE TESTING
        +
FAILURE TESTING
        +
REGRESSION TESTING
        =
SECURITY CONFIDENCE
```

A passing happy-path test is never sufficient to declare a security control
safe.

---

# 2. Security Testing Objectives

The Phase 3 test program must prove that:

1. unauthenticated users cannot access protected functionality
2. authenticated users cannot exceed their permissions
3. collectors cannot become users/admins
4. users cannot access unauthorized objects
5. clients cannot control authoritative security state
6. malformed events cannot enter trusted processing
7. oversized input cannot exhaust resources
8. replayed events do not create uncontrolled duplicate state
9. MongoDB access is protected
10. secrets remain protected
11. privileged configuration is protected
12. rule changes are controlled
13. routing-policy changes are controlled
14. audit history is protected
15. API abuse is controlled
16. secure errors do not leak internals
17. production configuration cannot silently run insecurely
18. critical failures do not produce false success
19. security controls remain intact after normal feature changes
20. no critical unresolved security defect remains

---

# 3. Testing Principles

## 3.1 Test the Security Boundary, Not Just the UI

A hidden button is not a security control.

Every security decision must be tested at the backend boundary.

---

## 3.2 Negative Tests Are Mandatory

For every privileged operation, test:

```text
valid actor
+
wrong actor
+
unauthenticated actor
+
forged identity
+
wrong role
+
malformed request
```

---

## 3.3 Attack the Assumptions

Testing should intentionally attempt:

- forged tokens
- forged roles
- forged event sources
- object-ID manipulation
- malformed JSON
- oversized input
- replay
- event flooding
- rule injection
- database injection
- configuration tampering
- privilege escalation

---

## 3.4 No Silent Failures

A failed security operation must not silently succeed.

Examples:

```text
Authorization denied
→ no state modification
```

```text
Database failure
→ no false successful write
```

```text
Invalid configuration
→ safe startup failure
```

---

# 4. Test Classification

Each security test receives one of four outcomes.

### PASS

Expected behavior is demonstrated.

### FAIL

Required security behavior is missing or incorrect.

### BLOCKED

The test could not run due to an external dependency or environment
problem.

A blocked test is NOT a pass.

### NOT APPLICABLE

The test is explicitly outside the current MVP scope and documented as
such.

---

# 5. Severity of Security Findings

Security findings are classified as:

## CRITICAL

Examples:

- authentication bypass
- authorization bypass
- arbitrary code execution
- unauthorized rule manipulation
- unauthorized database access
- audit destruction
- secret exposure enabling system compromise

A CRITICAL issue blocks the phase.

---

## HIGH

Examples:

- privilege escalation
- event-injection bypass
- major evidence manipulation
- serious rate-limit bypass
- sensitive data exposure
- major configuration bypass

A HIGH issue normally blocks the phase unless explicitly risk-accepted by
the security owner.

---

## MEDIUM

Examples:

- limited information disclosure
- incomplete abuse protection
- weaker-than-intended audit context
- non-critical authorization edge case

Must be fixed or explicitly risk-accepted.

---

## LOW

Examples:

- minor hardening issue
- limited diagnostic information leakage with low impact
- non-security-critical configuration weakness

May be tracked for later remediation.

---

# 6. Test Environment Requirements

Security testing should use:

- isolated test database
- test credentials
- synthetic events
- non-production secrets
- deterministic configuration
- controlled network environment
- dedicated test users
- dedicated collector identities

Never run destructive security tests against production.

---

# 7. Test Identity Set

The security test environment should contain at minimum:

```text
analyst_user
admin_user
collector_identity
service_identity
unauthorized_user
```

Where useful, create multiple analyst identities to test horizontal
authorization.

---

# 8. Authentication Test Suite

## AUTH-01 — Missing Token

### Attempt

Access a protected endpoint without authentication.

### Expected

```text
401 Unauthorized
```

No protected state is returned.

---

## AUTH-02 — Malformed Token

### Attempt

Provide an invalid token structure.

### Expected

Authentication fails.

No protected state is returned.

---

## AUTH-03 — Invalid Signature

### Attempt

Modify/tamper with a signed token.

### Expected

Authentication fails.

---

## AUTH-04 — Expired Token

### Attempt

Use an expired token.

### Expected

Authentication fails.

---

## AUTH-05 — Wrong Issuer/Audience

Where issuer/audience are configured:

### Attempt

Use a valid-looking token with incorrect issuer/audience.

### Expected

Authentication fails.

---

## AUTH-06 — Forged Role

### Attempt

Modify token/client state to claim:

```text
SECURITY_ADMIN
```

while authenticated as an analyst.

### Expected

Backend rejects the forged role.

---

## AUTH-07 — Token Leakage

### Attempt

Inspect:

- logs
- audit records
- API errors
- event details
- reports

after authentication.

### Expected

No token values are exposed.

---

# 9. Password Authentication Tests

If password-based authentication is used:

## AUTH-PWD-01

Plaintext passwords are never stored.

## AUTH-PWD-02

Password values never appear in logs.

## AUTH-PWD-03

Password values never appear in audit records.

## AUTH-PWD-04

Wrong password does not expose whether an account exists when the policy
requires generic failure.

## AUTH-PWD-05

Weak/invalid passwords follow the configured password policy.

## AUTH-PWD-06

Password authentication occurs only over protected transport in
production.

---

# 10. Authorization Test Suite

## RBAC-01 — Analyst Can Perform Analyst Operations

Verify:

- incident read
- evidence read
- timeline read
- report read
- routing read
- permitted workflow actions

Expected:

All explicitly allowed operations succeed.

---

## RBAC-02 — Analyst Cannot Modify Rules

Attempt:

```text
POST /api/v1/rules
```

as analyst.

Expected:

```text
403 Forbidden
```

No rule is created.

---

## RBAC-03 — Analyst Cannot Modify Routing Policies

Attempt routing-policy administration as analyst.

Expected:

Access denied.

No state change.

---

## RBAC-04 — Analyst Cannot Read Unrestricted Audit History

Attempt unrestricted audit access as analyst.

Expected:

Access denied unless the specific endpoint/policy permits limited access.

---

## RBAC-05 — Admin Can Perform Authorized Administrative Operations

Verify that authorized admin operations succeed.

Every privileged operation must still generate appropriate audit records.

---

# 11. Horizontal Authorization Tests

These are critical.

## HAUTH-01 — User A Cannot Access User B's Incident

### Setup

Create:

```text
Incident A → User A
Incident B → User B
```

### Attempt

User A requests Incident B.

### Expected

Access denied.

---

## HAUTH-02 — User A Cannot Access User B's Events

Attempt direct event access using another user's/object's ID.

Expected:

Access denied.

---

## HAUTH-03 — User A Cannot Access User B's Report

Expected:

Access denied.

---

## HAUTH-04 — ID Enumeration Does Not Grant Access

Change object identifiers repeatedly.

Expected:

Authorization remains enforced.

---

# 12. Vertical Privilege Tests

## VAUTH-01

Analyst attempts admin configuration.

Expected:

Denied.

## VAUTH-02

Collector attempts analyst operation.

Expected:

Denied.

## VAUTH-03

Collector attempts admin operation.

Expected:

Denied.

## VAUTH-04

Internal service attempts unrelated privileged operation.

Expected:

Denied according to service capability.

---

# 13. Collector Authentication Tests

## COL-01 — Valid Collector

Valid collector identity submits a valid event.

Expected:

Event accepted.

---

## COL-02 — Unknown Collector

Unrecognized collector attempts ingestion.

Expected:

Rejected.

---

## COL-03 — Forged Collector Identity

Attempt to alter source identity without valid authorization.

Expected:

Rejected or canonical source identity derived from authenticated collector
identity.

---

## COL-04 — Collector Attempts Rule Modification

Expected:

Denied.

---

## COL-05 — Collector Attempts Incident Modification

Expected:

Denied.

---

# 14. Input Validation Tests

## VAL-01 — Missing Required Field

Submit SecurityEvent without a required field.

Expected:

Validation failure.

No trusted event created.

---

## VAL-02 — Wrong Type

Example:

```json
{
  "event_type": 123
}
```

Expected:

Validation failure.

---

## VAL-03 — Invalid Timestamp

Use malformed timestamp.

Expected:

Validation failure.

---

## VAL-04 — Unsupported Event Type

Submit unsupported event type.

Expected:

Rejected according to canonical event policy.

---

## VAL-05 — Unknown Top-Level Fields

Submit unexpected top-level fields.

Expected:

Rejected unless explicitly permitted by the contract.

---

## VAL-06 — Malformed Nested Details

Submit invalid `details` structure.

Expected:

Rejected safely.

---

# 15. Oversized Input Tests

## SIZE-01 — Oversized Event

Submit event larger than configured limit.

Expected:

Rejected.

---

## SIZE-02 — Oversized Field

Submit a huge source IP/endpoint/description-like value.

Expected:

Rejected.

---

## SIZE-03 — Deeply Nested Payload

Attempt excessive JSON nesting.

Expected:

Rejected safely.

---

# 16. MongoDB Injection Tests

## DB-01 — Operator Injection

Attempt to inject MongoDB operators through API parameters or object
identifiers.

Example concept:

```text
{"$ne": null}
```

Expected:

Treated as data/invalid input, never executable query logic.

---

## DB-02 — Raw Query Injection

Attempt to pass database query syntax through filters.

Expected:

Rejected.

---

## DB-03 — Arbitrary Field Query

Attempt to access unsupported database fields.

Expected:

Rejected.

---

# 17. Event Injection Tests

## EVENT-01 — Fake Event

Submit fabricated security event as unauthorized source.

Expected:

Rejected.

---

## EVENT-02 — Authenticated But Malformed Event

Valid collector identity sends malformed event.

Expected:

Rejected by validation.

Collector authentication alone is not sufficient.

---

## EVENT-03 — Source Spoofing

Attempt to authenticate as one source while claiming to be another.

Expected:

Rejected or authoritative source identity overrides the spoofed value.

---

# 18. Replay and Duplicate Tests

## REPLAY-01 — Same Event Twice

Submit identical event twice.

Expected:

Duplicate handling prevents uncontrolled duplicate state.

---

## REPLAY-02 — Same Source Event ID

Submit same source event ID with identical content.

Expected:

Duplicate policy is applied.

---

## REPLAY-03 — Same Event ID With Different Content

Submit an existing event ID with different content.

Expected:

Conflict or rejection.

The event must not silently change.

---

# 19. Event Flooding Tests

## FLOOD-01 — High Request Rate

Send events faster than the configured ingestion rate.

Expected:

- rate limiting/backpressure/rejection activates
- system remains responsive
- legitimate security state is protected

---

## FLOOD-02 — Multiple Sources

Simulate multiple collectors producing excessive load.

Expected:

One noisy source cannot silently consume unlimited shared resources.

---

## FLOOD-03 — Large Event + High Volume

Combine large payloads with high event rate.

Expected:

System rejects or throttles safely.

---

# 20. Authentication Abuse Tests

## ABUSE-AUTH-01 — Repeated Failed Login

Attempt repeated invalid authentication.

Expected:

Rate limiting or configured abuse protection activates.

---

## ABUSE-AUTH-02 — Credential Enumeration

Test whether login behavior reveals account existence unnecessarily.

Expected:

Generic failure behavior where required by policy.

---

# 21. API Abuse Tests

## API-01 — Pagination Abuse

Attempt:

```text
limit=999999999
```

Expected:

Rejected or capped.

---

## API-02 — Negative Offset

Expected:

Validation failure.

---

## API-03 — Invalid Sort Field

Expected:

Rejected.

---

## API-04 — Arbitrary Sort Expression

Expected:

Rejected.

---

## API-05 — Arbitrary Filter Expression

Expected:

Rejected.

---

# 22. Rule Security Tests

## RULE-01 — Unauthorized Rule Creation

Analyst attempts to create rule.

Expected:

Denied.

---

## RULE-02 — Unauthorized Rule Modification

Analyst attempts to modify rule.

Expected:

Denied.

---

## RULE-03 — Executable Rule Payload

Attempt to submit executable code inside the rule definition.

Examples:

```text
Python
JavaScript
shell commands
dynamic expressions
```

Expected:

Rejected.

---

## RULE-04 — Excessively Complex Rule

Submit a rule that could create excessive computation.

Expected:

Rejected or bounded according to rule-complexity limits.

---

## RULE-05 — Rule Version Integrity

Create Rule V1, then V2.

Expected:

V1 remains identifiable.

Detection history identifies which version produced each detection.

---

## RULE-06 — Rule Disable Audit

Disable a rule.

Expected:

- action authorized
- rule state changes
- AuditEvent created

---

# 23. Routing Security Tests

## ROUTE-01 — Unauthorized Routing Policy Change

Analyst attempts to modify policy.

Expected:

Denied.

---

## ROUTE-02 — Routing Input Tampering

Client attempts to supply fake:

```text
severity
complexity
skill
business criticality
```

to force routing.

Expected:

Server derives or validates authoritative values.

---

## ROUTE-03 — Routing Override Authorization

Unauthorized user attempts routing override.

Expected:

Denied.

---

## ROUTE-04 — Valid Human Override

Authorized analyst performs routing override.

Expected:

- override succeeds
- original recommendation remains preserved
- actor recorded
- timestamp recorded
- AuditEvent generated

---

# 24. Incident Integrity Tests

## INC-01 — Unauthorized Incident Modification

Expected:

Denied.

---

## INC-02 — Unauthorized Severity Change

Expected:

Denied.

---

## INC-03 — Authorized Severity Override

Expected:

- change succeeds
- old value preserved where required
- new value stored
- reason stored
- AuditEvent generated

---

## INC-04 — Unauthorized Incident Deletion

Expected:

Denied.

---

# 25. Evidence Integrity Tests

## EVID-01 — Event Mutation Attempt

Attempt to modify historical SecurityEvent content through normal APIs.

Expected:

Denied.

---

## EVID-02 — Evidence Reference Integrity

Delete or alter a referenced event through unauthorized means.

Expected:

Denied.

---

## EVID-03 — Timeline Fabrication

Attempt to create a timeline item that does not reference actual evidence
or an explicit derived result.

Expected:

Rejected.

---

# 26. Audit Security Tests

## AUDIT-01 — Privileged Action Creates Audit Event

Perform:

- rule modification
- routing-policy modification
- severity override
- routing override

Expected:

AuditEvent exists.

---

## AUDIT-02 — Audit Record Cannot Be Silently Deleted

Normal application user attempts deletion.

Expected:

Denied.

---

## AUDIT-03 — Audit Record Cannot Be Silently Modified

Attempt direct modification through application interface.

Expected:

Denied.

---

## AUDIT-04 — Audit Does Not Contain Secrets

Inspect audit records.

Expected:

No:

- passwords
- tokens
- private keys
- database credentials

---

# 27. Secret Protection Tests

## SECRET-01

Search source repository for known secret values.

Expected:

No real secrets.

---

## SECRET-02

Inspect application logs.

Expected:

No secrets.

---

## SECRET-03

Inspect API responses.

Expected:

No secrets.

---

## SECRET-04

Inspect error responses.

Expected:

No secrets.

---

## SECRET-05

Inspect SecurityEvents.

Expected:

No authentication secrets.

---

## SECRET-06

Inspect Reports.

Expected:

No leaked credentials/tokens.

---

# 28. Production Configuration Tests

## CONFIG-01 — Missing Production Signing Key

Expected:

Application refuses to start safely.

---

## CONFIG-02 — Placeholder Production Secret

Expected:

Application refuses to start.

---

## CONFIG-03 — Debug Mode in Production

Expected:

Rejected or disabled.

---

## CONFIG-04 — Wildcard Privileged CORS

Expected:

Rejected or explicitly blocked by production policy.

---

## CONFIG-05 — Public MongoDB

Expected:

Deployment configuration check fails.

---

## CONFIG-06 — Audit Disabled

Expected:

If audit is mandatory, production startup or deployment validation fails.

---

# 29. Configuration Authorization Tests

## CONFIG-AUTH-01

Analyst attempts security configuration change.

Expected:

Denied.

---

## CONFIG-AUTH-02

Admin changes security configuration.

Expected:

- authorized
- validated
- audited

---

## CONFIG-AUTH-03

Invalid configuration import

Expected:

Rejected before activation.

---

## CONFIG-AUTH-04

Malicious configuration import

Attempt executable or unsupported configuration.

Expected:

Rejected.

---

# 30. CORS Tests

## CORS-01

Authorized frontend origin.

Expected:

Allowed.

## CORS-02

Unauthorized origin.

Expected:

Blocked.

## CORS-03

Credentialed cross-origin request from unauthorized origin.

Expected:

Blocked.

---

# 31. TLS Tests

For production-equivalent environments:

## TLS-01

HTTPS/API access works with valid certificate.

## TLS-02

Insecure plaintext access is rejected or redirected according to the
deployment policy.

## TLS-03

Certificate/key configuration is validated.

## TLS-04

Private key is never logged.

---

# 32. Secure Error Tests

## ERROR-01

Trigger controlled validation error.

Expected:

Safe error response.

---

## ERROR-02

Trigger unexpected internal error.

Expected:

- safe client response
- request ID
- protected diagnostic logging

---

## ERROR-03

Database error.

Expected:

No raw database details exposed.

---

## ERROR-04

Authentication error.

Expected:

No secret/token details exposed.

---

# 33. Dependency Security Tests

The build pipeline should run:

- dependency vulnerability scan
- package audit where appropriate
- outdated/high-risk dependency check
- test suite after dependency updates

Critical known vulnerabilities must be addressed before release unless
explicitly risk-accepted.

---

# 34. Service Isolation Tests

If services are separately deployed:

## SERVICE-01

Detection service attempts unauthorized rule modification.

Expected:

Denied.

## SERVICE-02

Collector service attempts incident modification.

Expected:

Denied.

## SERVICE-03

Report service attempts event mutation.

Expected:

Denied.

## SERVICE-04

Routing service attempts routing-policy modification.

Expected:

Denied unless explicitly authorized.

---

# 35. Failure-Handling Tests

## FAIL-01 — MongoDB Unavailable

Expected:

- API does not falsely report successful persistence
- safe error returned
- operational failure visible

---

## FAIL-02 — Authentication Service Failure

Expected:

Protected operations fail safely.

---

## FAIL-03 — Audit Failure

If an action requires mandatory auditing, the system must follow the
defined security policy rather than silently claiming the action was
successfully audited.

---

## FAIL-04 — Configuration Failure

Invalid security configuration causes safe failure.

---

## FAIL-05 — Dependency Timeout

Expected:

- bounded timeout
- safe failure
- no uncontrolled resource consumption

---

# 36. Regression Security Tests

Security tests must be run after changes to:

- authentication
- authorization
- API schemas
- MongoDB access
- configuration
- rules
- routing
- logging
- dependency versions

Security regressions are failures even when the feature itself appears
correct.

---

# 37. Automated Test Categories

The Phase 3 test suite should contain:

```text
Unit Tests
Integration Tests
API Security Tests
Authorization Tests
Database Security Tests
Configuration Tests
Negative Tests
Abuse Tests
Failure Tests
Regression Tests
```

Where practical, security tests should run automatically in CI.

---

# 38. Manual Security Verification

Some security tests require manual verification in addition to automated
tests.

Examples:

- browser session behavior
- cookie/token behavior
- CORS behavior
- TLS browser behavior
- administrative UI restrictions
- configuration/deployment verification
- secret-management integration

Manual verification must be recorded rather than treated as "probably
working."

---

# 39. Security Test Data

Security tests must use synthetic values.

Do not use:

- real credentials
- production tokens
- real customer data
- real private keys

Examples should use safe test values.

---

# 40. Evidence Required for a Passed Security Test

A test is not considered complete merely because the tester says:

> "It worked."

A meaningful security test should produce evidence such as:

- automated test result
- API response
- database assertion
- audit record
- log/metric evidence
- screenshot where visual verification matters
- deployment check output

The evidence should allow later review.

---

# 41. Regression Requirement

Every security defect discovered during development must result in:

1. root-cause analysis
2. fix
3. regression test
4. updated security-test evidence

The same vulnerability must not be allowed to return silently.

---

# 42. Security-Fix Review Rule

A security fix should not be considered complete until:

```text
Bug Found
   ↓
Root Cause
   ↓
Fix
   ↓
Targeted Regression Test
   ↓
Full Relevant Security Suite
   ↓
No Regression
```

---

# 43. Security Test Metrics

Track at minimum:

- total security tests
- passed
- failed
- blocked
- critical findings
- high findings
- medium findings
- low findings
- unresolved findings
- regression defects
- authentication failures tested
- authorization cases tested
- abuse scenarios tested

---

# 44. Phase 3 Security Gate

Phase 3 cannot be declared STABLE if any of the following remain unresolved:

- authentication bypass
- authorization bypass
- privilege escalation
- arbitrary rule-code execution
- unauthorized MongoDB access
- critical secret exposure
- silent audit destruction
- uncontrolled critical event injection
- critical data-integrity failure
- critical production configuration weakness

---

# 45. Risk Acceptance

A security issue may be accepted only when:

- severity is understood
- impact is documented
- exploitability is understood
- mitigation is documented
- owner is identified
- reason for acceptance is recorded
- follow-up is defined

"Not enough time" is not sufficient security justification.

---

# 46. Phase 3 Exit Criteria

Phase 3 passes only when:

### Authentication

All required authentication tests pass.

### Authorization

Role and object-level authorization tests pass.

### Event Security

Validation, injection, replay, and flooding tests pass.

### MongoDB

Database authentication/authorization and integrity tests pass.

### Secrets

No secret leakage is detected.

### Configuration

Production security configuration checks pass.

### Audit

Privileged security actions are auditable.

### Abuse Protection

High-risk endpoints have working protection.

### Failure Safety

Critical failure scenarios behave safely.

### Dependencies

No unresolved critical dependency security issue remains.

### Regression

The complete Phase 3 security regression suite passes.

---

# 47. Final Security Test Principle

The objective of Phase 3 security testing is not:

> "Prove that ProShield works when everything goes right."

The objective is:

> **"Prove that ProShield continues to protect its security boundaries
> when users, services, inputs, dependencies, and attackers do things they
> should not do."**

The test philosophy is:

```text
BUILD
  ↓
ATTACK
  ↓
OBSERVE
  ↓
FIX
  ↓
REGRESSION TEST
  ↓
RETEST
  ↓
STABILIZE
```

A secure ProShield foundation is one that has been **actively challenged,
not merely configured**.