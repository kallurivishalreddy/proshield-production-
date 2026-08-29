# ProShield — Authentication and RBAC

## 1. Purpose

This document defines the authentication, authorization, and role-based
access-control model for the ProShield MVP.

The objective is to ensure that:

- only authenticated identities access protected functionality
- every protected operation is authorized
- users receive only the permissions required for their role
- internal services and collectors have explicit identities
- privileged security operations are protected
- object-level access is enforced server-side
- all important privileged actions are auditable

This document is derived from:

- `SECURE_FOUNDATION.md`
- `THREAT_MODEL.md`
- `MVP_REQUIREMENTS.md`
- `ROUTING_MATRIX.md`
- `API_CONTRACTS.md`

---

# 2. Authentication vs Authorization

These are separate controls.

## Authentication

Authentication answers:

> Who is this caller?

Examples:

- analyst user
- security administrator
- collector
- internal service

## Authorization

Authorization answers:

> What is this caller allowed to do?

A successfully authenticated user is not automatically authorized to perform
every operation.

---

# 3. Identity Classes

The MVP recognizes four logical identity classes:

```text
1. Security Analyst
2. Security Admin / Security Lead
3. Security Collector
4. Internal ProShield Service
```

Each identity class has different permissions.

---

# 4. Security Analyst

## Purpose

The Security Analyst is the primary operational user.

The analyst uses ProShield to:

- inspect incidents
- review evidence
- inspect detections
- inspect timelines
- read reports
- review routing recommendations
- perform authorized investigation workflow actions
- perform authorized human overrides

---

# 5. Security Analyst Permissions

The analyst may:

### Incidents

- list authorized incidents
- view incident details
- view incident evidence
- view incident timeline
- view detections associated with incidents
- view reports
- view routing recommendations
- update allowed workflow status
- provide authorized severity override
- provide authorized classification override
- provide authorized routing override

### Events

- view events that the analyst is authorized to investigate

The analyst does not automatically have unrestricted access to all raw
security telemetry.

### Audit

The analyst does not automatically have unrestricted audit-history access.

Limited audit information may be exposed through the incident workflow when
required.

---

# 6. Security Analyst Restrictions

A Security Analyst must NOT automatically be allowed to:

- create/modify detection rules
- enable/disable detection rules
- modify routing policies
- modify security configuration
- manage service credentials
- manage database credentials
- delete audit records
- bypass authorization
- impersonate another user
- directly modify stored SecurityEvent documents
- directly modify stored Detection documents
- directly manipulate ProShield internal state

The analyst interacts through authorized application workflows.

---

# 7. Security Admin / Security Lead

## Purpose

The Security Admin is a privileged operational role responsible for
security configuration and oversight.

The admin may:

- perform all permitted analyst operations
- manage rules
- manage routing policies
- manage approved security configuration
- inspect security audit history
- perform authorized administrative actions

---

# 8. Security Admin Permissions

### Incident Operations

Admin may:

- view incidents
- inspect evidence
- inspect detections
- inspect timelines
- inspect reports
- review routing
- override routing
- override preliminary severity
- override classification
- manage permitted incident workflows

### Rule Management

Admin may:

- create rules
- view rules
- update rules
- create new rule versions
- enable/disable rules
- retire rules according to policy

Every rule change must be audited.

### Routing Policy Management

Admin may:

- create routing policies
- update routing policies
- version routing policies
- enable/disable routing policies
- inspect routing policy history

Every policy change must be audited.

### Audit

Admin may:

- query authorized audit records
- filter audit history
- investigate privileged activity

Normal application operations must not allow administrators to silently
rewrite historical audit records.

---

# 9. Security Admin Restrictions

Even administrators must not automatically receive unrestricted ability to:

- bypass security validation
- inject arbitrary SecurityEvents
- execute arbitrary code through rules
- expose secrets
- directly modify database internals
- disable all security controls without audit
- perform unrestricted destructive response actions

Administrative power is still constrained by the security model.

---

# 10. Collector Identity

A collector is a source identity used to submit security telemetry.

Examples:

```text
simulator
nginx-adapter
waf-adapter
rate-limit-adapter
tls-adapter
network-adapter
```

The exact naming convention is implementation-defined but must be stable.

---

# 11. Collector Permissions

Collectors should have the minimum permissions required to:

- authenticate to the ingestion interface
- submit SecurityEvents
- identify their own source
- receive ingestion/validation responses

Collectors should NOT automatically be able to:

- read unrelated incidents
- modify incidents
- modify rules
- modify routing policies
- access audit administration
- change security configuration

A collector's ability to submit telemetry does not imply administrative
access.

---

# 12. Collector Trust Model

Collectors are not assumed to be fully trusted merely because they are
internal.

The ingestion boundary must still enforce:

- authentication
- validation
- payload limits
- source attribution
- abuse protection
- replay/duplicate controls

An authenticated collector may still send:

- malformed events
- incorrect data
- duplicated events
- excessive event volume

The ingestion layer must therefore validate the content independently.

---

# 13. Internal ProShield Services

Internal services are application identities.

Examples:

- event ingestion service
- normalization service
- rule engine
- correlation engine
- incident manager
- report generator
- routing engine
- audit service

Not every service must be independently deployed in the MVP.

The logical identity boundary still matters.

---

# 14. Internal Service Permissions

Services should use least privilege.

Examples:

### Ingestion Service

May:

- validate events
- persist accepted SecurityEvents
- publish/forward validated events

Should not:

- modify rules
- change routing policies
- override incident severity

### Rule Engine

May:

- read canonical SecurityEvents
- read enabled rules
- create Detections
- write detection-processing state

Should not:

- modify rules unless explicitly authorized through rule-management
  workflows
- perform administrative configuration changes

### Correlation Engine

May:

- read events
- read detections
- create/update correlation results

Should not:

- change source evidence

### Incident Manager

May:

- create incidents
- associate evidence
- manage incident workflow state according to policy

Should not:

- silently change detection rules

### Report Generator

May:

- read incident/evidence data
- generate reports
- store report results

Should not:

- modify underlying security evidence

### Routing Engine

May:

- read incident context
- read routing policies
- create routing recommendations

Should not:

- alter routing policy without explicit administrative authority

### Audit Service

May:

- create audit records

Should not provide ordinary callers with unrestricted deletion or
rewriting of historical audit data.

---

# 15. Role and Service Separation

The architecture must preserve the distinction:

```text
Human identity
≠
Collector identity
≠
Internal service identity
```

An internal service must not impersonate a human analyst.

A collector must not impersonate an administrator.

An analyst must not impersonate an internal service.

---

# 16. Object-Level Authorization

Role checks alone are insufficient.

ProShield must also validate whether the caller is authorized to access the
specific object.

Examples:

```text
GET /api/v1/incidents/{incident_id}
```

must verify that the caller may access that incident.

Similarly:

```text
GET /api/v1/events/{event_id}
```

must verify event visibility.

The system must never use:

```text
"knowing the ID = permission"
```

as an authorization mechanism.

---

# 17. Resource Authorization Rules

## SecurityEvent

Access according to:

- role
- investigation scope
- source/data sensitivity
- security policy

## Detection

Access according to authorized incident/investigation scope.

## Incident

Access only if the caller is authorized to view the incident.

## Report

Access only if the caller may view the corresponding incident.

## RoutingRecommendation

Access according to incident authorization and role.

## Rule

Read access may be broader than write access.

Write access is privileged.

## RoutingPolicy

Administrative access only.

## AuditEvent

Security Admin / Security Lead access unless a limited operational view is
explicitly provided.

---

# 18. Authorization Deny-by-Default

The authorization system must follow:

```text
No explicit permission
        ↓
DENY
```

Permissions must be positively granted.

Do not implement:

```text
ALLOW EVERYTHING
+
hide restricted UI buttons
```

Frontend visibility is not authorization.

---

# 19. Permission Naming

Permissions should be explicit enough to support clear policy.

Conceptual permissions include:

```text
incident:read
incident:update
incident:override_severity
incident:override_classification
incident:override_routing

event:read
event:ingest

detection:read

report:read
report:regenerate

rule:read
rule:create
rule:update
rule:enable
rule:disable

routing_policy:read
routing_policy:create
routing_policy:update

audit:read

configuration:read
configuration:update
```

The final permission implementation may use equivalent naming, but the
semantic separation must remain.

---

# 20. Role-to-Permission Matrix

The initial MVP baseline is:

| Permission | Analyst | Admin |
|---|---:|---:|
| incident:read | ✅ | ✅ |
| incident:update | ✅ | ✅ |
| incident:override_severity | ✅ | ✅ |
| incident:override_classification | ✅ | ✅ |
| incident:override_routing | ✅ | ✅ |
| event:read | ✅* | ✅ |
| event:ingest | ❌ | ❌ |
| detection:read | ✅ | ✅ |
| report:read | ✅ | ✅ |
| report:regenerate | ✅ | ✅ |
| rule:read | ✅ | ✅ |
| rule:create | ❌ | ✅ |
| rule:update | ❌ | ✅ |
| rule:enable | ❌ | ✅ |
| rule:disable | ❌ | ✅ |
| routing_policy:read | ✅ | ✅ |
| routing_policy:create | ❌ | ✅ |
| routing_policy:update | ❌ | ✅ |
| audit:read | ❌ | ✅ |
| configuration:read | ❌ | ✅ |
| configuration:update | ❌ | ✅ |

`event:read` remains subject to object/data-scope authorization.

This matrix is the initial MVP policy and may be refined when the actual
workflow/UI is implemented.

---

# 21. Permission Matrix for Collectors

| Capability | Collector |
|---|---:|
| event:ingest | ✅ |
| event:read | ❌ |
| detection:read | ❌ |
| incident:read | ❌ |
| report:read | ❌ |
| rule:read | ❌ |
| rule:update | ❌ |
| routing_policy:read | ❌ |
| routing_policy:update | ❌ |
| audit:read | ❌ |
| configuration:update | ❌ |

A collector should use a dedicated source identity and credentials.

---

# 22. Permission Matrix for Internal Services

Internal-service permissions are capability-based.

They should be granted only what the service requires.

Example:

| Service | Primary Permissions |
|---|---|
| Ingestion | event:ingest |
| Detection | event:read + detection:create |
| Correlation | event:read + detection:read + correlation:write |
| Incident Manager | incident:create/update |
| Report Generator | incident:read + report:write |
| Routing Engine | incident:read + routing_policy:read + routing_recommendation:write |
| Audit Service | audit:write |
| Rule Management | rule:read/create/update/status |

The exact implementation may use service scopes rather than literal
permission names.

---

# 23. Authentication Context

Every protected request should produce a trusted authentication context
containing at least:

- identity ID
- identity type
- role(s)
- authorized scopes/permissions
- authentication status

The application uses this server-side context for authorization.

The frontend must never be allowed to define its own role.

---

# 24. Identity Claims

If tokens contain identity claims, the backend must validate them.

Security-sensitive claims should include only values required for
authorization and identity.

Do not trust arbitrary client-provided claims.

The backend must verify:

- token integrity
- issuer where applicable
- audience where applicable
- expiration
- subject
- relevant role/scope information

The exact token contract belongs to the implementation/security phase.

---

# 25. Token Storage and Handling

The implementation must avoid exposing tokens unnecessarily.

Rules:

- tokens are never logged
- tokens are never written into audit records
- tokens are never included in SecurityEvent `details`
- tokens are never returned unnecessarily after authentication
- expired/invalid tokens are rejected

Browser storage strategy must be selected based on the final authentication
mechanism and threat model.

---

# 26. Password Requirements

If password-based authentication is used:

- passwords must never be stored plaintext
- passwords must never be logged
- passwords must be hashed with an appropriate password-hashing algorithm
- authentication failures should avoid unnecessary account enumeration
- password input must use secure transport in production

Exact password policy will be finalized in implementation.

---

# 27. Service Credentials

Each production collector/service should use separate credentials where
practical.

Do not reuse:

```text
one global secret
```

across every service.

Separate identities improve:

- least privilege
- auditability
- rotation
- compromise containment

---

# 28. Privileged Role Protection

Administrator credentials are highly sensitive.

Production should consider stronger protections such as:

- stronger authentication
- short session lifetime
- step-up authentication for critical changes
- detailed auditing

The exact controls depend on deployment requirements.

---

# 29. Session Security

Sessions/tokens must have controlled lifetime.

Requirements:

- expiration
- secure invalidation strategy where applicable
- no indefinite privileged sessions
- secure logout behavior
- reauthentication where required for high-impact actions

---

# 30. Failed Authentication and Authorization

Authentication and authorization failures should:

- return safe status codes
- avoid leaking sensitive detail
- generate relevant operational/security logs
- be observable for abuse detection

Repeated failures should be subject to rate limiting or additional
protection.

---

# 31. Human Override Authorization

Human overrides are privileged workflow operations even when performed by
an analyst.

Examples:

- severity override
- classification override
- routing override

The backend must verify:

- authenticated actor
- required permission
- valid target
- valid value
- reason where required

The override must create an AuditEvent.

---

# 32. Rule Management Authorization

Only authorized administrators may:

- create rules
- update rules
- enable/disable rules
- retire rules

Rules must be validated before activation.

A rule-management request must not allow:

- arbitrary executable code
- arbitrary database queries
- unauthorized severity definitions
- unauthorized routing behavior

---

# 33. Routing Policy Authorization

Only authorized administrators may modify routing policies.

A routing-policy change must:

- validate the policy
- create a new version where appropriate
- record the actor
- record the timestamp
- preserve previous versions
- generate an AuditEvent

---

# 34. Configuration Authorization

Security-sensitive configuration must be restricted to administrators or
controlled deployment processes.

Examples:

- authentication configuration
- database connection configuration
- retention settings
- rate limits
- collector credentials
- security toggles

Normal analysts do not receive configuration-management permissions.

---

# 35. Audit Authorization

Audit history is sensitive.

Default MVP policy:

```text
Security Admin
→ audit read

Security Analyst
→ no unrestricted audit read
```

Limited audit information may still be visible within an incident workflow
where required.

---

# 36. Database Credential Separation

The ProShield application should use dedicated database credentials.

Security administrators do not receive database credentials merely because
they are application administrators.

Database administration remains a separate infrastructure privilege.

---

# 37. Privilege Escalation Protection

The authorization system must prevent:

- analyst → admin escalation
- collector → analyst escalation
- collector → admin escalation
- service → human identity impersonation
- API client → internal-service privilege escalation

Role and permission assignment must not be user-controlled.

---

# 38. Horizontal Access Protection

A user with access to one incident must not automatically access another
incident merely by changing the identifier.

Tests must verify:

```text
User A → Incident A ✅
User A → Incident B ❌
```

when the policy does not authorize User A to see Incident B.

The same principle applies to:

- events
- reports
- audit information
- administrative objects

---

# 39. Vertical Access Protection

Tests must verify:

```text
Analyst → allowed analyst operation ✅
Analyst → admin-only operation ❌

Admin → authorized admin operation ✅
```

The API must enforce these permissions independently of UI controls.

---

# 40. Service-to-Service Authorization

If ProShield uses separate services/processes, internal communication must
be authenticated and authorized according to service identity.

A compromised service should not automatically obtain unrestricted
privileges across the system.

This supports least-privilege containment.

---

# 41. Authorization Failure Behavior

On authorization failure:

- do not perform the action
- do not modify state
- return safe error
- record the event where appropriate
- do not reveal unnecessary object information

For some sensitive resources, `404 Not Found` may be preferable to
revealing whether an object exists.

The final endpoint contract will define the appropriate behavior.

---

# 42. Authentication/Authorization Audit Events

At minimum, the system should be capable of auditing:

- login success
- login failure
- logout
- privileged action
- rule modification
- routing-policy modification
- configuration modification
- human override
- authorization failure when security policy requires it

Audit records must not contain credentials or tokens.

---

# 43. Access Review

Production deployments should periodically review:

- users
- roles
- service identities
- collector credentials
- permissions
- admin access

Inactive or unnecessary identities should be disabled or removed according
to policy.

---

# 44. Security Testing Requirements

The authentication/RBAC implementation must test:

### Authentication

- missing token
- malformed token
- expired token
- invalid token
- tampered token
- wrong issuer/audience where applicable

### Role Enforcement

- analyst allowed operations
- analyst denied admin operations
- admin allowed authorized admin operations

### Object Authorization

- unauthorized incident access
- unauthorized event access
- unauthorized report access
- unauthorized routing access

### Privilege Escalation

- role manipulation
- forged role claims
- permission bypass
- service impersonation

### Collector Security

- valid collector
- invalid collector
- collector privilege escalation
- collector attempting admin operations

### Human Override

- unauthorized override
- valid override
- override audit generation

---

# 45. Acceptance Criteria

The authentication and RBAC foundation is correct when:

### AC-RBAC-01

Protected endpoints require authentication.

### AC-RBAC-02

Roles are enforced server-side.

### AC-RBAC-03

Analysts cannot perform admin-only configuration operations.

### AC-RBAC-04

Collectors cannot access analyst/admin functionality.

### AC-RBAC-05

Internal services receive only required capabilities.

### AC-RBAC-06

Object-level authorization prevents unauthorized cross-object access.

### AC-RBAC-07

Role/permission claims cannot be forged by the client.

### AC-RBAC-08

Privileged operations are audited.

### AC-RBAC-09

Human overrides are authorized and audited.

### AC-RBAC-10

Rule and routing-policy management is restricted to authorized admins.

### AC-RBAC-11

Authentication failures do not expose sensitive account information.

### AC-RBAC-12

Tokens/credentials are never exposed through logs or audit records.

### AC-RBAC-13

Database credentials are not exposed to normal users.

### AC-RBAC-14

Authorization failures do not modify protected state.

### AC-RBAC-15

Security tests cover horizontal and vertical privilege boundaries.

---

# 46. Future Extensions

Future versions may introduce:

- more granular RBAC
- attribute-based access control
- organization/tenant isolation
- delegated administration
- analyst skill matrices
- individual analyst assignment
- enterprise identity federation
- MFA/step-up authentication
- service mesh identity

These are not required for the initial MVP unless a concrete deployment
requirement makes them necessary.

---

# 47. Final Authentication and Authorization Principle

The ProShield security model must follow:

```text
IDENTITY
   ↓
AUTHENTICATION
   ↓
ROLE / SERVICE IDENTITY
   ↓
PERMISSION
   ↓
OBJECT-LEVEL AUTHORIZATION
   ↓
ACTION
   ↓
AUDIT
```

The fundamental rule is:

> **Being authenticated does not mean being authorized, and being
> authorized for one security operation does not grant permission to
> manipulate unrelated security state.**

Every protected action must be authorized server-side and must operate
according to least privilege.