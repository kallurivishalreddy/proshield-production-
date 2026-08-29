# ProShield — Security Configuration

## 1. Purpose

This document defines how security-sensitive configuration is stored,
provided, validated, changed, and protected in the ProShield MVP.

Configuration is part of the security boundary.

Incorrect configuration can:

- disable authentication
- expose MongoDB
- weaken authorization
- expose secrets
- disable rate protection
- reduce auditability
- weaken TLS
- create unsafe collector access
- change detection or routing behavior

Therefore configuration must be treated as controlled security data.

---

## 2. Configuration Principles

ProShield configuration must follow:

- secure by default
- least privilege
- no secrets in source code
- no secrets in Git
- explicit environment separation
- fail-fast validation for critical settings
- audited changes for runtime security configuration
- controlled secret rotation
- configuration version awareness
- no client authority over privileged configuration

---

## 3. Configuration Categories

ProShield configuration is divided into:

```text
1. Application configuration
2. Security configuration
3. Database configuration
4. Authentication configuration
5. Collector configuration
6. Detection-rule configuration
7. Routing-policy configuration
8. Retention configuration
9. Operational limits
10. Deployment configuration
```

Not every category should be managed through the same mechanism.

---

# 4. Application Configuration

General application configuration may include:

- application name
- environment
- API version
- listening address
- listening port
- frontend origin configuration
- feature flags where appropriate

Application configuration must not contain secrets unless explicitly
required and securely injected.

---

# 5. Environment Separation

ProShield must distinguish at least:

```text
development
testing
production
```

Each environment must have separate configuration and credentials.

Production credentials must never be copied into development configuration.

Testing must use dedicated test data and credentials.

---

# 6. Development Configuration

Development configuration should optimize for:

- fast local development
- clear diagnostics
- safe local defaults
- local MongoDB access
- simulated security events

Development may use:

- localhost
- development-only credentials
- non-production certificates
- local simulated collectors

Development configuration must never become the production configuration
by accident.

---

# 7. Testing Configuration

Testing configuration must be isolated from production.

Testing should use:

- separate database or database namespace
- dedicated credentials
- deterministic data
- controlled event scenarios
- predictable retention/testing behavior

Tests must not require production secrets.

---

# 8. Production Configuration

Production configuration must enforce stronger requirements.

At minimum:

- authentication enabled
- authorization enabled
- secure secrets
- TLS where required
- restricted CORS
- protected MongoDB
- rate/resource controls
- auditing enabled
- secure error behavior
- no debug mode
- no development credentials

The application should fail to start when critical production security
configuration is invalid.

---

# 9. Secrets Management

Secrets include:

- MongoDB credentials
- authentication signing keys
- service credentials
- collector credentials
- encryption keys
- API credentials
- integration secrets

Secrets must never be hard-coded.

Bad:

```python
JWT_SECRET = "my-secret"
```

Good conceptual pattern:

```text
Application
    ↓
Secure configuration source
    ↓
Secret injected at runtime
```

The exact production secret-management platform may vary by deployment.

---

# 10. Secret Storage

Secrets should be stored using a secure secret-management mechanism
appropriate to the deployment.

Examples may include:

- environment-injected secrets
- managed secret stores
- deployment-platform secret stores

Plaintext secret files must not be committed to source control.

---

# 11. `.env` Usage

Local development may use environment files for convenience.

Rules:

- `.env` must not be committed
- `.env.example` may document required variable names
- real secrets must never be placed in `.env.example`
- production should use a proper secret/configuration mechanism

Example:

```text
.env
.env.local
```

may be ignored by Git.

Example documentation:

```text
MONGODB_URI=<provided-securely>
AUTH_SIGNING_KEY=<provided-securely>
```

---

# 12. Required Security Configuration

The exact variable names are implementation-dependent, but the MVP must
support secure configuration for at least:

```text
Application environment
MongoDB connection
Authentication signing/verification
Token/session configuration
CORS origins
TLS configuration
Rate limits
Request-size limits
Event-size limits
Retention settings
Collector credentials
Rule configuration
Routing configuration
```

---

# 13. MongoDB Configuration

MongoDB configuration must include:

- connection URI
- database name
- authentication credentials as required
- TLS settings for production where required
- connection timeout
- operation timeout where appropriate

MongoDB credentials must never be exposed to application clients.

---

# 14. MongoDB Connection Security

Production MongoDB must:

- require authentication
- use restricted application credentials
- not be publicly exposed
- allow only authorized application/deployment sources
- use TLS where appropriate to the deployment
- use secure connection configuration

The application must not connect using an unrestricted database-admin
account for normal runtime operations.

---

# 15. MongoDB Credential Separation

Separate credentials should be considered for:

- application runtime
- administrative maintenance
- testing
- migration/index-management operations

The runtime application should receive the smallest permission set needed
for normal operation.

---

# 16. Authentication Configuration

Authentication configuration may include:

- token/session lifetime
- issuer
- audience
- signing algorithm
- password policy
- authentication endpoint limits
- session configuration

Security-sensitive values must be protected.

---

# 17. Signing-Key Security

If signed tokens are used:

- signing keys must be stored as secrets
- keys must never be committed to source
- keys must never appear in logs
- production keys must differ from development keys
- expired/rotated keys must be handled according to the authentication
  strategy

A development placeholder key must never be accepted in production.

---

# 18. Secret Validation

At startup, the application should validate critical secret configuration.

Examples:

- required secret exists
- secret is not a known placeholder
- secret meets minimum security requirements
- production secret differs from development placeholder

If a critical security secret is missing or invalid:

```text
production startup
→ FAIL
```

rather than silently running insecurely.

---

# 19. Secret Rotation

Secrets must be replaceable without modifying source code.

Rotation should support, where practical:

- new credential creation
- application configuration update
- validation
- transition
- old credential revocation

The exact rotation mechanism depends on deployment infrastructure.

---

# 20. Collector Configuration

Each collector may require configuration such as:

- source identity
- endpoint
- credentials
- certificates
- polling interval
- connection settings
- event mapping configuration

Collector credentials must be stored separately from general application
configuration where practical.

---

# 21. Collector Credential Principle

A collector credential should grant only the permission required for that
collector.

For example:

```text
NGINX Collector
→ NGINX source access / event submission
```

It should not automatically grant:

```text
rule management
incident administration
routing-policy management
```

---

# 22. Runtime Configuration vs Build Configuration

Separate:

```text
Build-time configuration
```

from:

```text
Runtime security configuration
```

Secrets should normally be runtime configuration.

Examples:

```text
Build:
application code
frontend assets
dependencies

Runtime:
MongoDB URI
signing key
collector credentials
CORS origins
retention
rate limits
```

This prevents secrets from becoming embedded into build artifacts.

---

# 23. Configuration Validation

All security-sensitive configuration must be validated.

Validation should check:

- required values
- format
- allowed values
- ranges
- environment-specific restrictions
- dependency requirements

Examples:

```text
retention_days > 0
rate_limit > 0
CORS origin is valid
database URI is valid
production secret is not placeholder
```

---

# 24. Secure Defaults

Defaults should favor security.

Examples:

```text
authentication = required
authorization = required
audit = enabled
debug = disabled in production
TLS = required where applicable
unbounded queries = disabled
unbounded payloads = disabled
wildcard privileged CORS = disabled
```

---

# 25. CORS Configuration

CORS must be explicitly configured.

Development example:

```text
http://localhost:3000
```

or the actual configured frontend origin.

Production should contain only authorized frontend origins.

Do not use unrestricted:

```text
*
```

for privileged authenticated APIs unless there is a documented security
reason.

---

# 26. TLS Configuration

Production communication should use TLS.

Configuration may include:

- certificate path/reference
- private-key path/reference
- trusted CA configuration
- minimum TLS version
- approved cipher/security policy where required

Private keys must be treated as secrets.

Local development may use localhost/non-TLS communication when appropriately
isolated.

---

# 27. Request Limits

Configuration must support bounded:

- request body size
- event size
- `details` size
- pagination limit
- query complexity
- API request rate

The exact values should be derived from expected MVP workload and testing.

Limits must be enforced server-side.

---

# 28. Rate Limiting Configuration

High-risk endpoints must have configurable rate limits.

Examples:

- authentication
- event ingestion
- rule management
- routing policy management
- report generation
- future response actions

Rate limits should be stricter for privileged/security-sensitive
operations.

---

# 29. Retention Configuration

Retention should be configurable by data class.

Initial operational defaults:

```text
Security Events        → 90 days
Detections             → 180 days
Correlations           → 180 days
Incidents              → 1 year
Reports                → 1 year
Audit Events           → 1 year
Rule History           → system life unless archived
Routing Policy History → system life unless archived
```

These are MVP defaults.

They are not legal or regulatory retention guarantees.

Deployments may configure different values.

---

# 30. Rule Configuration

Detection rules are security-sensitive configuration.

Rules must be:

- versioned
- validated
- authorized
- auditable
- stored safely
- protected from arbitrary code execution

Rules must not be loaded from an untrusted path without validation.

---

# 31. Rule Configuration Integrity

The system should know:

- rule ID
- rule version
- enabled state
- author/actor
- creation time
- modification time
- activation time
- previous version where applicable

A rule change must be distinguishable from an event-processing action.

---

# 32. Routing Policy Configuration

Routing policies are also security-sensitive.

Configuration should preserve:

- policy ID
- version
- enabled state
- routing conditions
- created/updated timestamps
- actor/change history

Changes must be authorized and audited.

---

# 33. Feature Flags

Feature flags may be used for controlled rollout.

Security-sensitive features must not be enabled merely because a frontend
flag is set.

Server-side enforcement is required.

Example:

Bad:

```text
frontend says "admin enabled"
→ backend trusts it
```

Correct:

```text
frontend requests admin operation
→ backend checks authorization
```

---

# 34. Configuration Changes

Security-sensitive runtime configuration changes should follow:

```text
Authenticated Administrator
        ↓
Authorization
        ↓
Validation
        ↓
Change
        ↓
AuditEvent
```

The old and new relevant values should be distinguishable where safe.

Secrets themselves should not be copied into audit records.

---

# 35. Configuration Versioning

Where configuration changes affect security behavior, preserve enough
version information to determine which configuration was active when an
incident occurred.

Examples:

- rule version
- routing-policy version
- relevant configuration version

This supports incident reconstruction.

---

# 36. Configuration Rollback

Security configuration should be recoverable where practical.

Examples:

- disable faulty rule
- restore previous rule version
- restore previous routing policy
- restore previous non-secret security configuration

Rollback itself is a privileged and auditable action.

---

# 37. Production Configuration Guardrails

Production should reject configurations such as:

- placeholder signing keys
- default administrative passwords
- debug mode
- unrestricted CORS
- public MongoDB connection
- missing authentication
- missing authorization
- disabled audit
- invalid TLS configuration where TLS is required
- unrestricted event payload size

The application must fail safely rather than start insecurely.

---

# 38. Development Safety

Development environments may be more permissive for convenience, but must
remain isolated.

Development must not:

- connect accidentally to production MongoDB
- reuse production credentials
- send simulated events to production
- write test incidents into production
- expose production secrets

Environment identity must be explicit.

---

# 39. Testing Configuration Safety

Automated tests must use dedicated:

- database
- credentials
- secrets
- configuration
- event data

Tests must not depend on production configuration.

Tests should also verify that security checks remain enabled.

---

# 40. Configuration Logging

The system may log non-sensitive configuration state for diagnostics.

It must not log:

- passwords
- tokens
- signing keys
- database passwords
- private keys
- collector secrets

Example:

Safe:

```text
environment=production
audit=enabled
rate_limit=100
```

Unsafe:

```text
mongodb_password=...
jwt_secret=...
```

---

# 41. Configuration Export

If configuration can be exported:

- secrets must be excluded or separately protected
- exported rules must retain version information
- routing policies must retain version information
- export actions should be auditable where appropriate

---

# 42. Configuration Import

If configuration can be imported:

- authenticate the caller
- authorize the operation
- validate structure
- validate semantics
- reject executable content
- validate version compatibility
- perform safe dry-run/validation where practical
- audit the import

Configuration import must not become an arbitrary code-execution path.

---

# 43. Environment Variables and Naming

Configuration names should be consistent and documented.

Example conceptual names:

```text
PROSHIELD_ENV
MONGODB_URI
MONGODB_DATABASE
AUTH_SIGNING_KEY
AUTH_TOKEN_EXPIRATION
CORS_ALLOWED_ORIGINS
RATE_LIMIT_EVENT_INGEST
MAX_EVENT_SIZE
SECURITY_EVENT_RETENTION_DAYS
INCIDENT_RETENTION_DAYS
AUDIT_RETENTION_DAYS
```

Exact variable names may differ in implementation, but naming must remain
clear and consistent.

---

# 44. Configuration Precedence

The system should define predictable precedence.

Recommended conceptual order:

```text
Secure runtime configuration
        ↓
Environment-specific configuration
        ↓
Safe application defaults
```

A less-secure configuration source must not silently override a more
secure production policy.

---

# 45. Secret Exposure Testing

The Phase 3 test suite must verify that secrets do not appear in:

- API responses
- logs
- audit events
- error messages
- SecurityEvents
- Reports
- configuration exports

This should be tested automatically where practical.

---

# 46. Configuration Security Monitoring

Important configuration changes should generate monitoring/audit signals.

Examples:

- signing key change
- database configuration change
- rule activation/deactivation
- routing policy change
- retention change
- rate-limit change
- CORS change
- privileged access change

---

# 47. Configuration Failure Behavior

If critical configuration is invalid:

### Development

Provide a clear actionable error.

### Testing

Fail the test/setup rather than silently falling back.

### Production

Fail securely.

Example:

```text
Missing production authentication signing key
→ application does not start
```

not:

```text
Missing key
→ generate insecure temporary key
→ continue running
```

---

# 48. Configuration and AI Boundary

Future AI configuration may include:

- provider credentials
- model identifiers
- rate limits
- safety settings
- feature flags

These must follow the same secret/configuration rules.

AI configuration must not weaken deterministic security configuration.

---

# 49. Configuration Security Acceptance Criteria

Configuration management is correct when:

### AC-CONFIG-01

No secrets are committed to source control.

### AC-CONFIG-02

Production rejects placeholder security secrets.

### AC-CONFIG-03

MongoDB runtime credentials use least privilege.

### AC-CONFIG-04

Collector credentials are separated appropriately.

### AC-CONFIG-05

Security-sensitive configuration changes are authorized.

### AC-CONFIG-06

Security-sensitive configuration changes are audited.

### AC-CONFIG-07

Secrets never appear in logs, API responses, or audit records.

### AC-CONFIG-08

Retention values are configurable and validated.

### AC-CONFIG-09

Request/event/rate limits are configurable and bounded.

### AC-CONFIG-10

Development and production configurations are separated.

### AC-CONFIG-11

Invalid critical production configuration causes safe startup failure.

### AC-CONFIG-12

Rule and routing configuration is versioned and protected.

### AC-CONFIG-13

Configuration import/export cannot bypass authorization or execute code.

### AC-CONFIG-14

Configuration tests verify secure defaults.

---

# 50. Phase 3 Configuration Completion Criteria

This document is complete as a Phase 3 design when:

- secret categories are defined
- environment separation is defined
- MongoDB configuration security is defined
- authentication configuration requirements are defined
- collector configuration requirements are defined
- TLS requirements are defined
- rate/event/request limits are defined
- retention configuration is defined
- rule configuration is protected
- routing configuration is protected
- secure startup validation is defined
- configuration-change auditing is defined
- secret exposure testing is defined

---

# 51. Explicit Non-Goals

The MVP does not require:

- enterprise secret-management platform integration
- HSM infrastructure
- complex multi-region configuration management
- dynamic global configuration service
- Kubernetes-native configuration infrastructure
- automatic secret rotation across every future provider

These may be added when deployment requirements justify them.

---

# 52. Final Security Configuration Principle

ProShield configuration must follow:

```text
STORE SECURELY
     +
VALIDATE
     +
AUTHORIZE
     +
AUDIT
     +
ROTATE
     +
FAIL SAFE
```

The fundamental rule is:

> **Configuration that can change the security behavior of ProShield must
> be treated as security-sensitive data, not as ordinary application
> settings.**