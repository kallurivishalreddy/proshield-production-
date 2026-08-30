"""ProShield authentication / authorization foundation (Phase 4.8).

This package provides the **minimal** identity / authentication /
authorization / session layer the Phase 4.8 backend requires.

It is intentionally small, on purpose. The package:

* provides a fixed, closed-set role catalogue (``analyst`` /
  ``admin`` / ``collector`` / ``internal_service``),
* issues + verifies HMAC-signed opaque session tokens,
* reuses the existing :mod:`app.domain.errors` taxonomy
  (``AuthenticationRequiredError`` / ``AuthorizationError``),
* defines an :class:`Identity` (principal) object the proxy /
  core services can carry, and
* implements per-identity permission checks via
  :class:`Permission`.

The package is **NOT** a new IAM system. It exists so:

1. the Phase 4.8 proxy / gateway boundary can verify a
   session token presented by a client without inventing a
   parallel login architecture;
2. the Phase 4.8 incident / report / routing engines can
   perform object-level authorization checks against the
   caller's :class:`Identity`;
3. a future centralised IAM (MFA, federation, stronger
   roles / permissions, device policies, ...) can replace this
   layer without forcing the proxy / case / report / routing
   engines to be rewritten. The boundary the rest of the
   backend depends on is the :class:`Identity` and
   :class:`Permission` interface, not the on-the-wire token
   technology.

What this package does NOT do
----------------------------

* It does NOT introduce enterprise IAM, MFA, federation,
  PKI, HSM, or any external identity provider integration.
* It does NOT persist user records. The MVP ships a
  deterministic in-memory identity catalogue; Phase 4.8
  documents the future-IAM migration as deferred work.
* It does NOT expose backend secrets. The signing key is
  sourced from :class:`app.config.ProShieldConfig`; tests
  inject deterministic keys.
* It does NOT silently trust caller-supplied identity.
  Every protected operation validates the session token
  server-side and re-derives the :class:`Identity` from
  the verified token.
"""
from __future__ import annotations

from .errors import (
    AuthenticationError,
    IdentityError,
    InvalidSessionTokenError,
    PermissionDeniedError,
    SessionExpiredError,
)
from .identity import (
    ANALYST_ROLE,
    ADMIN_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
    Identity,
    IdentityStore,
    InMemoryIdentityStore,
    Role,
)
from .permissions import (
    ALL_PERMISSIONS,
    Permission,
    ROLE_PERMISSIONS,
    has_permission,
)
from .session import (
    SessionToken,
    SessionTokenService,
    SessionVerifier,
    VerifierResult,
)

__all__ = [
    "ADMIN_ROLE",
    "ALL_PERMISSIONS",
    "ANALYST_ROLE",
    "COLLECTOR_ROLE",
    "INTERNAL_SERVICE_ROLE",
    "AuthenticationError",
    "Identity",
    "IdentityError",
    "IdentityStore",
    "InMemoryIdentityStore",
    "InvalidSessionTokenError",
    "Permission",
    "PermissionDeniedError",
    "ROLE_PERMISSIONS",
    "Role",
    "SessionExpiredError",
    "SessionToken",
    "SessionTokenService",
    "SessionVerifier",
    "VerifierResult",
    "has_permission",
]