"""Auth domain errors.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md,
           docs/PHASE 3/AUTH_RBAC.md.

Every error here is a :class:`app.domain.errors.DomainError`
subclass so the proxy / gateway, the API surface, and the
audit subsystem can translate them via the same safe-error
envelope (safe_message, internal_detail, http_status, code).

The Phase 4.8 slice keeps the auth error catalogue small,
on purpose:

* :class:`AuthenticationError` — generic supertype.
* :class:`InvalidSessionTokenError` — malformed / tampered /
  unrecognised token. ``http_status = 401``.
* :class:`SessionExpiredError` — token well-formed but past
  expiry. ``http_status = 401``.
* :class:`PermissionDeniedError` — authenticated identity
  lacks the requested permission. ``http_status = 403``.

The legacy :class:`app.domain.errors.AuthenticationRequiredError`
/ :class:`app.domain.errors.AuthorizationError` remain the
canonical primitives raised at the call site; the proxy
translates them into the proxy-friendly wire envelope.
"""
from __future__ import annotations

from ..domain.errors import (
    AuthenticationRequiredError,
    AuthorizationError,
    DomainError,
)


class IdentityError(DomainError):
    """Base class for all ProShield identity / auth domain errors.

    The Phase 4.8 slice raises :class:`AuthenticationRequiredError`
    / :class:`AuthorizationError` (already defined in
    :mod:`app.domain.errors`) at the call site; this class
    exists for completeness and as the supertype for the
    auth-internal error catalogue below.
    """


class AuthenticationError(AuthenticationRequiredError):
    """The presented session token is missing, malformed, or
    unverifiable.

    Same wire behaviour as the canonical
    :class:`app.domain.errors.AuthenticationRequiredError`
    (``http_status = 401``); the alias exists so callers can
    catch the auth-specific exception class without importing
    :mod:`app.domain.errors` directly.
    """


class InvalidSessionTokenError(AuthenticationError):
    """The token does not match the issued signature / format.

    Raised when the token is malformed (wrong prefix, wrong
    structure, wrong HMAC). Distinct from
    :class:`SessionExpiredError` (well-formed but expired).
    """


class SessionExpiredError(AuthenticationError):
    """The token is well-formed but its ``exp`` claim is in
    the past.

    The verifier treats expired tokens the same as invalid
    tokens at the wire boundary; the distinction exists for
    logging / observability only.
    """


class PermissionDeniedError(AuthorizationError):
    """The authenticated identity lacks the requested permission.

    Same wire behaviour as the canonical
    :class:`app.domain.errors.AuthorizationError`
    (``http_status = 403``); the alias exists so callers can
    catch the auth-specific exception class without importing
    :mod:`app.domain.errors` directly.
    """


__all__ = [
    "AuthenticationError",
    "IdentityError",
    "InvalidSessionTokenError",
    "PermissionDeniedError",
    "SessionExpiredError",
]