"""Source Management domain errors (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

The source-management layer adds a small, closed-set error
catalogue that mirrors the documented boundary pattern of the
Phase 4.7 rule layer and the Phase 4.8 incident layer:

* :class:`SourceManagementError` - base.
* :class:`SourceInstanceNotFoundError` - an unknown ``source_instance_id``.
* :class:`DuplicateSourceInstanceError` - a configured source with
  the same identity already exists.
* :class:`SourceInstanceStateError` - the requested lifecycle
  transition is not allowed from the current state.
* :class:`SourceConfigurationError` - the supplied
  ``SourceInstanceConfiguration`` failed the documented gates
  (closed set connector types, endpoint bounds, secret material
  leakage, etc.).
* :class:`SourceAuthorizationError` - the caller's identity lacks
  the documented permission for the requested operation.
* :class:`SourceIdentityTokenError` - a source-identity token failed
  verification (missing, malformed, expired, wrong signature,
  unknown source instance).
* :class:`SourceIntegrityError` - the source identity is trusted but
  the inbound payload claims a connector_type or source string
  inconsistent with the registered source instance.
* :class:`SourceRateLimitedError` - the per-source-instance budget
  was exhausted.
* :class:`SourceRetiredError` - the source instance is retired; no
  new telemetry may be accepted.

Every error carries a ``safe_message`` suitable for the client and
an ``internal_detail`` reserved for server-side logs.
"""
from __future__ import annotations

from ..domain.errors import (
    AuthenticationRequiredError,
    AuthorizationError,
    ConflictEventError,
    DomainError,
    NotFoundError,
    PersistenceError,
    ValidationError,
)


class SourceManagementError(DomainError):
    """Base class for all source-management domain errors."""


class SourceInstanceNotFoundError(SourceManagementError, NotFoundError):
    """The requested ``source_instance_id`` is unknown."""

    code = "source_instance_not_found"
    http_status = 404


class DuplicateSourceInstanceError(SourceManagementError, ConflictEventError):
    """A source instance with the same identity is already registered."""

    code = "duplicate_source_instance"
    http_status = 409


class SourceInstanceStateError(SourceManagementError):
    """The requested lifecycle transition is not allowed.

    Used for every transition that violates the documented state
    machine: ``register -> configure -> validate -> enable ->
    receive`` and ``disable`` / ``retire`` / ``reinstate``.
    """

    code = "source_instance_state_error"
    http_status = 409


class SourceConfigurationError(SourceManagementError, ValidationError):
    """The supplied configuration failed documented validation gates."""

    code = "source_configuration_error"
    http_status = 400


class SourceAuthorizationError(SourceManagementError, AuthorizationError):
    """The caller's identity lacks the documented permission."""

    code = "source_authorization_error"
    http_status = 403


class SourceIdentityTokenError(
    SourceManagementError, AuthenticationRequiredError
):
    """A source-identity token failed verification."""

    code = "source_identity_token_error"
    http_status = 401


class SourceIntegrityError(SourceManagementError):
    """The inbound payload's source identity does not match the
    registered source instance.

    Used by the ingress proxy when the token is valid but the
    body / connector_type / source string in the payload claims
    an origin different from the registered source instance.
    """

    code = "source_integrity_error"
    http_status = 403


class SourceRateLimitedError(SourceManagementError):
    """The per-source-instance budget was exhausted."""

    code = "source_rate_limited"
    http_status = 429


class SourceRetiredError(SourceManagementError):
    """The source instance is retired; no new telemetry may be accepted.

    Distinct from a disabled source: a disabled source may be
    re-enabled; a retired source has its lifecycle closed.
    """

    code = "source_retired"
    http_status = 410


class SourcePersistenceError(SourceManagementError, PersistenceError):
    """The source-instance persistence layer failed."""

    code = "source_persistence_error"
    http_status = 503


__all__ = [
    "DuplicateSourceInstanceError",
    "SourceAuthorizationError",
    "SourceConfigurationError",
    "SourceIdentityTokenError",
    "SourceInstanceNotFoundError",
    "SourceInstanceStateError",
    "SourceIntegrityError",
    "SourceManagementError",
    "SourcePersistenceError",
    "SourceRateLimitedError",
    "SourceRetiredError",
]