"""Capability Registry domain errors (Phase 5.1).

Reference: docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md
(section 11), docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md
(section 18).

Closed-set error catalogue mirroring the Phase 4.9 source-management
boundary pattern. Every error carries a ``safe_message`` for the client
and an ``internal_detail`` reserved for server-side logs.
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


class CapabilityManagementError(DomainError):
    """Base class for all capability-registry domain errors."""


class CapabilityNotFoundError(CapabilityManagementError, NotFoundError):
    """The requested ``capability_id`` is unknown."""

    code = "capability_not_found"
    http_status = 404


class CapabilityAlreadyExistsError(CapabilityManagementError, ConflictEventError):
    """A capability with the same ``capability_id`` already exists."""

    code = "duplicate_capability"
    http_status = 409


class CapabilityStateError(CapabilityManagementError):
    """The requested lifecycle transition is not allowed."""

    code = "capability_state_error"
    http_status = 409


class CapabilityConfigurationError(CapabilityManagementError, ValidationError):
    """Supplied capability payload failed documented validation gates."""

    code = "capability_configuration_error"
    http_status = 400


class CapabilityAuthorizationError(CapabilityManagementError, AuthorizationError):
    """The caller's identity lacks the documented permission."""

    code = "capability_authorization_error"
    http_status = 403


class CapabilityPersistenceError(CapabilityManagementError, PersistenceError):
    """The capability persistence layer failed."""

    code = "capability_persistence_error"
    http_status = 503


__all__ = [
    "CapabilityAlreadyExistsError",
    "CapabilityAuthorizationError",
    "CapabilityConfigurationError",
    "CapabilityManagementError",
    "CapabilityNotFoundError",
    "CapabilityPersistenceError",
    "CapabilityStateError",
]
