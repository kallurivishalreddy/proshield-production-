"""Domain errors for the ingestion boundary.

These errors are the contract surface between the ingestion service and
its callers. They carry enough information to support the documented
safe-error model (docs/PHASE 3/SECURE_FOUNDATION.md, Section 30) without
leaking internals: stack traces, full driver messages, secrets, or paths.

Layers above MUST translate these to safe client-facing responses and
MUST NOT echo internal error bodies.
"""
from __future__ import annotations

from typing import Optional


class DomainError(Exception):
    """Base class for all ProShield domain errors.

    The ``safe_message`` is what callers are allowed to surface to clients.
    The ``internal_detail`` is for server-side diagnostic logs only and
    must never be returned to a client.
    """

    code: str = "domain_error"
    http_status: int = 500

    def __init__(
        self,
        safe_message: str,
        internal_detail: Optional[str] = None,
        *,
        field: Optional[str] = None,
    ) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.internal_detail = internal_detail
        self.field = field


class ValidationError(DomainError):
    """Input failed documented validation rules (schema, types, bounds)."""

    code = "validation_error"
    http_status = 400


class AuthenticationRequiredError(DomainError):
    """Protected operation attempted without valid identity."""

    code = "authentication_required"
    http_status = 401


class AuthorizationError(DomainError):
    """Identity does not have permission for the attempted operation."""

    code = "forbidden"
    http_status = 403


class NotFoundError(DomainError):
    """Requested object does not exist OR is hidden by object-level authz."""

    code = "not_found"
    http_status = 404


class DuplicateEventError(DomainError):
    """An event with this canonical identity was already accepted.

    This is the documented idempotent path: same identity + same content
    returns the original. Callers should treat this as a successful
    no-op rather than a failure.
    """

    code = "duplicate_event"
    http_status = 200  # not an error from the caller's perspective


class ConflictEventError(DomainError):
    """Same canonical identity but different content.

    This is the documented replay/inconsistency path
    (docs/PHASE 1/THREAT_MODEL.md T02, docs/PHASE 2/SECURITY_EVENT_SCHEMA.md
    Section 16). A re-delivered event claiming an existing event_id but with
    different fields is rejected as inconsistent so it cannot silently
    overwrite or shadow evidence.
    """

    code = "conflict_event"
    http_status = 409


class IngestionError(DomainError):
    """Generic failure inside the ingestion pipeline.

    Specific subclasses cover the most important cases (validation,
    duplicate, conflict). Use this only when nothing more specific fits.
    """

    code = "ingestion_error"
    http_status = 500


class PersistenceError(DomainError):
    """Persistence layer failed (MongoDB unreachable, write error, ...).

    The safe message MUST NOT include the underlying driver error string;
    the internal detail MAY include it for server-side logs only.
    """

    code = "persistence_error"
    http_status = 503
