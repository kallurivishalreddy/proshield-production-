"""Incident / case domain errors.

Reference: docs/PHASE 2/API_CONTRACTS.md (AC-RBAC-06 object-
level authorization), docs/PHASE 4/PHASE 4-08.

The incident error catalogue is small, on purpose:

* :class:`IncidentError` — base.
* :class:`CaseNotFoundError` — the case id is unknown /
  hidden by object-level authz (``http_status = 404``).
* :class:`CaseAccessDeniedError` — the authenticated
  identity lacks ``case:read`` (or the case is owned by
  another subject and the caller lacks ``case:read:any``).
  ``http_status = 403``.
* :class:`CaseEvidenceError` — the evidence underlying the
  case is missing or malformed; the orchestrator falls
  back to an explicit failure rather than inventing a
  substitute.
* :class:`InvalidIncidentInputError` — bad input to the
  service (``http_status = 400``).

The proxy translates every incident error via the same
safe-error envelope used elsewhere (safe_message,
internal_detail, code, http_status).
"""
from __future__ import annotations

from ..domain.errors import (
    AuthorizationError,
    DomainError,
    NotFoundError,
    ValidationError,
)


class IncidentError(DomainError):
    """Base class for all incident / case domain errors."""


class CaseNotFoundError(NotFoundError):
    """The requested case does not exist or is hidden by
    object-level authorization.

    The proxy returns ``404`` for both "does not exist"
    and "exists but not yours" so the wire response does
    not leak the existence of a case the caller is not
    authorized to see (IDOR defense).
    """


class CaseAccessDeniedError(AuthorizationError):
    """The authenticated identity lacks the case-level
    permission needed to perform the requested operation.

    Distinguished from :class:`CaseNotFoundError` only in
    the safe-error ``message``; the HTTP status is the
    same ``403``.
    """


class CaseEvidenceError(IncidentError):
    """The evidence referenced by the case is missing or
    malformed.

    The orchestrator catches this and routes to an
    explicit failure path; it never silently fabricates
    a substitute.
    """

    code = "case_evidence_error"
    http_status = 409


class InvalidIncidentInputError(ValidationError):
    """The incident service received an input that violates
    its contract.
    """


__all__ = [
    "CaseAccessDeniedError",
    "CaseEvidenceError",
    "CaseNotFoundError",
    "IncidentError",
    "InvalidIncidentInputError",
]