"""Report engine domain errors."""
from __future__ import annotations

from ..domain.errors import (
    AuthorizationError,
    DomainError,
    NotFoundError,
    ValidationError,
)


class ReportError(DomainError):
    """Base class for all report engine domain errors."""


class ReportNotFoundError(NotFoundError):
    """The requested report does not exist or is hidden by
    object-level authorization.
    """


class ReportAccessDeniedError(AuthorizationError):
    """The authenticated identity lacks ``report:read`` (or
    the case owning the report is invisible).
    """


class InvalidReportInputError(ValidationError):
    """The report service received an input that violates
    its contract.
    """


__all__ = [
    "InvalidReportInputError",
    "ReportAccessDeniedError",
    "ReportError",
    "ReportNotFoundError",
]