"""Routing engine domain errors."""
from __future__ import annotations

from ..domain.errors import (
    DomainError,
    ValidationError,
)


class RoutingError(DomainError):
    """Base class for all routing domain errors."""


class InvalidRoutingInputError(ValidationError):
    """The routing engine received an input that violates
    its contract.
    """


__all__ = [
    "InvalidRoutingInputError",
    "RoutingError",
]