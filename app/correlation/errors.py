"""Correlation engine errors.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 87-91).

The correlation engine's domain errors are :class:`DomainError`
subclasses so a future HTTP API layer can translate them into the
documented safe-error envelope (Phase 3, Section 30).

The error hierarchy is intentionally narrow:

* :class:`CorrelationError` — base for every correlation engine
  domain error.
* :class:`InvalidCorrelationInputError` — a bad input (a
  non-:class:`Detection`, a naive datetime, an out-of-range
  window, an empty key, etc.) reached the engine. The engine
  refuses rather than silently coercing.
* :class:`CorrelationKeyError` — a correlation key (the
  source+endpoint tuple or similar) is missing or malformed.
* :class:`CorrelationWindowError` — a time window is zero, negative,
  or otherwise nonsensical.

The engine never raises bare :class:`Exception` for normal input
flow; all unexpected exceptions are quarantined to
``CorrelationResult.errors`` (mirroring the per-event detection
engine's behaviour, Section 91).
"""
from __future__ import annotations

from typing import Optional

from ..domain.errors import DomainError


class CorrelationError(DomainError):
    """Base class for all correlation-engine domain errors."""


class InvalidCorrelationInputError(CorrelationError):
    """The correlation engine received input that violates its
    documented contract.

    Examples:

    * a non-:class:`Detection` object passed as a detection,
    * a naive ``datetime`` (the engine requires timezone-aware
      UTC datetimes),
    * a malformed :class:`CorrelationKey`,
    * a negative or zero time window in a pattern.

    The engine refuses to coerce silently; the caller is
    expected to fix the input.
    """


class CorrelationKeyError(CorrelationError):
    """A correlation key is missing or malformed.

    The correlation engine requires that every detection's
    evidence point back to a SecurityEvent (DET-08) and that
    the event's source_ip + endpoint pair be present and
    non-empty for the brute-force clustering pattern. A
    detection whose event lacks those fields cannot be
    correlated.
    """


class CorrelationWindowError(CorrelationError):
    """A correlation time window is malformed.

    The window must be a positive duration. A zero or negative
    window is meaningless and is rejected at construction time
    so the engine never enters a "no time" state.
    """
