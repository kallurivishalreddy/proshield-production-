"""Severity / Confidence engine domain errors.

Reference:
    docs/PHASE 2/DOMAIN_DATA_MODEL.md, Sections 10 and 11.
    docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
    Section 66.

The severity / confidence engine's domain errors are
:class:`DomainError` subclasses so a future HTTP API layer
can translate them into the documented safe-error envelope
(Phase 3, Section 30).

The error hierarchy is intentionally narrow:

* :class:`SeverityError`              - base for every
                                        severity / confidence
                                        domain error.
* :class:`InvalidSeverityInputError`  - a bad input (a
                                        non-Detection, a
                                        non-Correlation, a
                                        naive datetime, a
                                        malformed id, etc.)
                                        reached the engine.
                                        The engine refuses
                                        rather than silently
                                        coercing.
* :class:`SeverityEvidenceError`      - the evidence
                                        underlying a
                                        :class:`Detection` /
                                        :class:`Correlation`
                                        is missing or
                                        malformed; the
                                        engine SKIPS the
                                        subject rather than
                                        inventing a
                                        substitute. Errors
                                        are quarantined to
                                        :class:`SeverityResult.errors`.

The engine never raises a bare :class:`Exception` for normal
input flow; all unexpected exceptions are quarantined to
:class:`SeverityResult.errors`.
"""
from __future__ import annotations

from ..domain.errors import DomainError


class SeverityError(DomainError):
    """Base class for all severity / confidence engine
    domain errors."""


class InvalidSeverityInputError(SeverityError):
    """The severity / confidence engine received input that
    violates its documented contract.

    Examples:

    * a non-:class:`Detection` passed as a detection,
    * a non-:class:`Correlation` passed as a correlation,
    * a naive ``datetime`` (the engine requires
      timezone-aware UTC datetimes),
    * a missing or malformed evidence id.

    The engine refuses to coerce silently; the caller is
    expected to fix the input.
    """


class SeverityEvidenceError(SeverityError):
    """The evidence underlying a detection or correlation is
    missing or malformed.

    The engine SKIPS the offending subject rather than
    inventing a substitute. The error is reported via the
    :class:`SeverityResult.errors` channel.
    """
