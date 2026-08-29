"""Timeline-engine domain errors.

Reference: docs/PHASE 2/DOMAIN_DATA_MODEL.md (evidence principle);
docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 66
(timeline responsibility).

The timeline engine's domain errors are :class:`DomainError`
subclasses so a future HTTP API layer can translate them into
the documented safe-error envelope (Phase 3, Section 30).

The error hierarchy is intentionally narrow:

* :class:`TimelineError`              - base for every timeline
                                        domain error.
* :class:`InvalidTimelineInputError`  - a bad input (a non-SecurityEvent,
                                        a non-Detection, a non-Correlation,
                                        a naive datetime, a malformed id,
                                        etc.) reached the engine. The engine
                                        refuses rather than silently coercing.
* :class:`TimelineEvidenceError`      - a piece of evidence is missing
                                        (a detection references an event
                                        not in the events lookup, a
                                        correlation references detections
                                        not in the detections list) or is
                                        malformed (a missing event_id, an
                                        empty extra). The engine skips the
                                        offending evidence rather than
                                        inventing a substitute.

The engine never raises a bare :class:`Exception` for normal input
flow; all unexpected exceptions are quarantined to
:class:`TimelineResult.errors` (mirroring the per-event detection
and the cross-event correlation engines).
"""
from __future__ import annotations

from ..domain.errors import DomainError


class TimelineError(DomainError):
    """Base class for all timeline-engine domain errors."""


class InvalidTimelineInputError(TimelineError):
    """The timeline engine received input that violates its
    documented contract.

    Examples:

    * a non-:class:`SecurityEvent` passed as an event,
    * a non-:class:`Detection` passed as a detection,
    * a non-:class:`Correlation` passed as a correlation,
    * a naive ``datetime`` (the engine requires timezone-aware
      UTC datetimes),
    * a missing or malformed :class:`TimelineItem` identifier.

    The engine refuses to coerce silently; the caller is
    expected to fix the input.
    """


class TimelineEvidenceError(TimelineError):
    """A piece of timeline evidence is missing or malformed.

    A :class:`Detection` whose underlying :class:`SecurityEvent`
    is not in the events lookup is missing evidence. A
    :class:`Correlation` whose underlying detections are not in
    the detections list is missing evidence. The timeline engine
    SKIPS such evidence rather than inventing a substitute. The
    error is reported via the :class:`TimelineResult.errors`
    channel.
    """
