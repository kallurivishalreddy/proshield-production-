"""Detection engine errors.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 87-91).

The detection engine is the deterministic per-event evaluation
pipeline. Errors are domain errors (subclasses of
:class:`app.domain.errors.DomainError`) so the future HTTP API
layer can translate them into the documented safe-error envelope
(Phase 3, Section 30).
"""
from __future__ import annotations

from typing import Optional

from ..domain.errors import DomainError


class DetectionError(DomainError):
    """Base class for all detection-engine domain errors."""


class DetectionEngineError(DetectionError):
    """A detection-engine contract was violated.

    Examples include being asked to evaluate an event with an
    empty / un-registered registry, or supplying a non-engine
    argument where one was required.
    """


class NoRuleRegistryError(DetectionEngineError):
    """The engine was constructed without a RuleRegistry.

    The engine cannot evaluate any event without an authoritative
    rule catalogue. The constructor refuses this state.
    """


class InvalidEventError(DetectionError):
    """The event passed to ``DetectionEngine.run`` is not a valid
    canonical ``SecurityEvent``.

    The engine does not validate the model itself (Pydantic does
    that on construction); this error is reserved for the case
    where a non-event object reaches the engine.
    """


class DetectionIdGenerationError(DetectionEngineError):
    """The engine could not generate a deterministic detection_id.

    The detection_id pattern is strict (``det-<uuidv7>``). The
    only documented way this can fail is an internal
    UUID-generation error; the engine reports it as a domain
    error rather than crashing.
    """
