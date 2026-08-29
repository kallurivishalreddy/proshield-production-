"""The deterministic correlation engine.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 87-91).

The engine is the **centralized cross-event layer** of the
documented ProShield detection pipeline. It consumes a
sequence of per-event :class:`app.detection.models.Detection`
records plus the underlying :class:`SecurityEvent` objects
they reference, and runs each pattern in the catalogue to
produce zero or more :class:`Correlation` records.

Design rules (mirroring the per-event detection engine)
--------------------------------------------------------

* **Deterministic.** Same inputs + same ``now`` -> same
  :class:`CorrelationResult`. The engine does NOT call
  ``datetime.now()``; ``now`` is injected.
* **Per-batch.** The engine does NOT carry cross-call state.
  Every invocation is independent. Persistence of correlations
  is the caller's job; the engine is pure in-memory grouping.
* **Total.** A bad input (a non-Detection, a naive datetime, a
  pattern that raises) is caught and routed to
  ``CorrelationResult.errors``. The engine never raises a
  bare :class:`Exception` for normal input flow.
* **Fail-closed per pattern.** One pattern that raises during
  grouping does not stop the other patterns.
* **No cross-source coupling.** The engine does not import
  any connector. The same engine will work for the future WAF,
  rate-limiter, network, TLS, and IAM connectors because the
  patterns operate on canonical Detection records.

What the engine does NOT do
----------------------------

* It does NOT persist correlations. The calling service
  (``app/detection/pipeline.py``) owns persistence.
* It does NOT call out to MongoDB, FastAPI, the network, or
  any connector. It is pure in-memory grouping.
* It does NOT assign severity, confidence, incident creation,
  or routing.
* It does NOT invent evidence. A pattern that requires a
  field a detection does not have is the pattern's
  responsibility to skip; the engine never substitutes a
  placeholder.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Mapping, Optional, Sequence

from ..detection.models import Detection
from ..domain.security_event import SecurityEvent
from .errors import (
    CorrelationError,
    InvalidCorrelationInputError,
)
from .models import Correlation, CorrelationResult
from .patterns import CorrelationPattern


_MAX_ERROR_LEN = 512


class CorrelationEngine:
    """The deterministic, fail-closed-per-pattern correlation engine.

    Construction
    ------------

    ``patterns`` is a sequence of :class:`CorrelationPattern`
    instances. The engine stores the patterns as a tuple (so
    iteration is deterministic) and runs each in order. The
    engine does NOT mutate any pattern.

    Run
    ---

    :meth:`run` is the single public entry point. The caller
    passes:

    * ``detections`` — a sequence of per-event
      :class:`app.detection.models.Detection` records. Order
      does not matter (the engine sorts internally).
    * ``events`` — a ``{event_id: SecurityEvent}`` lookup
      containing the underlying events the detections
      reference. Detections whose event is missing from the
      lookup are **skipped** (never invented).
    * ``now`` — an optional timezone-aware UTC datetime. If
      omitted, the engine uses ``datetime.now(timezone.utc)``
      captured once per call.

    The engine returns a frozen :class:`CorrelationResult`. The
    engine does NOT persist the result; that is the caller's
    job.
    """

    def __init__(
        self,
        patterns: Sequence[CorrelationPattern],
    ) -> None:
        if patterns is None:
            raise InvalidCorrelationInputError(
                safe_message="CorrelationEngine requires a patterns sequence",
                internal_detail="got None",
            )
        validated: List[CorrelationPattern] = []
        for i, p in enumerate(patterns):
            if not isinstance(p, CorrelationPattern):
                raise InvalidCorrelationInputError(
                    safe_message=(
                        "CorrelationEngine pattern list must contain only "
                        "CorrelationPattern instances"
                    ),
                    internal_detail=(
                        f"position {i}: got {type(p).__name__}"
                    ),
                )
            validated.append(p)
        validated.sort(
            key=lambda p: (p.pattern_id, p.pattern_version)
        )
        self._patterns: tuple = tuple(validated)

    @property
    def patterns(self) -> Sequence[CorrelationPattern]:
        """Read-only view of the pattern catalogue (tuple, sorted)."""
        return self._patterns

    def run(
        self,
        detections: Sequence[Detection],
        events: Mapping[str, SecurityEvent],
        *,
        now: Optional[datetime] = None,
    ) -> CorrelationResult:
        """Run the correlation engine against the given detections.

        Parameters
        ----------
        detections:
            Per-event :class:`Detection` records. The engine
            does not assume any particular order; it sorts the
            inputs internally where it matters.
        events:
            ``{event_id: SecurityEvent}`` lookup. Detections
            whose ``event_id`` is not in this mapping are
            silently skipped (no invented evidence).
        now:
            Optional timezone-aware UTC datetime to use as the
            correlation timestamp. If ``None``, the engine
            uses ``datetime.now(timezone.utc)`` captured once
            per call. If a naive datetime is passed, the engine
            raises :class:`InvalidCorrelationInputError`.

        Returns
        -------
        :class:`CorrelationResult`
            Frozen result with all produced correlations and
            any pattern-level errors. The engine always returns
            a result; it never raises under normal operating
            conditions.
        """
        if detections is None:
            raise InvalidCorrelationInputError(
                safe_message="detections is required",
                internal_detail="got None",
            )
        if events is None:
            raise InvalidCorrelationInputError(
                safe_message="events mapping is required",
                internal_detail="got None",
            )

        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise InvalidCorrelationInputError(
                safe_message="now must be a datetime",
                internal_detail=f"got {type(now).__name__}",
            )
        elif now.tzinfo is None:
            raise InvalidCorrelationInputError(
                safe_message="now must be timezone-aware (UTC)",
                internal_detail="got a naive datetime",
            )

        events_dict: Dict[str, SecurityEvent] = dict(events)

        usable: List[Detection] = []
        for d in detections:
            if not isinstance(d, Detection):
                raise InvalidCorrelationInputError(
                    safe_message=(
                        "all entries in detections must be Detection instances"
                    ),
                    internal_detail=f"got {type(d).__name__}",
                )
            if d.event_id not in events_dict:
                continue
            if d.detected_at.tzinfo is None:
                continue
            usable.append(d)

        errors: List[str] = []
        correlations: List[Correlation] = []
        patterns_considered = len(self._patterns)
        patterns_evaluated = 0

        for pattern in self._patterns:
            try:
                selected = pattern.select(usable, events_dict)
                if not selected:
                    continue
                patterns_evaluated += 1
                produced = pattern.group(selected, events_dict, now=now)
            except CorrelationError as exc:
                errors.append(
                    _truncate(
                        f"pattern {pattern.pattern_id} v{pattern.pattern_version} "
                        f"failed: {exc.safe_message}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    _truncate(
                        f"pattern {pattern.pattern_id} v{pattern.pattern_version} "
                        f"raised unexpected {type(exc).__name__}: {exc}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            correlations.extend(produced)

        correlations.sort(
            key=lambda c: (c.pattern_id, c.correlation_id)
        )

        return CorrelationResult(
            correlations=tuple(correlations),
            patterns_considered=patterns_considered,
            patterns_evaluated=patterns_evaluated,
            detections_consumed=len(usable),
            errors=tuple(errors),
            produced_at=now,
        )


def _truncate(s: str, n: int) -> str:
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + "..."