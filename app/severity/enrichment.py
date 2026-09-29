"""Evidence-faithful enrichment of detections / correlations.

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md
(gaps 5 and 6).

This module is the **composition point** between the documented
:mod:`app.severity` engine and the persistence layer. It exists
because the Phase 4.4 detection contract and the Phase 4.5
correlation contract deliberately do NOT assign severity or
confidence (that responsibility belongs to the severity engine per
Section 66 of DETECTION_ENGINEERING_AND_FUTURE_AI.md) — but the
analyst wire views need the composed bands persisted with the
record, not recomputed ad hoc per request.

Two helpers, both deterministic functions of the documented
evidence fields:

* :func:`enrich_detection`   - composes the per-detection
  ``SeverityBand`` via the real SeverityEngine and carries the
  supporting event's provenance pointer onto the detection.
* :func:`enrich_correlation` - composes the per-correlation
  ``ConfidenceBand`` via the real SeverityEngine.

Both return a copy of the frozen input model (the input is never
mutated — original evidence is never rewritten). Failures inside
the severity engine leave the band empty ("" -> wire ``null`` /
UI "UNRATED") and are logged; enrichment NEVER fabricates a band
and NEVER blocks persistence.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from ..domain.security_event import SecurityEvent
from .engine import SeverityEngine
from .models import (
    ConfidenceAssessment,
    SeverityAssessment,
    SeverityAssessmentSubject,
)

_log = logging.getLogger(__name__)

_ENGINE = SeverityEngine()


def enrich_detection(
    detection: Any,
    event: Optional[SecurityEvent],
    *,
    now: Optional[datetime] = None,
) -> Any:
    """Return a copy of ``detection`` with severity + source provenance.

    * ``severity``  - the SeverityEngine's per-detection band for
      this exact detection (given the supporting event when the
      caller has it — the engine's evidence-completeness signal then
      reflects the real lookup).
    * ``source_instance_id`` - the ingesting source instance recorded
      on the event's provenance (empty when the event arrived
      without source-management).
    * ``capability_id`` - the **server-derived** capability recorded on
      the event's provenance (Phase 5.2 §8/§12). Empty when the
      supporting event carries no derived capability; it is never
      taken from the request payload or from the rule definition.
    """
    if detection is None:
        return None
    source_instance_id = ""
    capability_id = ""
    if event is not None:
        source_instance_id = str(
            getattr(getattr(event, "provenance", None),
                    "source_instance_id", "") or "",
        )[:96]
        # Phase 5.2 (§8/§12): carry the **server-derived** capability of the
        # supporting evidence onto the detection. The value is read from the
        # event's provenance only — the ingress boundary is the single
        # place that decides it (from the authenticated SourceInstance), so
        # a detection cannot self-declare an owner the evidence never had.
        # Deliberate note on §8's wording ("copied from rule at fire time"):
        # for a capability-owned rule the two values are *always* equal by
        # construction, because RuleMetadata.matches_capability only lets a
        # capability-owned rule fire when the event's capability equals the
        # rule's. Reading the event instead of the rule means a legacy rule
        # (no capability of its own) cannot stamp a capability it does not
        # own, which is strictly stronger provenance.
        capability_id = str(
            getattr(getattr(event, "provenance", None),
                    "capability_id", "") or "",
        )[:64]
    severity = ""
    try:
        events_map: Dict[str, SecurityEvent] = (
            {event.event_id: event} if event is not None else {}
        )
        result = _ENGINE.run(
            detections=[detection], events=events_map, now=now,
        )
        for assessment in result.severity_assessments:
            if (
                assessment.subject_kind
                is SeverityAssessmentSubject.DETECTION
                and assessment.subject_id == detection.detection_id
            ):
                severity = assessment.band.value
                break
    except Exception as exc:  # noqa: BLE001 - never block persistence
        _log.warning(
            "severity.detection_enrichment_failed",
            extra={
                "detection_id": getattr(detection, "detection_id", "?"),
                "error_type": type(exc).__name__,
            },
        )
    return detection.model_copy(update={
        "severity": severity,
        "source_instance_id": source_instance_id,
        "capability_id": capability_id,
    })


def enrich_correlation(correlation: Any, *, now: Optional[datetime] = None) -> Any:
    """Return a copy of ``correlation`` with the composed confidence band."""
    if correlation is None:
        return None
    confidence = ""
    try:
        result = _ENGINE.run(correlations=[correlation], now=now)
        for assessment in result.confidence_assessments:
            if (
                assessment.subject_kind
                is SeverityAssessmentSubject.CORRELATION
                and assessment.subject_id == correlation.correlation_id
            ):
                confidence = assessment.band.value
                break
    except Exception as exc:  # noqa: BLE001 - never block persistence
        _log.warning(
            "severity.correlation_enrichment_failed",
            extra={
                "correlation_id": getattr(
                    correlation, "correlation_id", "?"
                ),
                "error_type": type(exc).__name__,
            },
        )
    return correlation.model_copy(update={"confidence": confidence})


__all__ = ["enrich_correlation", "enrich_detection"]
