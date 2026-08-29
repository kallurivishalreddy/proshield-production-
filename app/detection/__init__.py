"""ProShield detection engine package (Phase 4.4 + 4.5).

Phase 4.4 ships the **deterministic per-event detection engine**:

* :class:`app.detection.engine.DetectionEngine` -- the per-event
  evaluation pipeline that selects applicable approved+enabled
  rules for a canonical ``SecurityEvent``, calls ``Rule.evaluate``
  on each, and translates the matched ``RuleEvaluation`` results
  into frozen :class:`app.detection.models.Detection` records.
* :class:`app.detection.models.Detection` -- the documented
  detection contract (DET-07, DET-08). Frozen, immutable, BSON-safe.
* :class:`app.detection.models.DetectionResult` -- the per-event
  output of the engine (the result of one canonical event flowing
  through the documented "SecurityEvent -> identify source ->
  identify event type -> select applicable rules -> run relevant
  rules -> create detections" pipeline, Section 12).

Phase 4.5 adds:

* :class:`app.detection.pipeline.DetectionPipeline` -- the
  documented wiring of ingestion -> detection engine -> detection
  persistence. The pipeline is total: persistence failures for a
  detection are logged, not raised.
* :class:`app.detection.pipeline.PipelineResult` -- the per-event
  pipeline output.

The engine is the single source of truth for "which rules fired
on this event, and what did they observe". It is **deliberately
per-event**. Cross-event state, time windows, counts, and grouping
are the responsibility of the correlation engine (Phase 4.5
companion package, ``app.correlation``).

The engine does NOT implement:

* the correlation engine (Sections 14-17);
* the timeline / severity / confidence engines;
* the incident engine, the report engine, the routing engine, the
  audit engine, the AI engine, or the HTTP API surfaces.
* correlation persistence (a future slice).
"""
from __future__ import annotations

from .engine import DetectionEngine
from .errors import (
    DetectionEngineError,
    DetectionError,
    DetectionIdGenerationError,
    InvalidEventError,
    NoRuleRegistryError,
)
from .models import Detection, DetectionResult
from .pipeline import DetectionPipeline, PipelineResult

__all__ = [
    "Detection",
    "DetectionEngine",
    "DetectionEngineError",
    "DetectionError",
    "DetectionIdGenerationError",
    "DetectionPipeline",
    "DetectionResult",
    "InvalidEventError",
    "NoRuleRegistryError",
    "PipelineResult",
]