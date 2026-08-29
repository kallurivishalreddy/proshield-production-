"""ProShield correlation engine (Phase 4.5).

The correlation engine is the **centralized** cross-event layer that
sits above the per-event detection engine
(``app/detection/engine.py``) and is responsible for grouping
multiple ``Detection`` records into a single, evidence-backed
**Correlation** result.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 66, 87-91), and
           docs/PHASE 4/PHASE 4-01-04-CORE-REVIEW.md (Phase 4.5 handoff).

Why centralization matters
--------------------------

The detection engineering document is explicit (Section 87):
"rules must not carry state that varies between calls in a way
that produces non-deterministic evaluations." Per-event rules
deliberately do NOT count, window, or group. Correlation is a
**separate layer** that consumes per-event detections and groups
them. Centralization has three documented benefits:

1. **No cross-rule coupling** — correlation reads only Detection
   records; individual rules and connectors never see each other.
2. **Connector-agnostic** — the same correlation engine will work
   for the future WAF, rate-limiter, TLS/network, IAM, and SIEM
   connectors because it operates on canonical Detection records,
   not on connector-specific telemetry.
3. **Deterministic + auditable** — the correlation input is the
   finite, time-bounded set of Detections matching a correlation
   pattern's keys; the output is a frozen, BSON-safe
   :class:`Correlation` record with explicit evidence references.

What this layer DOES
--------------------

* Define the :class:`Correlation` and :class:`CorrelationResult`
  contract (frozen, BSON-safe, evidence-referencing).
* Define the :class:`CorrelationEngine` — a deterministic, total,
  in-memory grouping engine that consumes a stream of Detection
  records plus a finite correlation-pattern catalogue and produces
  Correlation records.
* Define a **single, defensible** correlation pattern
  (:class:`BruteForceClusteringPattern`) derived from the observed
  NGINX telemetry. Cross-source patterns (WAF + NGINX, etc.) are
  explicitly **deferred** because the WAF, network, and
  rate-limiter connectors do not exist in the MVP; inventing
  cross-source correlation would invent evidence (forbidden by the
  correlation rules of evidence).

What this layer DOES NOT do
---------------------------

* It does NOT replace the per-event detection engine. Per-event
  detection remains the authoritative source of *what was
  observed*; correlation groups *related observations*.
* It does NOT assign severity, confidence, or routing. Those
  belong to the future severity / confidence / incident / routing
  engines (the report's Section 6 lists the deferrals).
* It does NOT call out to pymongo, FastAPI, the network, or any
  per-connector logic. The engine is pure in-memory grouping
  over a provided sequence of :class:`app.detection.models.Detection`
  records. Persistence is the responsibility of the calling
  service (``app/detection/pipeline.py`` / Phase 4.5 wiring).
* It does NOT carry hidden state across calls. Every
  :class:`CorrelationEngine` instance is constructed fresh per
  call site; the engine reads the catalogue and the input
  detections on every invocation.
* It does NOT use AI, ML, or statistical inference. Every
  correlation decision is a deterministic, threshold-based group
  over a documented key-set and time window.
"""
from __future__ import annotations

from .engine import CorrelationEngine
from .errors import (
    CorrelationError,
    CorrelationKeyError,
    CorrelationWindowError,
    InvalidCorrelationInputError,
)
from .models import (
    Correlation,
    CorrelationKey,
    CorrelationResult,
    CorrelationTrigger,
)
from .patterns import BruteForceClusteringPattern, CorrelationPattern

__all__ = [
    "BruteForceClusteringPattern",
    "Correlation",
    "CorrelationEngine",
    "CorrelationError",
    "CorrelationKey",
    "CorrelationKeyError",
    "CorrelationPattern",
    "CorrelationResult",
    "CorrelationTrigger",
    "CorrelationWindowError",
    "InvalidCorrelationInputError",
]
