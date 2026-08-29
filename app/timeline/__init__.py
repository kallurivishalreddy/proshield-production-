"""ProShield attack-timeline engine (Phase 4.6).

The timeline engine is the **dedicated timeline component**
sitting between the Phase 4.5 correlation engine and the
future Phase 4.7 incident engine. It is responsible for
organising the evidence already produced by:

* the Phase 4.1 ingestion layer (the :class:`SecurityEvent`
  records - the *observed* facts),
* the Phase 4.4 per-event detection engine (the
  :class:`Detection` records - the per-event derived
  intelligence), and
* the Phase 4.5 cross-event correlation engine (the
  :class:`Correlation` records - the cross-event derived
  intelligence),

chronologically, on a single bounded timeline. The engine is
**deterministic**, **pure**, **total**, and **fail-closed per
item**: a single bad input is quarantined to
:class:`TimelineResult.errors`; the rest of the evidence still
produces its timeline items.

Reference:
    docs/PHASE 2/DOMAIN_DATA_MODEL.md, Section 8 (TimelineEvent)
    and Section 21 (Core Relationships).
    docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
    Section 66 (timeline responsibility is downstream of
    detection + correlation).
    docs/PHASE 0/MVP_REQUIREMENTS.md (evidence principle).

What this layer DOES
--------------------

* Define the :class:`TimelineItem` and :class:`TimelineResult`
  contract (frozen, BSON-safe, evidence-referencing).
* Define the :class:`TimelineEngine` - a deterministic, total,
  in-memory organiser that consumes a stream of
  :class:`SecurityEvent`, :class:`Detection`, and
  :class:`Correlation` records and produces a chronologically
  ordered :class:`TimelineResult`.

What this layer DOES NOT do
---------------------------

* It does NOT perform new correlation. Correlation is the
  Phase 4.5 correlation engine's job; the timeline merely
  *orders* the correlations' evidence.
* It does NOT assign severity, confidence, or routing. Those
  are the responsibilities of the Phase 4.6 severity /
  confidence engine (:mod:`app.severity`) and the future
  incident / routing engines.
* It does NOT call out to pymongo, FastAPI, the network, or
  any per-connector logic. It is pure in-memory organisation
  over a provided sequence of canonical evidence records.
* It does NOT carry hidden state across calls. Every
  :class:`TimelineEngine` instance is constructed fresh per
  call site; the engine reads the input on every invocation.
* It does NOT use AI, ML, or statistical inference. Every
  ordering decision is a deterministic sort of a documented
  sort key.
"""
from __future__ import annotations

from .engine import TimelineEngine
from .errors import (
    InvalidTimelineInputError,
    TimelineError,
    TimelineEvidenceError,
)
from .models import (
    MAX_TIMELINE_DESCRIPTION_LEN,
    MAX_TIMELINE_EVIDENCE_REFS,
    MAX_TIMELINE_EVIDENCE_REF_LEN,
    MAX_TIMELINE_ITEMS,
    MAX_TIMELINE_REASONING_LEN,
    MAX_TIMELINE_RESULT_ERRORS,
    MAX_TIMELINE_RESULT_TIMELINE_ITEMS,
    TIMELINE_ID_PATTERN,
    TimelineId,
    TimelineItem,
    TimelineItemKind,
    TimelineResult,
)

__all__ = [
    "InvalidTimelineInputError",
    "MAX_TIMELINE_DESCRIPTION_LEN",
    "MAX_TIMELINE_EVIDENCE_REFS",
    "MAX_TIMELINE_EVIDENCE_REF_LEN",
    "MAX_TIMELINE_ITEMS",
    "MAX_TIMELINE_REASONING_LEN",
    "MAX_TIMELINE_RESULT_ERRORS",
    "MAX_TIMELINE_RESULT_TIMELINE_ITEMS",
    "TIMELINE_ID_PATTERN",
    "TimelineEngine",
    "TimelineError",
    "TimelineEvidenceError",
    "TimelineId",
    "TimelineItem",
    "TimelineItemKind",
    "TimelineResult",
]
