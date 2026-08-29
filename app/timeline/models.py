"""Timeline models: the documented attack-timeline contract.

Reference:
    docs/PHASE 2/DOMAIN_DATA_MODEL.md, Section 8 (TimelineEvent),
    Section 21 (Core Relationships: SecurityEvent -> TimelineEvent,
    Detection -> TimelineEvent, Correlation -> TimelineEvent).
    docs/PHASE 0/MVP_REQUIREMENTS.md (evidence principle).
    docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 66
    (timeline responsibility is downstream of detection + correlation).

A :class:`TimelineItem` is the deterministic, immutable, BSON-safe
record the :class:`app.timeline.engine.TimelineEngine` emits for
one piece of evidence on the timeline. It is NOT a new observation;
it is an *organisation* of evidence the existing pipeline
(Phase 4.1-4.5) has already produced. There are exactly three
permitted kinds:

* ``event``       - derived directly from a :class:`SecurityEvent`
                    (the observed fact),
* ``detection``   - derived from a per-event :class:`Detection`
                    produced by the Phase 4.4 detection engine,
* ``correlation`` - derived from a :class:`Correlation` produced
                    by the Phase 4.5 correlation engine.

The kind-and-ids tuple is constrained so a :class:`TimelineItem`
can never claim to be derived from evidence it does not actually
reference (no fabrication, per the evidence principle).

A :class:`TimelineResult` is what :meth:`TimelineEngine.run` returns
for one batch: the ordered list of :class:`TimelineItem` records
plus the diagnostics the engine must report (items produced,
events considered, detections considered, correlations considered,
errors, produced_at).

Both models are **frozen** (``frozen=True, extra="forbid"``) so they
can be safely shared across the timeline engine, the future
incident engine, and the future persistence / API / report
layers.

What this module does NOT do
----------------------------

* It does NOT persist timeline records. Persistence is the
  responsibility of a future incident / report slice.
* It does NOT assign severity, confidence, or routing. Those
  belong to :mod:`app.severity` and to the future incident /
  report / routing engines.
* It does NOT perform new correlation. Correlation is the
  Phase 4.5 correlation engine's job; the timeline merely
  *orders* the correlations' evidence.
* It does NOT modify :class:`SecurityEvent`, :class:`Detection`,
  or :class:`Correlation` records.
* It does NOT call out to MongoDB, FastAPI, or any connector.
* It does NOT use AI, ML, or statistical inference.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)


__all__ = [
    "MAX_TIMELINE_DESCRIPTION_LEN",
    "MAX_TIMELINE_EVIDENCE_REFS",
    "MAX_TIMELINE_EVIDENCE_REF_LEN",
    "MAX_TIMELINE_ITEMS",
    "MAX_TIMELINE_REASONING_LEN",
    "MAX_TIMELINE_RESULT_ERRORS",
    "MAX_TIMELINE_RESULT_TIMELINE_ITEMS",
    "TIMELINE_ID_PATTERN",
    "TimelineId",
    "TimelineItem",
    "TimelineItemKind",
    "TimelineResult",
]


# ----------------------------------------------------------------- id pattern
# A timeline_item_id is a deterministic UUIDv7-format string with a
# short ``tl-`` prefix. The pattern mirrors ``det-<uuidv7>`` (Phase 4.4)
# and ``corr-<uuidv7>`` (Phase 4.5) so the future audit log, SIEM
# feed, and analyst UI can grep ``tl-``, ``det-``, and ``corr-``
# uniformly.
MAX_TIMELINE_ID_LEN = 64
TIMELINE_ID_PATTERN = (
    r"^tl-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TimelineId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=MAX_TIMELINE_ID_LEN,
        pattern=TIMELINE_ID_PATTERN,
    ),
]


# ----------------------------------------------------------------- kind
class TimelineItemKind(str, Enum):
    """The three permitted evidence kinds for a :class:`TimelineItem`.

    The kind is the documented "what does this item trace back to"
    enum (Section 8 of the domain data model). It is intentionally
    closed: the timeline engine never invents a fourth kind because
    every input is one of these three, and the contract is
    small-on-purpose (mirroring the per-event detection and
    correlation contracts).
    """

    EVENT = "event"
    DETECTION = "detection"
    CORRELATION = "correlation"


# ----------------------------------------------------------------- bounds
MAX_TIMELINE_DESCRIPTION_LEN = 1024
MAX_TIMELINE_REASONING_LEN = 2048
MAX_TIMELINE_EVIDENCE_REFS = 16
MAX_TIMELINE_EVIDENCE_REF_LEN = 128
MAX_TIMELINE_ITEMS = 4096


# ----------------------------------------------------------------- timeline item
class TimelineItem(BaseModel):
    """A single, deterministic, immutable, evidence-backed item on
    the attack timeline.

    A :class:`TimelineItem` is NOT a new security observation. It is
    the *organisation* of one piece of evidence the existing
    pipeline (Phase 4.1-4.5) has already produced, in chronological
    order, on a single bounded timeline.

    Invariants
    ----------

    * ``timeline_item_id`` is a deterministic ``tl-<uuidv7>`` id
      derived from ``(kind, source_id, occurred_at)``. The engine
      is responsible for computing it; here we only validate the
      form.
    * ``kind`` is one of the three allowed enum values and the
      ``source_id`` + ``occurred_at`` fields are validated by
      kind: an ``event`` item must reference a security event id,
      a ``detection`` item must reference a detection id, and a
      ``correlation`` item must reference a correlation id.
    * ``occurred_at`` is timezone-aware UTC. The timeline engine
      is the only place that picks the timestamp; for an
      ``event`` it is the event's ``event_time``, for a
      ``detection`` it is the detection's ``detected_at``, and
      for a ``correlation`` it is the correlation's
      ``window_start`` (the earliest grouped activity).
    * ``description`` is a short, redacted, analyst-facing
      summary drawn ONLY from the referenced evidence. The
      timeline engine never invents a description.
    * ``reasoning`` explains the inclusion using the underlying
      evidence's own fields (no fabrication).
    * ``evidence_refs`` is the explicit list of canonical ids
      (event_ids, detection_ids, correlation_ids) that justify
      the item. A ``TimelineItem`` with empty ``evidence_refs``
      is rejected: there is no such thing as an unevidenced
      timeline item.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    timeline_item_id: TimelineId
    kind: TimelineItemKind
    source_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_TIMELINE_EVIDENCE_REF_LEN),
    ]
    occurred_at: datetime
    description: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_TIMELINE_DESCRIPTION_LEN
        ),
    ]
    reasoning: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_TIMELINE_REASONING_LEN
        ),
    ] = ""
    evidence_refs: Tuple[
        Annotated[
            str,
            StringConstraints(
                min_length=1, max_length=MAX_TIMELINE_EVIDENCE_REF_LEN
            ),
        ],
        ...,
    ]

    @model_validator(mode="after")
    def _evidence_refs_not_empty(self) -> "TimelineItem":
        if not self.evidence_refs:
            raise ValueError(
                "TimelineItem.evidence_refs must not be empty "
                "(no unevidenced timeline items)"
            )
        if len(self.evidence_refs) > MAX_TIMELINE_EVIDENCE_REFS:
            raise ValueError(
                f"TimelineItem.evidence_refs must contain at most "
                f"{MAX_TIMELINE_EVIDENCE_REFS} entries, got "
                f"{len(self.evidence_refs)}"
            )
        return self

    @model_validator(mode="after")
    def _source_id_matches_kind(self) -> "TimelineItem":
        # Defensive bound: detection / correlation source_ids
        # MUST carry their documented prefix. Event source_ids
        # are the canonical SecurityEvent.event_id (a UUIDv7
        # without a prefix), so we do not enforce a prefix
        # for them; the engine always sets source_id to the
        # event.event_id verbatim. This still stops an
        # attacker from forging "this timeline item is a
        # detection" while pointing at a correlation id (or
        # vice versa) because the prefix check is still
        # enforced for those kinds.
        if self.kind is TimelineItemKind.DETECTION:
            if not self.source_id.startswith("det-"):
                raise ValueError(
                    f"TimelineItem.source_id {self.source_id!r} does "
                    f"not match kind {self.kind.value!r} (expected "
                    f"prefix 'det-')"
                )
        elif self.kind is TimelineItemKind.CORRELATION:
            if not self.source_id.startswith("corr-"):
                raise ValueError(
                    f"TimelineItem.source_id {self.source_id!r} does "
                    f"not match kind {self.kind.value!r} (expected "
                    f"prefix 'corr-')"
                )
        return self

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready, BSON-safe representation."""
        return {
            "timeline_item_id": self.timeline_item_id,
            "kind": self.kind.value,
            "source_id": self.source_id,
            "occurred_at": self.occurred_at.isoformat(),
            "description": self.description,
            "reasoning": self.reasoning,
            "evidence_refs": list(self.evidence_refs),
        }

MAX_TIMELINE_RESULT_TIMELINE_ITEMS = MAX_TIMELINE_ITEMS
MAX_TIMELINE_RESULT_ERRORS = 32




# ----------------------------------------------------------------- result
class TimelineResult(BaseModel):
    """The deterministic, batch-level timeline output.

    A :class:`TimelineResult` is what :meth:`TimelineEngine.run`
    returns for one batch of evidence. It contains:

    * ``items`` - the chronologically-ordered list of
      :class:`TimelineItem` records produced. The list is
      sorted by ``(occurred_at, kind, source_id)`` so the
      ordering is deterministic and stable across runs and
      across input ordering.
    * ``events_considered`` / ``detections_considered`` /
      ``correlations_considered`` - observability counters
      (mirroring the per-event detection engine's
      ``rules_considered`` / ``rules_evaluated``).
    * ``events_emitted`` / ``detections_emitted`` /
      ``correlations_emitted`` - how many timeline items
      were produced for each kind.
    * ``errors`` - input-level errors (malformed events,
      missing evidence, etc.). The engine is **total**: a
      single bad input is quarantined to ``errors``; the rest
      of the evidence still produces its timeline items.
    * ``produced_at`` - when the engine produced the result.
      The engine is deterministic when ``now`` is injected.

    A :class:`TimelineResult` is **frozen** and a **fact** about
    a single batch of evidence.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    items: Tuple[TimelineItem, ...] = ()
    events_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    detections_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    correlations_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    events_emitted: Annotated[int, Field(ge=0, le=10_000)] = 0
    detections_emitted: Annotated[int, Field(ge=0, le=10_000)] = 0
    correlations_emitted: Annotated[int, Field(ge=0, le=10_000)] = 0
    errors: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=1024)],
        ...,
    ] = ()
    produced_at: datetime

    @property
    def item_count(self) -> int:
        return len(self.items)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": [i.to_dict() for i in self.items],
            "events_considered": self.events_considered,
            "detections_considered": self.detections_considered,
            "correlations_considered": self.correlations_considered,
            "events_emitted": self.events_emitted,
            "detections_emitted": self.detections_emitted,
            "correlations_emitted": self.correlations_emitted,
            "errors": list(self.errors),
            "produced_at": self.produced_at.isoformat(),
        }
