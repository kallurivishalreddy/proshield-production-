"""Correlation models: the cross-event correlation contract.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 66, 87-91).

This module is the *correlation contract*. It is to the
correlation engine what :mod:`app.detection.models` is to the
per-event detection engine:

* A :class:`Correlation` is a frozen, immutable, BSON-safe
  record that one correlation pattern produced, pointing to the
  per-event detections that justified it.
* A :class:`CorrelationResult` is what the engine returns to its
  caller: the produced correlations, the patterns that were
  evaluated, and any errors (mirroring the per-event
  :class:`DetectionResult`).

The contract is intentionally small, on purpose, mirroring the
per-event detection contract (Sections 8, 9, 13, 87):

* ``correlation_id`` — deterministic UUIDv7 ``corr-<uuidv7>`` id
  derived from the inputs (pattern id, detection ids, key,
  window). The same inputs produce the same id; this is the
  audit-friendly determinism that the detection engine already
  established for ``detection_id`` (Phase 4.4 D-2 fix).
* ``pattern_id`` + ``pattern_version`` — which correlation
  pattern produced the record.
* ``key`` — the correlation key the pattern used to group the
  underlying detections.
* ``detection_ids`` — every per-event detection that participated
  (the correlation's evidence; mirrors ``detection.evidence_refs``
  but for the *event* level).
* ``event_ids`` — every underlying SecurityEvent (derived from
  the detection set; the canonical events are the ultimate
  evidence).
* ``window_start`` / ``window_end`` — the time window the
  pattern's grouping covered (UTC, timezone-aware).
* ``count`` — number of detections grouped.
* ``reasoning`` — a short, redacted, analyst-facing string.
* ``extra`` — pattern-specific structured metadata (BSON-safe
  primitives only).
* ``correlated_at`` — when the engine produced the correlation.

Both models are **frozen** (``frozen=True, extra="forbid"``) so
they can be safely shared across the correlation engine, the
future incident engine, the future persistence layer, and the
future routing / report / SIEM feed layers.

What this module does NOT do
----------------------------

* It does NOT assign severity, confidence, or routing.
* It does NOT persist correlations. The engine produces them; a
  future slice owns persistence, indexing, and the
  ``correlation_id`` -> document mapping.
* It does NOT call out to MongoDB, the network, or any connector.
  The engine is pure in-memory grouping.
* It does NOT use AI, ML, or statistical inference.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, FrozenSet, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from ..detection.models import DetectionId, MAX_DETECTION_ID_LEN


# Re-export the detection id type for callers that want a single import
# surface for correlation evidence.
__all__ = [
    "Correlation",
    "CorrelationId",
    "CorrelationKey",
    "CorrelationResult",
    "CorrelationTrigger",
    "CentralizedCorrelationResult",
    "EventId",
    "MAX_CORRELATION_CAPABILITIES",
    "MAX_CORRELATION_REASONING_LEN",
]


# ----------------------------------------------------------------- centralized
class CentralizedCorrelationResult(BaseModel):
    """The Phase 4.8 centralized-analysis result.

    A :class:`CentralizedCorrelationResult` is what
    :meth:`CorrelationEngine.run_centralized` returns.
    It is a thin extension of :class:`CorrelationResult`
    carrying:

    * ``new_correlations`` - the correlations produced by
      the engine that are NOT in
      ``existing_correlation_ids``. The incident service
      uses this set to build the case's centralized
      context without walking the existing catalogue.
    * ``existing_correlation_ids`` - the snapshot of the
      ids the engine was told were already in the case;
      the orchestrator can use this for diagnostics.

    The ``correlations`` field is the union of the
    existing + new correlations (deduped, original order
    preserved).

    A :class:`CentralizedCorrelationResult` is **frozen**
    and a **fact** about one analyst-requested centralized
    run.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    correlations: Tuple[Correlation, ...] = ()
    new_correlations: Tuple[Correlation, ...] = ()
    patterns_considered: Annotated[
        int, Field(ge=0, le=MAX_CORRELATION_RESULT_PATTERNS)
    ] = 0
    patterns_evaluated: Annotated[
        int, Field(ge=0, le=MAX_CORRELATION_RESULT_PATTERNS)
    ] = 0
    detections_consumed: Annotated[int, Field(ge=0, le=10_000)] = 0
    errors: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=1024)],
        ...,
    ] = ()
    produced_at: datetime
    existing_correlation_ids: FrozenSet[str] = frozenset()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlations": [c.to_dict() for c in self.correlations],
            "new_correlations": [c.to_dict() for c in self.new_correlations],
            "patterns_considered": self.patterns_considered,
            "patterns_evaluated": self.patterns_evaluated,
            "detections_consumed": self.detections_consumed,
            "errors": list(self.errors),
            "produced_at": self.produced_at.isoformat(),
            "existing_correlation_ids": sorted(
                self.existing_correlation_ids
            ),
        }


# ----------------------------------------------------------------- id pattern
# A correlation_id is a deterministic UUIDv7-format string with a
# short ``corr-`` prefix. The pattern mirrors ``det-<uuidv7>``
# (Phase 4.4) so a future persistence layer, audit log, or SIEM
# feed can grep ``corr-`` and ``det-`` uniformly.
MAX_CORRELATION_ID_LEN = 64
CORRELATION_ID_PATTERN = (
    r"^corr-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CorrelationId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=MAX_CORRELATION_ID_LEN,
        pattern=CORRELATION_ID_PATTERN,
    ),
]


# The canonical SecurityEvent's event_id is a UUIDv7-formatted
# string of bounded length. We mirror the constraint used in
# ``app.detection.models.Detection.event_id`` so a correlation's
# event_ids list is BSON-safe and grep-friendly.
EventId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_DETECTION_ID_LEN),
]


# ----------------------------------------------------------------- pattern id
# ``pattern_id`` follows the documented rule_id pattern
# (``app/rules/types.py``). The correlation pattern is, in effect,
# a rule that happens to operate on a stream of detections rather
# than a single event; the rule contract already enforces the
# character set we want.
PatternId = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=64,
        pattern=r"^([A-Z][A-Z0-9]*|[0-9]+)(-([A-Z][A-Z0-9]*|[0-9]+))*$",
    ),
]
PatternVersion = Annotated[int, Field(ge=1, le=999_999)]


# ----------------------------------------------------------------- key
MAX_KEY_PART_LEN = 64
MAX_KEY_PARTS = 8


class CorrelationKey(BaseModel):
    """A correlation key — the (possibly multi-part) identifier the
    pattern uses to group detections.

    The shape is intentionally small and JSON-shaped. Each part is
    a string of bounded length. The string rendering of a key is
    the canonical form used for grouping and for evidence display
    in the analyst-facing reasoning.

    A correlation key for the brute-force clustering pattern
    carries two parts:

    * ``source_ip`` — the source IP that produced the grouped
      auth failures,
    * ``endpoint`` — the redacted endpoint those failures
      targeted.

    Empty parts are rejected at construction; a key with no
    parts is rejected. The engine never invents a key value
    for a missing field — it skips the detection instead (see
    ``app/correlation/engine.py``).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    parts: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=MAX_KEY_PART_LEN)],
        ...,
    ]

    @property
    def as_tuple(self) -> Tuple[str, ...]:
        """The key as a plain tuple (hashable, dict-key-friendly)."""
        return self.parts

    def __str__(self) -> str:
        return "|".join(self.parts)

    @field_validator("parts")
    @classmethod
    def _at_least_one_part(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("CorrelationKey must have at least one part")
        if len(v) > MAX_KEY_PARTS:
            raise ValueError(
                f"CorrelationKey has too many parts ({len(v)} > {MAX_KEY_PARTS})"
            )
        return v


# ----------------------------------------------------------------- trigger
# A trigger is a stable enumeration of WHY a correlation fired.
# It is the documented input to the future severity / confidence
# engines (Section 66). Correlations produced by the Phase 4.5
# brute-force pattern always have the trigger
# ``brute_force_count_threshold``; future patterns can add their
# own without changing the model.
MAX_TRIGGER_LEN = 64

_ALLOWED_TRIGGERS: frozenset[str] = frozenset(
    {
        # Brute-force clustering: >=N auth failures from same
        # source_ip to same auth-shaped endpoint within window.
        "brute_force_count_threshold",
    }
)


def _validate_trigger(v: str) -> str:
    if v not in _ALLOWED_TRIGGERS:
        raise ValueError(
            f"trigger {v!r} is not a documented correlation trigger; "
            f"allowed: {sorted(_ALLOWED_TRIGGERS)}"
        )
    return v


CorrelationTrigger = Annotated[
    str,
    StringConstraints(min_length=3, max_length=MAX_TRIGGER_LEN),
]

# Use a field validator via a small Pydantic-friendly wrapper so the
# trigger allow-list is enforced at construction time. We expose a
# plain helper rather than a model field because :class:`Correlation`
# uses ``CorrelationTrigger`` as a typed annotation; a free function
# keeps the constraint visible at the call site.
validate_trigger = _validate_trigger


# ----------------------------------------------------------------- correlation
MAX_CORRELATION_REASONING_LEN = 2048
MAX_CORRELATION_DETECTIONS = 256
MAX_CORRELATION_EVENTS = 256
MAX_CORRELATION_EXTRA = 16
# Phase 5.2 (§8/§12): bound on the derived ``capability_ids`` tuple. A
# correlation groups detections that all share one capability in practice;
# the bound exists so a future multi-capability pattern cannot store an
# unbounded list, mirroring the ``MAX_CORRELATION_EXTRA`` D-4 fix.
MAX_CORRELATION_CAPABILITIES = 16


class Correlation(BaseModel):
    """A single, evidence-backed cross-event correlation record.

    A :class:`Correlation` is the correlation engine's documented
    output. It is the **fact** that "the inputs to this pattern
    were grouped and met the pattern's threshold" — nothing more,
    nothing less. Severity, confidence, incident creation,
    routing, and reporting are all the responsibility of later
    slices.

    The :attr:`detection_ids` and :attr:`event_ids` lists are the
    correlation's **evidence**. They make every correlation
    traceable: an analyst can read the correlations for an
    incident and immediately see which per-event detections and
    underlying SecurityEvents backed the grouping.

    :class:`Correlation` is **frozen** and a **fact**.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    correlation_id: CorrelationId
    pattern_id: PatternId
    pattern_version: PatternVersion
    trigger: CorrelationTrigger
    key: CorrelationKey
    detection_ids: Tuple[DetectionId, ...]
    event_ids: Tuple[EventId, ...]
    window_start: datetime
    window_end: datetime
    count: Annotated[int, Field(ge=1, le=MAX_CORRELATION_DETECTIONS)]
    reasoning: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_CORRELATION_REASONING_LEN),
    ]
    correlated_at: datetime
    # D-4 fix: enforce the documented ``MAX_CORRELATION_EXTRA``
    # bound at the model layer so that a future pattern cannot
    # silently store an unbounded ``extra`` payload (which would
    # bypass the documented pattern metadata contract).
    extra: Annotated[
        Tuple[Tuple[str, Any], ...],
        Field(max_length=MAX_CORRELATION_EXTRA),
    ] = ()
    # Capability patch gap 6: the documented ConfidenceBand composed
    # by the SeverityEngine at persistence time. Empty = not composed
    # (the wire renders null; the UI renders "—" — never a fabricated
    # number). The engine itself still does NOT assign confidence:
    # composition happens at the documented severity layer.
    confidence: Annotated[str, StringConstraints(max_length=32)] = ""
    # Capability patch gap 2: allocator-assigned human id
    # (``CORR-000001``), assigned at persistence time. Not part of the
    # deterministic ``correlation_id`` derivation.
    human_id: Annotated[str, StringConstraints(max_length=32)] = ""
    # Phase 5.2 (§8, §12): the capabilities that owned the member
    # detections, derived from those detections (never from the pattern
    # or the request). Stored sorted + de-duplicated so the value is
    # deterministic and replay-stable. An empty tuple means no member
    # detection carried a derived capability (pre-5.2 evidence, or an
    # event ingested outside the binding-aware ingress) — the wire
    # renders ``null`` rather than inventing an owner. An empty *item*
    # is rejected outright (the item pattern requires a well-formed
    # ``cap-*`` id); the producer filters blanks before constructing.
    # Like ``human_id`` this is NOT part of the ``correlation_id``
    # derivation.
    capability_ids: Annotated[
        Tuple[
            Annotated[
                str,
                StringConstraints(
                    max_length=64, pattern=r"^cap-[a-z][a-z0-9-]{1,47}$"
                ),
            ],
            ...,
        ],
        Field(max_length=MAX_CORRELATION_CAPABILITIES),
    ] = ()

    @field_validator("trigger")
    @classmethod
    def _check_trigger(cls, v: str) -> str:
        return _validate_trigger(v)

    @field_validator("detection_ids")
    @classmethod
    def _at_least_one_detection(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("Correlation must reference at least one detection")
        if len(v) > MAX_CORRELATION_DETECTIONS:
            raise ValueError(
                f"too many detection_ids ({len(v)} > {MAX_CORRELATION_DETECTIONS})"
            )
        # De-duplicate while preserving order so the caller's
        # evidence list is stable.
        seen: set = set()
        out: list = []
        for d in v:
            if d not in seen:
                seen.add(d)
                out.append(d)
        return tuple(out)

    @field_validator("event_ids")
    @classmethod
    def _bounded_event_ids(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_CORRELATION_EVENTS:
            raise ValueError(
                f"too many event_ids ({len(v)} > {MAX_CORRELATION_EVENTS})"
            )
        return v

    @field_validator("capability_ids")
    @classmethod
    def _normalise_capability_ids(
        cls, v: Tuple[str, ...]
    ) -> Tuple[str, ...]:
        """De-duplicate and sort so the derived list is deterministic.

        ``capability_ids`` is *derived* from the member detections; sorting
        keeps the stored value replay-stable regardless of detection order.
        The producer already drops blanks, so an empty item never reaches
        here in practice; the comprehension is defence in depth.
        """
        if len(v) > MAX_CORRELATION_CAPABILITIES:
            raise ValueError(
                "too many capability_ids "
                f"({len(v)} > {MAX_CORRELATION_CAPABILITIES})"
            )
        return tuple(sorted({c for c in v if c}))

    @field_validator("window_end")
    @classmethod
    def _window_end_after_start(cls, v: datetime, info) -> datetime:
        start = info.data.get("window_start")
        if start is not None and v < start:
            raise ValueError("window_end must be >= window_start")
        return v

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready, BSON-safe representation."""
        return {
            "correlation_id": self.correlation_id,
            "pattern_id": self.pattern_id,
            "pattern_version": self.pattern_version,
            "trigger": self.trigger,
            "key": list(self.key.parts),
            "detection_ids": list(self.detection_ids),
            "event_ids": list(self.event_ids),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "count": self.count,
            "reasoning": self.reasoning,
            "confidence": self.confidence or None,
            "human_id": self.human_id or None,
            "capability_ids": list(self.capability_ids),
            "correlated_at": self.correlated_at.isoformat(),
            "extra": dict(self.extra),
        }


# ----------------------------------------------------------------- result
MAX_CORRELATION_RESULT_PATTERNS = 32
MAX_CORRELATION_RESULT_ERRORS = 32


class CorrelationResult(BaseModel):
    """The deterministic, batch-level correlation output.

    A :class:`CorrelationResult` is what the
    :class:`app.correlation.engine.CorrelationEngine` returns for
    a single call. It contains:

    * ``correlations`` — the list of :class:`Correlation` records
      produced (empty if no pattern matched).
    * ``patterns_considered`` — number of correlation patterns
      the engine looked at.
    * ``patterns_evaluated`` — number of patterns the engine
      actually grouped detections under.
    * ``detections_consumed`` — number of input detections the
      engine processed.
    * ``errors`` — pattern- or engine-level errors. A pattern
      that raises during grouping is quarantined here; the rest
      of the patterns still produce their correlations. The
      correlation engine is **fail-closed per pattern but not per
      pipeline**: the pipeline is total.
    * ``produced_at`` — when the engine produced the result. The
      engine is deterministic when ``now`` is injected.

    A :class:`CorrelationResult` is **frozen** and a **fact** about
    a single batch of detections.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    correlations: Tuple[Correlation, ...] = ()
    patterns_considered: Annotated[
        int, Field(ge=0, le=MAX_CORRELATION_RESULT_PATTERNS)
    ] = 0
    patterns_evaluated: Annotated[
        int, Field(ge=0, le=MAX_CORRELATION_RESULT_PATTERNS)
    ] = 0
    detections_consumed: Annotated[int, Field(ge=0, le=10_000)] = 0
    errors: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=1024)],
        ...,
    ] = ()
    produced_at: datetime

    @property
    def correlation_count(self) -> int:
        return len(self.correlations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlations": [c.to_dict() for c in self.correlations],
            "patterns_considered": self.patterns_considered,
            "patterns_evaluated": self.patterns_evaluated,
            "detections_consumed": self.detections_consumed,
            "errors": list(self.errors),
            "produced_at": self.produced_at.isoformat(),
        }
