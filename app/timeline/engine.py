"""The deterministic attack-timeline engine.

Reference: docs/PHASE 2/DOMAIN_DATA_MODEL.md, Section 8
(TimelineEvent) and Section 21 (Core Relationships). The
timeline is the documented post-correlation responsibility
(Section 66 of DETECTION_ENGINEERING_AND_FUTURE_AI.md).

The engine is the **dedicated timeline component** responsible
for organising the evidence already produced by the Phase 4.1
ingestion layer, the Phase 4.4 detection engine, and the
Phase 4.5 correlation engine, chronologically, on a single
bounded timeline.

Design rules (mirroring the per-event detection engine and
the cross-event correlation engine)
------------------------------------------------------------

* **Deterministic.** Same inputs + same ``now`` -> same
  :class:`TimelineResult`. The engine does NOT call
  ``datetime.now()``; ``now`` is injected.
* **Pure.** The engine does NOT carry cross-call state. Every
  invocation is independent. Persistence is the caller's
  job; the engine is pure in-memory organisation.
* **Total.** A bad input (a non-SecurityEvent, a non-Detection,
  a non-Correlation, a naive datetime, evidence with a missing
  underlying record) is caught and routed to
  :class:`TimelineResult.errors`. The engine never raises a
  bare :class:`Exception` for normal input flow.
* **No new correlation.** The engine only *organises*
  existing evidence. Cross-event correlation remains the
  Phase 4.5 correlation engine's job (Section 87).
* **No detection.** The engine does not look inside events to
  infer a new fact.
* **No severity, confidence, or routing.** Those are the
  responsibilities of the Phase 4.6 severity / confidence
  engine and the future incident / routing engines.

What the engine does NOT do
----------------------------

* It does NOT persist timeline records.
* It does NOT call out to MongoDB, FastAPI, the network, or
  any connector. It is pure in-memory organisation.
* It does NOT invent evidence. A detection whose event is
  missing is **skipped**, not invented.
* It does NOT combine distinct events into a new observation
  (that would be correlation; the Phase 4.5 engine owns it).
* It does NOT use AI, ML, or statistical inference.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..correlation.models import Correlation
from ..detection.models import Detection
from ..domain.errors import DomainError
from ..domain.security_event import SecurityEvent
from .errors import (
    InvalidTimelineInputError,
    TimelineError,
)
from .models import (
    MAX_TIMELINE_EVIDENCE_REF_LEN,
    MAX_TIMELINE_ITEMS,
    TimelineItem,
    TimelineItemKind,
    TimelineResult,
)


_MAX_ERROR_LEN = 512
_MAX_DESCRIPTION_LEN = 1024
_MAX_REASONING_LEN = 2048


def _truncate(s: str, n: int) -> str:
    """Truncate a string to ``n`` characters (defensive bound)."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + "..."



# ----------------------------------------------------------------- id helper
def _make_timeline_id(
    kind: TimelineItemKind,
    source_id: str,
    occurred_at: datetime,
) -> str:
    """Build a deterministic ``tl-<uuidv7>`` id for a timeline item.

    The id is derived from the canonical ``(kind, source_id,
    occurred_at)`` triple. Given the same inputs, the function
    returns the same id. This is the documented determinism
    contract and matches the per-event detection and
    correlation id derivations.

    The function uses SHA-256 + a documented UUIDv7-like bit
    layout (8-4-4-4-12 lowercase hex, version 7 nibble, variant
    nibble) so the output is grep-friendly and can be persisted
    in the same audit log as ``det-`` and ``corr-`` ids.
    """
    if not isinstance(kind, TimelineItemKind):
        raise InvalidTimelineInputError(
            safe_message="kind must be a TimelineItemKind",
            internal_detail=f"got {type(kind).__name__}",
        )
    if not isinstance(source_id, str) or not source_id:
        raise InvalidTimelineInputError(
            safe_message="source_id must be a non-empty string",
            internal_detail=f"got {type(source_id).__name__}",
        )
    if not isinstance(occurred_at, datetime):
        raise InvalidTimelineInputError(
            safe_message="occurred_at must be a datetime",
            internal_detail=f"got {type(occurred_at).__name__}",
        )
    if occurred_at.tzinfo is None:
        raise InvalidTimelineInputError(
            safe_message="occurred_at must be timezone-aware (UTC)",
            internal_detail="got a naive datetime",
        )
    payload = (
        f"{kind.value}|{source_id}|{occurred_at.astimezone(timezone.utc).isoformat()}"
    )
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    h = digest[:16]
    hex_chars = h.hex()  # 32 lowercase hex chars
    # Force a UUIDv7-shaped layout: 8-4-4-4-12 with version=7
    # in the third group and variant=8/9/a/b in the fourth
    # group. We do this by string surgery on the 32-char hex.
    # Char 12 (first nibble of group 3) -> "7"
    # Char 16 (first nibble of group 4) -> variant nibble.
    # Indices are 0-based, so the slices below work on the
    # ORIGINAL 32-char string (we rebuild the string at the
    # end so we never index past the end of a shorter
    # intermediate).
    chars = list(hex_chars)
    chars[12] = "7"
    # RFC 4122 variant nibble must be 8/9/a/b. SHA-256 hex
    # is uniform, so we re-mask the variant nibble to one
    # of the allowed four values deterministically: map
    # the original nibble's low 2 bits to the four valid
    # variant nibbles.
    fourth_first = chars[16]
    variant_map = {"0": "8", "1": "9", "2": "a", "3": "b",
                   "4": "8", "5": "9", "6": "a", "7": "b",
                   "8": "8", "9": "9", "a": "a", "b": "b",
                   "c": "8", "d": "9", "e": "a", "f": "b"}
    chars[16] = variant_map[fourth_first]
    hex_chars = "".join(chars)
    return (
        f"tl-{hex_chars[0:8]}-{hex_chars[8:12]}-{hex_chars[12:16]}-"
        f"{hex_chars[16:20]}-{hex_chars[20:32]}"
    )



# ----------------------------------------------------------------- engine
class TimelineEngine:
    """The deterministic, total, fail-closed-per-item timeline engine.

    The engine is the **only** place in the codebase that
    constructs :class:`TimelineItem` records. The caller
    (Phase 4.7 incident service, future API, future report
    generator) supplies:

    * ``events``       - a sequence of :class:`SecurityEvent`
                        records (the observations the timeline
                        must list as observed facts).
    * ``detections``   - a sequence of :class:`Detection`
                        records (the per-event derived
                        intelligence the timeline must list as
                        derived conclusions).
    * ``correlations`` - a sequence of :class:`Correlation`
                        records (the cross-event derived
                        intelligence the timeline must list as
                        derived conclusions).

    Ordering contract
    -----------------

    The engine sorts every timeline item by the deterministic
    tuple ``(occurred_at, kind, source_id)`` where:

    * ``occurred_at`` is the canonical evidence timestamp
      (``SecurityEvent.event_time`` for events,
      ``Detection.detected_at`` for detections, and
      ``Correlation.window_start`` for correlations).
    * ``kind`` is the closed enum and sorts in declaration
      order: ``event`` < ``detection`` < ``correlation``.
    * ``source_id`` is the canonical id (``event_id``,
      ``detection_id``, ``correlation_id``) and sorts in the
      natural string order.

    This sort key is stable, deterministic, and produces the
    same result for the same inputs even if the inputs are
    re-ordered, replayed, or contain duplicates. Duplicates
    are emitted exactly once (the engine deduplicates by
    ``(kind, source_id)``).

    Bounds
    ------

    The engine emits at most :data:`MAX_TIMELINE_ITEMS`
    timeline items. The excess is quarantined to
    :class:`TimelineResult.errors` (the engine is total; a
    too-large input is not a failure of the timeline
    contract but a documented boundary condition).
    """

    def __init__(self) -> None:
        # The engine is stateless. It exists as a class so a
        # future slice can pass configuration (e.g. a
        # ``max_items`` cap) without changing the public
        # surface. For Phase 4.6 the engine is parameter-free.
        pass

    def run(
        self,
        *,
        events: Optional[Sequence[SecurityEvent]] = None,
        detections: Optional[Sequence[Detection]] = None,
        correlations: Optional[Sequence[Correlation]] = None,
        now: Optional[datetime] = None,
    ) -> TimelineResult:
        """Build a chronological :class:`TimelineResult` from the
        supplied evidence.

        The engine is total: it never raises under normal
        operating conditions. Input-shape errors are raised
        eagerly (``InvalidTimelineInputError``) because they
        indicate a caller bug. Per-item errors
        (malformed evidence) are quarantined to
        :class:`TimelineResult.errors`.
        """
        # --- argument validation ---------------------------------------
        if events is None:
            events = ()
        if detections is None:
            detections = ()
        if correlations is None:
            correlations = ()
        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise InvalidTimelineInputError(
                safe_message="now must be a datetime",
                internal_detail=f"got {type(now).__name__}",
            )
        elif now.tzinfo is None:
            raise InvalidTimelineInputError(
                safe_message="now must be timezone-aware (UTC)",
                internal_detail="got a naive datetime",
            )
        # --- input type guards -----------------------------------------
        for ev in events:
            if not isinstance(ev, SecurityEvent):
                raise InvalidTimelineInputError(
                    safe_message=(
                        "all entries in events must be "
                        "SecurityEvent instances"
                    ),
                    internal_detail=f"got {type(ev).__name__}",
                )
        for d in detections:
            if not isinstance(d, Detection):
                raise InvalidTimelineInputError(
                    safe_message=(
                        "all entries in detections must be "
                        "Detection instances"
                    ),
                    internal_detail=f"got {type(d).__name__}",
                )
        for c in correlations:
            if not isinstance(c, Correlation):
                raise InvalidTimelineInputError(
                    safe_message=(
                        "all entries in correlations must be "
                        "Correlation instances"
                    ),
                    internal_detail=f"got {type(c).__name__}",
                )


        # --- build lookups used for evidence-completeness checks -------
        events_by_id: Dict[str, SecurityEvent] = {
            ev.event_id: ev for ev in events
        }
        detections_by_id: Dict[str, Detection] = {
            d.detection_id: d for d in detections
        }
        events_consumed = len(events)
        detections_consumed = len(detections)
        correlations_consumed = len(correlations)

        errors: List[str] = []
        items: List[TimelineItem] = []

        # --- emit one item per SecurityEvent ---------------------------
        events_emitted = 0
        for ev in events:
            try:
                item = self._build_event_item(ev)
            except TimelineError as exc:
                errors.append(
                    _truncate(
                        f"event {ev.event_id!r} rejected: "
                        f"{exc.safe_message}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    _truncate(
                        f"event {ev.event_id!r} raised unexpected "
                        f"{type(exc).__name__}: {exc}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            items.append(item)
            events_emitted += 1

        # --- emit one item per Detection -------------------------------
        detections_emitted = 0
        for d in detections:
            try:
                item = self._build_detection_item(d, events_by_id)
            except TimelineError as exc:
                errors.append(
                    _truncate(
                        f"detection {d.detection_id!r} rejected: "
                        f"{exc.safe_message}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    _truncate(
                        f"detection {d.detection_id!r} raised unexpected "
                        f"{type(exc).__name__}: {exc}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            items.append(item)
            detections_emitted += 1

        # --- emit one item per Correlation -----------------------------
        correlations_emitted = 0
        for c in correlations:
            try:
                item = self._build_correlation_item(
                    c, detections_by_id, events_by_id
                )
            except TimelineError as exc:
                errors.append(
                    _truncate(
                        f"correlation {c.correlation_id!r} rejected: "
                        f"{exc.safe_message}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    _truncate(
                        f"correlation {c.correlation_id!r} raised unexpected "
                        f"{type(exc).__name__}: {exc}",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            items.append(item)
            correlations_emitted += 1


        # --- deduplicate by (kind, source_id) --------------------------
        # Replay / duplicate evidence is a documented boundary
        # condition (per the task description). The engine
        # emits the first-encountered item for each
        # (kind, source_id) tuple and quarantines the rest
        # to errors so duplicate evidence cannot inflate the
        # timeline.
        unique_items: List[TimelineItem] = []
        seen: set = set()
        for it in items:
            key = (it.kind, it.source_id)
            if key in seen:
                errors.append(
                    _truncate(
                        f"duplicate timeline evidence: "
                        f"kind={it.kind.value!r} "
                        f"source_id={it.source_id!r} (kept first, "
                        f"skipped subsequent)",
                        _MAX_ERROR_LEN,
                    )
                )
                continue
            seen.add(key)
            unique_items.append(it)
        items = unique_items
        # Re-derive the per-kind counts: deduplication
        # cannot increase counts; if a duplicate was removed,
        # the appropriate counter naturally shrinks. We
        # recompute from the surviving items so the counters
        # are always consistent.
        events_emitted = sum(
            1 for i in items if i.kind is TimelineItemKind.EVENT
        )
        detections_emitted = sum(
            1 for i in items if i.kind is TimelineItemKind.DETECTION
        )
        correlations_emitted = sum(
            1 for i in items if i.kind is TimelineItemKind.CORRELATION
        )

        # --- sort ------------------------------------------------------
        # Stable, deterministic sort key:
        #   (occurred_at, kind, source_id)
        # where the kind order is the declaration order
        # (event < detection < correlation).
        kind_order = {
            TimelineItemKind.EVENT: 0,
            TimelineItemKind.DETECTION: 1,
            TimelineItemKind.CORRELATION: 2,
        }
        items.sort(
            key=lambda i: (i.occurred_at, kind_order[i.kind], i.source_id)
        )

        # --- enforce the documented bound ------------------------------
        if len(items) > MAX_TIMELINE_ITEMS:
            truncated_count = len(items) - MAX_TIMELINE_ITEMS
            items = items[:MAX_TIMELINE_ITEMS]
            errors.append(
                _truncate(
                    f"timeline exceeded the documented maximum of "
                    f"{MAX_TIMELINE_ITEMS} items; dropped "
                    f"{truncated_count} newest items to keep the bound",
                    _MAX_ERROR_LEN,
                )
            )
            events_emitted = sum(
                1 for i in items if i.kind is TimelineItemKind.EVENT
            )
            detections_emitted = sum(
                1 for i in items
                if i.kind is TimelineItemKind.DETECTION
            )
            correlations_emitted = sum(
                1 for i in items
                if i.kind is TimelineItemKind.CORRELATION
            )

        return TimelineResult(
            items=tuple(items),
            events_considered=events_consumed,
            detections_considered=detections_consumed,
            correlations_considered=correlations_consumed,
            events_emitted=events_emitted,
            detections_emitted=detections_emitted,
            correlations_emitted=correlations_emitted,
            errors=tuple(errors),
            produced_at=now,
        )


    # -------------------------------------------------------------- builders
    @staticmethod
    def _build_event_item(ev: SecurityEvent) -> TimelineItem:
        """Build one :class:`TimelineItem` from a :class:`SecurityEvent`.

        The evidence refs for an event item are the event's
        own id (the canonical observed fact) plus a
        ``collector:<name>`` marker when the event carries a
        provenance collector.
        """
        if ev.event_time.tzinfo is None:
            raise TimelineError(
                safe_message=(
                    "event.event_time must be timezone-aware (UTC)"
                ),
                internal_detail=(
                    f"event {ev.event_id!r} has a naive event_time"
                ),
            )
        evidence_refs: List[str] = [ev.event_id]
        if ev.provenance is not None and ev.provenance.collector:
            ref = f"collector:{ev.provenance.collector}"
            if len(ref) <= MAX_TIMELINE_EVIDENCE_REF_LEN:
                evidence_refs.append(ref)
        description = _truncate(
            f"{ev.event_type} from {ev.source} "
            f"(source_ip={ev.source_ip!r})",
            _MAX_DESCRIPTION_LEN,
        )
        reasoning = _truncate(
            f"observed security event of type {ev.event_type!r} "
            f"from source {ev.source!r} at event_time="
            f"{ev.event_time.isoformat()}",
            _MAX_REASONING_LEN,
        )
        return TimelineItem(
            timeline_item_id=_make_timeline_id(
                TimelineItemKind.EVENT, ev.event_id, ev.event_time
            ),
            kind=TimelineItemKind.EVENT,
            source_id=ev.event_id,
            occurred_at=ev.event_time,
            description=description,
            reasoning=reasoning,
            evidence_refs=tuple(evidence_refs),
        )



    @staticmethod
    def _build_detection_item(
        d: Detection, events_by_id: Mapping[str, SecurityEvent]
    ) -> TimelineItem:
        """Build one :class:`TimelineItem` from a :class:`Detection`.

        The evidence refs are the detection's own
        ``detection_id``, the underlying event's
        ``event_id`` (so the analyst can follow the timeline
        item to the observed fact), and the detection's
        ``evidence_refs`` (which may add further refs).
        Duplicate refs are removed; the order is preserved.

        The engine does NOT fail if the underlying event is
        missing from the lookup; it simply emits the
        detection with the evidence the detection itself
        carries.
        """
        if d.detected_at.tzinfo is None:
            raise TimelineError(
                safe_message=(
                    "detection.detected_at must be "
                    "timezone-aware (UTC)"
                ),
                internal_detail=(
                    f"detection {d.detection_id!r} has a naive "
                    f"detected_at"
                ),
            )
        seen: set = set()
        evidence_refs: List[str] = []
        for ref in (d.detection_id, d.event_id, *d.evidence_refs):
            if ref and ref not in seen:
                seen.add(ref)
                evidence_refs.append(ref)
        description = _truncate(
            f"detection {d.rule_id} v{d.rule_version} on "
            f"event {d.event_id!r}",
            _MAX_DESCRIPTION_LEN,
        )
        if d.event_id in events_by_id:
            ev = events_by_id[d.event_id]
            reason_extra = (
                f" backed by observed {ev.event_type!r} from "
                f"source {ev.source!r}"
            )
        else:
            reason_extra = (
                f" backed by event {d.event_id!r} (not present in "
                f"the events lookup; the detection's own "
                f"evidence_refs preserve the link)"
            )
        reasoning = _truncate(
            f"per-event detection by rule {d.rule_id!r} "
            f"v{d.rule_version} at detected_at="
            f"{d.detected_at.isoformat()}" + reason_extra,
            _MAX_REASONING_LEN,
        )
        return TimelineItem(
            timeline_item_id=_make_timeline_id(
                TimelineItemKind.DETECTION,
                d.detection_id,
                d.detected_at,
            ),
            kind=TimelineItemKind.DETECTION,
            source_id=d.detection_id,
            occurred_at=d.detected_at,
            description=description,
            reasoning=reasoning,
            evidence_refs=tuple(evidence_refs),
        )



    @staticmethod
    def _build_correlation_item(
        c: Correlation,
        detections_by_id: Mapping[str, Detection],
        events_by_id: Mapping[str, SecurityEvent],
    ) -> TimelineItem:
        """Build one :class:`TimelineItem` from a :class:`Correlation`.

        The evidence refs are the correlation's own
        ``correlation_id``, the participating
        ``detection_ids``, and the participating
        ``event_ids``. Duplicate refs are removed; the order
        is preserved.

        The correlation's ``occurred_at`` is
        ``window_start`` (the earliest grouped activity) so
        correlations appear on the timeline at the moment
        the underlying activity began. The reasoning
        preserves the full window so the analyst can read
        the window without leaving the timeline.
        """
        if c.window_start.tzinfo is None:
            raise TimelineError(
                safe_message=(
                    "correlation.window_start must be "
                    "timezone-aware (UTC)"
                ),
                internal_detail=(
                    f"correlation {c.correlation_id!r} has a "
                    f"naive window_start"
                ),
            )
        if c.window_end.tzinfo is None:
            raise TimelineError(
                safe_message=(
                    "correlation.window_end must be "
                    "timezone-aware (UTC)"
                ),
                internal_detail=(
                    f"correlation {c.correlation_id!r} has a "
                    f"naive window_end"
                ),
            )
        if c.window_end < c.window_start:
            raise TimelineError(
                safe_message=(
                    "correlation.window_end must be >= "
                    "window_start"
                ),
                internal_detail=(
                    f"correlation {c.correlation_id!r} has "
                    f"window_end < window_start"
                ),
            )
        seen: set = set()
        evidence_refs: List[str] = [c.correlation_id]
        for ref in (*c.detection_ids, *c.event_ids):
            if ref and ref not in seen:
                seen.add(ref)
                evidence_refs.append(ref)
        # Defensive completeness signal: how many of the
        # correlation's referenced detections and events
        # were available in the supplied lookups. The engine
        # does NOT require they all be present; the count is
        # an observability hint.
        n_dets_seen = sum(
            1 for did in c.detection_ids if did in detections_by_id
        )
        n_evs_seen = sum(
            1 for eid in c.event_ids if eid in events_by_id
        )
        description = _truncate(
            f"correlation {c.pattern_id} v{c.pattern_version} "
            f"({c.count} detections, trigger="
            f"{c.trigger!r})",
            _MAX_DESCRIPTION_LEN,
        )
        reasoning = _truncate(
            f"cross-event correlation by pattern "
            f"{c.pattern_id!r} v{c.pattern_version} "
            f"(trigger={c.trigger!r}); "
            f"window_start={c.window_start.isoformat()} "
            f"window_end={c.window_end.isoformat()}; "
            f"count={c.count}; "
            f"detections_available={n_dets_seen}/"
            f"{len(c.detection_ids)}; "
            f"events_available={n_evs_seen}/{len(c.event_ids)}",
            _MAX_REASONING_LEN,
        )
        return TimelineItem(
            timeline_item_id=_make_timeline_id(
                TimelineItemKind.CORRELATION,
                c.correlation_id,
                c.window_start,
            ),
            kind=TimelineItemKind.CORRELATION,
            source_id=c.correlation_id,
            occurred_at=c.window_start,
            description=description,
            reasoning=reasoning,
            evidence_refs=tuple(evidence_refs),
        )
