"""Unit tests for the Phase 4.6 timeline models."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.timeline.models import (
    MAX_TIMELINE_DESCRIPTION_LEN,
    MAX_TIMELINE_EVIDENCE_REFS,
    MAX_TIMELINE_REASONING_LEN,
    TIMELINE_ID_PATTERN,
    TimelineItem,
    TimelineItemKind,
    TimelineResult,
)


FIXED = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _ev(*, tid=None, sid="ev-01923456-7890-7abc-9def-0123456789ab"):
    return TimelineItem(
        timeline_item_id=(
            tid or "tl-01923456-7890-7abc-9def-0123456789ab"
        ),
        kind=TimelineItemKind.EVENT,
        source_id=sid,
        occurred_at=FIXED,
        description="event item",
        reasoning="r",
        evidence_refs=(sid,),
    )


class TestTimelineIdPattern:
    def test_well_formed_id_accepted(self):
        t = _ev()
        assert t.timeline_item_id.startswith("tl-")

    def test_bad_prefix_rejected(self):
        with pytest.raises(PydanticValidationError):
            _ev(tid="det-01923456-7890-7abc-9def-0123456789ab")

    def test_non_uuidv7_version_rejected(self):
        with pytest.raises(PydanticValidationError):
            _ev(tid="tl-01923456-7890-6abc-9def-0123456789ab")


class TestKind:
    def test_kinds(self):
        assert TimelineItemKind.EVENT.value == "event"
        assert TimelineItemKind.DETECTION.value == "detection"
        assert TimelineItemKind.CORRELATION.value == "correlation"


class TestSourcePrefix:
    def test_event_source_id_no_prefix_required(self):
        # Events use the canonical SecurityEvent.event_id
        # (a UUIDv7 without a prefix). The engine sets
        # source_id to the event_id verbatim, so the
        # model does NOT require a prefix for events.
        t = _ev(sid="01923456-7890-7abc-9def-0123456789ab")
        assert t.source_id == "01923456-7890-7abc-9def-0123456789ab"

    def test_detection_source_id_must_start_with_det(self):
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.DETECTION,
                source_id="01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description="d",
                reasoning="r",
                evidence_refs=("01923456-7890-7abc-9def-0123456789ab",),
            )



class TestEvidenceRefs:
    def test_empty_evidence_refs_rejected(self):
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.EVENT,
                source_id="ev-01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description="d",
                reasoning="r",
                evidence_refs=(),
            )

    def test_too_many_evidence_refs_rejected(self):
        too_many = tuple(
            f"ev-01923456-7890-7abc-9def-{i:012d}" for i in range(20)
        )
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.EVENT,
                source_id="ev-01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description="d",
                reasoning="r",
                evidence_refs=too_many,
            )


class TestFrozen:
    def test_frozen(self):
        t = _ev()
        with pytest.raises(Exception):
            t.description = "x"  # type: ignore[misc]


class TestExtra:
    def test_extra_forbid(self):
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.EVENT,
                source_id="ev-01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description="d",
                reasoning="r",
                evidence_refs=("ev-01923456-7890-7abc-9def-0123456789ab",),
                made_up="x",  # type: ignore[call-arg]
            )


class TestDescriptionBounds:
    def test_max_description(self):
        d = "x" * (MAX_TIMELINE_DESCRIPTION_LEN + 1)
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.EVENT,
                source_id="ev-01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description=d,
                reasoning="r",
                evidence_refs=("ev-01923456-7890-7abc-9def-0123456789ab",),
            )

    def test_max_reasoning(self):
        r = "x" * (MAX_TIMELINE_REASONING_LEN + 1)
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.EVENT,
                source_id="ev-01923456-7890-7abc-9def-0123456789ab",
                occurred_at=FIXED,
                description="d",
                reasoning=r,
                evidence_refs=("ev-01923456-7890-7abc-9def-0123456789ab",),
            )


class TestResult:
    def test_empty_result(self):
        r = TimelineResult(produced_at=FIXED)
        assert r.item_count == 0
        assert r.events_considered == 0
        assert r.errors == ()

    def test_to_dict(self):
        r = TimelineResult(produced_at=FIXED, events_considered=3)
        d = r.to_dict()
        assert d["items"] == []
        assert d["events_considered"] == 3
        assert d["produced_at"] == FIXED.isoformat()

    def test_extra_forbid(self):
        with pytest.raises(PydanticValidationError):
            TimelineResult(produced_at=FIXED, foo="bar")  # type: ignore[call-arg]

    def test_frozen(self):
        r = TimelineResult(produced_at=FIXED)
        with pytest.raises(Exception):
            r.items = ()  # type: ignore[misc]


def test_id_pattern_constant():
    assert TIMELINE_ID_PATTERN.startswith("^tl-")


    def test_correlation_source_id_must_start_with_corr(self):
        with pytest.raises(PydanticValidationError):
            TimelineItem(
                timeline_item_id="tl-01923456-7890-7abc-9def-0123456789ab",
                kind=TimelineItemKind.CORRELATION,
                source_id="det-abc",
                occurred_at=FIXED,
                description="c",
                reasoning="r",
                evidence_refs=("det-abc",),
            )

