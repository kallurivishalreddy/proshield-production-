"""Unit tests for the Phase 4.6 timeline engine.

Tests cover the documented ProShield method:
    positive / negative / boundary / duplicate / replay /
    deterministic repeat / out-of-order / large input.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.correlation.models import (
    Correlation,
    CorrelationKey,
)
from app.detection.models import Detection
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules.types import RuleCategory
from app.timeline import TimelineEngine
from app.timeline.errors import InvalidTimelineInputError
from app.timeline.models import TimelineItemKind


FIXED = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _ev(*, event_id, event_time, source_ip="198.51.100.7",
        endpoint="/api/login", source="nginx",
        event_type="authentication_failure"):
    return SecurityEvent(
        event_id=event_id,
        event_time=event_time,
        ingested_at=event_time,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        endpoint=endpoint,
        provenance=SecurityEventProvenance(
            collector="test", source_event_id=f"src-{event_id}"
        ),
        details={"status_code": 401},
    )


def _det(*, event_id, detected_at, rule_id="NGINX-AUTH-FAILURE-001",
         rule_version=1):
    return Detection(
        detection_id=f"det-{uuid7(timestamp_ms=int(detected_at.timestamp() * 1000))}",
        rule_id=rule_id,
        rule_version=rule_version,
        category=RuleCategory.SOURCE_SPECIFIC,
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="test",
        detected_at=detected_at,
    )



class TestConstruction:
    def test_engine_constructs(self):
        e = TimelineEngine()
        assert e is not None


class TestEmpty:
    def test_empty_inputs(self):
        e = TimelineEngine()
        r = e.run(now=FIXED)
        assert r.item_count == 0
        assert r.events_emitted == 0
        assert r.errors == ()


class TestInputValidation:
    def test_now_must_be_datetime(self):
        e = TimelineEngine()
        with pytest.raises(InvalidTimelineInputError):
            e.run(now="not a datetime")  # type: ignore[arg-type]

    def test_now_must_be_timezone_aware(self):
        e = TimelineEngine()
        with pytest.raises(InvalidTimelineInputError):
            e.run(now=datetime(2026, 1, 1))

    def test_non_event_rejected(self):
        e = TimelineEngine()
        with pytest.raises(InvalidTimelineInputError):
            e.run(events=["not a security event"], now=FIXED)  # type: ignore[list-item]

    def test_non_detection_rejected(self):
        e = TimelineEngine()
        with pytest.raises(InvalidTimelineInputError):
            e.run(detections=["not a detection"], now=FIXED)  # type: ignore[list-item]

    def test_non_correlation_rejected(self):
        e = TimelineEngine()
        with pytest.raises(InvalidTimelineInputError):
            e.run(correlations=["not a correlation"], now=FIXED)  # type: ignore[list-item]


class TestSingleDetection:
    def test_single_detection_emits_one_item(self):
        eid = "01923456-7890-7abc-9def-0123456789ab"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        r = TimelineEngine().run(
            events=[ev], detections=[d], now=FIXED
        )
        assert r.item_count == 2
        assert r.detections_emitted == 1
        assert r.events_emitted == 1
        # Items are ordered by (occurred_at, kind, source_id).
        # The event and the detection share occurred_at = FIXED;
        # event < detection in the kind order.
        assert r.items[0].kind == TimelineItemKind.EVENT
        assert r.items[1].kind == TimelineItemKind.DETECTION


class TestSingleCorrelation:
    def test_single_correlation_emits_one_item(self):
        eid1 = "01923456-7890-7abc-9def-0123456789ab"
        eid2 = "01923456-7890-7abc-9def-0123456789ac"
        eid3 = "01923456-7890-7abc-9def-0123456789ad"
        eid4 = "01923456-7890-7abc-9def-0123456789ae"
        ev1 = _ev(event_id=eid1, event_time=FIXED)
        ev2 = _ev(event_id=eid2, event_time=FIXED + timedelta(seconds=10))
        d1 = _det(event_id=eid1, detected_at=FIXED)
        d2 = _det(event_id=eid2, detected_at=FIXED + timedelta(seconds=10))
        corr = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-0123456789ab",
            window_start=FIXED,
            window_end=FIXED + timedelta(seconds=10),
            detection_ids=(d1.detection_id, d2.detection_id),
            event_ids=(eid1, eid2),
        )
        r = TimelineEngine().run(
            events=[ev1, ev2], detections=[d1, d2],
            correlations=[corr], now=FIXED,
        )
        assert r.item_count == 5  # 2 events + 2 detections + 1 correlation
        assert r.correlations_emitted == 1
        # The correlation item has occurred_at = window_start = FIXED.
        # The event at FIXED sorts first (event=0 < detection=1 <
        # correlation=2 in the kind order).
        kinds = [i.kind for i in r.items]
        # event, detection, correlation, event, detection
        assert kinds[0] == TimelineItemKind.EVENT
        assert kinds[1] == TimelineItemKind.DETECTION
        assert kinds[2] == TimelineItemKind.CORRELATION
        assert kinds[3] == TimelineItemKind.EVENT
        assert kinds[4] == TimelineItemKind.DETECTION


def _corr(*, correlation_id, window_start, window_end,
          detection_ids, event_ids, count=None):
    if count is None:
        count = len(detection_ids)
    return Correlation(
        correlation_id=correlation_id,
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=tuple(detection_ids),
        event_ids=tuple(event_ids),
        window_start=window_start,
        window_end=window_end,
        count=count,
        reasoning="test correlation",
        correlated_at=window_end,
    )


class TestChronologicalOrdering:
    def test_out_of_order_input_sorted(self):
        e1 = _ev(event_id="01923456-7890-7abc-9def-000000000001",
                 event_time=FIXED)
        e2 = _ev(event_id="01923456-7890-7abc-9def-000000000002",
                 event_time=FIXED + timedelta(minutes=10))
        e3 = _ev(event_id="01923456-7890-7abc-9def-000000000003",
                 event_time=FIXED + timedelta(minutes=20))
        r = TimelineEngine().run(events=[e3, e1, e2], now=FIXED)
        times = [i.occurred_at for i in r.items]
        assert times == sorted(times)

    def test_equal_timestamps_broken_by_kind(self):
        eid1 = "01923456-7890-7abc-9def-000000000001"
        eid2 = "01923456-7890-7abc-9def-000000000002"
        d1 = _det(event_id=eid1, detected_at=FIXED)
        d2 = _det(event_id=eid2, detected_at=FIXED)
        ev1 = _ev(event_id=eid1, event_time=FIXED)
        ev2 = _ev(event_id=eid2, event_time=FIXED)
        r = TimelineEngine().run(
            events=[ev1, ev2], detections=[d1, d2], now=FIXED
        )
        # event, event, detection, detection
        kinds = [i.kind for i in r.items]
        assert kinds == [
            TimelineItemKind.EVENT,
            TimelineItemKind.EVENT,
            TimelineItemKind.DETECTION,
            TimelineItemKind.DETECTION,
        ]

    def test_equal_timestamps_broken_by_source_id(self):
        d1 = _det(event_id="01923456-7890-7abc-9def-000000000001",
                  detected_at=FIXED)
        d2 = _det(event_id="01923456-7890-7abc-9def-000000000002",
                  detected_at=FIXED)
        ev1 = _ev(event_id="01923456-7890-7abc-9def-000000000001",
                  event_time=FIXED)
        ev2 = _ev(event_id="01923456-7890-7abc-9def-000000000002",
                  event_time=FIXED)
        r = TimelineEngine().run(
            events=[ev1, ev2], detections=[d1, d2], now=FIXED
        )
        sids = [i.source_id for i in r.items]
        assert sids == sorted(sids)


class TestDeduplication:
    def test_duplicate_events_deduplicated(self):
        ev = _ev(event_id="01923456-7890-7abc-9def-000000000001",
                 event_time=FIXED)
        r = TimelineEngine().run(events=[ev, ev, ev], now=FIXED)
        assert r.item_count == 1
        assert r.events_emitted == 1
        # The duplicates are quarantined to errors so the
        # analyst can see them.
        assert any("duplicate" in e for e in r.errors)

    def test_duplicate_detections_deduplicated(self):
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        r = TimelineEngine().run(
            events=[ev], detections=[d, d, d], now=FIXED
        )
        # 1 event + 1 detection
        assert r.item_count == 2
        assert r.detections_emitted == 1
        assert any("duplicate" in e for e in r.errors)

    def test_duplicate_correlations_deduplicated(self):
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        corr = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000001",
            window_start=FIXED,
            window_end=FIXED,
            detection_ids=(d.detection_id,),
            event_ids=(eid,),
        )
        r = TimelineEngine().run(
            events=[ev], detections=[d],
            correlations=[corr, corr, corr], now=FIXED,
        )
        assert r.correlations_emitted == 1


class TestDeterministicRepeat:
    def test_same_inputs_same_output(self):
        ev1 = _ev(event_id="01923456-7890-7abc-9def-000000000001",
                  event_time=FIXED)
        ev2 = _ev(event_id="01923456-7890-7abc-9def-000000000002",
                  event_time=FIXED + timedelta(seconds=10))
        d1 = _det(event_id="01923456-7890-7abc-9def-000000000001",
                  detected_at=FIXED)
        d2 = _det(event_id="01923456-7890-7abc-9def-000000000002",
                  detected_at=FIXED + timedelta(seconds=10))
        corr = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000001",
            window_start=FIXED,
            window_end=FIXED + timedelta(seconds=10),
            detection_ids=(d1.detection_id, d2.detection_id),
            event_ids=(ev1.event_id, ev2.event_id),
        )
        eng = TimelineEngine()
        r1 = eng.run(
            events=[ev1, ev2], detections=[d1, d2],
            correlations=[corr], now=FIXED,
        )
        r2 = eng.run(
            events=[ev1, ev2], detections=[d1, d2],
            correlations=[corr], now=FIXED,
        )
        ids1 = [i.timeline_item_id for i in r1.items]
        ids2 = [i.timeline_item_id for i in r2.items]
        assert ids1 == ids2


class TestLargeInput:
    def test_many_items_sorted_and_deduplicated(self):
        # Build 100 events with monotonically increasing
        # event_time. The engine should emit 100 timeline
        # items in the same order.
        events = []
        for i in range(100):
            eid = f"01923456-7890-7abc-9def-{i:012d}"
            events.append(
                _ev(event_id=eid, event_time=FIXED + timedelta(seconds=i))
            )
        r = TimelineEngine().run(events=events, now=FIXED)
        assert r.item_count == 100
        # Items in order.
        ids = [i.source_id for i in r.items]
        assert ids == sorted(ids)
        assert r.errors == ()

    def test_overflow_truncates_with_error(self):
        # Build MAX_TIMELINE_ITEMS + 50 items. The engine
        # should emit the first MAX_TIMELINE_ITEMS in
        # chronological order and quarantine the rest to
        # errors (not raise).
        from app.timeline.models import MAX_TIMELINE_ITEMS
        n = MAX_TIMELINE_ITEMS + 50
        events = [
            _ev(
                event_id=f"01923456-7890-7abc-9def-{i:012d}",
                event_time=FIXED + timedelta(seconds=i),
            )
            for i in range(n)
        ]
        r = TimelineEngine().run(events=events, now=FIXED)
        assert r.item_count == MAX_TIMELINE_ITEMS
        # The newest items were dropped (engine keeps the
        # first MAX_TIMELINE_ITEMS, not the last).
        first_id = r.items[0].source_id
        assert first_id == events[0].event_id
        # The overflow is reported.
        assert any("exceeded" in e for e in r.errors)


class TestMalformedInputs:
    def test_naive_event_dropped(self):
        # A naive-datetime event is rejected (the engine is
        # total so the error is reported, not raised).
        good = _ev(
            event_id="01923456-7890-7abc-9def-000000000001",
            event_time=FIXED,
        )
        # Use model_construct to bypass the SecurityEvent's
        # Pydantic timezone validation, simulating a
        # corruption that the engine should still defend
        # against at the engine boundary.
        bad = SecurityEvent.model_construct(
            event_id="01923456-7890-7abc-9def-000000000002",
            event_time=datetime(2026, 1, 1),  # naive!
            ingested_at=datetime(2026, 1, 1),
            source="nginx",
            event_type="authentication_failure",
            source_ip="198.51.100.7",
            endpoint="/api/login",
            provenance=SecurityEventProvenance(
                collector="t", source_event_id="x"
            ),
        )
        r = TimelineEngine().run(events=[good, bad], now=FIXED)
        assert r.events_emitted == 1
        assert any("rejected" in e for e in r.errors)

    def test_naive_detection_dropped(self):
        good_ev = _ev(
            event_id="01923456-7890-7abc-9def-000000000001",
            event_time=FIXED,
        )
        bad = Detection(
            detection_id="det-01923456-7890-7abc-9def-000000000099",
            rule_id="R-1",
            rule_version=1,
            category="source_specific",
            event_id="01923456-7890-7abc-9def-000000000001",
            evidence_refs=("01923456-7890-7abc-9def-000000000001",),
            reasoning="r",
            detected_at=datetime(2026, 1, 1),  # naive!
        )
        r = TimelineEngine().run(
            events=[good_ev], detections=[bad], now=FIXED
        )
        assert r.detections_emitted == 0
        assert any("rejected" in e for e in r.errors)

    def test_correlation_window_end_before_start_dropped(self):
        good_ev = _ev(
            event_id="01923456-7890-7abc-9def-000000000001",
            event_time=FIXED,
        )
        d = _det(
            event_id="01923456-7890-7abc-9def-000000000001",
            detected_at=FIXED,
        )
        # Use model_construct to bypass the Pydantic
        # window-end >= window-start validation, simulating
        # a corruption that the engine should still defend
        # against at the engine boundary.
        bad_corr = Correlation.model_construct(
            correlation_id="corr-01923456-7890-7abc-9def-000000000099",
            pattern_id="NGINX-CORR-BRUTEFORCE-001",
            pattern_version=1,
            trigger="brute_force_count_threshold",
            key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
            detection_ids=(d.detection_id,),
            event_ids=(good_ev.event_id,),
            window_start=FIXED + timedelta(seconds=10),
            window_end=FIXED,  # before start
            count=1,
            reasoning="malformed",
            correlated_at=FIXED,
        )
        r = TimelineEngine().run(
            events=[good_ev], detections=[d],
            correlations=[bad_corr], now=FIXED,
        )
        assert r.correlations_emitted == 0
        assert any("rejected" in e for e in r.errors)


class TestEvidenceTraceability:
    def test_event_item_includes_collector_when_present(self):
        ev = _ev(
            event_id="01923456-7890-7abc-9def-000000000001",
            event_time=FIXED,
        )
        r = TimelineEngine().run(events=[ev], now=FIXED)
        item = r.items[0]
        assert "collector:test" in item.evidence_refs
        assert ev.event_id in item.evidence_refs

    def test_detection_item_includes_event_id_even_if_missing(self):
        eid = "01923456-7890-7abc-9def-000000000001"
        d = _det(event_id=eid, detected_at=FIXED)
        r = TimelineEngine().run(detections=[d], now=FIXED)
        item = r.items[0]
        # The detection's evidence_refs preserve the link
        # to the event even when the event is not in the
        # supplied lookup.
        assert eid in item.evidence_refs
        assert d.detection_id in item.evidence_refs

    def test_correlation_item_includes_all_detection_and_event_ids(self):
        eid1 = "01923456-7890-7abc-9def-000000000001"
        eid2 = "01923456-7890-7abc-9def-000000000002"
        d1 = _det(event_id=eid1, detected_at=FIXED)
        d2 = _det(event_id=eid2, detected_at=FIXED)
        corr = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000001",
            window_start=FIXED,
            window_end=FIXED,
            detection_ids=(d1.detection_id, d2.detection_id),
            event_ids=(eid1, eid2),
        )
        r = TimelineEngine().run(
            detections=[d1, d2], correlations=[corr], now=FIXED,
        )
        corr_item = next(
            i for i in r.items if i.kind == TimelineItemKind.CORRELATION
        )
        assert corr.correlation_id in corr_item.evidence_refs
        assert d1.detection_id in corr_item.evidence_refs
        assert d2.detection_id in corr_item.evidence_refs
        assert eid1 in corr_item.evidence_refs
        assert eid2 in corr_item.evidence_refs

