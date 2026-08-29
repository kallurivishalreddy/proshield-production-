"""Unit tests for the correlation engine."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import pytest

from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.correlation.errors import (
    InvalidCorrelationInputError,
)
from app.correlation.models import CorrelationResult
from app.correlation.patterns import CorrelationPattern
from app.detection.models import Detection
from app.domain.security_event import SecurityEvent
from app.domain.uuid7 import uuid7
from tests.unit._correlation_helpers import make_burst


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


class TestConstruction:
    def test_accepts_empty_pattern_list(self) -> None:
        e = CorrelationEngine(patterns=[])
        assert e.patterns == ()

    def test_accepts_patterns(self) -> None:
        e = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        assert len(e.patterns) == 1

    def test_rejects_non_pattern(self) -> None:
        with pytest.raises(InvalidCorrelationInputError):
            CorrelationEngine(patterns=["not a pattern"])  # type: ignore[list-item]

    def test_rejects_none(self) -> None:
        with pytest.raises(InvalidCorrelationInputError):
            CorrelationEngine(patterns=None)  # type: ignore[arg-type]

    def test_patterns_are_sorted_by_id(self) -> None:
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class DummyPattern(CorrelationPattern):
            @property
            def pattern_id(self) -> str:
                return "AAA-DUMMY-001"

            @property
            def pattern_version(self) -> int:
                return 1

            @property
            def trigger(self) -> str:
                return "brute_force_count_threshold"

            def select(self, detections, events):
                return []

            def group(self, detections, events, *, now):
                return []

        e = CorrelationEngine(
            patterns=[BruteForceClusteringPattern(), DummyPattern()]
        )
        assert e.patterns[0].pattern_id == "AAA-DUMMY-001"
        assert e.patterns[1].pattern_id == "NGINX-CORR-BRUTEFORCE-001"


class TestInputValidation:
    def test_detections_required(self) -> None:
        e = CorrelationEngine(patterns=[])
        with pytest.raises(InvalidCorrelationInputError):
            e.run(detections=None, events={})  # type: ignore[arg-type]

    def test_events_required(self) -> None:
        e = CorrelationEngine(patterns=[])
        with pytest.raises(InvalidCorrelationInputError):
            e.run(detections=[], events=None)  # type: ignore[arg-type]

    def test_now_must_be_datetime(self) -> None:
        e = CorrelationEngine(patterns=[])
        with pytest.raises(InvalidCorrelationInputError):
            e.run(
                detections=[],
                events={},
                now="not a datetime",  # type: ignore[arg-type]
            )

    def test_now_must_be_timezone_aware(self) -> None:
        e = CorrelationEngine(patterns=[])
        with pytest.raises(InvalidCorrelationInputError):
            e.run(
                detections=[],
                events={},
                now=datetime(2026, 1, 1),
            )

    def test_non_detection_raises(self) -> None:
        e = CorrelationEngine(patterns=[])
        with pytest.raises(InvalidCorrelationInputError):
            e.run(
                detections=["not a detection"],  # type: ignore[list-item]
                events={},
            )


class TestSkipBehaviour:
    def test_detection_without_event_is_skipped(self) -> None:
        events, detections = make_burst(n=4, start=FIXED_NOW)
        events_by_id = {
            events[0].event_id: events[0],
            events[1].event_id: events[1],
        }
        e = CorrelationEngine(patterns=[BruteForceClusteringPattern()])
        result = e.run(
            detections=detections, events=events_by_id, now=FIXED_NOW
        )
        assert result.correlation_count == 0
        assert result.detections_consumed == 2

    def test_naive_detected_at_is_skipped(self) -> None:
        events, detections = make_burst(n=4, start=FIXED_NOW)
        detections[0] = detections[0].model_copy(
            update={"detected_at": FIXED_NOW.replace(tzinfo=None)}
        )
        events_by_id = {e.event_id: e for e in events}
        e = CorrelationEngine(patterns=[BruteForceClusteringPattern()])
        result = e.run(
            detections=detections, events=events_by_id, now=FIXED_NOW
        )
        assert result.correlation_count == 0
        assert result.detections_consumed == 3


class TestFailClosedPerPattern:
    def test_raising_pattern_is_quarantined(self) -> None:
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class BadPattern(CorrelationPattern):
            @property
            def pattern_id(self) -> str:
                return "BAD-PATTERN-001"

            @property
            def pattern_version(self) -> int:
                return 1

            @property
            def trigger(self) -> str:
                return "brute_force_count_threshold"

            def select(self, detections, events):
                return detections

            def group(self, detections, events, *, now):
                raise RuntimeError("boom")

        events, detections = make_burst(n=4, start=FIXED_NOW)
        events_by_id = {e.event_id: e for e in events}
        e = CorrelationEngine(patterns=[BadPattern()])
        result = e.run(
            detections=detections, events=events_by_id, now=FIXED_NOW
        )
        assert result.correlation_count == 0
        assert len(result.errors) == 1
        assert "BAD-PATTERN-001" in result.errors[0]

    def test_good_pattern_runs_alongside_bad(self) -> None:
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class BadPattern(CorrelationPattern):
            @property
            def pattern_id(self) -> str:
                return "BAD-001"

            @property
            def pattern_version(self) -> int:
                return 1

            @property
            def trigger(self) -> str:
                return "brute_force_count_threshold"

            def select(self, detections, events):
                return []

            def group(self, detections, events, *, now):
                return []

        events, detections = make_burst(n=4, start=FIXED_NOW)
        events_by_id = {e.event_id: e for e in events}
        e = CorrelationEngine(
            patterns=[BadPattern(), BruteForceClusteringPattern()]
        )
        result = e.run(
            detections=detections, events=events_by_id, now=FIXED_NOW
        )
        assert result.correlation_count == 1
        assert result.errors == ()


class TestOrdering:
    def test_correlations_sorted_by_pattern_id_then_correlation_id(self) -> None:
        events1, det1 = make_burst(
            n=4, start=FIXED_NOW, source_ip="198.51.100.7"
        )
        events2, det2 = make_burst(
            n=4,
            start=FIXED_NOW,
            source_ip="198.51.100.99",
        )
        all_evs = {e.event_id: e for e in events1 + events2}
        e = CorrelationEngine(patterns=[BruteForceClusteringPattern()])
        result = e.run(
            detections=det1 + det2, events=all_evs, now=FIXED_NOW
        )
        assert result.correlation_count == 2
        ids = [c.correlation_id for c in result.correlations]
        assert ids == sorted(ids)


class TestEmpty:
    def test_empty_inputs_returns_empty_result(self) -> None:
        e = CorrelationEngine(patterns=[BruteForceClusteringPattern()])
        result = e.run(detections=[], events={}, now=FIXED_NOW)
        assert result.correlation_count == 0
        assert result.patterns_considered == 1
        assert result.patterns_evaluated == 0
        assert result.detections_consumed == 0
        assert result.errors == ()
        assert isinstance(result, CorrelationResult)

    def test_no_patterns_returns_empty(self) -> None:
        events, detections = make_burst(n=4, start=FIXED_NOW)
        events_by_id = {e.event_id: e for e in events}
        e = CorrelationEngine(patterns=[])
        result = e.run(
            detections=detections, events=events_by_id, now=FIXED_NOW
        )
        assert result.correlation_count == 0
        assert result.patterns_considered == 0