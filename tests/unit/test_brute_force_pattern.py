"""Unit tests for the brute-force correlation pattern.

The tests follow the Phase 4.5 testing method:

  observe real telemetry
  -> build the event sequence
  -> run through the real backend
  -> verify the expected correlation
  -> test benign sequence
  -> test near-miss sequence
  -> test threshold boundary
  -> test time-window boundary
  -> test unrelated-source/event isolation
  -> test duplicate/replay behavior
  -> verify evidence references
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.correlation.models import CorrelationResult
from app.correlation.patterns import (
    DEFAULT_BRUTEFORCE_THRESHOLD,
    DEFAULT_BRUTEFORCE_WINDOW,
)
from app.detection.models import Detection
from app.domain.security_event import SecurityEvent
from app.domain.uuid7 import uuid7
from tests.unit._correlation_helpers import (
    _det,
    _ev,
    make_burst,
)


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


class TestPatternIdentity:
    def test_pattern_id(self) -> None:
        p = BruteForceClusteringPattern()
        assert p.pattern_id == "NGINX-CORR-BRUTEFORCE-001"

    def test_pattern_version(self) -> None:
        p = BruteForceClusteringPattern()
        assert p.pattern_version == 1

    def test_trigger(self) -> None:
        p = BruteForceClusteringPattern()
        assert p.trigger == "brute_force_count_threshold"

    def test_default_window(self) -> None:
        p = BruteForceClusteringPattern()
        assert p.window == DEFAULT_BRUTEFORCE_WINDOW
        assert p.threshold == DEFAULT_BRUTEFORCE_THRESHOLD


class TestPositive:
    def test_four_failures_same_key_correlates(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=4, start=start, step=timedelta(seconds=10)
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1
        corr = result.correlations[0]
        assert corr.pattern_id == "NGINX-CORR-BRUTEFORCE-001"
        assert corr.count == 4
        assert corr.key.parts == ("198.51.100.7", "/api/login")
        assert set(corr.detection_ids) == {d.detection_id for d in detections}
        assert set(corr.event_ids) == {e.event_id for e in events}
        assert "brute-force clustering" in corr.reasoning
        assert "198.51.100.7" in corr.reasoning
        assert corr.window_start == start
        assert corr.window_end == start + timedelta(seconds=30)

    def test_ten_failures_same_key_correlates_once(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=10, start=start, step=timedelta(seconds=5)
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1
        assert result.correlations[0].count == 10


class TestBenign:
    def test_three_failures_no_correlation(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=3, start=start, step=timedelta(seconds=10)
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0

    def test_single_failure_no_correlation(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=1, start=start, step=timedelta(seconds=10)
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0


class TestThresholdBoundary:
    def test_exactly_at_threshold_correlates(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=DEFAULT_BRUTEFORCE_THRESHOLD, start=start
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1

    def test_one_below_threshold_does_not_correlate(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=DEFAULT_BRUTEFORCE_THRESHOLD - 1, start=start
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0


class TestTimeWindowBoundary:
    def test_failures_within_window_correlate(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=4,
            start=start,
            step=DEFAULT_BRUTEFORCE_WINDOW / 3,
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1

    def test_failures_outside_window_do_not_correlate(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=4,
            start=start,
            step=DEFAULT_BRUTEFORCE_WINDOW,
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0

    def test_custom_window(self) -> None:
        p = BruteForceClusteringPattern(
            window=timedelta(minutes=1),
            threshold=2,
        )
        start = FIXED_NOW
        events, detections = make_burst(
            n=2, start=start, step=timedelta(seconds=30)
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(patterns=[p])
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1


class TestUnrelatedIsolation:
    def test_different_source_ip_produces_two_correlations(self) -> None:
        start = FIXED_NOW
        ev1, det1 = make_burst(
            n=4, start=start, source_ip="198.51.100.7"
        )
        ev2, det2 = make_burst(
            n=4,
            start=start,
            source_ip="198.51.100.99",
        )
        all_evs = {e.event_id: e for e in ev1 + ev2}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=det1 + det2,
            events=all_evs,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 2

    def test_different_endpoint_produces_two_correlations(self) -> None:
        start = FIXED_NOW
        ev1, det1 = make_burst(
            n=4, start=start, endpoint="/api/login"
        )
        ev2, det2 = make_burst(
            n=4, start=start, endpoint="/api/signup"
        )
        all_evs = {e.event_id: e for e in ev1 + ev2}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=det1 + det2,
            events=all_evs,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 2

    def test_non_auth_detections_ignored(self) -> None:
        start = FIXED_NOW
        ev1, det1 = make_burst(
            n=3,
            start=start,
            rule_id="NGINX-AUTH-FAILURE-001",
        )
        ev2, det2 = make_burst(
            n=4,
            start=start,
            rule_id="NGINX-RATE-LIMIT-001",
            event_type="rate_limit_exceeded",
        )
        all_evs = {e.event_id: e for e in ev1 + ev2}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=det1 + det2,
            events=all_evs,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0

    def test_missing_source_ip_is_skipped(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(n=4, start=start)
        events[0] = events[0].model_copy(
            update={"source_ip": None}
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0

    def test_missing_endpoint_is_skipped(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(n=4, start=start)
        events[0] = events[0].model_copy(
            update={"endpoint": None}
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 0


class TestReplay:
    def test_duplicate_detections_do_not_double_count_id(self) -> None:
        """CORRELATION-01 regression.

        A single event that triggers two rules (e.g.
        NGINX-AUTH-FAILURE-001 + NGINX-AUTH-BRUTEFORCE-001)
        must NOT inflate the correlation ``count``. The
        reported ``count`` is the number of distinct
        auth-failure events in the window, NOT the number
        of detection rows.
        """
        start = FIXED_NOW
        events, detections = make_burst(n=4, start=start)
        events_by_id = {e.event_id: e for e in events}
        # A duplicate detection for the first event (same
        # event_id, different rule) simulates two rules
        # firing on a single event.
        dup = _det(
            event_id=events[0].event_id,
            rule_id="NGINX-AUTH-FAILURE-001",
            detected_at=detections[0].detected_at,
        )
        detections = [dup] + detections
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1
        # ``count`` is the distinct event count (4), not the
        # detection row count (5). The duplicate detection
        # is preserved in ``detection_ids`` so an analyst
        # can still see both rule firings.
        assert result.correlations[0].count == 4
        # The detection_count extra captures the row count.
        extra = dict(result.correlations[0].extra)
        assert extra.get("detection_count") == 5

    def test_replay_yields_deterministic_id(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(n=4, start=start)
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        r1 = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        r2 = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert r1.correlations[0].correlation_id == r2.correlations[0].correlation_id


class TestDeterminism:
    def test_input_order_does_not_affect_output(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(n=4, start=start)
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        r1 = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        r2 = engine.run(
            detections=list(reversed(detections)),
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert r1.correlations[0].correlation_id == r2.correlations[0].correlation_id
        assert r1.correlations[0].detection_ids == r2.correlations[0].detection_ids


class TestOutOfOrder:
    def test_reversed_event_timestamps_still_correlate(self) -> None:
        start = FIXED_NOW
        events, detections = make_burst(
            n=4, start=start, step=timedelta(seconds=10)
        )
        reversed_events = list(reversed(events))
        events_by_id = {e.event_id: e for e in reversed_events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        assert result.correlation_count == 1
        assert result.correlations[0].count == 4


class TestLongEndpoint:
    """D-1 regression: long (65–128 char) endpoints must still correlate.

    Before the fix, ``redact_endpoint`` returned up to 128 chars
    but ``CorrelationKey.parts`` was bounded at 64 chars, so the
    pattern's ``CorrelationKey(parts=(...))`` raised a
    ``ValidationError`` that the engine silently quarantined. The
    fix truncates the key part to 64 chars inside the pattern;
    the full 128-char redacted endpoint is still used for the
    analyst-facing ``reasoning`` and evidence.
    """

    def _run_with_endpoint(self, endpoint: str) -> CorrelationResult:
        events, detections = make_burst(
            n=4, start=FIXED_NOW, step=timedelta(seconds=10), endpoint=endpoint
        )
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        return engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )

    def test_64_char_endpoint_correlates(self) -> None:
        # Boundary: exactly MAX_KEY_PART_LEN chars is still allowed.
        endpoint = "/" + "a" * 63  # 64 chars
        assert len(endpoint) == 64
        result = self._run_with_endpoint(endpoint)
        assert result.correlation_count == 1
        assert result.errors == ()

    def test_80_char_endpoint_correlates(self) -> None:
        # The original D-1 reproduction: an 80-char endpoint must
        # produce a correlation (no silent ValidationError
        # swallowed by the engine).
        endpoint = "/api/" + "a" * 75  # 80 chars
        assert len(endpoint) == 80
        result = self._run_with_endpoint(endpoint)
        assert result.correlation_count == 1
        assert result.errors == ()
        # The key part is truncated to MAX_KEY_PART_LEN (64).
        key_ep = result.correlations[0].key.parts[1]
        assert len(key_ep) == 64
        # The full redacted endpoint is still preserved in the
        # analyst-facing reasoning (preserves evidence).
        assert endpoint in result.correlations[0].reasoning

    def test_128_char_endpoint_correlates(self) -> None:
        # The upper bound of the redact_endpoint output.
        endpoint = "/api/" + "a" * 123  # 128 chars
        assert len(endpoint) == 128
        result = self._run_with_endpoint(endpoint)
        assert result.correlation_count == 1
        assert result.errors == ()

    def test_200_char_endpoint_correlates(self) -> None:
        # Beyond the documented redact_endpoint max_len; the
        # input would already be > MAX_REDACTED_ENDPOINT_LEN so
        # ``redact_endpoint`` will return a 128-char
        # truncation-with-suffix; the key part is then truncated
        # to 64 chars.
        endpoint = "/api/" + "a" * 195  # 200 chars
        assert len(endpoint) == 200
        result = self._run_with_endpoint(endpoint)
        assert result.correlation_count == 1
        assert result.errors == ()

    def test_long_endpoints_with_same_prefix_correlate_together(
        self,
    ) -> None:
        # Two long endpoints sharing the first 64 chars should
        # collapse into the same key (intentional behavior of
        # truncating to 64 chars without a suffix).
        endpoint_a = "/api/" + "a" * 75  # 80 chars
        endpoint_b = "/api/" + "a" * 100  # 105 chars
        events_a, dets_a = make_burst(
            n=2, start=FIXED_NOW, step=timedelta(seconds=10),
            endpoint=endpoint_a,
        )
        events_b, dets_b = make_burst(
            n=2,
            start=FIXED_NOW + timedelta(seconds=20),
            step=timedelta(seconds=10),
            endpoint=endpoint_b,
        )
        events = events_a + events_b
        detections = dets_a + dets_b
        events_by_id = {e.event_id: e for e in events}
        engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()]
        )
        result = engine.run(
            detections=detections,
            events=events_by_id,
            now=FIXED_NOW,
        )
        # All four events share the same first-64-char key.
        assert result.correlation_count == 1
        assert result.correlations[0].count == 4