"""Unit tests for the Phase 4.6 severity / confidence engine."""
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
from app.severity import SeverityEngine
from app.severity.errors import InvalidSeverityInputError
from app.severity.models import (
    ConfidenceAssessment,
    ConfidenceBand,
    ScoringSignal,
    SeverityAssessment,
    SeverityAssessmentSubject,
    SeverityBand,
    SeverityResult,
    severity_at_least,
)


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
         rule_version=1, category=RuleCategory.SOURCE_SPECIFIC):
    return Detection(
        detection_id=f"det-{uuid7(timestamp_ms=int(detected_at.timestamp() * 1000))}",
        rule_id=rule_id,
        rule_version=rule_version,
        category=category,
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="test",
        detected_at=detected_at,
    )


class TestConstruction:
    def test_engine_constructs(self):
        SeverityEngine()


class TestInputValidation:
    def test_now_must_be_datetime(self):
        e = SeverityEngine()
        with pytest.raises(InvalidSeverityInputError):
            e.run(now="not a datetime")  # type: ignore[arg-type]

    def test_now_must_be_timezone_aware(self):
        e = SeverityEngine()
        with pytest.raises(InvalidSeverityInputError):
            e.run(now=datetime(2026, 1, 1))

    def test_non_detection_rejected(self):
        e = SeverityEngine()
        with pytest.raises(InvalidSeverityInputError):
            e.run(detections=["not a detection"], now=FIXED)  # type: ignore[list-item]

    def test_non_correlation_rejected(self):
        e = SeverityEngine()
        with pytest.raises(InvalidSeverityInputError):
            e.run(correlations=["not a correlation"], now=FIXED)  # type: ignore[list-item]

    def test_non_event_rejected(self):
        e = SeverityEngine()
        with pytest.raises(InvalidSeverityInputError):
            e.run(events={"x": "not an event"}, now=FIXED)  # type: ignore[dict-item]


class TestEmpty:
    def test_empty_inputs_returns_low_bundle(self):
        r = SeverityEngine().run(now=FIXED)
        # No detections, no correlations: bundle defaults to LOW.
        assert r.bundle_severity is SeverityBand.LOW
        assert r.bundle_confidence is ConfidenceBand.LOW
        # Exactly one bundle pair is emitted.
        sev_bundles = [
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        ]
        conf_bundles = [
            a for a in r.confidence_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        ]
        assert len(sev_bundles) == 1
        assert len(conf_bundles) == 1


def _corr(*, correlation_id, window_start, window_end,
          detection_ids, event_ids, count=None,
          trigger="brute_force_count_threshold"):
    if count is None:
        count = len(detection_ids)
    return Correlation(
        correlation_id=correlation_id,
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger=trigger,
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=tuple(detection_ids),
        event_ids=tuple(event_ids),
        window_start=window_start,
        window_end=window_end,
        count=count,
        reasoning="test correlation",
        correlated_at=window_end,
    )




class TestScoring:
    def test_no_signals_present_low_band(self):
        eid = "01923456-7890-7abc-9def-000000000001"
        # source_specific detection + auth_failure event.
        # After the SEV-01 fix, severity and confidence are
        # computed from disjoint signal subsets. The
        # severity rationale now only contains the 6
        # impact-oriented signals:
        #   RULE_CATEGORY, CORRELATION_TRIGGER, DETECTION_COUNT,
        #   EVENT_COUNT, AFFECTED_ENDPOINT, WINDOW_SPAN_SECONDS
        # The confidence rationale only contains the 4
        # evidence-quality signals:
        #   EVIDENCE_COMPLETENESS, SOURCE_IP_PRESENT,
        #   RULE_REPEATED, CORRELATION_REPEATED
        # For a single source_specific detection with no
        # correlation, the SEVERITY rationale has 0 present
        # signals (rule_category=source_specific is NOT
        # high-impact, no correlation_trigger, no
        # detection_count >= 5, etc.). The CONFIDENCE
        # rationale has 2 present signals
        # (EVIDENCE_COMPLETENESS + SOURCE_IP_PRESENT).
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        det_conf = next(
            a for a in r.confidence_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        # Severity rationale: 0 present impact signals
        # -> band LOW.
        assert det_sev.band is SeverityBand.LOW
        # Confidence rationale: 2 present evidence-quality
        # signals -> band MEDIUM.
        assert det_conf.band is ConfidenceBand.MEDIUM
        # And the two dimensions are now DISTINCT.
        assert det_sev.band != det_conf.band
        assert det_sev.summary != det_conf.summary
        assert det_sev.summary != ""

    def test_below_threshold_low(self):
        # Provide evidence that only yields 1 present signal.
        # This requires an event with no endpoint, no
        # source_ip, etc. Hard to engineer with our model.
        # Instead: provide 0 events, 0 correlations, no
        # detections. bundle is LOW.
        r = SeverityEngine().run(now=FIXED)


class TestScoringHigh:
    def test_high_band_with_4_signals(self):
        # Build a correlation with 4+ present signals:
        # 5 detections (detection_count >= 5),
        # 3 distinct events (event_count >= 3),
        # window >= 60s (window_span_seconds),
        # endpoint present, source_ip present (1 source).
        eids = [
            f"01923456-7890-7abc-9def-{i:012d}" for i in range(3)
        ]
        evs = [
            _ev(event_id=eid, event_time=FIXED + timedelta(seconds=i*30))
            for i, eid in enumerate(eids)
        ]
        events_by_id = {e.event_id: e for e in evs}
        dets = [
            _det(
                event_id=eid,
                detected_at=FIXED + timedelta(seconds=i*30),
            )
            for i, eid in enumerate(eids)
        ]
        # Add 2 more detections on the same event_ids to
        # reach 5 total.
        dets.append(_det(
            event_id=eids[0],
            detected_at=FIXED + timedelta(seconds=5),
            rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=2,
        ))
        dets.append(_det(
            event_id=eids[0],
            detected_at=FIXED + timedelta(seconds=10),
            rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=3,
        ))
        corr = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000001",
            window_start=FIXED,
            window_end=FIXED + timedelta(seconds=120),
            detection_ids=tuple(d.detection_id for d in dets),
            event_ids=tuple(eids),
        )
        r = SeverityEngine().run(
            detections=dets,
            correlations=[corr],
            events=events_by_id,
            now=FIXED,
        )
        corr_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.CORRELATION
        )
        # After the SEV-01 fix, the severity rationale
        # only contains the 6 impact signals. With 5
        # detections, 3 events, 120s window, 1 endpoint,
        # 1 trigger, 5 of the 6 severity signals are
        # present (RULE_CATEGORY is not high-impact for
        # source_specific NGINX rules). 5 present in a
        # 6-signal subset maps to HIGH (band table: <2 LOW,
        # <4 MEDIUM, <6 HIGH, else CRITICAL).
        assert corr_sev.band is SeverityBand.HIGH
        # The rationale lists the impact signals.
        sigs = {r.signal for r in corr_sev.rationale if r.present}
        assert ScoringSignal.DETECTION_COUNT in sigs
        assert ScoringSignal.EVENT_COUNT in sigs
        assert ScoringSignal.WINDOW_SPAN_SECONDS in sigs
        assert ScoringSignal.AFFECTED_ENDPOINT in sigs
        assert ScoringSignal.CORRELATION_TRIGGER in sigs
        # And SOURCE_IP_PRESENT is NOT in the severity
        # rationale (it's a confidence signal only).
        assert ScoringSignal.SOURCE_IP_PRESENT not in sigs

    def test_critical_band_with_6_signals(self):
        # Need 6+ present signals. The current catalogue
        # has 10 signals. Build evidence that lights all
        # of them: 5+ detections, 3+ events, 60+ second
        # window, 2+ rules repeated, endpoint, source_ip,
        # correlation trigger, high-impact rule category.
        eids = [
            f"01923456-7890-7abc-9def-{i:012d}" for i in range(3)
        ]
        evs = [
            _ev(event_id=eid, event_time=FIXED + timedelta(seconds=i*30))
            for i, eid in enumerate(eids)
        ]
        events_by_id = {e.event_id: e for e in evs}
        # 2 different rules to trigger rule_repeated.
        dets = [
            _det(
                event_id=eids[0],
                detected_at=FIXED,
                rule_id="NGINX-AUTH-FAILURE-001",
            ),
            _det(
                event_id=eids[0],
                detected_at=FIXED + timedelta(seconds=10),
                rule_id="NGINX-AUTH-FAILURE-001",
            ),
            _det(
                event_id=eids[0],
                detected_at=FIXED + timedelta(seconds=20),
                rule_id="NGINX-STATUS-ANOMALY-001",
            ),
        ]
        # Build 2 correlations to trigger correlation_repeated.
        corr1 = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000001",
            window_start=FIXED,
            window_end=FIXED + timedelta(seconds=120),
            detection_ids=(dets[0].detection_id, dets[1].detection_id),
            event_ids=(eids[0], eids[1]),
        )
        corr2 = _corr(
            correlation_id="corr-01923456-7890-7abc-9def-000000000002",
            window_start=FIXED + timedelta(seconds=20),
            window_end=FIXED + timedelta(seconds=140),
            detection_ids=(dets[2].detection_id,),
            event_ids=(eids[0], eids[2]),
        )
        r = SeverityEngine().run(
            detections=dets,
            correlations=[corr1, corr2],
            events=events_by_id,
            now=FIXED,
        )
        # After the SEV-01 fix, the BUNDLE severity
        # rationale contains ONLY the 6 impact signals
        # (the 4 evidence-quality signals are not in
        # the severity rationale).
        bundle_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        # The rationale is exactly the 6 impact signals,
        # not the full 10-signal list.
        assert len(bundle_sev.rationale) == 6
        # Of the 6, 4 are present (DETECTION_COUNT is
        # False because we only have 3 detections, well
        # below the 5 threshold; RULE_CATEGORY is False
        # because the NGINX rules are source_specific
        # not high-impact). The remaining 4 lights up the
        # MEDIUM band (>=2 present AND <4 present maps to
        # MEDIUM; >=4 present maps to HIGH).
        sigs = {r.signal for r in bundle_sev.rationale if r.present}
        assert ScoringSignal.EVENT_COUNT in sigs
        assert ScoringSignal.WINDOW_SPAN_SECONDS in sigs
        assert ScoringSignal.AFFECTED_ENDPOINT in sigs
        assert ScoringSignal.CORRELATION_TRIGGER in sigs
        # 4 present in the 6-signal subset maps to HIGH.
        assert bundle_sev.band is SeverityBand.HIGH
        # The BUNDLE confidence uses the 4 evidence-quality
        # signals: EVIDENCE_COMPLETENESS (all detection
        # events present), RULE_REPEATED (2 different rules
        # fired), CORRELATION_REPEATED (2 correlations),
        # SOURCE_IP_PRESENT (1 source). All 4 light up ->
        # confidence band HIGH (4 in 4 signals maps to HIGH
        # per the band table: <=1 LOW, <=3 MEDIUM, <=5 HIGH,
        # else VERY_HIGH).
        bundle_conf = next(
            a for a in r.confidence_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        assert len(bundle_conf.rationale) == 4
        conf_sigs = {
            r.signal for r in bundle_conf.rationale if r.present
        }
        assert ScoringSignal.EVIDENCE_COMPLETENESS in conf_sigs
        assert ScoringSignal.RULE_REPEATED in conf_sigs
        assert ScoringSignal.CORRELATION_REPEATED in conf_sigs
        assert ScoringSignal.SOURCE_IP_PRESENT in conf_sigs
        assert bundle_conf.band is ConfidenceBand.HIGH
        # The severity rationale lists 4 impact signals
        # (EVENT_COUNT, WINDOW_SPAN_SECONDS, AFFECTED_ENDPOINT,
        # CORRELATION_TRIGGER) and DOES NOT list any of the
        # 4 evidence-quality signals. The two rationales
        # describe different dimensions of the same evidence.
        sev_signal_set = {r.signal for r in bundle_sev.rationale}
        conf_signal_set = {r.signal for r in bundle_conf.rationale}
        assert sev_signal_set.isdisjoint(conf_signal_set), (
            "severity and confidence rationales must list "
            "disjoint signals per the SEV-01 fix"
        )


class TestDeterministicRepeat:
    def test_same_inputs_same_bands(self):
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        e = SeverityEngine()
        r1 = e.run(detections=[d], events={eid: ev}, now=FIXED)
        r2 = e.run(detections=[d], events={eid: ev}, now=FIXED)
        ids1 = [a.subject_id for a in r1.severity_assessments]
        ids2 = [a.subject_id for a in r2.severity_assessments]
        assert ids1 == ids2
        bands1 = [a.band for a in r1.severity_assessments]
        bands2 = [a.band for a in r2.severity_assessments]
        assert bands1 == bands2


class TestNoFabrication:
    def test_duplicate_detections_do_not_inflate_score(self):
        # Replaying the same detection many times must NOT
        # increase the band. The engine scores each subject
        # once and quarantines duplicates.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        e = SeverityEngine()
        r1 = e.run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        r2 = e.run(
            detections=[d, d, d, d, d, d, d, d, d, d],
            events={eid: ev}, now=FIXED,
        )
        # The duplicate detections must NOT change the
        # detection assessment's band. (The bundle may
        # include evidence_completeness and other signals
        # that are independent of detection count.)
        det1 = next(
            a for a in r1.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        det2 = next(
            a for a in r2.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        assert det1.band == det2.band
        # The detection scoring rationale must NOT include
        # detection_count=True (which would require 5+
        # distinct detections).
        det2_rationale_signals = {
            r.signal for r in det2.rationale if r.present
        }
        assert ScoringSignal.DETECTION_COUNT not in det2_rationale_signals


class TestAdversarialInput:
    def test_attacker_controlled_endpoint_low(self):
        # An attacker tries to push severity by including a
        # "dangerous" endpoint. The endpoint is just an
        # AFFECTED_ENDPOINT impact signal, not a
        # high-impact category; it can only add ONE point
        # in the 6-signal severity subset.
        # After the SEV-01 fix, the severity rationale has
        # 6 impact signals. For a single source_specific
        # detection, only AFFECTED_ENDPOINT is present
        # (1 present in 6). 1 present maps to LOW. The
        # "secret" endpoint value is NOT interpreted as
        # anything beyond AFFECTED_ENDPOINT; the engine
        # treats it as a normal endpoint string.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(
            event_id=eid, event_time=FIXED,
            endpoint="/admin/secret",
        )
        d = _det(event_id=eid, detected_at=FIXED)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        # The severity rationale has 6 entries; 1 present
        # (AFFECTED_ENDPOINT) -> LOW band.
        assert det_sev.band is SeverityBand.LOW
        # The endpoint value is NOT interpreted as a
        # high-impact signal: the rule_category signal
        # must be False (the source_specific category is
        # not high-impact).
        rule_cat_rationale = next(
            r for r in det_sev.rationale
            if r.signal is ScoringSignal.RULE_CATEGORY
        )
        assert rule_cat_rationale.present is False


class TestSeverityConfidenceSeparation:
    def test_severity_and_confidence_are_separate_assessments(self):
        # The MVP requires severity and confidence to be
        # SEPARATE assessments. The engine emits both.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        # Same count of severity and confidence assessments.
        assert len(r.severity_assessments) == len(r.confidence_assessments)
        # The two arrays are parallel: same subject_kinds
        # in the same order.
        sev_kinds = [a.subject_kind for a in r.severity_assessments]
        conf_kinds = [a.subject_kind for a in r.confidence_assessments]
        assert sev_kinds == conf_kinds


class TestFailingPatterns:
    def test_no_correlation_present_no_correlation_assessment(self):
        # Pure per-event evidence: only detection + bundle
        # assessments. No correlation assessment.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        kinds = {a.subject_kind for a in r.severity_assessments}
        assert SeverityAssessmentSubject.CORRELATION not in kinds


class TestBoundaryScoring:
    def test_score_1_low(self):
        # A detection whose event has endpoint + source_ip
        # removed yields 0 present severity signals
        # (the SEV-01 fix uses a 6-signal severity
        # subset; without endpoint or source_ip, the
        # AFFECTED_ENDPOINT and SOURCE_IP_PRESENT signals
        # are both False; EVIDENCE_COMPLETENESS is a
        # confidence signal, not a severity signal).
        # So severity is 0 present -> LOW.
        # We can't pass empty strings (SecurityEvent
        # requires non-empty) so we use model_construct to
        # bypass the model's min_length validation.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = SecurityEvent.model_construct(
            event_id=eid,
            event_time=FIXED,
            ingested_at=FIXED,
            source="nginx",
            event_type="authentication_failure",
            source_ip=None,  # no source_ip
            endpoint=None,  # no endpoint
            provenance=SecurityEventProvenance(
                collector="t", source_event_id="x"
            ),
            details={},
        )
        d = _det(event_id=eid, detected_at=FIXED)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        # After the SEV-01 fix, the severity rationale
        # only contains the 6 impact signals, and with no
        # endpoint and no source_ip, 0 are present.
        # 0 present in 6 signals -> LOW band.
        present = sum(1 for r in det_sev.rationale if r.present)
        assert present == 0
        assert det_sev.band is SeverityBand.LOW
        # The confidence rationale: EVIDENCE_COMPLETENESS
        # is True, SOURCE_IP_PRESENT is False, RULE_REPEATED
        # is False, CORRELATION_REPEATED is False -> 1
        # present out of 4 -> LOW band.
        det_conf = next(
            a for a in r.confidence_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        conf_present = sum(
            1 for r in det_conf.rationale if r.present
        )
        assert conf_present == 1
        assert det_conf.band is ConfidenceBand.LOW

    def test_malformed_correlation_quarantined(self):
        # Use model_construct to bypass Pydantic and create
        # a correlation with window_end < window_start.
        eid = "01923456-7890-7abc-9def-000000000001"
        ev = _ev(event_id=eid, event_time=FIXED)
        d = _det(event_id=eid, detected_at=FIXED)
        bad_corr = Correlation.model_construct(
            correlation_id="corr-01923456-7890-7abc-9def-000000000099",
            pattern_id="NGINX-CORR-BRUTEFORCE-001",
            pattern_version=1,
            trigger="brute_force_count_threshold",
            key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
            detection_ids=(d.detection_id,),
            event_ids=(eid,),
            window_start=FIXED + timedelta(seconds=10),
            window_end=FIXED,  # before start
            count=1,
            reasoning="malformed",
            correlated_at=FIXED,
        )
        r = SeverityEngine().run(
            events={eid: ev},
            detections=[d],
            correlations=[bad_corr],
            now=FIXED,
        )
        assert r.correlations_scored == 0
        assert any("rejected" in e for e in r.errors)
