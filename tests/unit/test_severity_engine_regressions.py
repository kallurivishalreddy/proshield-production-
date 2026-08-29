"""Regression tests for the Phase 4.6 review findings F-1
through F-4 (and F-7 memory-pressure)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.correlation.models import (
    Correlation,
    CorrelationKey,
)
from app.detection.models import Detection
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.rules.types import RuleCategory
from app.severity import (
    MAX_SEVERITY_RESULT_ASSESSMENTS,
    MAX_SEVERITY_RESULT_ERRORS,
    SeverityAssessmentSubject,
    SeverityEngine,
    ScoringSignal,
)


FIXED = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _ev(*, event_id, event_time=FIXED,
        source_ip="198.51.100.7", endpoint="/api/login"):
    return SecurityEvent(
        event_id=event_id,
        event_time=event_time,
        ingested_at=event_time,
        source="nginx",
        event_type="authentication_failure",
        source_ip=source_ip,
        endpoint=endpoint,
        provenance=SecurityEventProvenance(
            collector="test",
            source_event_id=f"src-{event_id}",
        ),
        details={"status_code": 401},
    )


def _det(*, event_id, detected_at=FIXED,
         rule_id="NGINX-AUTH-FAILURE-001",
         rule_version=1, category=RuleCategory.SOURCE_SPECIFIC,
         detection_id=None):
    return Detection(
        detection_id=(
            detection_id or f"det-{event_id}"
        ),
        rule_id=rule_id,
        rule_version=rule_version,
        category=category,
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="r",
        detected_at=detected_at,
    )


def _corr(*, detection_ids, event_ids, correlation_id=None,
          trigger="brute_force_count_threshold", count=None,
          window_start=FIXED, window_end=None):
    if window_end is None:
        window_end = window_start + timedelta(seconds=600)
    if count is None:
        count = len(detection_ids)
    return Correlation(
        correlation_id=(
            correlation_id
            or f"corr-{event_ids[0] if event_ids else '00000000'}"
        ),
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        pattern_id="BRUTEFORCE-PATTERN-001",
        pattern_version=1,
        trigger=trigger,
        count=count,
        window_start=window_start,
        window_end=window_end,
        detection_ids=detection_ids,
        event_ids=event_ids,
        reasoning="brute force",
        correlated_at=FIXED,
    )
class TestF1RuleCategoryPerDetection:
    """F-1 regression: ``RULE_CATEGORY`` must flip to
    ``present=True`` for ``COMMON_BEHAVIORAL`` and
    ``CROSS_SOURCE_CORRELATION`` detections."""

    def test_common_behavioral_fires_rule_category(self):
        eid = "01923456-0000-7abc-9def-000000000001"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid,
                 category=RuleCategory.COMMON_BEHAVIORAL)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        sig = next(
            rl for rl in det_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is True, (
            f"F-1 regression: COMMON_BEHAVIORAL should fire "
            f"RULE_CATEGORY, got detail={sig.detail!r}"
        )
        assert "common_behavioral" in sig.detail

    def test_cross_source_correlation_fires_rule_category(self):
        eid = "01923456-0000-7abc-9def-000000000002"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid,
                 category=RuleCategory.CROSS_SOURCE_CORRELATION)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        sig = next(
            rl for rl in det_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is True
        assert "cross_source_correlation" in sig.detail

    def test_source_specific_does_not_fire_rule_category(self):
        eid = "01923456-0000-7abc-9def-000000000003"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid,
                 category=RuleCategory.SOURCE_SPECIFIC)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        sig = next(
            rl for rl in det_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is False
        assert "not high-impact" in sig.detail

    def test_per_detection_detail_does_not_mislabel_category(self):
        """The per-detection detail must not call a
        COMMON_BEHAVIORAL detection 'source_specific'."""
        eid = "01923456-0000-7abc-9def-000000000004"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid,
                 category=RuleCategory.COMMON_BEHAVIORAL)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        det_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.DETECTION
        )
        sig = next(
            rl for rl in det_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert "source_specific" not in sig.detail, (
            "F-1 regression: per-detection detail for "
            "COMMON_BEHAVIORAL must not claim 'source_specific'"
        )
class TestF1RuleCategoryPerCorrelation:
    """F-1 regression: per-correlation scorer."""

    def test_correlation_with_high_impact_underlying_fires_signal(self):
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(3)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [
            _det(event_id=eid,
                 category=RuleCategory.COMMON_BEHAVIORAL)
            for eid in eids
        ]
        corr = _corr(
            detection_ids=tuple(d.detection_id for d in dets),
            event_ids=tuple(eids),
        )
        r = SeverityEngine().run(
            detections=dets, correlations=[corr],
            events=events, now=FIXED,
        )
        corr_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.CORRELATION
        )
        sig = next(
            rl for rl in corr_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is True, (
            f"F-1 regression: per-correlation "
            f"RULE_CATEGORY should fire for COMMON_BEHAVIORAL, "
            f"got detail={sig.detail!r}"
        )

    def test_correlation_with_only_source_specific_does_not_fire(self):
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(3)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [
            _det(event_id=eid,
                 category=RuleCategory.SOURCE_SPECIFIC)
            for eid in eids
        ]
        corr = _corr(
            detection_ids=tuple(d.detection_id for d in dets),
            event_ids=tuple(eids),
        )
        r = SeverityEngine().run(
            detections=dets, correlations=[corr],
            events=events, now=FIXED,
        )
        corr_sev = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.CORRELATION
        )
        sig = next(
            rl for rl in corr_sev.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is False


class TestF1RuleCategoryBundle:
    """F-1 regression: bundle scorer."""

    def test_bundle_with_high_impact_fires_signal(self):
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(7)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [
            _det(event_id=eid,
                 category=RuleCategory.COMMON_BEHAVIORAL)
            for eid in eids
        ]
        r = SeverityEngine().run(
            detections=dets, events=events, now=FIXED
        )
        bundle = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        sig = next(
            rl for rl in bundle.rationale
            if rl.signal is ScoringSignal.RULE_CATEGORY
        )
        assert sig.present is True
        assert "high-impact" in sig.detail

class TestF2BundleEvidenceRefs:
    """F-2 regression: bundle evidence_refs accumulator
    must be bounded. Realistic batches that exceed
    ``MAX_SEVERITY_EVIDENCE_REFS = 32`` must NOT crash the
    engine."""

    def test_bundle_with_40_detections_does_not_crash(self):
        n = 40
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i in range(1, n + 1)
        ]
        r = SeverityEngine().run(
            detections=dets, events=events, now=FIXED
        )
        bundle = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        assert (
            len(bundle.evidence_refs)
            <= MAX_SEVERITY_RESULT_ASSESSMENTS
        )
        assert bundle.evidence_refs[0] == "bundle:overall"
        assert any("exceeded" in e for e in r.errors), (
            f"expected overflow error, got {list(r.errors)}"
        )

    def test_bundle_correlation_ids_preserved_first(self):
        n = 40
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i in range(1, n + 1)
        ]
        corr = _corr(
            detection_ids=tuple(d.detection_id for d in dets),
            event_ids=(eid,),
        )
        r = SeverityEngine().run(
            detections=dets, correlations=[corr],
            events=events, now=FIXED,
        )
        bundle = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        assert corr.correlation_id in bundle.evidence_refs

    def test_bundle_evidence_refs_preserved_when_input_bounded(self):
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(3)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [_det(event_id=eid) for eid in eids]
        r = SeverityEngine().run(
            detections=dets, events=events, now=FIXED
        )
        bundle = next(
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        )
        assert all("exceeded" not in e for e in r.errors)
        for d in dets:
            assert d.detection_id in bundle.evidence_refs


class TestF2PerCorrelationEvidenceRefs:
    """F-2 regression: a correlation with > 31 underlying
    detection_ids + event_ids must produce a per-correlation
    assessment (not silently dropped)."""

    def test_correlation_with_many_ids_produces_assessment(self):
        n = 40
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(n)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i, eid in enumerate(eids, start=1)
        ]
        corr = _corr(
            detection_ids=tuple(d.detection_id for d in dets),
            event_ids=tuple(eids),
        )
        r = SeverityEngine().run(
            detections=dets, correlations=[corr],
            events=events, now=FIXED,
        )
        corr_sev = [
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.CORRELATION
            and a.subject_id == corr.correlation_id
        ]
        assert len(corr_sev) == 1
        assert (
            len(corr_sev[0].evidence_refs)
            <= MAX_SEVERITY_RESULT_ASSESSMENTS
        )
        assert corr_sev[0].evidence_refs[0] == corr.correlation_id


class TestF2BundleTryExcept:
    """F-2 regression: the bundle scorer is wrapped in
    try/except so an unexpected exception is quarantined to
    errors, not raised."""

    def test_bundle_assessment_present_on_normal_input(self):
        eid = "01923456-0000-7abc-9def-000000000001"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid)
        r = SeverityEngine().run(
            detections=[d], events={eid: ev}, now=FIXED
        )
        bundle_subjects = [
            a for a in r.severity_assessments
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE
        ]
        assert len(bundle_subjects) == 1

class TestF3F4EngineSideCaps:
    """F-3 / F-4 regression: the engine enforces
    ``MAX_SEVERITY_RESULT_ASSESSMENTS`` and
    ``MAX_SEVERITY_RESULT_ERRORS`` at the engine boundary.
    (The Pydantic model has no ``max_length`` for these
    tuples; the engine is the right place to enforce the
    cap.)"""

    def test_input_cap_drops_excess_detections(self):
        n = MAX_SEVERITY_RESULT_ASSESSMENTS + 5
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i in range(1, n + 1)
        ]
        r = SeverityEngine().run(
            detections=dets, events=events, now=FIXED
        )
        assert (
            len(r.severity_assessments)
            <= MAX_SEVERITY_RESULT_ASSESSMENTS
        )
        assert (
            len(r.confidence_assessments)
            <= MAX_SEVERITY_RESULT_ASSESSMENTS
        )
        assert any("exceeded" in e for e in r.errors), (
            f"expected input-cap error, got {list(r.errors)}"
        )

    def test_severity_assessments_fits_within_documented_cap(self):
        eids = [
            f"01923456-0000-7abc-9def-{(i+1):012d}"
            for i in range(3)
        ]
        events = {eid: _ev(event_id=eid) for eid in eids}
        dets = [_det(event_id=eid) for eid in eids]
        r = SeverityEngine().run(
            detections=dets, events=events, now=FIXED
        )
        assert len(r.severity_assessments) == 4
        assert all("exceeded" not in e for e in r.errors)

    def test_errors_bounded_after_many_failures(self):
        eid = "01923456-0000-7abc-9def-000000000099"
        ev = _ev(event_id=eid)
        d = _det(event_id=eid)
        bad_corrs = [
            Correlation.model_construct(
                correlation_id=(
                    f"corr-01923456-0000-7abc-9def-{i:012x}"
                ),
                pattern_id="NGINX-CORR-BRUTEFORCE-001",
                pattern_version=1,
                trigger="brute_force_count_threshold",
                key=CorrelationKey(
                    parts=("198.51.100.7", "/api/login")
                ),
                detection_ids=(d.detection_id,),
                event_ids=(eid,),
                window_start=FIXED + timedelta(seconds=10),
                window_end=FIXED,  # before start
                count=1,
                reasoning="malformed",
                correlated_at=FIXED,
            )
            for i in range(60)
        ]
        r = SeverityEngine().run(
            detections=[d], events={eid: ev},
            correlations=tuple(bad_corrs), now=FIXED,
        )
        assert len(r.errors) <= MAX_SEVERITY_RESULT_ERRORS


class TestF7MemoryPressure:
    """F-7 regression: extreme input is rejected gracefully."""

    def test_input_over_cap_is_truncated_with_error(self):
        n = MAX_SEVERITY_RESULT_ASSESSMENTS * 4
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i in range(1, n + 1)
        ]
        r = SeverityEngine().run(
            detections=tuple(dets), events=events, now=FIXED
        )
        assert (
            len(r.severity_assessments)
            <= MAX_SEVERITY_RESULT_ASSESSMENTS
        )
        assert any(
            "exceeded the documented maximum" in e
            for e in r.errors
        )


class TestTotalEngine:
    """The engine is total: no uncaught exception escapes."""

    def test_engine_total_for_extreme_input(self):
        n = 60
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [
            _det(event_id=eid,
                 detection_id=f"det-01923456-0000-7abc-9def-{i:012d}")
            for i in range(1, n + 1)
        ]
        r = SeverityEngine().run(
            detections=tuple(dets), events=events, now=FIXED
        )
        assert r is not None

    def test_engine_total_for_many_correlations(self):
        n = 60
        eid = "01923456-0000-7abc-9def-000000000001"
        events = {eid: _ev(event_id=eid)}
        dets = [_det(event_id=eid)]
        corrs = [
            _corr(
                detection_ids=(dets[0].detection_id,),
                event_ids=(eid,),
                correlation_id=(
                    f"corr-01923456-0000-7abc-9def-{i:012d}"
                ),
            )
            for i in range(1, n + 1)
        ]
        r = SeverityEngine().run(
            detections=dets, correlations=tuple(corrs),
            events=events, now=FIXED,
        )
        assert r is not None

