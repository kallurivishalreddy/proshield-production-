"""Unit tests for the Phase 4.6 severity / confidence models."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.severity.models import (
    ConfidenceAssessment,
    ConfidenceBand,
    MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN,
    MAX_SEVERITY_EVIDENCE_REFS,
    SCORING_SIGNAL_PATTERN,
    ScoringRationale,
    ScoringSignal,
    Severity,
    SeverityAssessment,
    SeverityAssessmentSubject,
    SeverityBand,
    SeverityLevel,
    SeverityResult,
    confidence_at_least,
    severity_at_least,
)


FIXED = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _sev(*, band=SeverityBand.LOW, sid="det-01923456-7890-7abc-9def-0123456789ab"):
    return SeverityAssessment(
        subject_kind=SeverityAssessmentSubject.DETECTION,
        subject_id=sid,
        band=band,
        summary="test summary",
        rationale=(
            ScoringRationale(
                signal=ScoringSignal.RULE_CATEGORY,
                present=False,
                detail="category=source_specific",
            ),
        ),
        evidence_refs=(sid,),
    )


def _conf(*, band=ConfidenceBand.LOW, sid="det-01923456-7890-7abc-9def-0123456789ab"):
    return ConfidenceAssessment(
        subject_kind=SeverityAssessmentSubject.DETECTION,
        subject_id=sid,
        band=band,
        summary="test summary",
        rationale=(
            ScoringRationale(
                signal=ScoringSignal.RULE_CATEGORY,
                present=False,
                detail="category=source_specific",
            ),
        ),
        evidence_refs=(sid,),
    )


class TestBands:
    def test_severity_bands(self):
        assert SeverityBand.LOW.value == "low"
        assert SeverityBand.MEDIUM.value == "medium"
        assert SeverityBand.HIGH.value == "high"
        assert SeverityBand.CRITICAL.value == "critical"

    def test_confidence_bands(self):
        assert ConfidenceBand.LOW.value == "low"
        assert ConfidenceBand.MEDIUM.value == "medium"
        assert ConfidenceBand.HIGH.value == "high"
        assert ConfidenceBand.VERY_HIGH.value == "very_high"

    def test_aliases(self):
        assert Severity is SeverityBand
        assert SeverityLevel is SeverityBand


class TestComparators:
    def test_severity_at_least(self):
        assert severity_at_least(SeverityBand.CRITICAL, SeverityBand.LOW)
        assert severity_at_least(SeverityBand.HIGH, SeverityBand.HIGH)
        assert not severity_at_least(SeverityBand.LOW, SeverityBand.HIGH)

    def test_confidence_at_least(self):
        assert confidence_at_least(ConfidenceBand.VERY_HIGH, ConfidenceBand.LOW)
        assert confidence_at_least(ConfidenceBand.MEDIUM, ConfidenceBand.MEDIUM)
        assert not confidence_at_least(ConfidenceBand.LOW, ConfidenceBand.MEDIUM)


class TestScoringSignal:
    def test_signal_pattern_constant(self):
        assert SCORING_SIGNAL_PATTERN.startswith("^[a-z]")

    def test_signal_enum_has_documented_members(self):
        names = {s.value for s in ScoringSignal}
        assert "rule_category" in names
        assert "correlation_trigger" in names
        assert "detection_count" in names
        assert "event_count" in names
        assert "window_span_seconds" in names
        assert "affected_endpoint" in names
        assert "source_ip_present" in names
        assert "rule_repeated" in names
        assert "correlation_repeated" in names
        assert "evidence_completeness" in names




class TestSeverityAssessment:
    def test_detection_assessment_ok(self):
        a = _sev()
        assert a.subject_kind is SeverityAssessmentSubject.DETECTION
        assert a.subject_id.startswith("det-")

    def test_correlation_assessment_ok(self):
        a = SeverityAssessment(
            subject_kind=SeverityAssessmentSubject.CORRELATION,
            subject_id="corr-01923456-7890-7abc-9def-0123456789ab",
            band=SeverityBand.MEDIUM,
            summary="ok",
            rationale=(),
            evidence_refs=("corr-01923456-7890-7abc-9def-0123456789ab",),
        )
        assert a.band is SeverityBand.MEDIUM

    def test_bundle_assessment_ok(self):
        a = SeverityAssessment(
            subject_kind=SeverityAssessmentSubject.BUNDLE,
            subject_id="bundle:overall",
            band=SeverityBand.HIGH,
            summary="ok",
            rationale=(),
            evidence_refs=("bundle:overall",),
        )
        assert a.band is SeverityBand.HIGH

    def test_detection_with_corr_prefix_rejected(self):
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="corr-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=("corr-01923456-7890-7abc-9def-0123456789ab",),
            )

    def test_correlation_with_det_prefix_rejected(self):
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.CORRELATION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=("det-01923456-7890-7abc-9def-0123456789ab",),
            )

    def test_bundle_requires_bundle_prefix(self):
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.BUNDLE,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=("det-01923456-7890-7abc-9def-0123456789ab",),
            )

    def test_empty_evidence_refs_rejected(self):
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=(),
            )



class TestSeverityAssessmentMore:
    def test_too_many_evidence_refs_rejected(self):
        too_many = tuple(
            f"det-01923456-7890-7abc-9def-{i:012d}" for i in range(50)
        )
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=too_many,
            )

    def test_frozen(self):
        a = _sev()
        with pytest.raises(Exception):
            a.band = SeverityBand.HIGH  # type: ignore[misc]

    def test_extra_forbid(self):
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=(),
                evidence_refs=("det-01923456-7890-7abc-9def-0123456789ab",),
                made_up="y",  # type: ignore[call-arg]
            )

    def test_to_dict(self):
        a = _sev()
        d = a.to_dict()
        assert d["band"] == "low"
        assert d["subject_kind"] == "detection"
        assert d["subject_id"] == a.subject_id


class TestConfidenceAssessment:
    def test_assessment_ok(self):
        a = _conf()
        assert a.band is ConfidenceBand.LOW

    def test_band_very_high_allowed(self):
        a = _conf(band=ConfidenceBand.VERY_HIGH)
        assert a.band is ConfidenceBand.VERY_HIGH

    def test_to_dict(self):
        a = _conf()
        d = a.to_dict()
        assert d["band"] == "low"


class TestSeverityResult:
    def test_empty(self):
        r = SeverityResult(produced_at=FIXED)
        # No bundle assessment -> defaults to LOW.
        assert r.bundle_severity is SeverityBand.LOW
        assert r.bundle_confidence is ConfidenceBand.LOW
        assert r.detections_considered == 0
        assert r.correlations_considered == 0

    def test_with_bundle(self):
        bundle_sev = SeverityAssessment(
            subject_kind=SeverityAssessmentSubject.BUNDLE,
            subject_id="bundle:overall",
            band=SeverityBand.CRITICAL,
            summary="bundle",
            rationale=(),
            evidence_refs=("bundle:overall",),
        )
        bundle_conf = ConfidenceAssessment(
            subject_kind=SeverityAssessmentSubject.BUNDLE,
            subject_id="bundle:overall",
            band=ConfidenceBand.VERY_HIGH,
            summary="bundle",
            rationale=(),
            evidence_refs=("bundle:overall",),
        )
        r = SeverityResult(
            severity_assessments=(bundle_sev,),
            confidence_assessments=(bundle_conf,),
            produced_at=FIXED,
        )
        assert r.bundle_severity is SeverityBand.CRITICAL
        assert r.bundle_confidence is ConfidenceBand.VERY_HIGH

    def test_to_dict(self):
        r = SeverityResult(produced_at=FIXED)
        d = r.to_dict()
        assert d["bundle_severity"] == "low"
        assert d["bundle_confidence"] == "low"
        assert d["produced_at"] == FIXED.isoformat()

    def test_frozen(self):
        r = SeverityResult(produced_at=FIXED)
        with pytest.raises(Exception):
            r.severity_assessments = ()  # type: ignore[misc]


class TestRationaleBounds:
    def test_max_rationale(self):
        too_many = tuple(
            ScoringRationale(
                signal=ScoringSignal.RULE_CATEGORY,
                present=True,
                detail=f"k{i}",
            )
            for i in range(20)
        )
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary="x",
                rationale=too_many,
                evidence_refs=("det-01923456-7890-7abc-9def-0123456789ab",),
            )

    def test_summary_max_length(self):
        long = "x" * (MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN + 1)
        with pytest.raises(PydanticValidationError):
            SeverityAssessment(
                subject_kind=SeverityAssessmentSubject.DETECTION,
                subject_id="det-01923456-7890-7abc-9def-0123456789ab",
                band=SeverityBand.LOW,
                summary=long,
                rationale=(),
                evidence_refs=("det-01923456-7890-7abc-9def-0123456789ab",),
            )
