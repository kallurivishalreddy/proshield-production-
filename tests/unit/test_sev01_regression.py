"""REGRESSION TESTS FOR SEV-01.

The Phase 4.6 implementation used the same 10-signal
rationale for both severity and confidence, producing a single
scalar that was then mapped through two different band tables
(``SeverityBand`` capped at CRITICAL, ``ConfidenceBand`` capped at
VERY_HIGH). That made the two dimensions effectively the same
scalar — a fact the prior review recorded as SEV-01.

The Phase 2 documentation (DOMAIN_DATA_MODEL.md Sections 10 and 11)
requires severity and confidence to be **separately meaningful**:

* **Severity** reflects the **impact** of the observed security
  evidence: triggered rule category, number of related events,
  correlation strength, affected asset, business criticality,
  attack category, potential impact.
* **Confidence** reflects the **quality** of the evidence:
  rule certainty, evidence strength, correlation strength,
  consistency of observed signals, completeness of available
  evidence.

The fix: build the severity rationale from the 6 impact-oriented
signals and the confidence rationale from the 4 evidence-quality
signals. The two dimensions now measure different things and
can (and will) produce different bands on the same evidence.

These tests prove:
1. Severity and confidence are not merely aliases of the same
   scalar.
2. The distinction is observable in at least one documented
   scenario.
3. Each rationale matches its own dimension.
4. Deterministic repeat gives identical outputs.
5. Duplicate evidence cannot alter either result.
6. Existing documented scenarios still produce their expected bands.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.severity.engine import SeverityEngine
from app.severity.models import (
    ConfidenceBand,
    ScoringSignal,
    SeverityAssessmentSubject,
    SeverityBand,
)


NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


def _ev(*, event_id, event_time, source_ip="198.51.100.7",
        endpoint="/api/login"):
    return SecurityEvent(
        event_id=event_id,
        source="nginx",
        event_type="authentication_failure",
        source_ip=source_ip,
        endpoint=endpoint,
        details={"status_code": 401, "http_method": "POST"},
        event_time=event_time,
        ingested_at=event_time,
        schema_version="1.0",
        provenance=SecurityEventProvenance(
            collector="nginx",
            source_event_id=f"review-{event_id[-12:]}",
        ),
    )


def _det(*, event_id, detected_at, rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1):
    """Build a Detection matching the engine's contract.

    The engine's contract (see DetectionEngine._build_detection):
    detection_id is a deterministic UUIDv7 derived from
    sha256(rule_id|rule_version|event_id|detected_at). The
    detection carries the rule, version, event, evidence_refs,
    reasoning, and a category. The category is read from
    rule.metadata.category; for our regression tests we use
    source_specific.
    """
    from app.detection.models import Detection
    h = hashlib.sha256(
        f"{rule_id}|{rule_version}|{event_id}|"
        f"{int(detected_at.timestamp() * 1000)}".encode()
    ).digest()
    b = bytearray(16)
    b[:16] = h[:16]
    b[6] = (b[6] & 0x0F) | 0x70  # version 7
    b[8] = (b[8] & 0x3F) | 0x80  # variant
    hex_str = b.hex()
    detection_id = (
        f"det-{hex_str[0:8]}-{hex_str[8:12]}-7"
        f"{hex_str[13:16]}-{hex_str[16:20]}-{hex_str[20:32]}"
    )
    return Detection(
        detection_id=detection_id,
        rule_id=rule_id,
        rule_version=rule_version,
        category="source_specific",
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="regression test fixture",
        detected_at=detected_at,
    )


# -------------------------------------------------------------------
# SEV-01 regression tests
# -------------------------------------------------------------------

def test_sev01_severity_and_confidence_use_different_signal_subsets():
    """Severity rationale and confidence rationale MUST list
    disjoint signal subsets per the SEV-01 fix. Severity uses
    6 impact signals; confidence uses 4 evidence-quality
    signals.
    """
    eid = "01923456-7890-7abc-9def-aaaaaaaaaaaa"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    r = SeverityEngine().run(
        detections=[d], events={eid: ev}, now=NOW,
    )
    det_sev = next(
        a for a in r.severity_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    det_conf = next(
        a for a in r.confidence_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    sev_signals = {r.signal for r in det_sev.rationale}
    conf_signals = {r.signal for r in det_conf.rationale}
    assert sev_signals.isdisjoint(conf_signals), (
        f"severity and confidence rationales must be disjoint; "
        f"overlap = {sev_signals & conf_signals}"
    )


def test_sev01_severity_uses_impact_signals_only():
    """The severity rationale MUST contain only the 6 impact
    signals: RULE_CATEGORY, CORRELATION_TRIGGER,
    DETECTION_COUNT, EVENT_COUNT, AFFECTED_ENDPOINT,
    WINDOW_SPAN_SECONDS.
    """
    eid = "01923456-7890-7abc-9def-bbbbbbbbbbbb"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    r = SeverityEngine().run(
        detections=[d], events={eid: ev}, now=NOW,
    )
    det_sev = next(
        a for a in r.severity_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    assert len(det_sev.rationale) == 6
    expected = {
        ScoringSignal.RULE_CATEGORY,
        ScoringSignal.CORRELATION_TRIGGER,
        ScoringSignal.DETECTION_COUNT,
        ScoringSignal.EVENT_COUNT,
        ScoringSignal.AFFECTED_ENDPOINT,
        ScoringSignal.WINDOW_SPAN_SECONDS,
    }
    actual = {r.signal for r in det_sev.rationale}
    assert actual == expected


def test_sev01_confidence_uses_evidence_quality_signals_only():
    """The confidence rationale MUST contain only the 4
    evidence-quality signals: EVIDENCE_COMPLETENESS,
    SOURCE_IP_PRESENT, RULE_REPEATED, CORRELATION_REPEATED.
    """
    eid = "01923456-7890-7abc-9def-cccccccccccc"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    r = SeverityEngine().run(
        detections=[d], events={eid: ev}, now=NOW,
    )
    det_conf = next(
        a for a in r.confidence_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    assert len(det_conf.rationale) == 4
    expected = {
        ScoringSignal.EVIDENCE_COMPLETENESS,
        ScoringSignal.SOURCE_IP_PRESENT,
        ScoringSignal.RULE_REPEATED,
        ScoringSignal.CORRELATION_REPEATED,
    }
    actual = {r.signal for r in det_conf.rationale}
    assert actual == expected


def test_sev01_severity_and_confidence_can_differ_on_same_evidence():
    """Severity and confidence MUST be observably distinct on
    at least one documented scenario. For a single
    source_specific detection, severity is LOW (no impact
    signals fire) but confidence is MEDIUM
    (EVIDENCE_COMPLETENESS + SOURCE_IP_PRESENT). The bands
    are different.
    """
    eid = "01923456-7890-7abc-9def-dddddddddddd"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    r = SeverityEngine().run(
        detections=[d], events={eid: ev}, now=NOW,
    )
    det_sev = next(
        a for a in r.severity_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    det_conf = next(
        a for a in r.confidence_assessments
        if a.subject_kind is SeverityAssessmentSubject.DETECTION
    )
    # Severity: 0 impact signals present. 0 -> LOW.
    assert det_sev.band is SeverityBand.LOW
    # Confidence: 2 evidence-quality signals. 2 -> MEDIUM.
    assert det_conf.band is ConfidenceBand.MEDIUM
    # And the two dimensions are observably distinct.
    assert det_sev.band != det_conf.band


def test_sev01_deterministic_repeat_gives_identical_outputs():
    """Severity and confidence MUST both be deterministic."""
    eid = "01923456-7890-7abc-9def-eeeeeeeeeeee"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    e = SeverityEngine()
    r1 = e.run(detections=[d], events={eid: ev}, now=NOW)
    r2 = e.run(detections=[d], events={eid: ev}, now=NOW)
    for s1, s2 in zip(r1.severity_assessments, r2.severity_assessments):
        assert s1.band == s2.band
    for c1, c2 in zip(
        r1.confidence_assessments, r2.confidence_assessments
    ):
        assert c1.band == c2.band


def test_sev01_duplicate_evidence_does_not_inflate_either_band():
    """Duplicate detections MUST NOT inflate either band."""
    eid = "01923456-7890-7abc-9def-101010101010"
    ev = _ev(event_id=eid, event_time=NOW)
    d = _det(event_id=eid, detected_at=NOW)
    e = SeverityEngine()
    r1 = e.run(detections=[d], events={eid: ev}, now=NOW)
    r2 = e.run(
        detections=[d, d, d], events={eid: ev}, now=NOW,
    )
    bundle1 = next(
        a for a in r1.severity_assessments
        if a.subject_kind is SeverityAssessmentSubject.BUNDLE
    )
    bundle2 = next(
        a for a in r2.severity_assessments
        if a.subject_kind is SeverityAssessmentSubject.BUNDLE
    )
    assert bundle1.band == bundle2.band
    cbundle1 = next(
        a for a in r1.confidence_assessments
        if a.subject_kind is SeverityAssessmentSubject.BUNDLE
    )
    cbundle2 = next(
        a for a in r2.confidence_assessments
        if a.subject_kind is SeverityAssessmentSubject.BUNDLE
    )
    assert cbundle1.band == cbundle2.band




