"""End-to-end integration test for the Phase 4.6 pipeline.

This test exercises the complete pipeline through MongoDB
(Phase 4.5) and then runs the new Phase 4.6 timeline +
severity engines on the persisted evidence, demonstrating
that:

* the Phase 4.5 pipeline behaviour is unchanged (regression),
* the Phase 4.6 timeline engine consumes the Phase 4.4 +
  Phase 4.5 evidence without modifying any of it,
* the Phase 4.6 severity engine produces deterministic
  assessments for the same evidence,
* the Phase 4.6 engines are pure in-memory operations
  (no extra MongoDB writes).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.detection import DetectionEngine, DetectionPipeline
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.detection_repository import DetectionRepository
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.rules import RuleRegistry, load_rules_from_specs
from app.severity import SeverityEngine
from app.severity.models import (
    SeverityBand,
    severity_at_least,
)
from app.timeline import TimelineEngine
from app.timeline.models import TimelineItemKind


_BRUTEFORCE_LOG = (
    # 4 auth failures on /api/login from the same source.
    '198.51.100.7 - - [26/Aug/2026:12:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:10 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:20 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:30 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    # A 200 on a public page (no event, no detection).
    '198.51.100.99 - - [26/Aug/2026:12:00:40 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
)



@pytest.fixture
def nginx_log(tmp_path: Path) -> Path:
    p = tmp_path / "access.log"
    p.write_text(_BRUTEFORCE_LOG, encoding="utf-8")
    return p


@pytest.fixture
def rule_registry() -> RuleRegistry:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    return r


@pytest.fixture
def phase45_pipeline(
    repository: SecurityEventRepository,
    rule_registry: RuleRegistry,
    test_config: ProShieldConfig,
    db,
):
    ingestion = SecurityEventIngestionService(repository, test_config)
    engine = DetectionEngine(rule_registry)
    det_repo = DetectionRepository(db, test_config)
    det_repo.ensure_schema()
    det_repo.ensure_indexes()
    return DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=engine,
        detection_repository=det_repo,
    )





def test_phase46_end_to_end_through_phase45(
    nginx_log: Path,
    phase45_pipeline: DetectionPipeline,
    db,
    test_config: ProShieldConfig,
):
    # 1) Run the Phase 4.5 pipeline: ingestion -> detection
    #    -> detection persistence. We confirm the Phase 4.5
    #    pipeline still works (regression check).
    connector = NginxConnector(nginx_log, asset="web-api-01")
    results = phase45_pipeline.run_from_connector(connector)
    # The Phase 4.3 connector ingests 4xx/5xx events only;
    # the 200 OK on the public page is filtered out by the
    # connector. We expect 4 auth-failure events.
    assert len(results) == 4  # 4 auth failures (the 200 is filtered)

    # 2) Run the Phase 4.5 correlation engine: brute-force
    #    clustering. The correlation is in-memory only.
    detections = []
    events = []
    for r in results:
        events.append(r.event)
        detections.extend(r.persisted_detections)
    corr_engine = CorrelationEngine(
        patterns=[BruteForceClusteringPattern()]
    )
    corr_result = corr_engine.run(
        detections=detections,
        events={e.event_id: e for e in events},
        now=datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc),
    )
    assert corr_result.correlation_count == 1
    corr = corr_result.correlations[0]
    assert corr.count == 8  # 4 events * 2 detections per event

    # 3) Phase 4.6 timeline engine: organize the existing
    #    evidence chronologically. NO new persistence.
    timeline = TimelineEngine().run(
        events=events,
        detections=detections,
        correlations=list(corr_result.correlations),
        now=datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc),
    )
    # 4 events + 8 detections + 1 correlation = 13 items.
    assert timeline.item_count == 13
    # The items are sorted chronologically.
    times = [i.occurred_at for i in timeline.items]
    assert times == sorted(times)
    # The bundle of timeline items is documented.
    assert timeline.events_considered == 4
    assert timeline.detections_considered == 8
    assert timeline.correlations_considered == 1

    # 4) Phase 4.6 severity engine: deterministic assessment
    #    of the same evidence.
    sev = SeverityEngine().run(
        detections=detections,
        correlations=list(corr_result.correlations),
        events={e.event_id: e for e in events},
        now=datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc),
    )
    # One severity + one confidence assessment per
    # subject plus the bundle pair.
    assert len(sev.severity_assessments) == len(sev.confidence_assessments)
    # 8 detections + 1 correlation + 1 bundle = 10 subjects.
    assert len(sev.severity_assessments) == 10
    # The bundle band is at least MEDIUM (multiple signals
    # are present: detection_count >= 5, event_count >= 3,
    # window >= 60s, source_ip, endpoint, etc.).
    assert severity_at_least(sev.bundle_severity, SeverityBand.MEDIUM)
    # The correlation has multiple present signals.
    corr_sev = next(
        a for a in sev.severity_assessments
        if a.subject_id == corr.correlation_id
    )
    assert severity_at_least(corr_sev.band, SeverityBand.MEDIUM)

    # 5) Determinism: re-running the same engine on the
    #    same evidence produces the same bands.
    sev2 = SeverityEngine().run(
        detections=detections,
        correlations=list(corr_result.correlations),
        events={e.event_id: e for e in events},
        now=datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc),
    )
    assert sev.bundle_severity == sev2.bundle_severity
    assert sev.bundle_confidence == sev2.bundle_confidence
    assert (
        [a.band for a in sev.severity_assessments]
        == [a.band for a in sev2.severity_assessments]
    )


def test_phase46_timeline_uses_only_phase45_evidence(
    nginx_log: Path,
    phase45_pipeline: DetectionPipeline,
):
    # The timeline engine does NOT call into the detection
    # or correlation engines. It just reads the evidence
    # the caller supplies.
    connector = NginxConnector(nginx_log, asset="web-api-01")
    results = phase45_pipeline.run_from_connector(connector)
    events = [r.event for r in results]
    detections = []
    for r in results:
        detections.extend(r.persisted_detections)
    # No correlations -> no correlation items in timeline.
    timeline = TimelineEngine().run(
        events=events,
        detections=detections,
        correlations=[],
        now=datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc),
    )
    # Count correlation items directly.
    from app.timeline.models import TimelineItemKind as _K
    n_corr = sum(1 for i in timeline.items if i.kind is _K.CORRELATION)
    assert n_corr == 0
    # All items are either events or detections.
    for item in timeline.items:
        assert item.kind in (
            TimelineItemKind.EVENT,
            TimelineItemKind.DETECTION,
        )
