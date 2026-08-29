"""End-to-end integration test for the Phase 4.5 pipeline +
correlation engine, with real MongoDB.

The test demonstrates the documented Phase 4.5 flow:

  NGINX connector (Phase 4.3)
    -> SecurityEvent
    -> Ingestion service (Phase 4.1) -> MongoDB
    -> Detection engine (Phase 4.4) -> Detection per event
    -> DetectionRepository (Phase 4.5) -> MongoDB detections
    -> Correlation engine (Phase 4.5) -> Correlation records
    -> CorrelationRepository (Phase 4.5) -> MongoDB correlations

This is the proof that the Phase 4.5 wiring works through
the same canonical pipeline that real collectors use.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.correlation import (
    BruteForceClusteringPattern,
    Correlation,
    CorrelationEngine,
)
from app.correlation.models import CorrelationKey
from app.detection import DetectionEngine, DetectionPipeline
from app.detection.models import Detection
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.detection_repository import DetectionRepository
from app.persistence.security_event_repository import (
    SecurityEventRepository,
    _document_to_event,
)
from app.rules import (
    RuleRegistry,
    load_rules_from_specs,
)


_BRUTEFORCE_LOG = (
    # 4 auth failures on /api/login from the same source
    '198.51.100.7 - - [26/Aug/2026:12:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:10 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:20 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:30 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    # A 200 on a public page (no event, no detection)
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
def pipeline(
    repository: SecurityEventRepository,
    rule_registry: RuleRegistry,
    test_config: ProShieldConfig,
    db,
) -> DetectionPipeline:
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


def test_phase45_full_pipeline_correlates_brute_force(
    nginx_log: Path,
    pipeline: DetectionPipeline,
    db,
    test_config: ProShieldConfig,
) -> None:
    """The end-to-end Phase 4.5 flow."""
    connector = NginxConnector(nginx_log, asset="web-api-01")
    results = pipeline.run_from_connector(connector)
    assert len(results) == 4
    total_detections = sum(
        len(r.detection_result.detections) for r in results
    )
    # Each 401 produces 2 detections: FAILURE-001 (broad
    # 401) + BRUTEFORCE-001 (401/403 on auth-shaped endpoint).
    assert total_detections == 8
    det_repo = pipeline.detection_repository
    assert det_repo.count() == 8

    cursor = db[
        test_config.mongo_collection_events
    ].find({"source": "nginx"})
    all_detections: list[Detection] = []
    events_by_id: dict = {}
    for doc in cursor:
        ev = _document_to_event(doc)
        events_by_id[ev.event_id] = ev
        all_detections.extend(det_repo.find_by_event_id(ev.event_id))
    assert len(all_detections) == 8

    corr_engine = CorrelationEngine(
        patterns=[BruteForceClusteringPattern()]
    )
    corr_result = corr_engine.run(
        detections=all_detections,
        events=events_by_id,
        now=datetime(2026, 8, 26, 12, 1, 0, tzinfo=timezone.utc),
    )
    assert corr_result.correlation_count == 1
    corr = corr_result.correlations[0]
    assert corr.pattern_id == "NGINX-CORR-BRUTEFORCE-001"
    # The pattern groups by (source_ip, endpoint). The
    # 4 events produce 8 auth-failure detections (2 per event)
    # that all share the same key, so the correlation
    # count is 8.
    assert corr.count == 8
    assert corr.key.parts == ("198.51.100.7", "/api/login")

    corr_repo = CorrelationRepository(db, test_config)
    corr_repo.ensure_schema()
    corr_repo.ensure_indexes()
    persisted = corr_repo.create(corr)
    assert persisted is corr
    fetched = corr_repo.get_by_correlation_id(corr.correlation_id)
    assert fetched is not None
    assert fetched.correlation_id == corr.correlation_id

    # Idempotent re-persistence: count stays at 1.
    try:
        corr_repo.create(corr)
    except Exception:
        pass
    assert corr_repo.count() == 1


def test_phase45_correlation_repository_round_trip(
    db, test_config: ProShieldConfig
) -> None:
    """Correlation can be persisted and read back losslessly."""
    corr = Correlation(
        correlation_id="corr-01923456-7890-7abc-9def-0123456789ab",
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=(
            "det-01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "det-01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        event_ids=(
            "01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        window_start=datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 8, 26, 12, 0, 30, tzinfo=timezone.utc),
        count=2,
        reasoning="brute-force clustering: 2 auth failures from 198.51.100.7 to /api/login",
        correlated_at=datetime(2026, 8, 26, 12, 1, 0, tzinfo=timezone.utc),
    )
    repo = CorrelationRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    repo.create(corr)
    fetched = repo.get_by_correlation_id(corr.correlation_id)
    assert fetched is not None
    assert fetched.pattern_id == "NGINX-CORR-BRUTEFORCE-001"
    assert fetched.count == 2
    assert fetched.key.parts == ("198.51.100.7", "/api/login")
    assert len(fetched.detection_ids) == 2
    assert len(fetched.event_ids) == 2
    assert fetched.window_start == corr.window_start
    assert fetched.window_end == corr.window_end


def test_phase45_detection_repository_round_trip(
    db, test_config: ProShieldConfig
) -> None:
    """Detection can be persisted and read back losslessly."""
    det = Detection(
        detection_id="det-01923456-7890-7abc-9def-0123456789ab",
        rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1,
        category="source_specific",
        event_id="01923456-7890-7abc-9def-0123456789ab",
        evidence_refs=("01923456-7890-7abc-9def-0123456789ab",),
        reasoning="nginx HTTP 401 ...",
        detected_at=datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc),
    )
    repo = DetectionRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    repo.create(det)
    fetched = repo.get_by_detection_id(det.detection_id)
    assert fetched is not None
    assert fetched.detection_id == det.detection_id
    assert fetched.rule_id == "NGINX-AUTH-FAILURE-001"
    by_event = repo.find_by_event_id(det.event_id)
    assert len(by_event) == 1
    assert by_event[0].detection_id == det.detection_id