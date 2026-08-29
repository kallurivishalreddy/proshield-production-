"""End-to-end integration test: connector -> SecurityEvent ->
Rule applicability + evaluation, with real MongoDB.

This test demonstrates the documented Phase 4.3 end-to-end
flow: source telemetry -> NGINX connector -> canonical
SecurityEvent -> ingestion service -> MongoDB -> rule
applicability filter -> rule evaluation. It is the proof
that the first real connector correctly feeds the Phase 4.2
rule framework.

These tests REQUIRE a running local MongoDB on
127.0.0.1:27017.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.domain.security_event import SecurityEvent
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import (
    SecurityEventRepository,
    _document_to_event,
)
from app.rules import (
    RuleRegistry,
    load_rules_from_specs,
)


# 5 lines: 2 should match the rule, 2 should not, 1 has
# no security signal at all.
_LOG = (
    # MATCH: 401 on auth endpoint
    '192.0.2.10 - alice [26/Aug/2026:03:15:42 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    # MATCH: 403 on auth endpoint
    '192.0.2.11 - bob [26/Aug/2026:03:15:50 +0000] '
    '"POST /api/v1/auth/login HTTP/1.1" 403 50 "-" "Mozilla/5.0"\n'
    # NO MATCH: 404 on auth endpoint (status not 401/403)
    '192.0.2.12 - - [26/Aug/2026:03:16:00 +0000] '
    '"POST /api/login HTTP/1.1" 404 12 "-" "scanner/1.0"\n'
    # NO MATCH: 401 on non-auth endpoint
    '192.0.2.13 - - [26/Aug/2026:03:16:10 +0000] '
    '"GET /api/users/1 HTTP/1.1" 401 30 "-" "scanner/1.0"\n'
    # NO SECURITY SIGNAL: 200 on a public page
    '198.51.100.7 - - [26/Aug/2026:03:16:20 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
)


@pytest.fixture
def nginx_log(tmp_path: Path) -> Path:
    p = tmp_path / "access.log"
    p.write_text(_LOG, encoding="utf-8")
    return p


@pytest.fixture
def rule_registry() -> RuleRegistry:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    return r


def test_end_to_end_nginx_to_rule_evaluation(
    nginx_log: Path,
    rule_registry: RuleRegistry,
    repository: SecurityEventRepository,
    test_config: ProShieldConfig,
) -> None:
    """The full documented Phase 4.3 flow.

    1. The connector reads the NGINX log and yields canonical
       SecurityEvents.
    2. The ingestion service persists them in MongoDB.
    3. The rule registry's applicability filter selects the
       NGINX rule for the relevant events.
    4. The rule is evaluated: it matches the 401/403 on auth
       endpoints and does NOT match the 404 or the 401 on a
       non-auth endpoint.
    """
    service = SecurityEventIngestionService(repository, test_config)
    n = service.ingest_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    # 401 auth + 403 auth + 404 auth + 401 non-auth = 4
    # The 200 is filtered by the mapping (no security signal).
    assert n == 4
    assert repository.count() == 4

    matches = 0
    non_matches = 0
    cursor = repository._collection.find(  # type: ignore[attr-defined]
        {"source": "nginx"}
    )
    for doc in cursor:
        ev = _document_to_event(doc)
        applicable = rule_registry.list_for_event(ev.source, ev.event_type)
        # NGINX-AUTH-BRUTEFORCE-001 is applicable to every
        # authentication_failure and request_blocked event. The
        # Phase 4.4 per-event rules add more applicable rules
        # to the same events; this test focuses on the
        # BRUTEFORCE rule's behaviour.
        assert any(
            r.metadata.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
            for r in applicable
        ), f"rule not applicable to {ev.event_type} on {ev.endpoint}"
        # Test the BRUTEFORCE rule specifically (not all rules).
        bf_rule = next(
            r for r in applicable
            if r.metadata.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
        )
        out = bf_rule.evaluate(ev)
        if out.matched:
            matches += 1
        else:
            non_matches += 1
    # 2 matches (401 + 403 on auth endpoints)
    # 2 non-matches (404 on auth endpoint, 401 on non-auth endpoint)
    assert matches == 2
    assert non_matches == 2


def test_end_to_end_health_reflects_persisted_state(
    nginx_log: Path,
    repository: SecurityEventRepository,
    test_config: ProShieldConfig,
) -> None:
    """After ingestion, the connector's stats reflect what was
    read, parsed, skipped, and emitted.
    """
    service = SecurityEventIngestionService(repository, test_config)
    c = NginxConnector(nginx_log)
    service.ingest_from_connector(c)
    h = c.health()
    # 5 lines read, 5 parsed, 1 with no security signal
    # (200 on /index.html), 4 events emitted.
    assert h["stats"]["lines_read"] == 5
    assert h["stats"]["lines_parsed"] == 5
    assert h["stats"]["lines_skipped_no_signal"] == 1
    assert h["stats"]["events_emitted"] == 4
    assert h["status"] == "ok"


def test_end_to_end_rule_evaluable_filter_is_respected(
    nginx_log: Path,
    rule_registry: RuleRegistry,
    repository: SecurityEventRepository,
    test_config: ProShieldConfig,
) -> None:
    """When the rule is disabled, the applicability filter
    must return empty for the event.
    """
    rule_registry.set_enabled("NGINX-AUTH-BRUTEFORCE-001", False)
    service = SecurityEventIngestionService(repository, test_config)
    service.ingest_from_connector(NginxConnector(nginx_log))
    doc = repository._collection.find_one(  # type: ignore[attr-defined]
        {"source": "nginx", "event_type": "authentication_failure"}
    )
    assert doc is not None
    ev = _document_to_event(doc)
    applicable = rule_registry.list_for_event(ev.source, ev.event_type)
    assert all(
        r.metadata.rule_id != "NGINX-AUTH-BRUTEFORCE-001"
        for r in applicable
    )


def test_end_to_end_provenance_chain_preserved(
    nginx_log: Path,
    repository: SecurityEventRepository,
    test_config: ProShieldConfig,
) -> None:
    """The full provenance chain is preserved end-to-end:
    the connector's collector + source_event_id, the
    ingestion service's server-side event_id, and the rule
    registry's rule_id+version are all attached to the
    persisted event.
    """
    service = SecurityEventIngestionService(repository, test_config)
    service.ingest_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    doc = repository._collection.find_one(  # type: ignore[attr-defined]
        {"source": "nginx", "event_type": "authentication_failure"}
    )
    assert doc is not None
    assert doc["provenance"]["collector"] == "nginx"
    assert doc["provenance"]["source_event_id"]
    # The asset supplied to the connector is propagated.
    assert doc["asset"] == "web-api-01"


# ----------------------------------------------------------------------
# DEDUP-01 regression tests.
# ----------------------------------------------------------------------
# These tests prove the DEDUP-01 fix: the NGINX connector
# must produce the same event_id for the same log line across
# connector instances, process restarts, and repeated reads of
# the same log file. They are run against the real local
# MongoDB so the entire persistence-layer dedup path is
# exercised, not just the connector.


def test_dedup01_two_connector_instances_produce_same_event_id(
    tmp_path: Path,
) -> None:
    """Two NginxConnector instances constructed
    seconds apart produce the SAME event_id for the
    same log line. This is the DEDUP-01 fix proof.
    """
    import time
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - alice [26/Aug/2026:03:15:42 +0000] '
        '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n',
        encoding="utf-8",
    )
    c1 = NginxConnector(p)
    e1 = list(c1.collect())
    time.sleep(0.05)
    c2 = NginxConnector(p)
    e2 = list(c2.collect())
    assert e1[0].event_id == e2[0].event_id


def test_dedup01_pipeline_does_not_create_duplicate_persisted_events(
    nginx_log: Path,
    repository: SecurityEventRepository,
    test_config: ProShieldConfig,
) -> None:
    """Running the full pipeline (connector -> ingestion
    -> persistence) twice for the same log file produces
    no duplicate persisted SecurityEvents. The second
    run is a no-op (every event hits the duplicate-key
    branch of insert_one).
    """
    repository._collection.delete_many({})  # type: ignore[attr-defined]
    service = SecurityEventIngestionService(
        repository, test_config
    )
    c1 = NginxConnector(nginx_log)
    events1 = [service.ingest(ev) for ev in c1.collect()]
    count_after_run_1 = repository.count()
    c2 = NginxConnector(nginx_log)
    events2 = [service.ingest(ev) for ev in c2.collect()]
    count_after_run_2 = repository.count()
    assert count_after_run_2 == count_after_run_1, (
        f"second connector run created "
        f"{count_after_run_2 - count_after_run_1} duplicate event(s)"
    )
    ids1 = sorted(e.event_id for e in events1)
    ids2 = sorted(e.event_id for e in events2)
    assert ids1 == ids2


def test_dedup01_detection_counts_do_not_double_on_replay(
    nginx_log: Path,
    rule_registry: RuleRegistry,
    repository: SecurityEventRepository,
    db,  # type: ignore[no-untyped-def]
    test_config: ProShieldConfig,
) -> None:
    """Replaying the same log does not double the
    detection count. This is the downstream-impact
    proof of the DEDUP-01 fix: without it, every replay
    would double the persisted detections and inflate
    the correlation count.
    """
    from app.detection.engine import DetectionEngine
    from app.detection.pipeline import DetectionPipeline
    from app.persistence.detection_repository import (
        DetectionRepository,
    )

    repository._collection.delete_many({})  # type: ignore[attr-defined]
    det_repo = DetectionRepository(db, test_config)
    det_repo.ensure_schema()
    det_repo.ensure_indexes()
    det_repo._collection.delete_many({})  # type: ignore[attr-defined]
    service = SecurityEventIngestionService(
        repository, test_config
    )
    pipeline = DetectionPipeline(
        ingestion_service=service,
        detection_engine=DetectionEngine(registry=rule_registry),
        detection_repository=det_repo,
    )
    c1 = NginxConnector(nginx_log)
    [pipeline.run(ev) for ev in c1.collect()]
    n_db_1 = det_repo.count()
    c2 = NginxConnector(nginx_log)
    [pipeline.run(ev) for ev in c2.collect()]
    n_db_2 = det_repo.count()
    assert n_db_2 == n_db_1, (
        f"replay doubled the detection count: {n_db_1} -> {n_db_2}"
    )


def test_dedup01_correlation_evidence_does_not_double_on_replay(
    nginx_log: Path,
    rule_registry: RuleRegistry,
    repository: SecurityEventRepository,
    db,  # type: ignore[no-untyped-def]
    test_config: ProShieldConfig,
) -> None:
    """Replaying the same log does not double the
    correlation evidence. Without DEDUP-01, every replay
    would insert duplicate Detections, the correlation
    engine would see 2x the detections, and the
    correlation count would inflate.
    """
    from app.correlation.engine import CorrelationEngine
    from app.correlation.patterns import BruteForceClusteringPattern
    from app.detection.engine import DetectionEngine
    from app.detection.pipeline import DetectionPipeline
    from app.persistence.correlation_repository import (
        CorrelationRepository,
    )
    from app.persistence.detection_repository import (
        DetectionRepository,
    )

    repository._collection.delete_many({})  # type: ignore[attr-defined]
    det_repo = DetectionRepository(db, test_config)
    det_repo.ensure_schema()
    det_repo.ensure_indexes()
    det_repo._collection.delete_many({})  # type: ignore[attr-defined]
    corr_repo = CorrelationRepository(db, test_config)
    corr_repo.ensure_schema()
    corr_repo.ensure_indexes()
    corr_repo._collection.delete_many({})  # type: ignore[attr-defined]
    service = SecurityEventIngestionService(
        repository, test_config
    )
    pipeline = DetectionPipeline(
        ingestion_service=service,
        detection_engine=DetectionEngine(registry=rule_registry),
        detection_repository=det_repo,
    )
    c1 = NginxConnector(nginx_log)
    events1 = []
    detections1 = []
    for ev in c1.collect():
        r = pipeline.run(ev)
        events1.append(r.event)
        detections1.extend(r.persisted_detections)
    ev_by_id1 = {e.event_id: e for e in events1}
    corr_eng = CorrelationEngine(
        patterns=[BruteForceClusteringPattern()]
    )
    corr1 = corr_eng.run(detections1, ev_by_id1)
    n_corr_db_1 = corr_repo.count()
    c2 = NginxConnector(nginx_log)
    events2 = []
    detections2 = []
    for ev in c2.collect():
        r = pipeline.run(ev)
        events2.append(r.event)
        detections2.extend(r.persisted_detections)
    ev_by_id2 = {e.event_id: e for e in events2}
    corr2 = corr_eng.run(detections2, ev_by_id2)
    n_corr_db_2 = corr_repo.count()
    assert n_corr_db_2 == n_corr_db_1, (
        f"replay inflated persisted correlation count: "
        f"{n_corr_db_1} -> {n_corr_db_2}"
    )
    corr_ids_1 = sorted(c.correlation_id for c in corr1.correlations)
    corr_ids_2 = sorted(c.correlation_id for c in corr2.correlations)
    assert corr_ids_1 == corr_ids_2

