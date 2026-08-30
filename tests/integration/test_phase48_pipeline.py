"""End-to-end integration test for the Phase 4.8 backend layer.

Exercises the full Phase 4.8 stack against the real local
MongoDB:

* NGINX ingest (Phase 4.1) -> 4x 401 + 1x 200,
* detection (Phase 4.4) + correlation (Phase 4.5),
* incident creation (Phase 4.8) from real evidence,
* routing (Phase 4.8) for the case,
* normal investigation report (Phase 4.8),
* analyst-requested centralized correlation (Phase 4.8),
* centralized investigation report (Phase 4.8),
* close case (Phase 4.8).

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from app.auth import (
    ANALYST_ROLE,
    Identity,
    InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.detection import DetectionEngine, DetectionPipeline
from app.incidents.repository import IncidentRepository
from app.incidents.service import IncidentService
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.detection_repository import DetectionRepository
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_CLOSE_CASE,
    OP_GENERATE_CENTRALIZED_REPORT,
    OP_GENERATE_NORMAL_REPORT,
    OP_GET_CASE,
    OP_LIST_CASES,
    OP_LIST_REPORTS,
    OP_REQUEST_CENTRALIZED,
    OP_ROUTE_CASE,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.reports import ReportRepository, ReportService
from app.rules import RuleRegistry, load_rules_from_specs

_BASIC_NGINX_LOG = (
    '198.51.100.7 - - [26/Aug/2026:12:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:10 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:20 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:30 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.99 - - [26/Aug/2026:12:00:40 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
)


def _to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return dict(obj)


@pytest.fixture
def nginx_log(tmp_path: Path) -> Path:
    p = tmp_path / "access.log"
    p.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    return p


@pytest.fixture
def identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-analyst-002": Identity(
            subject_id="user-analyst-002", role=ANALYST_ROLE,
        ),
    })

@pytest.fixture
def proxy_stack(
    db, test_config: ProShieldConfig, identity_store: InMemoryIdentityStore
):
    test_config = ProShieldConfig(
        env_name=test_config.env_name,
        log_level=test_config.log_level,
        mongo_uri=test_config.mongo_uri,
        mongo_db=test_config.mongo_db,
        mongo_collection_events=test_config.mongo_collection_events,
        ingest_max_body_bytes=test_config.ingest_max_body_bytes,
        ingest_max_details_bytes=test_config.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=test_config.ingest_rate_limit_per_minute,
        connector_specs=[],
        auth_signing_key=new_development_signing_key(),
        proxy_centralized_rate_limit_per_minute=10,
    )
    event_repo = SecurityEventRepository(db, test_config)
    event_repo.ensure_schema()
    event_repo.ensure_indexes()
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    correlation_repo = CorrelationRepository(db, test_config)
    correlation_repo.ensure_schema()
    correlation_repo.ensure_indexes()
    incident_repo = IncidentRepository(db, test_config)
    incident_repo.ensure_schema()
    incident_repo.ensure_indexes()
    report_repo = ReportRepository(db, test_config)
    report_repo.ensure_schema()
    report_repo.ensure_indexes()
    ingestion = SecurityEventIngestionService(event_repo, test_config)
    registry = RuleRegistry()
    load_rules_from_specs(registry, ["app.rules._library.nginx"])
    detection_engine = DetectionEngine(registry)
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    correlation_engine = CorrelationEngine(
        patterns=[BruteForceClusteringPattern(
            threshold=4, window=timedelta(seconds=60),
        )]
    )
    incident_service = IncidentService(
        incident_repo,
        correlation_engine=correlation_engine,
        correlation_persister=lambda cs: [
            correlation_repo.create(c) for c in cs
        ],
    )
    # Phase 4.8 remediation: the report service is wired
    # with the incident service so that ``report.get`` can
    # enforce the canonical case-level authorization
    # boundary (see docs/PHASE 4/PHASE-04-08-REVIEW.md §2.4
    # and the post-review remediation in
    # docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md).
    report_service = ReportService(
        report_repo, incident_service=incident_service,
    )
    proxy = SecureProxy(
        config=test_config,
        identity_store=identity_store,
        incident_service=incident_service,
        report_service=report_service,
    )
    return {
        "config": test_config,
        "event_repo": event_repo,
        "detection_repo": detection_repo,
        "correlation_repo": correlation_repo,
        "incident_repo": incident_repo,
        "report_repo": report_repo,
        "pipeline": pipeline,
        "correlation_engine": correlation_engine,
        "incident_service": incident_service,
        "report_service": report_service,
        "proxy": proxy,
    }


def _run_ingest(
    pipeline: DetectionPipeline, nginx_log: Path,
) -> Tuple[List[Any], List[Any], List[Any]]:
    connector = NginxConnector(nginx_log, asset="web-api-01")
    results = pipeline.run_from_connector(connector)
    events = [r.event for r in results]
    detections = [d for r in results for d in r.detection_result.detections]
    return events, detections, results


def _issue_token(proxy: SecureProxy, subject_id: str) -> str:
    resp = proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject_id},
    ))
    assert resp.status == 200
    return resp.body["data"]["token"]


def _synthesize_centralized_extras() -> Tuple[List[Any], List[Any]]:
    from datetime import datetime, timezone
    from app.detection.models import Detection
    from app.domain.security_event import SecurityEvent
    extra_events = []
    extra_detections = []
    for i in range(4):
        ev_id = f"01a0c4fe-0000-7000-8000-{i + 10:012d}"
        det_id = f"det-000000{i + 10}-0000-7000-8000-{i + 10:012d}"
        ts = datetime(2026, 8, 26, 12, 5, i, tzinfo=timezone.utc)
        ev = SecurityEvent(
            event_id=ev_id, source="nginx",
            event_type="authentication_failure",
            event_time=ts, ingested_at=ts,
            source_ip="198.51.100.55",
            endpoint="/api/admin",
            provenance={"collector": "nginx", "source_event_id": f"int-{i}"},
        )
        dt = Detection(
            detection_id=det_id, rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=1, category="source_specific",
            event_id=ev_id, evidence_refs=(),
            reasoning="integration extra event", detected_at=ts,
        )
        extra_events.append(ev)
        extra_detections.append(dt)
    return extra_events, extra_detections


def test_phase48_full_pipeline_through_proxy(
    proxy_stack, nginx_log, identity_store
) -> None:
    """Full E2E: ingest -> detect -> correlate -> case ->
    routing -> normal report -> centralized -> centralized
    report -> close."""
    pipeline = proxy_stack["pipeline"]
    incident_service = proxy_stack["incident_service"]
    correlation_engine = proxy_stack["correlation_engine"]
    correlation_repo = proxy_stack["correlation_repo"]
    proxy: SecureProxy = proxy_stack["proxy"]

    events, detections, _ = _run_ingest(pipeline, nginx_log)
    assert len(events) == 4
    assert len(detections) >= 4

    correlation_result = correlation_engine.run(
        detections=detections,
        events={e.event_id: e for e in events},
    )
    for c in correlation_result.correlations:
        try:
            correlation_repo.create(c)
        except Exception:
            pass
    correlations = list(correlation_result.correlations)
    assert len(correlations) >= 1

    analyst_token = _issue_token(proxy, "user-analyst-001")
    other_token = _issue_token(proxy, "user-analyst-002")

    # The proxy's create_case handler is a documented stub
    # in this phase: it does not construct evidence. The
    # canonical entry point for case creation remains the
    # IncidentService; the proxy boundary is exercised for
    # every other read / transition / report operation.
    analyst = Identity(
        subject_id="user-analyst-001", role=ANALYST_ROLE,
    )
    case = incident_service.create_case(
        identity=analyst,
        title="Phase 4.8 E2E integration case",
        summary="Brute force from 198.51.100.7",
        events=events,
        detections=detections,
        correlations=correlations,
    )
    case_id = case.incident_id
    assert case_id.startswith("case-")

    resp = proxy.handle(ProxyRequest(
        operation=OP_GET_CASE,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={"incident_id": case_id},
    ))
    assert resp.status == 200, resp.body

    # IDOR: another analyst must see 404 (existence hidden).
    resp = proxy.handle(ProxyRequest(
        operation=OP_GET_CASE,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {other_token}"},
        body={"incident_id": case_id},
    ))
    assert resp.status == 404, resp.body

    resp = proxy.handle(ProxyRequest(
        operation=OP_ROUTE_CASE,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={"incident_id": case_id},
    ))
    assert resp.status == 200, resp.body
    assert resp.body["data"]["routing"]["state"] == "ok"

    resp = proxy.handle(ProxyRequest(
        operation=OP_LIST_CASES,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={"state": "open"},
    ))
    assert resp.status == 200, resp.body
    assert any(
        c["incident_id"] == case_id
        for c in resp.body["data"]["cases"]
    )

    normal_report_payload = {
        "incident_id": case_id,
        "events": [_to_dict(e) for e in events],
        "detections": [_to_dict(d) for d in detections],
        "correlations": [_to_dict(c) for c in correlations],
    }
    resp = proxy.handle(ProxyRequest(
        operation=OP_GENERATE_NORMAL_REPORT,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body=normal_report_payload,
    ))
    assert resp.status == 200, resp.body

    extra_events, extra_detections = _synthesize_centralized_extras()
    centralized_events = list(events) + extra_events
    centralized_detections = list(detections) + extra_detections

    resp = proxy.handle(ProxyRequest(
        operation=OP_REQUEST_CENTRALIZED,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={
            "incident_id": case_id,
            "reason": "broader analysis requested",
            "events": [_to_dict(e) for e in centralized_events],
            "detections": [_to_dict(d) for d in centralized_detections],
        },
    ))
    assert resp.status == 200, resp.body
    assert resp.body["data"]["failed"] is False
    assert len(resp.body["data"]["new_correlation_ids"]) >= 1

    centralized_report_payload = {
        "incident_id": case_id,
        "events": [_to_dict(e) for e in events],
        "detections": [_to_dict(d) for d in detections],
        "correlations": [_to_dict(c) for c in correlations],
        "centralized_correlations": [_to_dict(c) for c in correlations],
        "centralized_events": [_to_dict(e) for e in centralized_events],
        "centralized_detections": [_to_dict(d) for d in centralized_detections],
    }
    resp = proxy.handle(ProxyRequest(
        operation=OP_GENERATE_CENTRALIZED_REPORT,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body=centralized_report_payload,
    ))
    assert resp.status == 200, resp.body

    resp = proxy.handle(ProxyRequest(
        operation=OP_LIST_REPORTS,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={"incident_id": case_id},
    ))
    assert resp.status == 200, resp.body
    assert len(resp.body["data"]["reports"]) >= 2

    resp = proxy.handle(ProxyRequest(
        operation=OP_CLOSE_CASE,
        headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
        body={"incident_id": case_id, "reason": "investigation done"},
    ))
    assert resp.status == 200, resp.body
    assert resp.body["data"]["case"]["state"] == "closed"

    case = incident_service.get_case(
        Identity(subject_id="user-analyst-001", role=ANALYST_ROLE),
        case_id,
    )
    assert case.state.value == "closed"
