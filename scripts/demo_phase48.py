"""Phase 4.8 demo script: end-to-end investigation flow.

This script exercises the full Phase 4.8 backend pipeline
against a real local MongoDB:

* ingestion (Phase 4.1) -> NGINX 4x 401 + 1x 200,
* detection (Phase 4.4) + correlation (Phase 4.5) on
  the persisted events,
* incident creation (Phase 4.8) from real evidence,
* routing (Phase 4.8) for the case,
* normal investigation report (Phase 4.8),
* analyst-requested centralized correlation
  (Phase 4.8 via the proxy / incident service),
* centralized investigation report (Phase 4.8),
* failure paths: routing failure / IDOR / rate limits.

The demo runs against the dedicated ``proshield_demo_phase48``
database. Each run drops the database, re-bootstraps,
and re-runs the flow.

Usage::

    python -m scripts.demo_phase48
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.auth import (
    ADMIN_ROLE,
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
from app.detection import (
    DetectionEngine,
    DetectionPipeline,
)
from app.incidents import (
    IncidentRepository,
    IncidentService,
)
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
    OP_HEALTH,
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


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _build_test_config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="demo",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db="proshield_demo_phase48",
        mongo_collection_events="security_events_demo_phase48",
        auth_signing_key=new_development_signing_key(),
        auth_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=10000,
        proxy_max_request_bytes=32_768,
        proxy_max_response_bytes=1_048_576,
        proxy_centralized_rate_limit_per_minute=10,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        connector_specs=[],
    )


def _bootstrap_mongo(db, test_config: ProShieldConfig) -> None:
    incident_repo = IncidentRepository(db, test_config)
    incident_repo.ensure_schema()
    incident_repo.ensure_indexes()
    report_repo = ReportRepository(db, test_config)
    report_repo.ensure_schema()
    report_repo.ensure_indexes()
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    correlation_repo = CorrelationRepository(db, test_config)
    correlation_repo.ensure_schema()
    correlation_repo.ensure_indexes()
    event_repo = SecurityEventRepository(db, test_config)
    event_repo.ensure_schema()
    event_repo.ensure_indexes()


def _event_to_dict(e) -> dict:
    return {
        "event_id": e.event_id,
        "source": e.source,
        "event_type": e.event_type,
        "event_time": e.event_time.isoformat(),
        "endpoint": e.endpoint,
        "source_ip": e.source_ip,
        "asset": e.asset,
        "account": e.account,
    }


def _detection_to_dict(d) -> dict:
    return {
        "detection_id": d.detection_id,
        "rule_id": d.rule_id,
        "rule_version": d.rule_version,
        "category": d.category.value,
        "event_id": d.event_id,
        "evidence_refs": list(d.evidence_refs),
        "reasoning": d.reasoning,
        "detected_at": d.detected_at.isoformat(),
    }


def _correlation_to_dict(c) -> dict:
    return {
        "correlation_id": c.correlation_id,
        "pattern_id": c.pattern_id,
        "pattern_version": c.pattern_version,
        "trigger": c.trigger.value,
        "key": list(c.key.parts),
        "detection_ids": list(c.detection_ids),
        "event_ids": list(c.event_ids),
        "window_start": c.window_start.isoformat(),
        "window_end": c.window_end.isoformat(),
        "count": c.count,
        "reasoning": c.reasoning,
        "correlated_at": c.correlated_at.isoformat(),
    }


def _build_proxy_and_services(test_config, db, identity_store):
    """Construct the Phase 4.8 service / proxy stack."""
    event_repo = SecurityEventRepository(db, test_config)
    detection_repo = DetectionRepository(db, test_config)
    correlation_repo = CorrelationRepository(db, test_config)
    ingestion = SecurityEventIngestionService(event_repo, test_config)
    registry = RuleRegistry()
    load_rules_from_specs(registry, [])
    detection_engine = DetectionEngine(registry)
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    log_path = Path(ROOT) / "demo_phase48_nginx.log"
    log_path.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    connector = NginxConnector(log_path, asset="web-api-01")
    try:
        results = pipeline.run_from_connector(connector)
    finally:
        try:
            log_path.unlink()
        except OSError:
            pass
    events = [r.event for r in results]
    detections = [
        d for r in results for d in r.detection_result.detections
    ]
    correlation_engine = CorrelationEngine(
        patterns=[BruteForceClusteringPattern(
            threshold=4, window=timedelta(seconds=60),
        )]
    )
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
    incident_repo = IncidentRepository(db, test_config)
    report_repo = ReportRepository(db, test_config)
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
    return (
        proxy, incident_service, correlation_engine,
        events, detections, correlations,
    )


def main() -> int:
    _configure_logging()
    test_config = _build_test_config()
    from app.observability.logging import configure_logging
    configure_logging(test_config.log_level)
    from app.persistence.mongo import (
        check_connectivity,
        make_client,
        mongo_session,
    )
    try:
        client = make_client(test_config)
        check_connectivity(client)
        client.close()
    except Exception as exc:  # noqa: BLE001
        print(
            "ERROR: cannot reach MongoDB at",
            test_config.mongo_uri,
            file=sys.stderr,
        )
        print("cause:", type(exc).__name__, file=sys.stderr)
        return 2

    with mongo_session(test_config) as (_client, db):
        for name in db.list_collection_names():
            db.drop_collection(name)
        _bootstrap_mongo(db, test_config)

        identity_store = InMemoryIdentityStore({
            "user-analyst-001": Identity(
                subject_id="user-analyst-001",
                role=ANALYST_ROLE,
                display_name="Demo Analyst",
            ),
            "user-admin-001": Identity(
                subject_id="user-admin-001",
                role=ADMIN_ROLE,
                display_name="Demo Admin",
            ),
        })
        (
            proxy, incident_service, correlation_engine,
            events, detections, correlations,
        ) = _build_proxy_and_services(test_config, db, identity_store)
        analyst_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE,
            headers={},
            body={"subject_id": "user-analyst-001"},
        )).body["data"]["token"]

        print("\n========== NORMAL INVESTIGATION ==========")
        analyst = identity_store.get("user-analyst-001")
        case = incident_service.create_case(
            identity=analyst,
            title="Brute force login attempts",
            summary="4 x 401 from 198.51.100.7 to /api/login",
            events=events,
            detections=detections,
            correlations=correlations,
        )
        print("created case:", case.incident_id)

        resp = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body={"incident_id": case.incident_id},
        ))
        print("GET_CASE status:", resp.status)
        assert resp.status == 200

        resp = proxy.handle(ProxyRequest(
            operation=OP_ROUTE_CASE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body={"incident_id": case.incident_id},
        ))
        print("ROUTE_CASE:", json.dumps(resp.body, default=str)[:300])
        assert resp.status == 200

        report_payload = {
            "incident_id": case.incident_id,
            "events": [_event_to_dict(e) for e in events],
            "detections": [_detection_to_dict(d) for d in detections],
            "correlations": [_correlation_to_dict(c) for c in correlations],
        }
        resp = proxy.handle(ProxyRequest(
            operation=OP_GENERATE_NORMAL_REPORT,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body=report_payload,
        ))
        print("GENERATE_NORMAL_REPORT status:", resp.status)
        assert resp.status == 200, resp.body

        print("\n========== CENTRALIZED INVESTIGATION ==========")
        # Simulate broader evidence: the analyst hands the
        # centralized engine a wider window of failures from
        # the same source. These extra events/detections will
        # produce *new* correlation ids the original case did
        # not have, exercising the dedupe → new_ids path.
        from datetime import datetime, timezone
        from app.detection.models import Detection
        from app.domain.security_event import SecurityEvent
        extra_events = []
        extra_detections = []
        base_t = datetime(2026, 8, 26, 12, 5, 0, tzinfo=timezone.utc)
        for i in range(4):
            ev_id = f"01a0c4fe-0000-7000-8000-{i:012d}"
            det_id = f"det-0000000{i}-0000-7000-8000-{i:012d}"
            ev = SecurityEvent(
                event_id=ev_id,
                source="nginx",
                event_type="authentication_failure",
                event_time=base_t.replace(second=i * 5),
                ingested_at=base_t.replace(second=i * 5),
                source_ip="198.51.100.55",
                endpoint="/api/admin",
                provenance={"collector": "nginx", "source_event_id": f"extra-{i}"},
            )
            dt = Detection(
                detection_id=det_id,
                rule_id="NGINX-AUTH-FAILURE-001",
                rule_version=1,
                category="source_specific",
                event_id=ev_id,
                evidence_refs=(),
                reasoning="centralized extra event",
                detected_at=ev.event_time,
            )
            extra_events.append(ev)
            extra_detections.append(dt)
        centralized_events = list(events) + extra_events
        centralized_detections = list(detections) + extra_detections
        centralized_payload = {
            "incident_id": case.incident_id,
            "reason": "broader analysis requested",
            "events": [_event_to_dict(e) for e in centralized_events],
            "detections": [_detection_to_dict(d) for d in centralized_detections],
        }
        resp = proxy.handle(ProxyRequest(
            operation=OP_REQUEST_CENTRALIZED,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body=centralized_payload,
        ))
        print(
            "REQUEST_CENTRALIZED status:",
            resp.status,
            "failed:",
            resp.body["data"].get("failed"),
        )
        assert resp.status == 200, resp.body
        case = incident_service.get_case(analyst, case.incident_id)
        centralized_report_payload = {
            "incident_id": case.incident_id,
            "events": [_event_to_dict(e) for e in events],
            "detections": [_detection_to_dict(d) for d in detections],
            "correlations": [_correlation_to_dict(c) for c in correlations],
            "centralized_correlations": [
                _correlation_to_dict(c) for c in correlations
            ],
            "centralized_events": [
                _event_to_dict(e) for e in centralized_events
            ],
            "centralized_detections": [
                _detection_to_dict(d) for d in centralized_detections
            ],
        }
        resp = proxy.handle(ProxyRequest(
            operation=OP_GENERATE_CENTRALIZED_REPORT,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body=centralized_report_payload,
        ))
        print("GENERATE_CENTRALIZED_REPORT status:", resp.status)
        assert resp.status == 200, resp.body

        resp = proxy.handle(ProxyRequest(
            operation=OP_LIST_REPORTS,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body={"incident_id": case.incident_id},
        ))
        print(
            "LIST_REPORTS status:",
            resp.status,
            "count:",
            len(resp.body["data"]["reports"]),
        )
        assert resp.status == 200
        assert len(resp.body["data"]["reports"]) >= 2

        print("\n========== FAILURE PATHS ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE,
            headers={},
            body={"incident_id": case.incident_id},
        ))
        print("missing-token status:", resp.status)
        assert resp.status == 401

        identity_store._identities["user-analyst-002"] = Identity(
            subject_id="user-analyst-002",
            role=ANALYST_ROLE,
        )
        other_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE,
            headers={},
            body={"subject_id": "user-analyst-002"},
        )).body["data"]["token"]
        resp = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {other_token}"},
            body={"incident_id": case.incident_id},
        ))
        print("IDOR / hidden-case status:", resp.status)
        assert resp.status == 404

        for _ in range(int(test_config.proxy_centralized_rate_limit_per_minute)):
            proxy.handle(ProxyRequest(
                operation=OP_REQUEST_CENTRALIZED,
                headers={
                    PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
                },
                body=centralized_payload,
            ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_REQUEST_CENTRALIZED,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body=centralized_payload,
        ))
        print("centralized-rate-limit status:", resp.status)
        assert resp.status == 429

        resp = proxy.handle(ProxyRequest(
            operation=OP_HEALTH,
            headers={},
            body=None,
        ))
        print("health status:", resp.status)
        assert resp.status == 200

        print("\n========== CLOSE CASE ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_CLOSE_CASE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}"},
            body={"incident_id": case.incident_id, "reason": "demo done"},
        ))
        print("close status:", resp.status)
        assert resp.status == 200
        print("\nDEMO OK")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())