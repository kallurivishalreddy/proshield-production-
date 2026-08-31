"""Phase 4.9 — Source Management + trusted inbound integration demo.

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.
"""
from __future__ import annotations

import logging
import sys
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
from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.detection import DetectionEngine
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.correlation_repository import (
    CorrelationRepository,
)
from app.persistence.detection_repository import (
    DetectionRepository,
)
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_SOURCE_CONFIGURE,
    OP_SOURCE_ENABLE,
    OP_SOURCE_GET,
    OP_SOURCE_ISSUE_TOKEN,
    OP_SOURCE_LIST,
    OP_SOURCE_REGISTER,
    OP_SOURCE_RETIRE,
    OP_SOURCE_VALIDATE,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.rules import RuleRegistry, load_rules_from_specs
from app.sources import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenVerifier,
    SourceManagementService,
    SourceRegistry,
    SourceRepository,
)
from app.sources.ingress import (
    INGRESS_HEADER_AUTHORIZATION,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
)
from app.persistence.security_event_repository import (
    _document_to_event,
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
        mongo_db="proshield_demo_phase49",
        mongo_collection_events=(
            "security_events_demo_phase49"
        ),
        auth_signing_key=new_development_signing_key(),
        source_signing_key=new_development_signing_key(),
        source_token_lifetime_seconds=3600,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        proxy_rate_limit_per_minute=120,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_max_response_bytes=base.ingress_max_response_bytes,
    )


def main() -> int:
    _configure_logging()
    config = _build_test_config()
    print(
        f"\n=== Phase 4.9 demo "
        f"(mongo_db={config.mongo_db}) ==="
    )

    from app.persistence.mongo import mongo_session
    with mongo_session(config) as (_, db):
        for coll in [
            config.mongo_collection_events,
            "detections",
            "correlations",
            "incidents",
            "reports",
            "managed_rules",
            "source_instances",
        ]:
            db[coll].drop()
        security_event_repo = SecurityEventRepository(db, config)
        security_event_repo.ensure_schema()
        security_event_repo.ensure_indexes()
        detection_repo = DetectionRepository(db, config)
        detection_repo.ensure_schema()
        detection_repo.ensure_indexes()
        correlation_repo = CorrelationRepository(db, config)
        correlation_repo.ensure_schema()
        correlation_repo.ensure_indexes()
        source_repo = SourceRepository(db, config)
        source_repo.ensure_schema()
        source_repo.ensure_indexes()

        source_registry = SourceRegistry()
        token_issuer = SourceIdentityTokenIssuer(
            secret=config.source_signing_key,
            lifetime_seconds=3600,
        )
        source_service = SourceManagementService(
            repository=source_repo,
            registry=source_registry,
            token_issuer=token_issuer,
        )
        token_verifier = SourceIdentityTokenVerifier.from_secret(
            config.source_signing_key,
            max_lifetime_seconds=3600,
            source_resolver=lambda sid: source_repo.get(sid),
        )
        ingestion_service = SecurityEventIngestionService(
            security_event_repo, config,
        )
        ingress = InboundIngressProxy(
            config=config,
            registry=source_registry,
            token_verifier=token_verifier,
            ingestion_service=ingestion_service,
            authoritative_source_resolver=lambda sid: source_repo.get(sid),
        )

        identity_store = InMemoryIdentityStore({
            "user-admin-001": Identity(
                subject_id="user-admin-001", role=ADMIN_ROLE,
            ),
            "user-analyst-001": Identity(
                subject_id="user-analyst-001", role=ANALYST_ROLE,
            ),
        })
        proxy = SecureProxy(
            config=config,
            identity_store=identity_store,
        )
        proxy.attach_source_management_service(source_service)

        print("\n========== STEP 1: AUTH-ISSUE ==========")
        admin_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "user-admin-001"},
        )).body["data"]["token"]
        analyst_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "user-analyst-001"},
        )).body["data"]["token"]
        print("admin / analyst session tokens issued")

        print("\n========== STEP 2: SOURCE.LIST ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={},
        ))
        types = resp.body["data"]["supported_connector_types"]
        print(f"supported_connector_types: {types}")
        assert "nginx" in types
        assert "waf" in types

        print("\n========== STEP 3: SOURCE.REGISTER ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={
                "source_type": "nginx",
                "display_name": "Prod Nginx",
                "description": "production frontend",
                "tags": ["BACKEND", "PROD"],
                "asset_tags": ["web-app"],
            },
        ))
        assert resp.status == 200
        view = resp.body["data"]["source"]
        sid = view["source_instance_id"]
        print(f"registered: {sid}")
        assert view["state"] == "registered"

        print("\n========== STEP 4: CONFIGURE / VALIDATE / ENABLE ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_CONFIGURE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={
                "source_instance_id": sid,
                "configuration": {
                    "connection_type": "push",
                    "endpoint": "https://example.com/api/ingest",
                },
            },
        ))
        print(f"configure status={resp.status}")
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "configured"

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_VALIDATE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        print(f"validate status={resp.status}")
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "validated"

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        print(f"enable status={resp.status}")
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "enabled"

        print("\n========== STEP 5: ISSUE INGRESS TOKEN ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ISSUE_TOKEN,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        packed = resp.body["data"]["source_token"]
        print(f"token: {packed[:48]}...")
        assert "." in packed

        print("\n========== STEP 6: BENIGN TELEMETRY ==========")
        benign_events = [{
            "event_type": "request_blocked",
            "event_id": (
                "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f10"
            ),
            "source_event_id": "src-benign-001",
            "event_time": "2026-08-30T12:00:00Z",
            "source_ip": "203.0.113.50",
            "endpoint": "/index.html",
            "asset": "web-app",
            "details": {"http_method": "GET", "status_code": 200},
        }]
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={"events": benign_events},
        ))
        print(f"benign ingest status={resp.status}")
        print(f"accepted={resp.body['data']['accepted_event_ids']}")
        assert resp.status == 200
        assert len(resp.body["data"]["accepted_event_ids"]) == 1
        assert resp.body["data"]["rejected"] == []

        benign_event_id = (
            resp.body["data"]["accepted_event_ids"][0]
        )
        detections = detection_repo.find_by_event_id(
            benign_event_id,
        )
        assert len(detections) == 0, (
            f"unexpected detections for benign event: "
            f"{detections}"
        )
        print("benign event produced no detection (no false alert)")

        print("\n========== STEP 7: SUSPICIOUS TELEMETRY ==========")
        suspicious_events = []
        for i in range(4):
            suspicious_events.append({
                "event_type": "authentication_failure",
                "event_id": (
                    f"0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f{i + 20:02d}"
                ),
                "source_event_id": f"src-susp-{i:03d}",
                "event_time": f"2026-08-30T12:01:{i:02d}Z",
                "source_ip": "203.0.113.99",
                "endpoint": "/api/login",
                "asset": "web-app",
                "details": {
                    "http_method": "POST", "status_code": 401,
                },
            })
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={"events": suspicious_events},
        ))
        print(
            f"suspicious ingest accepted="
            f"{len(resp.body['data']['accepted_event_ids'])}"
        )
        assert resp.status == 200
        assert len(resp.body["data"]["accepted_event_ids"]) == 4

        print("\n========== STEP 8: DETECTION ==========")
        all_event_docs = list(
            security_event_repo._collection.find({})
        )
        all_events = [
            _document_to_event(d)
            for d in all_event_docs
        ]
        all_events = [e for e in all_events if e is not None]
        all_events.sort(key=lambda e: e.event_time)
        registry = RuleRegistry()
        load_rules_from_specs(
            registry,
            ["app.rules._library.nginx"],
        )
        detector = DetectionEngine(registry=registry)
        all_detections = []
        for event in all_events:
            if event.source != "nginx":
                continue
            result = detector.run(event=event)
            for d in result.detections:
                detection_repo.create(d)
                all_detections.append(d)
        print(f"detections produced: {len(all_detections)}")
        assert len(all_detections) >= 4
        rule_ids = {d.rule_id for d in all_detections}
        print(f"detection rule_ids: {sorted(rule_ids)}")
        assert "NGINX-AUTH-FAILURE-001" in rule_ids

        print("\n========== STEP 9: CORRELATION ==========")
        events_dict = {
            e.event_id: e for e in all_events
        }
        corr_engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()],
        )
        corr_result = corr_engine.run(
            detections=all_detections,
            events=events_dict,
        )
        for c in corr_result.correlations:
            correlation_repo.create(c)
        correlations = list(
            correlation_repo._collection.find({})
        )
        print(f"correlations produced: {len(correlations)}")
        assert len(correlations) >= 1

        print("\n========== STEP 10: RETIRE ==========")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_RETIRE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "retired"

        events_after = (
            security_event_repo.find_by_source_instance(sid)
        )
        print(f"historical events remaining: {len(events_after)}")
        assert len(events_after) == 5
        assert source_repo.count() == 1
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={"events": []},
        ))
        assert resp.status == 410
        print(f"post-retire telemetry status={resp.status}")
        print("\nDEMO OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())