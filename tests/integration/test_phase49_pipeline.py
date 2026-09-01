"""Phase 4.9 — Source-management integration tests against MongoDB.

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.
"""
from __future__ import annotations

import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict

import pytest

from app.auth import (
    ADMIN_ROLE,
    ANALYST_ROLE,
    Identity,
    InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
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
    OP_SOURCE_DISABLE,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.sources import (
    SourceConnectionType,
    SourceIdentityTokenIssuer,
    SourceIdentityTokenVerifier,
    SourceInstanceConfiguration,
    SourceManagementService,
    SourceRegistry,
    SourceRepository,
    SourceState,
    SourceType,
)
from app.sources.ingress import (
    INGRESS_HEADER_AUTHORIZATION,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
)
from app.correlation import (
    BruteForceClusteringPattern,
    CorrelationEngine,
)
from app.detection import DetectionEngine
from app.rules import RuleRegistry, load_rules_from_specs


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


class _InMemoryReplayStore:
    """R-1 test double: server-side single-use token store.

    Phase 4.9 ST-02 makes replay-store wiring mandatory at
    verifier construction; this in-memory implementation is
    sufficient for integration tests against MongoDB.
    """

    def __init__(self) -> None:
        self._used: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim(self, *, token_id, expires_at):
        with self._lock:
            if token_id in self._used:
                return False
            self._used[token_id] = expires_at
            return True

    def release(self, token_id):
        with self._lock:
            self._used.pop(token_id, None)

    def gc(self, now):
        with self._lock:
            expired = [
                tid for tid, exp in self._used.items() if exp <= now
            ]
            for tid in expired:
                del self._used[tid]
            return len(expired)


TEST_DB_NAME = "proshield_test_phase49"


@pytest.fixture(scope="session")
def test_config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB_NAME,
        mongo_collection_events=(
            f"security_events_{uuid.uuid4().hex[:8]}"
        ),
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        auth_signing_key=new_development_signing_key(),
        source_signing_key=new_development_signing_key(),
        source_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=120,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_max_response_bytes=base.ingress_max_response_bytes,
    )


@pytest.fixture(scope="session")
def mongo_client(test_config: ProShieldConfig):
    from app.persistence.mongo import (
        check_connectivity, make_client,
    )
    client = make_client(test_config)
    check_connectivity(client)
    yield client
    client.close()


@pytest.fixture(autouse=True)
def clean_db(mongo_client, test_config):
    db = mongo_client[TEST_DB_NAME]
    for name in db.list_collection_names():
        db.drop_collection(name)
    yield


@pytest.fixture
def db(mongo_client, test_config):
    return mongo_client[TEST_DB_NAME]


@pytest.fixture
def source_repo(db, test_config):
    repo = SourceRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


@pytest.fixture
def security_event_repo(db, test_config):
    repo = SecurityEventRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


@pytest.fixture
def detection_repo(db, test_config):
    repo = DetectionRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


@pytest.fixture
def correlation_repo(db, test_config):
    repo = CorrelationRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


@pytest.fixture
def source_service(source_repo, test_config):
    registry = SourceRegistry()
    issuer = SourceIdentityTokenIssuer(
        secret=test_config.source_signing_key,
        lifetime_seconds=3600,
    )
    svc = SourceManagementService(
        repository=source_repo,
        registry=registry,
        token_issuer=issuer,
    )
    return svc, registry, issuer


@pytest.fixture
def ingestion_service(security_event_repo, test_config):
    return SecurityEventIngestionService(
        security_event_repo, test_config,
    )


def _admin() -> Identity:
    return Identity(subject_id="user-admin-001", role=ADMIN_ROLE)


class TestSourceSchema:
    def test_schema_and_indexes_applied(
        self, source_repo,
    ) -> None:
        assert source_repo.count() == 0
        names = [
            idx["name"] for idx in source_repo._collection.list_indexes()
        ]
        assert "source_source_instance_id_unique" in names


class TestSourceLifecycleEndToEnd:
    def test_full_lifecycle_persists(
        self, source_service, source_repo,
    ) -> None:
        svc, registry, issuer = source_service
        view = svc.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="Prod Nginx",
        )
        sid = view.source_instance_id
        assert source_repo.count() == 1
        cfg = SourceInstanceConfiguration(
            connection_type=SourceConnectionType.PUSH,
            endpoint="https://example.com/api/ingest",
        )
        svc.configure(
            identity=_admin(),
            source_instance_id=sid,
            configuration=cfg,
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(identity=_admin(), source_instance_id=sid)
        assert registry.is_enabled(sid)
        svc.issue_ingress_token(
            identity=_admin(), source_instance_id=sid,
        )
        svc.retire(identity=_admin(), source_instance_id=sid)
        assert source_repo.count() == 1
        loaded = source_repo.get_required(sid)
        assert loaded.state is SourceState.RETIRED
        assert loaded.retired_at is not None


class TestSourceIdentityTokenRoundTrip:
    def test_token_verifies_against_persisted_source(
        self, source_service, source_repo,
    ) -> None:
        svc, registry, issuer = source_service
        view = svc.register(
            identity=_admin(),
            source_type=SourceType.WAF,
            display_name="Prod WAF",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_admin(),
            source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(identity=_admin(), source_instance_id=sid)
        packed = svc.issue_ingress_token(
            identity=_admin(), source_instance_id=sid,
        )
        verified = SourceIdentityTokenVerifier.from_secret(
            issuer.secret,
            max_lifetime_seconds=3600,
            source_resolver=lambda sid: source_repo.get(sid),
        ).verify(packed)
        assert verified.source_instance_id == sid
        assert verified.source == "waf"
        assert verified.source_type == "waf"


class TestIngressWithPersistedSource:
    def test_ingress_accepts_verified_event_and_persists_provenance(
        self, source_service, security_event_repo, source_repo, db, test_config,
    ) -> None:
        svc, registry, issuer = source_service
        view = svc.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="Prod Nginx",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_admin(),
            source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(identity=_admin(), source_instance_id=sid)

        verifier = SourceIdentityTokenVerifier.from_secret(issuer.secret, max_lifetime_seconds=3600, source_resolver=lambda sid: source_repo.get(sid), replay_store=_InMemoryReplayStore())
        ingestion = SecurityEventIngestionService(
            security_event_repo, test_config,
        )
        ingress = InboundIngressProxy(
            config=test_config,
            registry=registry,
            token_verifier=verifier,
            ingestion_service=ingestion,
            authoritative_source_resolver=lambda sid: source_repo.get(sid),
        )
        packed = issuer.pack(issuer.issue(
            source_instance_id=sid,
            source_type=SourceType.NGINX,
        ))
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={
                "events": [{
                    "event_type": "authentication_failure",
                    "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
                    "source_event_id": "src-001",
                    "event_time": "2026-08-30T12:00:00Z",
                    "source_ip": "203.0.113.10",
                    "endpoint": "/auth/login",
                    "asset": "web-app",
                    "account": {"id": "user-123"},
                    "details": {
                        "http_method": "POST",
                        "status_code": 401,
                    },
                }],
            },
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["accepted_event_ids"]) == 1

        event_id = resp.body["data"]["accepted_event_ids"][0]
        col = db[test_config.mongo_collection_events]
        doc = col.find_one({"event_id": event_id})
        assert doc is not None
        assert doc["source"] == "nginx"
        assert doc["provenance"]["source_instance_id"] == sid
        assert doc["provenance"]["collector"] == "nginx"

    def test_ingress_rejects_after_retire(
        self, source_service, security_event_repo, source_repo, test_config,
    ) -> None:
        svc, registry, issuer = source_service
        view = svc.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="Prod Nginx",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_admin(),
            source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(identity=_admin(), source_instance_id=sid)
        svc.retire(identity=_admin(), source_instance_id=sid)

        verifier = SourceIdentityTokenVerifier.from_secret(issuer.secret, max_lifetime_seconds=3600, source_resolver=lambda sid: source_repo.get(sid), replay_store=_InMemoryReplayStore())
        ingestion = SecurityEventIngestionService(
            security_event_repo, test_config,
        )
        ingress = InboundIngressProxy(
            config=test_config,
            registry=registry,
            token_verifier=verifier,
            ingestion_service=ingestion,
            authoritative_source_resolver=lambda sid: source_repo.get(sid),
        )
        packed = issuer.pack(issuer.issue(
            source_instance_id=sid,
            source_type=SourceType.NGINX,
        ))
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={"events": []},
        ))
        assert resp.status == 410
        assert "retired" in resp.body["error"]["code"]


class TestSourceProvenancePersistsAcrossPhase448:
    def test_retired_source_evidence_remains_queryable(
        self, source_service, security_event_repo, source_repo, db, test_config,
        detection_repo, correlation_repo,
    ) -> None:
        svc, registry, issuer = source_service
        view = svc.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="Prod Nginx",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_admin(),
            source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(identity=_admin(), source_instance_id=sid)

        verifier = SourceIdentityTokenVerifier.from_secret(issuer.secret, max_lifetime_seconds=3600, source_resolver=lambda sid: source_repo.get(sid), replay_store=_InMemoryReplayStore())
        ingestion = SecurityEventIngestionService(
            security_event_repo, test_config,
        )
        ingress = InboundIngressProxy(
            config=test_config,
            registry=registry,
            token_verifier=verifier,
            ingestion_service=ingestion,
            authoritative_source_resolver=lambda sid: source_repo.get(sid),
        )
        packed = issuer.pack(issuer.issue(
            source_instance_id=sid,
            source_type=SourceType.NGINX,
        ))
        events = []
        for i in range(4):
            eid = f"0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f{i:02d}"
            events.append({
                "event_type": "authentication_failure",
                "event_id": eid,
                "source_event_id": f"src-{i:03d}",
                "event_time": f"2026-08-30T12:00:{i:02d}Z",
                "source_ip": "203.0.113.10",
                "endpoint": "/api/login",
                "asset": "web-app",
                "details": {"http_method": "POST", "status_code": 401},
            })
        resp = ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}",
            },
            body={"events": events},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["accepted_event_ids"]) == 4

        evs = list(
            security_event_repo._collection.find({})
        )
        from app.persistence.security_event_repository import (
            _document_to_event,
        )
        evs = [
            _document_to_event(doc) for doc in evs
        ]
        evs = [e for e in evs if e is not None and e.source == "nginx"]
        registry = RuleRegistry()
        load_rules_from_specs(
            registry,
            ["app.rules._library.nginx"],
        )
        detector = DetectionEngine(registry=registry)
        detections = []
        for e in evs:
            result = detector.run(event=e)
            for d in result.detections:
                detection_repo.create(d)
                detections.append(d)
        correlation_engine = CorrelationEngine(
            patterns=[BruteForceClusteringPattern()],
        )
        events_dict = {e.event_id: e for e in evs}
        cor_result = correlation_engine.run(
            detections=detections,
            events=events_dict,
        )
        for c in cor_result.correlations:
            correlation_repo.create(c)

        svc.retire(identity=_admin(), source_instance_id=sid)
        events_after = security_event_repo.find_by_source_instance(sid)
        assert len(events_after) == 4
        all_docs = list(db[detection_repo._collection.name].find({}))
        assert len(all_docs) >= 4
        all_corrs = list(
            db[correlation_repo._collection.name].find({})
        )
        assert len(all_corrs) >= 1
        assert svc._repository.count() == 1


class TestSourceEndToEndThroughProxy:
    def test_full_e2e_lifecycle_through_proxy(
        self, source_service, test_config,
    ) -> None:
        svc, registry, issuer = source_service
        identity_store = InMemoryIdentityStore({
            "user-admin-001": Identity(
                subject_id="user-admin-001", role=ADMIN_ROLE,
            ),
            "user-analyst-001": Identity(
                subject_id="user-analyst-001", role=ANALYST_ROLE,
            ),
        })
        proxy = SecureProxy(
            config=test_config,
            identity_store=identity_store,
        )
        proxy.attach_source_management_service(svc)

        admin_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "user-admin-001"},
        )).body["data"]["token"]
        analyst_token = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "user-analyst-001"},
        )).body["data"]["token"]

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={},
        ))
        assert resp.status == 200
        assert resp.body["data"]["sources"] == []

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_type": "waf", "display_name": "Prod WAF"},
        ))
        assert resp.status == 200
        sid = resp.body["data"]["source"]["source_instance_id"]

        for op, body in [
            (
                OP_SOURCE_CONFIGURE,
                {
                    "source_instance_id": sid,
                    "configuration": {
                        "connection_type": "push",
                        "endpoint": "https://example.com/api/ingest",
                    },
                },
            ),
            (
                OP_SOURCE_VALIDATE,
                {"source_instance_id": sid},
            ),
            (
                OP_SOURCE_ENABLE,
                {"source_instance_id": sid},
            ),
        ]:
            resp = proxy.handle(ProxyRequest(
                operation=op,
                headers={
                    PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
                },
                body=body,
            ))
            assert resp.status == 200, (op, resp.body)

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ISSUE_TOKEN,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.status == 200
        packed = resp.body["data"]["source_token"]
        verifier = SourceIdentityTokenVerifier.from_secret(test_config.source_signing_key, max_lifetime_seconds=3600, replay_store=_InMemoryReplayStore())
        token = verifier.verify(packed)
        assert token.source_instance_id == sid

        for op in (
            OP_SOURCE_DISABLE, OP_SOURCE_ENABLE, OP_SOURCE_RETIRE,
        ):
            resp = proxy.handle(ProxyRequest(
                operation=op,
                headers={
                    PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
                },
                body={"source_instance_id": sid},
            ))
            assert resp.status == 200, (op, resp.body)

        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_GET,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "retired"
        cfg = resp.body["data"]["source"]["configuration"]
        assert "secret_ref" not in cfg