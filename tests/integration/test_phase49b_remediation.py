"""Phase 4.9 — Post-review remediation integration tests.

* D-2 — registry / repository consistency on persistence failure.
* D-3 — cross-process source-state consistency.
* S-3 — MongoDB operator-key safety in canonical events.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from app.auth.identity import ADMIN_ROLE, Identity
from app.config import ProShieldConfig
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.sources.errors import SourcePersistenceError
from app.sources.ingress import (
    INGRESS_HEADER_AUTHORIZATION,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstanceConfiguration,
    SourceInstanceId,
    SourceState,
    SourceType,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenVerifier,
    new_development_signing_key,
)
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)


class _InMemoryReplayStore:
    """R-1 test double: server-side single-use token store.

    Phase 4.9 ST-02 makes replay-store wiring mandatory at
    verifier construction; the in-memory implementation is
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


TEST_DB_NAME = "proshield_test_phase49b"


def _admin() -> Identity:
    return Identity(subject_id="user-admin-001", role=ADMIN_ROLE)


@pytest.fixture(scope="session")
def test_config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name=base.env_name,
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB_NAME,
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
def mongo_client(test_config):
    from pymongo import MongoClient
    client = MongoClient(
        test_config.mongo_uri, serverSelectionTimeoutMS=2000,
    )
    client.admin.command("ping")
    return client


@pytest.fixture(autouse=True)
def clean_db(mongo_client, test_config):
    db = mongo_client[test_config.mongo_db]
    for c in (
        test_config.mongo_collection_events,
                        "source_instances",
    ):
        db[c].delete_many({})
    yield
    for c in (
        test_config.mongo_collection_events,
                        "source_instances",
    ):
        db[c].delete_many({})


@pytest.fixture
def db(mongo_client, test_config):
    return mongo_client[test_config.mongo_db]


@pytest.fixture
def source_repo(db, test_config):
    return SourceRepository(db, test_config)


@pytest.fixture
def security_event_repo(db, test_config):
    return SecurityEventRepository(db, test_config)


# ===================================================================
# D-3: multi-process source-state consistency
# ===================================================================
class TestD3MultiProcessStateConsistency:
    """Two independent proxy instances share the same
    SourceRepository (authoritative state in MongoDB) but each
    has its own in-memory SourceRegistry.

    When process A retires/disables a source, process B must
    observe the new state via the authoritative resolver.
    """

    def _build_proxy(self, cfg, src_repo, sec_repo, registry):
        issuer = SourceIdentityTokenIssuer(
            secret=cfg.source_signing_key, lifetime_seconds=3600,
        )
        ingestion = SecurityEventIngestionService(sec_repo, cfg)
        # ST-02 fail-closed: a fresh in-memory replay store is
        # created per proxy so tokens can be replay-claimed.
        replay_store = _InMemoryReplayStore()
        verifier = SourceIdentityTokenVerifier.from_secret(
            cfg.source_signing_key,
            max_lifetime_seconds=3600,
            source_resolver=lambda sid: src_repo.get(sid),
            replay_store=replay_store,
        )
        return InboundIngressProxy(
            config=cfg,
            registry=registry,
            token_verifier=verifier,
            ingestion_service=ingestion,
            authoritative_source_resolver=lambda sid: src_repo.get(sid),
        ), issuer

    def _ingest(self, ingress, packed, eid):
        return ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {packed}"},
            body={
                "events": [{
                    "event_type": "authentication_failure",
                    "event_id": eid,
                    "event_time": "2026-08-30T12:00:00Z",
                    "source_ip": "203.0.113.10",
                    "endpoint": "/api/login",
                    "asset": "web-app",
                    "details": {"http_method": "POST"},
                }],
            },
        ))

    def test_retire_in_a_blocks_ingest_in_b(
        self, source_repo, security_event_repo, test_config,
    ) -> None:
        svc_a = SourceManagementService(
            repository=source_repo,
            registry=SourceRegistry(),
            token_issuer=SourceIdentityTokenIssuer(
                secret=test_config.source_signing_key,
                lifetime_seconds=3600,
            ),
        )
        ingress_a, issuer = self._build_proxy(
            test_config, source_repo, security_event_repo,
            SourceRegistry(),
        )
        ingress_b, _ = self._build_proxy(
            test_config, source_repo, security_event_repo,
            SourceRegistry(),
        )
        view = svc_a.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="A-retires-B",
        )
        sid = view.source_instance_id
        svc_a.configure(
            identity=_admin(), source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc_a.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc_a.enable(
            identity=_admin(), source_instance_id=sid,
        )
        packed = issuer.pack(issuer.issue(
            source_instance_id=SourceInstanceId(sid),
            source_type=SourceType.NGINX,
        ))
        r1 = self._ingest(
            ingress_b, packed,
            "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fb1",
        )
        assert r1.status == 200
        svc_a.retire(
            identity=_admin(), source_instance_id=sid,
        )
        # R-1 single-use: re-issue a fresh token, not reuse
        # ``packed`` (already claimed by ingress_b's replay
        # store).
        packed_2 = issuer.pack(issuer.issue(
            source_instance_id=SourceInstanceId(sid),
            source_type=SourceType.NGINX,
        ))
        r2 = self._ingest(
            ingress_b, packed_2,
            "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fb2",
        )
        assert r2.status == 410
        assert "retired" in r2.body["error"]["code"]

    def test_disable_in_a_blocks_ingest_in_b(
        self, source_repo, security_event_repo, test_config,
    ) -> None:
        svc_a = SourceManagementService(
            repository=source_repo,
            registry=SourceRegistry(),
            token_issuer=SourceIdentityTokenIssuer(
                secret=test_config.source_signing_key,
                lifetime_seconds=3600,
            ),
        )
        ingress_a, issuer = self._build_proxy(
            test_config, source_repo, security_event_repo,
            SourceRegistry(),
        )
        ingress_b, _ = self._build_proxy(
            test_config, source_repo, security_event_repo,
            SourceRegistry(),
        )
        view = svc_a.register(
            identity=_admin(),
            source_type=SourceType.NGINX,
            display_name="A-disables-B",
        )
        sid = view.source_instance_id
        svc_a.configure(
            identity=_admin(), source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc_a.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc_a.enable(
            identity=_admin(), source_instance_id=sid,
        )
        svc_a.disable(
            identity=_admin(), source_instance_id=sid,
        )
        packed = issuer.pack(issuer.issue(
            source_instance_id=SourceInstanceId(sid),
            source_type=SourceType.NGINX,
        ))
        r = self._ingest(
            ingress_b, packed,
            "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fb3",
        )
        assert r.status == 409
        assert "not_enabled" in r.body["error"]["code"]


# ===================================================================
# D-2: registry / repository consistency on persistence failure
# ===================================================================
class _ExplodingRepository:
    """Test double that fails the next write so we can observe
    that the in-memory registry did NOT silently claim success.
    """

    def __init__(self, real: SourceRepository) -> None:
        self._real = real
        self._fail_next = False

    def fail_next(self) -> None:
        self._fail_next = True

    def create(self, inst):
        if self._fail_next:
            self._fail_next = False
            raise SourcePersistenceError(
                safe_message="forced persistence failure",
                internal_detail="test double",
            )
        return self._real.create(inst)

    def upsert(self, inst):
        if self._fail_next:
            self._fail_next = False
            raise SourcePersistenceError(
                safe_message="forced persistence failure",
                internal_detail="test double",
            )
        return self._real.upsert(inst)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class TestD2RegistryConsistencyOnFailure:
    """If persistence fails, the in-memory registry must NOT
    have been updated. The next read returns the previous state.
    """

    def test_failed_persist_does_not_mutate_registry(
        self, source_repo, test_config,
    ) -> None:
        registry = SourceRegistry()
        exploding = _ExplodingRepository(source_repo)
        issuer = SourceIdentityTokenIssuer(
            secret=test_config.source_signing_key,
            lifetime_seconds=3600,
        )
        svc = SourceManagementService(
            repository=exploding,
            registry=registry,
            token_issuer=issuer,
        )
        view = svc.register(
            identity=_admin(), source_type=SourceType.NGINX,
            display_name="Good",
        )
        sid = view.source_instance_id
        assert registry.get(sid) is not None
        # Move the source into ENABLED so disable() is a legal
        # transition (REGISTERED -> DISABLED is not allowed).
        svc.configure(
            identity=_admin(), source_instance_id=sid,
            configuration=SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://example.com/api/ingest",
            ),
        )
        svc.validate_connection(
            identity=_admin(), source_instance_id=sid,
        )
        svc.enable(
            identity=_admin(), source_instance_id=sid,
        )
        assert registry.get(sid).state is SourceState.ENABLED

        exploding.fail_next()
        with pytest.raises(SourcePersistenceError):
            svc.disable(
                identity=_admin(), source_instance_id=sid,
            )
        after = registry.get(sid)
        assert after is not None
        assert after.state is SourceState.ENABLED
        persisted = source_repo.get(sid)
        assert persisted.state is SourceState.ENABLED


# ===================================================================
# S-3: MongoDB operator-key safety
# ===================================================================
class TestS3BsonOperatorKeySafety:
    def test_dollar_where_in_details_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fc1",
                event_time=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                ingested_at=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                source="nginx",
                event_type="authentication_failure",
                details={"$where": "1==1"},
                provenance=SecurityEventProvenance(
                    collector="nginx", source_event_id="s1",
                ),
            )

    def test_dollar_ne_in_details_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fc2",
                event_time=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                ingested_at=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                source="nginx",
                event_type="authentication_failure",
                details={"$ne": "x"},
                provenance=SecurityEventProvenance(
                    collector="nginx", source_event_id="s1",
                ),
            )

    def test_dotted_key_in_details_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fc3",
                event_time=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                ingested_at=datetime(
                    2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
                ),
                source="nginx",
                event_type="authentication_failure",
                details={"a.b": 1},
                provenance=SecurityEventProvenance(
                    collector="nginx", source_event_id="s1",
                ),
            )

    def test_safe_details_accepted(self) -> None:
        ev = SecurityEvent(
            event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fc4",
            event_time=datetime(
                2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
            ),
            ingested_at=datetime(
                2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
            ),
            source="nginx",
            event_type="authentication_failure",
            details={"http_method": "POST", "status_code": 401},
            provenance=SecurityEventProvenance(
                collector="nginx", source_event_id="s1",
            ),
        )
        assert ev.details["http_method"] == "POST"
