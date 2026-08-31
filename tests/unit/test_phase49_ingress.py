"""Phase 4.9 — Inbound ingress proxy tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import ProShieldConfig
from app.domain.security_event import SecurityEvent
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.sources.errors import SourceIdentityTokenError
from app.sources.ingress import (
    INGRESS_HEADER_AUTHORIZATION,
    INGRESS_HEADER_TOKEN,
    OP_HEALTH,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenVerifier,
    new_development_signing_key,
)
from tests.unit._phase49_fakes import FakeDatabase


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = new_development_signing_key()


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        ingest_max_body_bytes=16_384,
        ingest_max_details_bytes=8_192,
        source_signing_key=_SECRET,
        source_token_lifetime_seconds=3600,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=32_768,
        ingress_max_response_bytes=1_048_576,
    )


def _enabled_nginx_instance() -> SourceInstance:
    cfg = SourceInstanceConfiguration(
        connection_type=SourceConnectionType.PUSH,
        endpoint="https://example.com/api/ingest",
        proxy_path="",
        destination="",
        asset_tags=("web-app",),
        tags=(),
        references=(),
        secret_ref="",
    )
    return SourceInstance(
        source_instance_id=(
            "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
        ),
        source_type=SourceType.NGINX,
        source="nginx",
        display_name="Prod Nginx",
        description="",
        configuration=cfg,
        state=SourceState.ENABLED,
        created_by="user-admin-001",
        created_at=_NOW,
        updated_by="user-admin-001",
        updated_at=_NOW,
        last_validation_at=_NOW,
        tags=(),
        asset_tags=("web-app",),
        retired_at=None,
    )


def _ingestion_service() -> SecurityEventIngestionService:
    repo = SecurityEventRepository(FakeDatabase(), _config())
    return SecurityEventIngestionService(repo, _config())


def _proxy(
    registry: SourceRegistry = None,
    ingestion_service: SecurityEventIngestionService = None,
    rate_limit: int = 600,
) -> InboundIngressProxy:
    config = _config()
    object.__setattr__(
        config, "ingress_rate_limit_per_minute", rate_limit,
    )
    return InboundIngressProxy(
        config=config,
        registry=registry or SourceRegistry(),
        token_verifier=SourceIdentityTokenVerifier.from_secret(
            _SECRET, max_lifetime_seconds=3600,
        ),
        ingestion_service=(
            ingestion_service or _ingestion_service()
        ),
    )


def _issue(
    issuer: SourceIdentityTokenIssuer,
    instance: SourceInstance,
) -> str:
    return issuer.pack(issuer.issue(
        source_instance_id=instance.source_instance_id,
        source_type=instance.source_type,
    ))


def _issuer() -> SourceIdentityTokenIssuer:
    return SourceIdentityTokenIssuer(
        secret=_SECRET, lifetime_seconds=3600,
    )


class TestIngressBasics:
    def test_unknown_operation_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation="bogus.op",
            headers={}, body=None,
        ))
        assert resp.status == 400
        assert "unknown_operation" in resp.body["error"]["code"]

    def test_missing_operation_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation="",
            headers={}, body=None,
        ))
        assert resp.status == 400

    def test_oversized_request_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={},
            body={},
            body_bytes=10_000_000,
        ))
        assert resp.status == 400
        assert resp.body["error"]["code"] == "request_too_large"

    def test_health_is_open(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation=OP_HEALTH, headers={}, body=None,
        ))
        assert resp.status == 200
        assert resp.body["ok"] is True
        assert "ingress" in resp.body["data"]["boundary"]


class TestIngressAuthAndIdentity:
    def test_missing_token_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST, headers={}, body={
                "events": [{
                    "event_type": "authentication_failure",
                    "source_ip": "203.0.113.10",
                }],
            },
        ))
        assert resp.status == 401
        assert "source_identity_token" in resp.body["error"]["code"]

    def test_token_for_unknown_instance_rejected(self) -> None:
        reg = SourceRegistry()
        proxy = _proxy(registry=reg)
        inst = _enabled_nginx_instance()
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 404
        assert "source_instance_not_found" in resp.body["error"]["code"]

    def test_token_for_disabled_instance_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance().model_copy(
            update={"state": SourceState.DISABLED}
        )
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 409
        assert "not_enabled" in resp.body["error"]["code"]

    def test_token_for_retired_instance_rejected(self) -> None:
        from datetime import datetime as _dt, timezone as _tz
        reg = SourceRegistry()
        inst = _enabled_nginx_instance().model_copy(
            update={
                "state": SourceState.RETIRED,
                "retired_at": _dt(2026, 8, 30, 13, 0, 0, tzinfo=_tz.utc),
            }
        )
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 410
        assert "retired" in resp.body["error"]["code"]

    def test_tampered_token_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        head, mid, tail = token.split(".")
        mid_chars = list(mid)
        mid_chars[0] = "A" if mid_chars[0] != "A" else "B"
        tampered = f"{head}.{''.join(mid_chars)}.{tail}"
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {tampered}",
            },
            body={"events": []},
        ))
        assert resp.status == 401

    def test_token_with_legacy_token_header(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_TOKEN: token},
            body={"events": []},
        ))
        assert resp.status == 200

    def test_token_in_body_field(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={},
            body={"source_token": token, "events": []},
        ))
        assert resp.status == 200

    def test_token_wrong_source_type_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        from app.sources.models import SourceType as _ST
        forge = SourceIdentityTokenIssuer(
            secret=_SECRET, lifetime_seconds=3600,
        )
        fake_token = forge.pack(forge.issue(
            source_instance_id=inst.source_instance_id,
            source_type=_ST.WAF,
        ))
        proxy = _proxy(registry=reg)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {fake_token}",
            },
            body={"events": []},
        ))
        assert resp.status == 403
        assert "integrity" in resp.body["error"]["code"]


class TestIngressIngestion:
    def test_accepts_well_formed_event(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
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
        body = resp.body["data"]
        assert len(body["accepted_event_ids"]) == 1
        assert body["rejected"] == []

    def test_rejects_unknown_event_type(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={
                "events": [{
                    "event_type": "totally-bogus-type",
                    "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f13",
                    "source_event_id": "src-002",
                    "event_time": "2026-08-30T12:00:00Z",
                }],
            },
        ))
        assert resp.status == 200
        body = resp.body["data"]
        assert body["accepted_event_ids"] == []
        assert len(body["rejected"]) == 1

    def test_rejects_non_dict_event(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": ["not-a-dict"]},
        ))
        assert resp.status == 200
        body = resp.body["data"]
        assert body["accepted_event_ids"] == []
        assert body["rejected"][0]["reason"] == "not-a-dict"

    def test_rejects_non_list_events(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": "not-a-list"},
        ))
        assert resp.status == 400
        assert resp.body["error"]["code"] == "validation_error"

    def test_empty_events_batch_is_ok(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 200
        assert resp.body["data"]["accepted_event_ids"] == []


class TestIngressRateLimit:
    def test_rate_limit_blocks_after_budget(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg, rate_limit=2)
        token = _issue(_issuer(), inst)
        for _ in range(2):
            r = proxy.handle(IngressRequest(
                operation=OP_INGEST,
                headers={
                    INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
                },
                body={"events": []},
            ))
            assert r.status == 200
        r = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert r.status == 429
        assert "rate_limited" in r.body["error"]["code"]