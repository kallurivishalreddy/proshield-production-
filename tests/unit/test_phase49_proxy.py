"""Phase 4.9 — Proxy source-management wire-shape tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, Identity, InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_SOURCE_CONFIGURE,
    OP_SOURCE_DISABLE,
    OP_SOURCE_ENABLE,
    OP_SOURCE_GET,
    OP_SOURCE_ISSUE_TOKEN,
    OP_SOURCE_LIST,
    OP_SOURCE_LIST_TYPES,
    OP_SOURCE_REGISTER,
    OP_SOURCE_RETIRE,
    OP_SOURCE_VALIDATE,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.sources.trust import SourceIdentityTokenIssuer
from tests.unit._phase49_fakes import FakeDatabase


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        auth_signing_key=new_development_signing_key(),
        source_signing_key=new_development_signing_key(),
        source_token_lifetime_seconds=3600,
        ingest_max_body_bytes=16_384,
        ingest_max_details_bytes=8_192,
        ingest_rate_limit_per_minute=600,
        proxy_rate_limit_per_minute=10000,
        proxy_max_request_bytes=32_768,
        proxy_max_response_bytes=1_048_576,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=32_768,
        ingress_max_response_bytes=1_048_576,
    )


def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-admin-001": Identity(
            subject_id="user-admin-001", role=ADMIN_ROLE,
        ),
    })


def _token(proxy: SecureProxy, subject_id: str) -> str:
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject_id},
    )).body["data"]["token"]


def _proxy_with_source_service() -> SecureProxy:
    proxy = SecureProxy(
        config=_config(),
        identity_store=_identity_store(),
    )
    issuer = SourceIdentityTokenIssuer(
        secret=proxy._config.source_signing_key,
        lifetime_seconds=3600,
    )
    repo = SourceRepository(FakeDatabase(), proxy._config)
    registry = SourceRegistry()
    svc = SourceManagementService(
        repository=repo, registry=registry,
        token_issuer=issuer,
    )
    proxy.attach_source_management_service(svc)
    return proxy


class TestProxySourceAttach:
    def test_attach_validates_methods(self) -> None:
        proxy = SecureProxy(
            config=_config(),
            identity_store=_identity_store(),
        )
        with pytest.raises(ValueError):
            proxy.attach_source_management_service(object())

    def test_attach_accepts_none_to_disable(self) -> None:
        proxy = _proxy_with_source_service()
        proxy.attach_source_management_service(None)
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={
                PROXY_HEADER_AUTHORIZATION: (
                    f"Bearer {_token(proxy, 'user-analyst-001')}"
                ),
            },
            body={},
        ))
        assert resp.status == 400


class TestProxySourceList:
    def test_list_returns_supported_types_when_empty(self) -> None:
        proxy = _proxy_with_source_service()
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={
                PROXY_HEADER_AUTHORIZATION: (
                    f"Bearer {_token(proxy, 'user-analyst-001')}"
                ),
            },
            body={},
        ))
        assert resp.status == 200
        data = resp.body["data"]
        assert "sources" in data
        assert data["sources"] == []
        assert "nginx" in data["supported_connector_types"]

    def test_list_types_requires_auth(self) -> None:
        proxy = _proxy_with_source_service()
        # Without a session token the request is rejected
        # at the documented client boundary.
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST_TYPES,
            headers={},
            body={},
        ))
        assert resp.status == 401
        analyst_token = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST_TYPES,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={},
        ))
        assert resp.status == 200
        types = resp.body["data"]["supported_connector_types"]
        assert "nginx" in types
        assert "waf" in types


class TestProxySourceLifecycle:
    def _register(self, proxy: SecureProxy, admin_token: str) -> str:
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={
                "source_type": "nginx",
                "display_name": "Prod Nginx",
                "description": "frontend",
                "tags": ["PROD"],
                "asset_tags": ["web-app"],
            },
        ))
        assert resp.status == 200
        return resp.body["data"]["source"]["source_instance_id"]

    def test_register_then_get(self) -> None:
        proxy = _proxy_with_source_service()
        admin_token = _token(proxy, "user-admin-001")
        sid = self._register(proxy, admin_token)
        analyst_token = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_GET,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "registered"

    def test_register_rejects_non_admin(self) -> None:
        proxy = _proxy_with_source_service()
        analyst_token = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst_token}",
            },
            body={
                "source_type": "nginx",
                "display_name": "Prod",
            },
        ))
        assert resp.status == 403

    def test_register_unknown_source_type(self) -> None:
        proxy = _proxy_with_source_service()
        admin_token = _token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={
                "source_type": "bogus",
                "display_name": "Prod",
            },
        ))
        assert resp.status == 400

    def test_full_lifecycle(self) -> None:
        proxy = _proxy_with_source_service()
        admin_token = _token(proxy, "user-admin-001")
        sid = self._register(proxy, admin_token)
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
        assert resp.body["data"]["source"]["state"] == "configured"
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_VALIDATE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.body["data"]["source"]["state"] == "validated"
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.body["data"]["source"]["state"] == "enabled"
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_DISABLE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.body["data"]["source"]["state"] == "disabled"
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_RETIRE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.body["data"]["source"]["state"] == "retired"

    def test_configure_rejects_bad_connection_type(self) -> None:
        proxy = _proxy_with_source_service()
        admin_token = _token(proxy, "user-admin-001")
        sid = self._register(proxy, admin_token)
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_CONFIGURE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={
                "source_instance_id": sid,
                "configuration": {
                    "connection_type": "ftp",
                    "endpoint": "https://example.com/api/ingest",
                },
            },
        ))
        assert resp.status == 400

    def test_issue_token_when_enabled(self) -> None:
        proxy = _proxy_with_source_service()
        admin_token = _token(proxy, "user-admin-001")
        sid = self._register(proxy, admin_token)
        proxy.handle(ProxyRequest(
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
        proxy.handle(ProxyRequest(
            operation=OP_SOURCE_VALIDATE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ISSUE_TOKEN,
            headers={
                PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}",
            },
            body={"source_instance_id": sid},
        ))
        assert resp.status == 200
        packed = resp.body["data"]["source_token"]
        assert len(packed.split(".")) == 3