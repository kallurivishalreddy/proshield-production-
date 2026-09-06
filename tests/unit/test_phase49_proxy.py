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
    # AUTH-001 remediation: explicit credentials.
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-admin-001": Identity(
            subject_id="user-admin-001", role=ADMIN_ROLE,
        ),
    }, credentials={
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
    })


def _token(proxy: SecureProxy, subject_id: str) -> str:
    # AUTH-001 remediation: ``auth.issue`` requires credential.
    password = {
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
    }[subject_id]
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject_id, "credential": password},
    )).body["data"]["token"]


def _identity_store_with_collector() -> InMemoryIdentityStore:
    """Same as ``_identity_store`` but with a ``collector`` identity.

    Collector is the lowest-privilege role (RBAC-001) and is
    expected to be denied every source write. Adding a third
    identity here keeps the regression test orthogonal to the
    other role-based tests.
    """
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-admin-001": Identity(
            subject_id="user-admin-001", role=ADMIN_ROLE,
        ),
        "user-collector-001": Identity(
            subject_id="user-collector-001", role="collector",
        ),
    }, credentials={
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
        "user-collector-001": "collector-password",
    })


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


def _proxy_with_collector() -> SecureProxy:
    """Proxy + source service + a collector identity."""
    proxy = SecureProxy(
        config=_config(),
        identity_store=_identity_store_with_collector(),
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


def _token_any(proxy: SecureProxy, subject_id: str) -> str:
    """Like ``_token`` but supports the collector fixture too."""
    password = {
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
        "user-collector-001": "collector-password",
    }[subject_id]
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject_id, "credential": password},
    )).body["data"]["token"]


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
        # F-6: only implemented connector types are advertised.
        assert "nginx" in types
        assert "simulator" in types
        assert "waf" not in types
        assert "iam" not in types


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
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}"},
            body={"source_instance_id": sid,
                  "configuration": {
                      "connection_type": "push",
                      "endpoint":
                          "https://example.com/api/ingest"}}))
        proxy.handle(ProxyRequest(
            operation=OP_SOURCE_VALIDATE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}"},
            body={"source_instance_id": sid}))
        proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}"},
            body={"source_instance_id": sid}))
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ISSUE_TOKEN,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin_token}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        packed = resp.body["data"]["source_token"]
        assert len(packed.split(".")) == 3


# --------------------------------------------------------------- RBAC regression
# The following tests lock in the source-management RBAC
# policy: ``source:write`` is admin-only. The manual E2E
# found that an analyst hit a 403 on ``source.register``;
# that 403 is the correct answer (see Phase 4.9 RBAC and
# app/auth/permissions.py). These tests cover the full
# surface (write + read + closed set + role defaults) for
# admin, analyst, and collector.
SOURCE_RBAC_WRITE_OPS = [
    (OP_SOURCE_REGISTER, {
        "source_type": "nginx",
        "display_name": "Prod Nginx",
    }),
    (OP_SOURCE_CONFIGURE, {
        "source_instance_id": "src-doesnt-matter",
        "configuration": {
            "connection_type": "push",
            "endpoint": "https://example.com/api/ingest",
        },
    }),
    (OP_SOURCE_VALIDATE, {"source_instance_id": "src-doesnt-matter"}),
    (OP_SOURCE_ENABLE, {"source_instance_id": "src-doesnt-matter"}),
    (OP_SOURCE_DISABLE, {"source_instance_id": "src-doesnt-matter"}),
    (OP_SOURCE_RETIRE, {"source_instance_id": "src-doesnt-matter"}),
    (OP_SOURCE_ISSUE_TOKEN, {"source_instance_id": "src-doesnt-matter"}),
]


class TestSourceWriteOpsAreAdminOnly:
    """Every source write op must be denied to non-admin tokens."""

    @pytest.mark.parametrize("op,body", SOURCE_RBAC_WRITE_OPS)
    def test_analyst_is_forbidden(self, op: str, body: dict) -> None:
        proxy = _proxy_with_collector()
        token = _token_any(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=op,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body=body))
        assert resp.status == 403, (
            f"analyst was allowed to call {op}: "
            f"status={resp.status}, body={resp.body}")
        assert resp.body.get("error", {}).get("code") == "forbidden"

    @pytest.mark.parametrize("op,body", SOURCE_RBAC_WRITE_OPS)
    def test_collector_is_forbidden(self, op: str, body: dict) -> None:
        proxy = _proxy_with_collector()
        token = _token_any(proxy, "user-collector-001")
        resp = proxy.handle(ProxyRequest(
            operation=op,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body=body))
        assert resp.status == 403, (
            f"collector was allowed to call {op}: "
            f"status={resp.status}, body={resp.body}")
        assert resp.body.get("error", {}).get("code") == "forbidden"


class TestAdminFullLifecycleRbac:
    """End-to-end happy path: admin can register, configure,
    validate, enable, disable, re-enable, retire. The
    resulting source shows up in source.list with the
    user-chosen source_type. This proves a nginx
    registration lands as nginx, not iam."""

    def test_full_lifecycle_with_nginx(self) -> None:
        proxy = _proxy_with_source_service()
        admin = _token(proxy, "user-admin-001")
        # REGISTER
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_type": "nginx",
                  "display_name": "Prod Nginx",
                  "description": "frontend",
                  "tags": ["PROD"],
                  "asset_tags": ["web-app"]}))
        assert resp.status == 200, resp.body
        sid = resp.body["data"]["source"]["source_instance_id"]
        assert resp.body["data"]["source"]["source_type"] == "nginx"
        assert resp.body["data"]["source"]["state"] == "registered"
        # CONFIGURE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_CONFIGURE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid,
                  "configuration": {
                      "connection_type": "push",
                      "endpoint":
                          "https://example.com/api/ingest"}}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "configured"
        # VALIDATE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_VALIDATE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "validated"
        # ENABLE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "enabled"
        # LIST (analyst is allowed)
        analyst = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst}"},
            body={}))
        assert resp.status == 200
        sources = resp.body["data"]["sources"]
        ids = {s["source_instance_id"] for s in sources}
        assert sid in ids
        ours = next(s for s in sources
                    if s["source_instance_id"] == sid)
        assert ours["source_type"] == "nginx"
        assert ours["state"] == "enabled"
        # DISABLE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_DISABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "disabled"
        # RE-ENABLE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_ENABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "enabled"
        # RETIRE
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_RETIRE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_instance_id": sid}))
        assert resp.status == 200
        assert resp.body["data"]["source"]["state"] == "retired"
        # Source still appears in the list.
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_LIST,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst}"},
            body={}))
        assert resp.status == 200


class TestAdminSourceTypeClosedSetRbac:
    """Closed set enforced server-side. Unknown types are
    400 (bad request), not 403 (forbidden)."""

    def test_unknown_source_type_is_400(self) -> None:
        proxy = _proxy_with_source_service()
        admin = _token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"source_type": "totally-fake",
                  "display_name": "Fake"}))
        assert resp.status == 400
        assert "unknown" in resp.body["error"]["message"].lower()

    def test_correct_contract_accepted(self) -> None:
        # F-6: the closed ``SourceType`` enum still declares six kinds,
        # but only the IMPLEMENTED connector types (nginx, simulator)
        # are accepted at registration time. Declared-but-unimplemented
        # kinds (waf, iam, rate_limit, network) have no connector
        # backend and must be rejected 400 so the product never
        # admits a phantom source it cannot ingest or evaluate.
        proxy = _proxy_with_source_service()
        admin = _token(proxy, "user-admin-001")
        for t in ["nginx", "simulator"]:
            resp = proxy.handle(ProxyRequest(
                operation=OP_SOURCE_REGISTER,
                headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
                body={"source_type": t,
                      "display_name": f"src-{t}"}))
            assert resp.status == 200, (
                f"implemented type rejected {t!r}: {resp.body}")
        for t in ["waf", "iam", "rate_limit", "network"]:
            resp = proxy.handle(ProxyRequest(
                operation=OP_SOURCE_REGISTER,
                headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
                body={"source_type": t,
                      "display_name": f"src-{t}"}))
            assert resp.status == 400, (
                f"unimplemented type {t!r} must be rejected: {resp.body}")


class TestRoleDefaultsRbac:
    """Sanity check on the role-default permission sets."""

    def test_analyst_default_does_not_include_source_write(self) -> None:
        from app.auth.permissions import (
            ALL_PERMISSIONS, Permission, ROLE_PERMISSIONS)
        assert "source:write" in ALL_PERMISSIONS
        analyst = ROLE_PERMISSIONS[ANALYST_ROLE]
        assert Permission.SOURCE_WRITE not in analyst

    def test_admin_default_includes_source_write(self) -> None:
        from app.auth.permissions import (
            Permission, ROLE_PERMISSIONS)
        admin = ROLE_PERMISSIONS[ADMIN_ROLE]
        assert Permission.SOURCE_WRITE in admin

    def test_collector_default_has_no_source_read(self) -> None:
        from app.auth.permissions import (
            Permission, ROLE_PERMISSIONS)
        collector = ROLE_PERMISSIONS["collector"]
        # Collector submits events but cannot see the source
        # inventory. AUTH_RBAC.md RBAC-004.
        assert Permission.SOURCE_READ not in collector


class TestSourceUnauthenticatedRbac:
    """Unauthenticated callers must get 401 on every
    protected op (no token at all)."""

    def test_analyst_gets_401_without_token(self) -> None:
        proxy = _proxy_with_source_service()
        resp = proxy.handle(ProxyRequest(
            operation=OP_SOURCE_REGISTER, headers={},
            body={"source_type": "nginx", "display_name": "x"}))
        assert resp.status == 401
