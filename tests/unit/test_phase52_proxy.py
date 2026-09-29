"""Phase 5.2 — SecureProxy wire surface for Source Architecture 2.0.

Proves the Phase 5.2 operations are reachable, correctly authorised, and
shape-validated at the real wire boundary:

* anonymous access is rejected (401);
* a wrong-role identity is refused (403) on every write;
* a malformed binding payload is a 400;
* a valid admin binding succeeds and is audited;
* the migration surface is dry-run by default (writes nothing) and
  requires an admin to apply;
* ``source.audit`` 404s for an unknown source rather than returning an
  empty trail that looks like "nothing ever happened".

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md §19.
"""
from __future__ import annotations

import pytest

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, Identity, InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_SOURCE_AUDIT,
    OP_SOURCE_BIND_CAPABILITY,
    OP_SOURCE_MIGRATE,
    OP_SOURCE_MIGRATION_STATUS,
    OP_SOURCE_REGISTER,
    OP_SOURCE_ROTATE_TOKEN,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.sources.capability_binding import builtin_capability_index
from app.sources.migration import SourceCapabilityMigration
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.sources.trust import SourceIdentityTokenIssuer
from tests.unit._phase49_fakes import FakeDatabase, FakeSourceCollection

_SIGNING_KEY = "phase52-proxy-test-signing-key"
_PASSWORDS = {
    "user-analyst-001": "analyst-password",
    "user-admin-001": "admin-password",
}


class _AuditCollection(FakeSourceCollection):
    """Append-only audit double (no source_instance_id uniqueness)."""

    def insert_one(self, doc):
        import copy as _copy

        self.docs.append(_copy.deepcopy(dict(doc)))
        return type("R", (), {"inserted_id": "fake"})()


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_phase52_proxy",
        mongo_collection_events="security_events",
        auth_signing_key=new_development_signing_key(),
        source_signing_key=_SIGNING_KEY,
    )


def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore(
        {
            "user-analyst-001": Identity(
                subject_id="user-analyst-001", role=ANALYST_ROLE,
            ),
            "user-admin-001": Identity(
                subject_id="user-admin-001", role=ADMIN_ROLE,
            ),
        },
        credentials=dict(_PASSWORDS),
    )


def _lookup(capability_id: str):
    return builtin_capability_index().get(capability_id)


def _proxy() -> SecureProxy:
    proxy = SecureProxy(config=_config(), identity_store=_identity_store())
    db = FakeDatabase()
    repo = SourceRepository(db, proxy._config)
    audit = _AuditCollection()
    repo.audit_collection = lambda: audit
    svc = SourceManagementService(
        repository=repo,
        registry=SourceRegistry(),
        token_issuer=SourceIdentityTokenIssuer(secret=_SIGNING_KEY),
        capability_lookup=_lookup,
        audit_collection=audit,
    )
    proxy.attach_source_management_service(svc)
    proxy.attach_source_capability_migration(
        SourceCapabilityMigration(
            source_repository=repo,
            capability_lookup=_lookup,
            registry=None,
        ),
        audit_collection=audit,
    )
    proxy._test_audit = audit  # noqa: SLF001 - test inspection
    proxy._test_repo = repo  # noqa: SLF001 - test inspection
    return proxy


def _token(proxy: SecureProxy, subject: str) -> str:
    resp = proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE,
        headers={},
        body={
            "subject_id": subject,
            "credential": _PASSWORDS[subject],
        },
    ))
    assert resp.status == 200, resp.body
    return resp.body["data"]["token"]


def _call(proxy, op, token=None, body=None):  # noqa: ANN001
    headers = {}
    if token:
        headers[PROXY_HEADER_AUTHORIZATION] = f"Bearer {token}"
    return proxy.handle(ProxyRequest(
        operation=op, headers=headers, body=body or {},
    ))


def _register(proxy, token, name="p52-nginx") -> str:
    resp = _call(
        proxy, OP_SOURCE_REGISTER, token,
        {"source_type": "nginx", "display_name": name},
    )
    assert resp.status == 200, resp.body
    return resp.body["data"]["source"]["source_instance_id"]


_ANON_BODY = [
    (OP_SOURCE_BIND_CAPABILITY,
     {"source_instance_id": "x", "capability_id": "cap-nginx"}),
    (OP_SOURCE_ROTATE_TOKEN, {"source_instance_id": "x"}),
    (OP_SOURCE_MIGRATE, {"dry_run": True}),
]


class TestPhase52WireAuthz:
    @pytest.mark.parametrize("op,body", _ANON_BODY)
    def test_anonymous_write_is_rejected(self, op, body) -> None:
        resp = _call(_proxy(), op, None, body)
        assert resp.status == 401

    @pytest.mark.parametrize("op,body", _ANON_BODY)
    def test_analyst_write_is_forbidden(self, op, body) -> None:
        proxy = _proxy()
        token = _token(proxy, "user-analyst-001")
        resp = _call(proxy, op, token, body)
        assert resp.status == 403

    def test_analyst_can_read_migration_status(self) -> None:
        proxy = _proxy()
        token = _token(proxy, "user-analyst-001")
        resp = _call(proxy, OP_SOURCE_MIGRATION_STATUS, token, {})
        assert resp.status == 200, resp.body
        assert resp.body["data"]["dry_run"] is True

    def test_analyst_can_read_source_audit(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        analyst = _token(proxy, "user-analyst-001")
        resp = _call(proxy, OP_SOURCE_AUDIT, analyst,
                     {"source_instance_id": sid})
        assert resp.status == 200, resp.body
        actions = {r["action"] for r in resp.body["data"]["audit"]}
        assert "source_register" in actions


class TestPhase52WireBinding:
    def test_rebinding_the_held_binding_is_a_409(self) -> None:
        """An exact repeat bind is a conflict, not a silent re-write."""
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
            "capability_id": "cap-nginx",
            "mapping_profile_id": "nginx-access-default",
        })
        assert resp.status == 409
        assert (
            resp.body["error"]["code"]
            == "duplicate_source_capability_binding"
        )

    def test_admin_bind_capability_on_an_unbound_source_succeeds(
        self,
    ) -> None:
        """The wire remediation path for a quarantined/unbound legacy row."""
        from datetime import datetime, timezone

        from app.sources.models import (
            CapabilityBindingStatus, SourceInstance,
            SourceInstanceConfiguration, SourceState, SourceType,
        )

        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        now = datetime(2026, 9, 16, tzinfo=timezone.utc)
        sid = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f77-x"
        legacy = SourceInstance(
            source_instance_id=sid,
            source_type=SourceType.NGINX,
            source="nginx",
            display_name="legacy-unbound",
            description="",
            configuration=SourceInstanceConfiguration(
                connection_type="push",
                endpoint="https://legacy.example.test/hook",
                secret_ref="",
            ),
            state=SourceState.DISABLED,
            created_by="legacy-admin",
            created_at=now,
            updated_by="legacy-admin",
            updated_at=now,
            last_validation_at=None,
            tags=(),
            asset_tags=(),
            retired_at=None,
            capability_binding_status=(
                CapabilityBindingStatus.REQUIRES_VERIFICATION
            ),
        )
        repo = proxy._test_repo  # noqa: SLF001
        repo.create(legacy)
        svc = proxy._source_management_service  # noqa: SLF001
        svc.reload_from_repository()

        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
            "capability_id": "cap-nginx",
            "mapping_profile_id": "nginx-access-default",
        })
        assert resp.status == 200, resp.body
        assert resp.body["data"]["source"]["capability_id"] == "cap-nginx"
        assert (
            resp.body["data"]["source"]["capability_binding_status"]
            == "bound"
        )
        actions = {r["action"] for r in proxy._test_audit.docs}  # noqa: SLF001
        assert "source_bind_capability" in actions

    def test_missing_capability_id_is_a_400(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
        })
        assert resp.status == 400

    def test_unknown_capability_is_a_400(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
            "capability_id": "cap-does-not-exist",
        })
        assert resp.status == 400

    def test_planned_capability_binding_is_a_400(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
            "capability_id": "cap-waf",
        })
        assert resp.status == 400

    def test_undeclared_mapping_profile_is_a_400(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": sid,
            "capability_id": "cap-nginx",
            "mapping_profile_id": "no-such-profile",
        })
        assert resp.status == 400

    def test_unknown_source_binding_is_a_404(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        resp = _call(proxy, OP_SOURCE_BIND_CAPABILITY, admin, {
            "source_instance_id": (
                "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f99-z"
            ),
            "capability_id": "cap-nginx",
        })
        assert resp.status == 404

    def test_source_audit_unknown_source_is_a_404(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        resp = _call(proxy, OP_SOURCE_AUDIT, admin, {
            "source_instance_id": (
                "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f99-z"
            ),
        })
        assert resp.status == 404

    def test_rotate_token_before_enable_is_refused(self) -> None:
        """Rotation is a credential write: the source must be usable first."""
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        sid = _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_ROTATE_TOKEN, admin,
                     {"source_instance_id": sid})
        assert resp.status == 409


class TestPhase52WireMigration:
    def test_migrate_defaults_to_dry_run_and_writes_nothing(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        _register(proxy, admin)
        before = len(proxy._test_repo._collection.docs)  # noqa: SLF001
        resp = _call(proxy, OP_SOURCE_MIGRATE, admin, {})
        assert resp.status == 200, resp.body
        assert resp.body["data"]["dry_run"] is True
        assert resp.body["data"]["documents_modified"] == 0
        assert len(proxy._test_repo._collection.docs) == before  # noqa: SLF001

    def test_migrate_with_dry_run_false_applies(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        _register(proxy, admin)
        resp = _call(proxy, OP_SOURCE_MIGRATE, admin, {"dry_run": False})
        assert resp.status == 200, resp.body
        assert resp.body["data"]["dry_run"] is False

    def test_migrate_non_boolean_dry_run_is_a_400(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        resp = _call(proxy, OP_SOURCE_MIGRATE, admin, {"dry_run": "yes"})
        assert resp.status == 400

    def test_migration_status_reports_the_plan_shape(self) -> None:
        proxy = _proxy()
        admin = _token(proxy, "user-admin-001")
        resp = _call(proxy, OP_SOURCE_MIGRATION_STATUS, admin, {})
        assert resp.status == 200, resp.body
        data = resp.body["data"]
        assert data["migration_version"] == 1
        assert "sources" in data and "rules" in data
        assert "audit_trail" in data

    def test_migration_engine_missing_is_not_a_silent_zero(self) -> None:
        """A wiring gap must be loud, never a fake '0 changes'."""
        proxy = SecureProxy(
            config=_config(), identity_store=_identity_store(),
        )
        proxy.attach_source_management_service(
            SourceManagementService(
                repository=SourceRepository(FakeDatabase(), _config()),
                registry=SourceRegistry(),
                capability_lookup=_lookup,
            )
        )
        admin = _token(proxy, "user-admin-001")
        resp = _call(proxy, OP_SOURCE_MIGRATION_STATUS, admin, {})
        assert resp.status == 400
