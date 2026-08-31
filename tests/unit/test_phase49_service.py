"""Phase 4.9 — Source Management service tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.auth import ADMIN_ROLE, ANALYST_ROLE, Identity
from app.config import ProShieldConfig
from app.sources.errors import (
    SourceAuthorizationError,
    SourceConfigurationError,
    SourceInstanceNotFoundError,
    SourceInstanceStateError,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    new_development_signing_key,
)
from tests.unit._phase49_fakes import FakeDatabase


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
_ADMIN = Identity(subject_id="user-admin-001", role=ADMIN_ROLE)
_ANALYST = Identity(subject_id="user-analyst-001", role=ANALYST_ROLE)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        source_signing_key=new_development_signing_key(),
    )


def _service(
    config: ProShieldConfig = None,
    token_issuer: SourceIdentityTokenIssuer = None,
) -> SourceManagementService:
    repo = SourceRepository(FakeDatabase(), config or _config())
    registry = SourceRegistry()
    svc = SourceManagementService(
        repository=repo, registry=registry,
        token_issuer=token_issuer,
    )
    return svc


def _config_payload(**overrides) -> SourceInstanceConfiguration:
    base = {
        "connection_type": SourceConnectionType.PUSH,
        "endpoint": "https://example.com/api/ingest",
        "proxy_path": "",
        "destination": "",
        "asset_tags": (),
        "tags": (),
        "references": (),
        "secret_ref": "",
    }
    base.update(overrides)
    return SourceInstanceConfiguration(**base)


class TestServiceConstruction:
    def test_requires_repository(self) -> None:
        with pytest.raises(ValueError):
            SourceManagementService(
                repository=None, registry=SourceRegistry(),
            )

    def test_requires_registry(self) -> None:
        with pytest.raises(ValueError):
            SourceManagementService(
                repository=SourceRepository(FakeDatabase(), _config()),
                registry=None,
            )


class TestRegisterAuthorize:
    def test_register_requires_admin(self) -> None:
        svc = _service()
        with pytest.raises(SourceAuthorizationError):
            svc.register(
                identity=_ANALYST,
                source_type=SourceType.NGINX,
                display_name="Prod Nginx",
            )

    def test_register_creates_instance(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod Nginx",
            description="prod frontend",
            tags=("PROD",),
            asset_tags=("web-app",),
        )
        assert view.state == "registered"
        assert view.source == "nginx"
        assert view.source_type == "nginx"

    def test_register_rejects_empty_display_name(self) -> None:
        svc = _service()
        with pytest.raises(SourceConfigurationError):
            svc.register(
                identity=_ADMIN,
                source_type=SourceType.NGINX,
                display_name="",
            )

    def test_register_rejects_too_long_display_name(self) -> None:
        svc = _service()
        with pytest.raises(SourceConfigurationError):
            svc.register(
                identity=_ADMIN,
                source_type=SourceType.NGINX,
                display_name="x" * 200,
            )

    def test_register_rejects_unknown_source_type(self) -> None:
        svc = _service()
        with pytest.raises(SourceConfigurationError):
            svc.register(
                identity=_ADMIN,
                source_type="bogus",  # type: ignore[arg-type]
                display_name="Bogus",
            )


class TestConfigureAndValidate:
    def test_configure_registered_to_configured(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        view = svc.configure(
            identity=_ADMIN,
            source_instance_id=view.source_instance_id,
            configuration=_config_payload(),
        )
        assert view.state == "configured"

    def test_configure_unknown_raises(self) -> None:
        svc = _service()
        with pytest.raises(SourceInstanceNotFoundError):
            svc.configure(
                identity=_ADMIN,
                source_instance_id="src-not-an-id",
                configuration=_config_payload(),
            )

    def test_configure_rejects_non_admin(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        with pytest.raises(SourceAuthorizationError):
            svc.configure(
                identity=_ANALYST,
                source_instance_id=view.source_instance_id,
                configuration=_config_payload(),
            )

    def test_validate_rejects_http_endpoint(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        view = svc.configure(
            identity=_ADMIN,
            source_instance_id=view.source_instance_id,
            configuration=_config_payload(
                endpoint="http://example.com/api/ingest"
            ),
        )
        with pytest.raises(SourceConfigurationError):
            svc.validate_connection(
                identity=_ADMIN,
                source_instance_id=view.source_instance_id,
            )

    def test_validate_accepts_https_with_validator(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        view = svc.configure(
            identity=_ADMIN,
            source_instance_id=view.source_instance_id,
            configuration=_config_payload(),
        )
        view = svc.validate_connection(
            identity=_ADMIN,
            source_instance_id=view.source_instance_id,
            validator=lambda inst: True,
        )
        assert view.state == "validated"
        assert view.last_validation_at is not None

    def test_validate_rejects_when_validator_returns_false(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        view = svc.configure(
            identity=_ADMIN,
            source_instance_id=view.source_instance_id,
            configuration=_config_payload(),
        )
        with pytest.raises(SourceConfigurationError):
            svc.validate_connection(
                identity=_ADMIN,
                source_instance_id=view.source_instance_id,
                validator=lambda inst: False,
            )


class TestEnableDisableRetire:
    def _enabled(self) -> tuple:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN,
            source_instance_id=sid,
            configuration=_config_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        return svc, svc.enable(
            identity=_ADMIN, source_instance_id=sid,
        ).source_instance_id

    def test_enable_validated_to_enabled(self) -> None:
        svc, sid = self._enabled()
        view = svc.get(sid)
        assert view.state == "enabled"

    def test_disable_enabled_to_disabled(self) -> None:
        svc, sid = self._enabled()
        view = svc.disable(identity=_ADMIN, source_instance_id=sid)
        assert view.state == "disabled"

    def test_re_enable_disabled(self) -> None:
        svc, sid = self._enabled()
        svc.disable(identity=_ADMIN, source_instance_id=sid)
        view = svc.enable(identity=_ADMIN, source_instance_id=sid)
        assert view.state == "enabled"

    def test_enable_without_validation_rejected(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        with pytest.raises(SourceInstanceStateError):
            svc.enable(
                identity=_ADMIN,
                source_instance_id=view.source_instance_id,
            )

    def test_retire_preserves_doc(self) -> None:
        svc, sid = self._enabled()
        view = svc.retire(identity=_ADMIN, source_instance_id=sid)
        assert view.state == "retired"
        assert svc._repository.count() == 1

    def test_retire_is_idempotent(self) -> None:
        svc, sid = self._enabled()
        first = svc.retire(identity=_ADMIN, source_instance_id=sid)
        second = svc.retire(identity=_ADMIN, source_instance_id=sid)
        assert first.state == second.state == "retired"

    def test_retire_rejects_non_admin(self) -> None:
        svc, sid = self._enabled()
        with pytest.raises(SourceAuthorizationError):
            svc.retire(identity=_ANALYST, source_instance_id=sid)


class TestIssueIngressToken:
    def test_token_issue_requires_issuer(self) -> None:
        svc = _service(token_issuer=None)
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        with pytest.raises(SourceConfigurationError):
            svc.issue_ingress_token(
                identity=_ADMIN,
                source_instance_id=view.source_instance_id,
            )

    def test_token_issue_requires_validated_state(self) -> None:
        issuer = SourceIdentityTokenIssuer(
            secret=new_development_signing_key(),
            lifetime_seconds=60,
        )
        svc = _service(token_issuer=issuer)
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        with pytest.raises(SourceInstanceStateError):
            svc.issue_ingress_token(
                identity=_ADMIN,
                source_instance_id=view.source_instance_id,
            )

    def test_token_issue_succeeds_when_enabled(self) -> None:
        issuer = SourceIdentityTokenIssuer(
            secret=new_development_signing_key(),
            lifetime_seconds=60,
        )
        svc = _service(token_issuer=issuer)
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN,
            source_instance_id=sid,
            configuration=_config_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        svc.enable(identity=_ADMIN, source_instance_id=sid)
        packed = svc.issue_ingress_token(
            identity=_ADMIN, source_instance_id=sid,
        )
        assert isinstance(packed, str)
        assert len(packed.split(".")) == 3


class TestGetAndList:
    def test_get_unknown_raises(self) -> None:
        svc = _service()
        with pytest.raises(SourceInstanceNotFoundError):
            svc.get("src-not-an-id")

    def test_list_all_returns_views(self) -> None:
        svc = _service()
        svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        svc.register(
            identity=_ADMIN,
            source_type=SourceType.WAF,
            display_name="Staging",
        )
        views = svc.list_all()
        assert len(views) == 2

    def test_list_supported_connector_types(self) -> None:
        svc = _service()
        types = svc.list_supported_connector_types()
        assert SourceType.NGINX in types
        assert SourceType.WAF in types


class TestReloadFromRepository:
    def test_reload_populates_registry(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        svc._registry.remove(view.source_instance_id)
        assert svc._registry.get(view.source_instance_id) is None
        n = svc.reload_from_repository()
        assert n == 1
        assert svc._registry.get(view.source_instance_id) is not None


class TestUpdateMetadata:
    def _enabled(self) -> tuple:
        svc = _service()
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="Prod",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN,
            source_instance_id=sid,
            configuration=_config_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        svc.enable(identity=_ADMIN, source_instance_id=sid)
        return svc, sid

    def test_update_display_name(self) -> None:
        svc, sid = self._enabled()
        view = svc.update_metadata(
            identity=_ADMIN,
            source_instance_id=sid,
            display_name="Production Nginx",
        )
        assert view.display_name == "Production Nginx"

    def test_update_tags_and_asset_tags(self) -> None:
        svc, sid = self._enabled()
        view = svc.update_metadata(
            identity=_ADMIN,
            source_instance_id=sid,
            tags=("PROD", "BACKEND"),
            asset_tags=("web-app", "lb"),
        )
        assert "PROD" in view.tags
        assert "web-app" in view.asset_tags

    def test_update_rejects_empty_display_name(self) -> None:
        svc, sid = self._enabled()
        with pytest.raises(SourceConfigurationError):
            svc.update_metadata(
                identity=_ADMIN,
                source_instance_id=sid,
                display_name="",
            )

    def test_update_rejects_retired_source(self) -> None:
        svc, sid = self._enabled()
        svc.retire(identity=_ADMIN, source_instance_id=sid)
        with pytest.raises(SourceInstanceStateError):
            svc.update_metadata(
                identity=_ADMIN,
                source_instance_id=sid,
                display_name="New Name",
            )