"""Phase 4.9 — Source Management domain model tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.sources.models import (
    AssetTag,
    SourceConnectionType,
    SourceIdentityToken,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceInstanceHealth,
    SourceInstanceId,
    SourceInstanceView,
    SourceState,
    SourceType,
    Tag,
    source_string_for_type,
    source_type_for_string,
)


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _valid_config(**overrides):
    base = {
        "connection_type": SourceConnectionType.PUSH,
        "endpoint": "https://example.com/api/ingest",
        "proxy_path": "",
        "destination": "example",
        "asset_tags": (),
        "tags": (),
        "references": (),
        "secret_ref": "",
    }
    base.update(overrides)
    return base


def _valid_instance(**overrides):
    base = {
        "source_instance_id": (
            "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
        ),
        "source_type": SourceType.NGINX,
        "source": "nginx",
        "display_name": "Prod Nginx",
        "description": "",
        "configuration": SourceInstanceConfiguration(**_valid_config()),
        "state": SourceState.REGISTERED,
        "created_by": "user-admin-001",
        "created_at": _NOW,
        "updated_by": "user-admin-001",
        "updated_at": _NOW,
        "last_validation_at": None,
        "tags": (),
        "asset_tags": (),
        "retired_at": None,
    }
    base.update(overrides)
    return SourceInstance(**base)


class TestSourceTypeAndString:
    def test_source_string_for_type_is_stable(self) -> None:
        assert source_string_for_type(SourceType.NGINX) == "nginx"
        assert source_string_for_type(SourceType.WAF) == "waf"
        assert source_string_for_type(SourceType.IAM) == "iam"
        assert source_string_for_type(SourceType.RATE_LIMIT) == "rate_limit"
        assert source_string_for_type(SourceType.NETWORK) == "network"
        assert source_string_for_type(SourceType.SIMULATOR) == "simulator"

    def test_source_type_for_string_round_trip(self) -> None:
        for st in SourceType:
            assert source_type_for_string(source_string_for_type(st)) is st

    def test_unknown_source_string_returns_none(self) -> None:
        assert source_type_for_string("unknown") is None


class TestSourceInstanceConfiguration:
    def test_minimal_valid(self) -> None:
        cfg = SourceInstanceConfiguration(**_valid_config())
        assert cfg.connection_type is SourceConnectionType.PUSH
        assert cfg.endpoint == "https://example.com/api/ingest"

    def test_empty_endpoint_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(**_valid_config(endpoint=""))

    def test_whitespace_in_endpoint_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(
                **_valid_config(endpoint="https://example.com/path x")
            )

    def test_secret_substrings_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(
                **_valid_config(proxy_path="token=abc123")
            )
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(
                **_valid_config(destination="secret=zzz")
            )

    def test_to_safe_dict_strips_secret_ref(self) -> None:
        cfg = SourceInstanceConfiguration(
            **_valid_config(secret_ref="very-secret-value")
        )
        safe = cfg.to_safe_dict()
        assert "secret_ref" not in safe
        assert safe["secret_ref_set"] is True

    def test_to_safe_dict_marks_no_secret_when_empty(self) -> None:
        cfg = SourceInstanceConfiguration(
            **_valid_config(secret_ref="")
        )
        safe = cfg.to_safe_dict()
        assert safe["secret_ref_set"] is False

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(
                **_valid_config(not_a_field="x")
            )

    def test_too_many_asset_tags_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceConfiguration(
                **_valid_config(
                    asset_tags=tuple(
                        f"asset-{i}" for i in range(20)
                    )
                )
            )


class TestSourceInstance:
    def test_valid_nginx_instance(self) -> None:
        inst = _valid_instance()
        assert inst.source == "nginx"
        assert inst.source_type is SourceType.NGINX
        assert inst.state is SourceState.REGISTERED

    def test_mismatched_source_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _valid_instance(source="waf")

    def test_retired_requires_retired_at(self) -> None:
        with pytest.raises(ValidationError):
            _valid_instance(state=SourceState.RETIRED, retired_at=None)

    def test_non_retired_must_not_have_retired_at(self) -> None:
        with pytest.raises(ValidationError):
            _valid_instance(
                state=SourceState.ENABLED,
                retired_at=_NOW,
            )

    def test_to_view_omits_secrets(self) -> None:
        cfg = SourceInstanceConfiguration(
            **_valid_config(secret_ref="very-secret")
        )
        inst = _valid_instance(configuration=cfg)
        view = inst.to_view()
        assert view.state == "registered"
        assert view.source_type == "nginx"
        assert view.configuration["secret_ref_set"] is True
        assert "secret_ref" not in view.configuration

    def test_to_canonical_dict_round_trip(self) -> None:
        inst = _valid_instance()
        d = inst.to_canonical_dict()
        # The safe view strips ``secret_ref``; round-tripping
        # the canonical dict requires dropping the
        # ``secret_ref_set`` flag and re-attaching the empty
        # ``secret_ref`` (the repository's loader does this
        # at the persistence boundary).
        cfg = dict(d["configuration"])
        cfg.pop("secret_ref_set", None)
        cfg["secret_ref"] = ""
        d["configuration"] = cfg
        reloaded = SourceInstance.model_validate(d)
        assert reloaded.source_instance_id == inst.source_instance_id
        assert reloaded.state == inst.state
        assert reloaded.source_type == inst.source_type


class TestSourceIdentityToken:
    def test_basic_validation(self) -> None:
        tok = SourceIdentityToken(
            token_id="sit-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
            source_instance_id=(
                "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
            ),
            source_type="nginx",
            source="nginx",
            issued_at=_NOW,
            not_before=_NOW,
            expires_at=_NOW,
            nonce="x" * 24,
            signature="y" * 64,
        )
        assert tok.source == "nginx"

    def test_unknown_source_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceIdentityToken(
                token_id="sit-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
                source_instance_id=(
                    "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
                ),
                source_type="bogus",
                source="bogus",
                issued_at=_NOW,
                not_before=_NOW,
                expires_at=_NOW,
                nonce="x" * 24,
                signature="y" * 64,
            )


class TestSourceInstanceHealth:
    def test_valid_health(self) -> None:
        h = SourceInstanceHealth(
            state=SourceState.ENABLED,
            status="ok",
            last_received_at=None,
            last_validation_at=None,
            last_error="",
            received_count=0,
            rejected_count=0,
        )
        assert h.status == "ok"

    def test_negative_counters_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceHealth(
                state=SourceState.ENABLED,
                status="ok",
                received_count=-1,
            )

    def test_invalid_status_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceInstanceHealth(
                state=SourceState.ENABLED,
                status="garbage",
            )


class TestAliases:
    def test_source_instance_id_pattern_rejects_bad(self) -> None:
        from pydantic import TypeAdapter
        adapter = TypeAdapter(SourceInstanceId)
        with pytest.raises(ValidationError):
            adapter.validate_python("not-an-id")

    def test_asset_tag_pattern_rejects_uppercase(self) -> None:
        from pydantic import TypeAdapter
        adapter = TypeAdapter(AssetTag)
        with pytest.raises(ValidationError):
            adapter.validate_python("WebApp")

    def test_tag_pattern_rejects_lowercase(self) -> None:
        from pydantic import TypeAdapter
        adapter = TypeAdapter(Tag)
        with pytest.raises(ValidationError):
            adapter.validate_python("web")


class TestSourceInstanceView:
    def test_view_validates_state_string(self) -> None:
        inst = _valid_instance()
        view = inst.to_view()
        assert view.state in {
            s.value for s in SourceState
        }
        assert view.source_type in {
            t.value for t in SourceType
        }