"""Phase 4.9 — Source Management registry tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.sources.errors import (
    DuplicateSourceInstanceError,
    SourceInstanceNotFoundError,
    SourceInstanceStateError,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.registry import (
    ALLOWED_TRANSITIONS,
    SourceRegistry,
    SUPPORTED_CONNECTOR_TYPES,
    can_transition,
    supported_connector_types,
)


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _instance(
    *,
    handle: str = "prod",
    state: SourceState = SourceState.REGISTERED,
    source_type: SourceType = SourceType.NGINX,
) -> SourceInstance:
    cfg = SourceInstanceConfiguration(
        connection_type=SourceConnectionType.PUSH,
        endpoint="https://example.com/api/ingest",
        proxy_path="",
        destination="",
        asset_tags=(),
        tags=(),
        references=(),
        secret_ref="",
    )
    source_str_map = {
        SourceType.NGINX: "nginx",
        SourceType.WAF: "waf",
        SourceType.IAM: "iam",
        SourceType.RATE_LIMIT: "rate_limit",
        SourceType.NETWORK: "network",
        SourceType.SIMULATOR: "simulator",
    }
    return SourceInstance(
        source_instance_id=(
            f"src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-{handle}"
        ),
        source_type=source_type,
        source=source_str_map[source_type],
        display_name=f"Instance {handle}",
        description="",
        configuration=cfg,
        state=state,
        created_by="user-admin-001",
        created_at=_NOW,
        updated_by="user-admin-001",
        updated_at=_NOW,
        last_validation_at=None,
        tags=(),
        asset_tags=(),
        retired_at=(
            _NOW if state is SourceState.RETIRED else None
        ),
    )


class TestCanTransition:
    def test_registered_to_configured(self) -> None:
        assert can_transition(
            SourceState.REGISTERED, SourceState.CONFIGURED,
        )

    def test_registered_to_retired(self) -> None:
        assert can_transition(
            SourceState.REGISTERED, SourceState.RETIRED,
        )

    def test_registered_to_enabled_not_allowed(self) -> None:
        assert not can_transition(
            SourceState.REGISTERED, SourceState.ENABLED,
        )

    def test_retired_is_terminal(self) -> None:
        for target in SourceState:
            assert not can_transition(SourceState.RETIRED, target)

    def test_enabled_can_be_disabled(self) -> None:
        assert can_transition(SourceState.ENABLED, SourceState.DISABLED)

    def test_validated_can_be_enabled(self) -> None:
        assert can_transition(
            SourceState.VALIDATED, SourceState.ENABLED,
        )


class TestAllowedTransitionsExhaustive:
    def test_all_states_have_a_transition_record(self) -> None:
        for state in SourceState:
            assert state in ALLOWED_TRANSITIONS


class TestSupportedConnectorTypes:
    def test_supported_set_is_locked(self) -> None:
        # F-6: only implemented connector types are supported. The
        # SourceType enum declares a wider possible set, but the
        # supported/implemented set is locked to what the product can
        # actually ingest + evaluate today.
        assert SUPPORTED_CONNECTOR_TYPES == frozenset({
            SourceType.NGINX,
            SourceType.SIMULATOR,
        })
        assert SourceType.WAF not in SUPPORTED_CONNECTOR_TYPES

    def test_supported_list_is_sorted(self) -> None:
        types = supported_connector_types()
        assert types == sorted(types, key=lambda t: t.value)


class TestRegistryBasics:
    def test_register_and_get(self) -> None:
        reg = SourceRegistry()
        inst = _instance()
        reg.register(inst)
        assert reg.get(inst.source_instance_id) == inst

    def test_register_duplicate_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _instance()
        reg.register(inst)
        with pytest.raises(DuplicateSourceInstanceError):
            reg.register(inst)

    def test_get_unknown_returns_none(self) -> None:
        reg = SourceRegistry()
        assert reg.get("src-not-an-id") is None

    def test_get_required_unknown_raises(self) -> None:
        reg = SourceRegistry()
        with pytest.raises(SourceInstanceNotFoundError):
            reg.get_required("src-not-an-id")

    def test_list_all_is_sorted(self) -> None:
        reg = SourceRegistry()
        a = _instance(handle="a")
        b = _instance(handle="b")
        c = _instance(handle="c")
        reg.register(c)
        reg.register(a)
        reg.register(b)
        assert [i.source_instance_id for i in reg.list_all()] == sorted(
            [a.source_instance_id, b.source_instance_id, c.source_instance_id]
        )

    def test_list_by_state(self) -> None:
        reg = SourceRegistry()
        reg.register(_instance(handle="a", state=SourceState.REGISTERED))
        reg.register(_instance(handle="b", state=SourceState.ENABLED))
        enabled = reg.list_by_state(SourceState.ENABLED)
        assert len(enabled) == 1
        assert enabled[0].state is SourceState.ENABLED

    def test_list_by_type(self) -> None:
        reg = SourceRegistry()
        reg.register(
            _instance(handle="a", source_type=SourceType.NGINX)
        )
        reg.register(
            _instance(handle="b", source_type=SourceType.WAF)
        )
        waf = reg.list_by_type(SourceType.WAF)
        assert len(waf) == 1
        assert waf[0].source_type is SourceType.WAF

    def test_remove_unknown_raises(self) -> None:
        reg = SourceRegistry()
        with pytest.raises(SourceInstanceNotFoundError):
            reg.remove("src-not-an-id")

    def test_remove_known(self) -> None:
        reg = SourceRegistry()
        inst = _instance()
        reg.register(inst)
        reg.remove(inst.source_instance_id)
        assert reg.get(inst.source_instance_id) is None


class TestRegistryReplace:
    def test_replace_known(self) -> None:
        reg = SourceRegistry()
        a = _instance(state=SourceState.REGISTERED)
        reg.register(a)
        b = a.model_copy(update={"state": SourceState.CONFIGURED})
        reg.replace(b)
        assert reg.get(a.source_instance_id).state is SourceState.CONFIGURED

    def test_replace_unknown_raises(self) -> None:
        reg = SourceRegistry()
        inst = _instance()
        with pytest.raises(SourceInstanceNotFoundError):
            reg.replace(inst)

    def test_replace_invalid_type_raises(self) -> None:
        reg = SourceRegistry()
        with pytest.raises(TypeError):
            reg.replace("not-an-instance")


class TestRegistryTransition:
    def test_valid_transition_updates_state(self) -> None:
        reg = SourceRegistry()
        a = _instance(state=SourceState.REGISTERED)
        reg.register(a)
        updated = reg.transition(
            source_instance_id=a.source_instance_id,
            target=SourceState.CONFIGURED,
        )
        assert updated.state is SourceState.CONFIGURED
        assert reg.get(a.source_instance_id).state is SourceState.CONFIGURED

    def test_invalid_transition_raises(self) -> None:
        reg = SourceRegistry()
        a = _instance(state=SourceState.REGISTERED)
        reg.register(a)
        with pytest.raises(SourceInstanceStateError):
            reg.transition(
                source_instance_id=a.source_instance_id,
                target=SourceState.ENABLED,
            )

    def test_transition_unknown_raises(self) -> None:
        reg = SourceRegistry()
        with pytest.raises(SourceInstanceNotFoundError):
            reg.transition(
                source_instance_id="src-not-an-id",
                target=SourceState.CONFIGURED,
            )

    def test_transition_to_retired_sets_retired_at(self) -> None:
        reg = SourceRegistry()
        a = _instance(state=SourceState.ENABLED)
        reg.register(a)
        updated = reg.transition(
            source_instance_id=a.source_instance_id,
            target=SourceState.RETIRED,
        )
        assert updated.state is SourceState.RETIRED
        assert updated.retired_at is not None

    def test_is_enabled(self) -> None:
        reg = SourceRegistry()
        a = _instance(state=SourceState.ENABLED)
        reg.register(a)
        assert reg.is_enabled(a.source_instance_id) is True
        reg.transition(
            source_instance_id=a.source_instance_id,
            target=SourceState.DISABLED,
        )
        assert reg.is_enabled(a.source_instance_id) is False

    def test_known_ids_is_sorted(self) -> None:
        reg = SourceRegistry()
        reg.register(_instance(handle="c"))
        reg.register(_instance(handle="a"))
        reg.register(_instance(handle="b"))
        ids = reg.known_ids()
        assert ids == tuple(sorted(ids))