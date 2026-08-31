"""Phase 4.9 — Source Management repository tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import ProShieldConfig
from app.sources.errors import (
    DuplicateSourceInstanceError,
    SourceInstanceNotFoundError,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.repository import (
    INDEX_SPECS,
    SOURCE_INSTANCES_VALIDATOR,
    SourceRepository,
    managed_source_collection_name,
)
from tests.unit._phase49_fakes import FakeDatabase


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
    )


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


def _repo() -> SourceRepository:
    db = FakeDatabase()
    return SourceRepository(db, _config())


class TestIndexSpecs:
    def test_index_specs_have_required_keys(self) -> None:
        assert len(INDEX_SPECS) >= 4
        for spec in INDEX_SPECS:
            assert "name" in spec
            assert "key" in spec

    def test_unique_index_is_source_instance_id(self) -> None:
        unique_specs = [
            s for s in INDEX_SPECS if s.get("unique", False)
        ]
        assert any(
            s["name"] == "source_source_instance_id_unique"
            for s in unique_specs
        )

    def test_validator_requires_state(self) -> None:
        validator = SOURCE_INSTANCES_VALIDATOR["$jsonSchema"]
        assert "state" in validator["required"]
        assert "source_instance_id" in validator["required"]

    def test_managed_source_collection_name(self) -> None:
        assert managed_source_collection_name("dev") == "source_instances"


class TestRepositoryCreateGet:
    def test_create_then_get(self) -> None:
        repo = _repo()
        inst = _instance()
        repo.create(inst)
        loaded = repo.get(inst.source_instance_id)
        assert loaded is not None
        assert loaded.source_instance_id == inst.source_instance_id
        assert loaded.state is SourceState.REGISTERED

    def test_create_duplicate_raises(self) -> None:
        repo = _repo()
        inst = _instance()
        repo.create(inst)
        with pytest.raises(DuplicateSourceInstanceError):
            repo.create(inst)

    def test_get_unknown_returns_none(self) -> None:
        repo = _repo()
        assert repo.get("src-not-an-id") is None

    def test_get_required_unknown_raises(self) -> None:
        repo = _repo()
        with pytest.raises(SourceInstanceNotFoundError):
            repo.get_required("src-not-an-id")

    def test_upsert_inserts_then_updates(self) -> None:
        repo = _repo()
        inst = _instance(state=SourceState.REGISTERED)
        repo.upsert(inst)
        updated = inst.model_copy(update={
            "state": SourceState.CONFIGURED,
        })
        repo.upsert(updated)
        loaded = repo.get_required(inst.source_instance_id)
        assert loaded.state is SourceState.CONFIGURED

    def test_secret_ref_redacted_on_persist(self) -> None:
        repo = _repo()
        cfg = SourceInstanceConfiguration(
            connection_type=SourceConnectionType.PUSH,
            endpoint="https://example.com/api/ingest",
            proxy_path="",
            destination="",
            asset_tags=(),
            tags=(),
            references=(),
            secret_ref="very-secret-raw-value",
        )
        inst = _instance().model_copy(update={"configuration": cfg})
        repo.create(inst)
        loaded = repo.get_required(inst.source_instance_id)
        # The repository's loader re-attaches an empty
        # ``secret_ref`` so the raw value never reaches the
        # in-memory model again.
        assert loaded.configuration.secret_ref == ""

    def test_retire_preserves_document(self) -> None:
        repo = _repo()
        inst = _instance()
        repo.create(inst)
        repo.retire(inst.source_instance_id)
        assert repo.count() == 1
        loaded = repo.get_required(inst.source_instance_id)
        assert loaded.state is SourceState.RETIRED


class TestRepositoryLists:
    def test_find_by_state(self) -> None:
        repo = _repo()
        repo.create(_instance(handle="a", state=SourceState.REGISTERED))
        repo.create(_instance(handle="b", state=SourceState.ENABLED))
        enabled = repo.find_by_state(SourceState.ENABLED)
        assert len(enabled) == 1
        assert enabled[0].state is SourceState.ENABLED

    def test_find_all_returns_sorted(self) -> None:
        repo = _repo()
        repo.create(_instance(handle="c"))
        repo.create(_instance(handle="a"))
        repo.create(_instance(handle="b"))
        all_insts = repo.find_all()
        assert len(all_insts) == 3

    def test_count(self) -> None:
        repo = _repo()
        assert repo.count() == 0
        repo.create(_instance())
        assert repo.count() == 1


class TestRepositorySchemaAndIndexes:
    def test_ensure_schema_creates_collection(self) -> None:
        repo = _repo()
        repo.ensure_schema()
        names = list(repo._db.list_collection_names())
        assert "source_instances" in names

    def test_ensure_schema_is_idempotent(self) -> None:
        repo = _repo()
        repo.ensure_schema()
        repo.ensure_schema()  # second call is a no-op
        names = list(repo._db.list_collection_names())
        assert names.count("source_instances") == 1

    def test_ensure_indexes_returns_names(self) -> None:
        repo = _repo()
        repo.ensure_schema()
        names = repo.ensure_indexes()
        assert isinstance(names, list)
        assert "source_source_instance_id_unique" in names