"""Phase 5.2 — Source Architecture 2.0 (real MongoDB integration).

These tests REQUIRE the local MongoDB (127.0.0.1:27017) via the shared
integration conftest. They prove, against a real database:

* the Phase 5.2 ``source_instances`` validator and the new capability
  indexes are actually applied on a fresh database;
* ``$jsonSchema`` accepts a properly bound source and **rejects** a
  malformed capability reference written directly to the collection;
* the append-only ``source_audit`` collection exists with its validator;
* the legacy migration is deterministic, audited, idempotent and
  restart-safe against persisted rows (not fakes);
* a migrated binding and its audit trail survive a simulated restart;
* an unresolvable legacy row is quarantined with **no** invented owner.

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md §19.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pymongo.errors import WriteError

from app.auth.identity import Identity
from app.persistence.bootstrap import ensure_all_collections
from app.sources.audit import SOURCE_AUDIT_COLLECTION
from app.sources.capability_binding import builtin_capability_index
from app.sources.migration import SourceCapabilityMigration
from app.sources.models import SourceType
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService

_NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)

_SOURCE_TYPES = ("nginx", "simulator", "waf", "iam", "rate_limit", "network")


def _admin() -> Identity:
    return Identity(subject_id="admin", role="admin", permissions=())


def _lookup(capability_id: str):
    return builtin_capability_index().get(capability_id)


@pytest.fixture()
def src_repo(db, test_config) -> SourceRepository:
    repo = SourceRepository(db=db, config=test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    repo.ensure_audit_schema()
    repo.ensure_audit_indexes()
    return repo


def _service(repo: SourceRepository) -> SourceManagementService:
    svc = SourceManagementService(
        repository=repo,
        registry=SourceRegistry(),
        capability_lookup=_lookup,
        audit_collection=repo.audit_collection(),
    )
    svc.reload_from_repository()
    return svc


def _restart(repo: SourceRepository) -> SourceManagementService:
    """Simulate a process restart: fresh registry, same database."""
    return _service(repo)


def _engine(repo: SourceRepository) -> SourceCapabilityMigration:
    return SourceCapabilityMigration(
        source_repository=repo,
        capability_lookup=_lookup,
        registry=None,
    )


def _raw_legacy_doc(sid: str, source_type: str) -> dict:
    """A pre-Phase-5.2 persisted row, written straight into MongoDB."""
    return {
        "source_instance_id": sid,
        "human_id": "",
        "source_type": source_type,
        "source": source_type,
        "display_name": f"legacy-{source_type}",
        "description": "",
        "configuration": {
            "connection_type": "push",
            "endpoint": "https://legacy.example.test/hook",
            "proxy_path": "",
            "destination": "legacy",
            "asset_tags": [],
            "tags": [],
            "references": [],
            "secret_ref_set": False,
        },
        "state": "enabled",
        "created_by": "legacy-admin",
        "created_at": _NOW,
        "updated_by": "legacy-admin",
        "updated_at": _NOW,
        "last_validation_at": _NOW,
        "tags": [],
        "asset_tags": [],
        "retired_at": None,
    }


_SID_A = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f11-a"
_SID_B = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-b"
_SID_C = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f13-c"


# ---------------------------------------------------------------------------
# A. Fresh-database schema, validator and index set
# ---------------------------------------------------------------------------
def test_bootstrap_creates_source_audit_and_capability_indexes(db, test_config):
    ensure_all_collections(db, test_config)

    assert SOURCE_AUDIT_COLLECTION in set(db.list_collection_names())

    idx = {i["name"] for i in db["source_instances"].list_indexes()}
    assert "source_capability_id" in idx
    assert "source_capability_binding_status" in idx

    info = db.command(
        "listCollections", filter={"name": "source_instances"},
    )
    validator = info["cursor"]["firstBatch"][0]["options"]["validator"]
    props = validator["$jsonSchema"]["properties"]
    for key in (
        "capability_id",
        "capability_version",
        "mapping_profile_id",
        "capability_binding_status",
        "capability_bound_at",
    ):
        assert key in props, key
    assert validator["$jsonSchema"]["additionalProperties"] is False


def test_validator_accepts_a_bound_source(src_repo, db):
    svc = _service(src_repo)
    view = svc.register(
        identity=_admin(),
        source_type=SourceType.NGINX,
        display_name="mongo-bound-nginx",
    )
    assert view.capability_id == "cap-nginx"
    raw = db["source_instances"].find_one(
        {"source_instance_id": view.source_instance_id}
    )
    assert raw["capability_id"] == "cap-nginx"
    assert raw["capability_binding_status"] == "bound"
    assert raw["capability_version"] == 1
    assert raw["mapping_profile_id"] == "nginx-access-default"


def test_validator_rejects_a_malformed_capability_id(src_repo, db):
    doc = _raw_legacy_doc(_SID_A, "nginx")
    doc["capability_id"] = "NOT-A-CAPABILITY-ID"
    doc["capability_binding_status"] = "bound"
    doc["capability_version"] = 1
    with pytest.raises(WriteError):
        db["source_instances"].insert_one(doc)


def test_validator_rejects_an_unknown_binding_status(src_repo, db):
    doc = _raw_legacy_doc(_SID_A, "nginx")
    doc["capability_binding_status"] = "totally-made-up"
    with pytest.raises(WriteError):
        db["source_instances"].insert_one(doc)


# ---------------------------------------------------------------------------
# B. Legacy migration against persisted rows
# ---------------------------------------------------------------------------
def _insert_legacy(db, *docs) -> None:
    for doc in docs:
        db["source_instances"].insert_one(dict(doc))


def test_migration_dry_run_writes_nothing(src_repo, db):
    _insert_legacy(db, _raw_legacy_doc(_SID_A, "nginx"))
    before = db["source_instances"].find_one(
        {"source_instance_id": _SID_A}
    )
    report = _engine(src_repo).run(dry_run=True)
    assert report.sources_bound == 1
    assert report.documents_modified == 0
    assert report.audit_records_written == 0
    after = db["source_instances"].find_one(
        {"source_instance_id": _SID_A}
    )
    assert after == before
    assert db[SOURCE_AUDIT_COLLECTION].count_documents({}) == 0


def test_migration_applies_deterministic_mapping_and_audits(src_repo, db):
    _insert_legacy(
        db,
        _raw_legacy_doc(_SID_A, "nginx"),
        _raw_legacy_doc(_SID_B, "simulator"),
    )
    report = _engine(src_repo).run(dry_run=False)
    assert report.sources_bound == 2
    assert report.audit_records_written == 2

    by_sid = {
        d["source_instance_id"]: d
        for d in db["source_instances"].find({})
    }
    assert by_sid[_SID_A]["capability_id"] == "cap-nginx"
    assert by_sid[_SID_A]["capability_binding_status"] == "bound"
    assert by_sid[_SID_B]["capability_id"] == "cap-simulator"

    audits = list(db[SOURCE_AUDIT_COLLECTION].find({}))
    assert len(audits) == 2
    assert {a["action"] for a in audits} == {"source_capability_bind"}
    a = next(
        x for x in audits
        if x["source_instance_id"] == _SID_A
    )
    assert a["capability_id"] == "cap-nginx"
    assert a["before"]["capability_id"] is None
    assert a["after"]["capability_id"] == "cap-nginx"
    # Historical lineage untouched by the migration.
    assert a["before"]["source_type"] == "nginx"


def test_migration_is_idempotent_and_writes_no_second_audit(src_repo, db):
    _insert_legacy(
        db,
        _raw_legacy_doc(_SID_A, "nginx"),
        _raw_legacy_doc(_SID_B, "simulator"),
    )
    engine = _engine(src_repo)
    engine.run(dry_run=False)
    assert db[SOURCE_AUDIT_COLLECTION].count_documents({}) == 2

    second = engine.run(dry_run=False)
    assert second.sources_bound == 0
    assert second.sources_quarantined == 0
    assert second.documents_modified == 0
    assert second.is_noop is True
    assert db[SOURCE_AUDIT_COLLECTION].count_documents({}) == 2


def test_unresolvable_legacy_row_is_quarantined_not_invented(src_repo, db):
    """A row whose capability cannot be resolved is quarantined, not guessed.

    On a schema-validated deployment both ``source_type`` and ``source`` are
    enum-constrained, so an *unknown source type* cannot be written at all
    (asserted separately below). The reachable unresolvable case is a known
    source type whose mapped capability is genuinely absent from the
    registry — exactly what this test exercises.
    """
    _insert_legacy(db, _raw_legacy_doc(_SID_C, "nginx"))
    engine = SourceCapabilityMigration(
        source_repository=src_repo,
        capability_lookup=lambda cid: None,  # registry cannot resolve it
        registry=None,
    )
    report = engine.run(dry_run=False)
    assert report.sources_quarantined == 1

    raw = db["source_instances"].find_one(
        {"source_instance_id": _SID_C}
    )
    assert raw["capability_id"] is None
    assert raw["capability_binding_status"] == "requires_verification"
    assert raw["capability_version"] is None
    # History preserved: the legacy row keeps its original type.
    assert raw["source_type"] == "nginx"

    audit = db[SOURCE_AUDIT_COLLECTION].find_one(
        {"source_instance_id": _SID_C}
    )
    assert audit["action"] == "source_capability_quarantine"
    assert audit["capability_id"] is None


def test_schema_rejects_an_unknown_source_type(src_repo, db):
    """Documented boundary: an unknown source type is unwritable.

    This is why the migration's "unknown source type" quarantine branch is
    only reachable for data written *before* the validator existed (a
    ``collMod`` never re-validates existing documents). It is pinned here so
    the behaviour is explicit rather than assumed.
    """
    with pytest.raises(WriteError):
        db["source_instances"].insert_one(
            _raw_legacy_doc(_SID_C, "mainframe")
        )


def test_migration_does_not_resurrect_a_bound_row(src_repo, db):
    """A committed binding is never re-derived by a later run."""
    _insert_legacy(db, _raw_legacy_doc(_SID_A, "nginx"))
    _engine(src_repo).run(dry_run=False)
    # A second engine over the same persisted data must be a no-op.
    assert _engine(src_repo).run(dry_run=False).sources_already_bound == 1


def test_migrated_binding_survives_a_restart(src_repo, db):
    _insert_legacy(db, _raw_legacy_doc(_SID_A, "nginx"))
    _engine(src_repo).run(dry_run=False)

    restarted = _restart(src_repo)
    view = restarted.get(_SID_A)
    assert view.capability_id == "cap-nginx"
    assert view.capability_binding_status == "bound"
    assert view.capability_version == 1
    # The audit trail is durable too.
    assert db[SOURCE_AUDIT_COLLECTION].count_documents(
        {"source_instance_id": _SID_A}
    ) >= 1


def test_quarantined_source_cannot_be_registered_into_service_state(src_repo, db):
    """A quarantined row stays quarantined across a restart."""
    _insert_legacy(db, _raw_legacy_doc(_SID_C, "nginx"))
    SourceCapabilityMigration(
        source_repository=src_repo,
        capability_lookup=lambda cid: None,
        registry=None,
    ).run(dry_run=False)
    restarted = _restart(src_repo)
    view = restarted.get(_SID_C)
    assert view.capability_binding_status == "requires_verification"
    assert view.capability_id is None


def test_human_ids_remain_monotonic_across_restarts(src_repo, db):
    svc = _service(src_repo)
    first = svc.register(
        identity=_admin(),
        source_type=SourceType.NGINX,
        display_name="mono-1",
    )
    assert first.human_id

    restarted = _restart(src_repo)
    second = restarted.register(
        identity=_admin(),
        source_type=SourceType.NGINX,
        display_name="mono-2",
    )
    assert second.human_id
    assert second.human_id != first.human_id
    seq_a = int(first.human_id.split("-")[1])
    seq_b = int(second.human_id.split("-")[1])
    assert seq_b > seq_a


def test_bound_source_lifecycle_works_end_to_end_on_mongo(
    src_repo, db, test_config
):
    from app.sources.models import (
        SourceConnectionType,
        SourceInstanceConfiguration,
    )
    from app.sources.trust import (
        SourceIdentityTokenIssuer,
        SourceIdentityTokenVerifier,
    )

    # A dedicated key: the shared test_config intentionally carries no
    # signing key, and production refuses to issue tokens without one.
    key = "phase52-mongo-integration-signing-key"
    issuer = SourceIdentityTokenIssuer(secret=key)
    svc = SourceManagementService(
        repository=src_repo,
        registry=SourceRegistry(),
        token_issuer=issuer,
        capability_lookup=_lookup,
        audit_collection=src_repo.audit_collection(),
    )
    view = svc.register(
        identity=_admin(),
        source_type=SourceType.NGINX,
        display_name="mongo-lifecycle",
    )
    sid = view.source_instance_id
    svc.configure(
        identity=_admin(),
        source_instance_id=sid,
        configuration=SourceInstanceConfiguration(
            connection_type=SourceConnectionType.PUSH,
            endpoint="https://ingest.example.test/hook",
            secret_ref="",
        ),
    )
    svc.validate_connection(identity=_admin(), source_instance_id=sid)
    enabled = svc.enable(identity=_admin(), source_instance_id=sid)
    assert enabled.state == "enabled"
    token = svc.issue_ingress_token(
        identity=_admin(), source_instance_id=sid,
    )
    assert token.count(".") == 2

    # The token carries the server-derived capability claim.
    verifier = SourceIdentityTokenVerifier.from_secret(
        key,
        source_resolver=lambda s: src_repo.get(s),
        require_replay_store=False,
    )
    verified = verifier.verify(token)
    assert verified.capability_id == "cap-nginx"
    assert verified.source_instance_id == sid

    # Lifecycle + token writes are auditable.
    actions = {
        d["action"] for d in db[SOURCE_AUDIT_COLLECTION].find(
            {"source_instance_id": sid}
        )
    }
    assert "source_register" in actions
    assert "source_token_issue" in actions