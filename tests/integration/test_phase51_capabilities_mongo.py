"""Phase 5.1 real-Mongo regression tests (finding 5.1-01 + 5.1-02 + 5.1-04).

These tests REQUIRE the local MongoDB (127.0.0.1:27017) via the shared
integration conftest. They prove:

* 5.1-01: ``capability.disable`` on a planned capability is refused
  (409) BEFORE any write; the persisted document stays valid and is
  fully readable after a simulated restart (fresh repository +
  registry); the next legal lifecycle transition works.
* 5.1-01 (defense-in-depth): the repository pre-persist guard rejects
  a model-invalid cross-field state (impl=planned + status=disabled)
  so NO writer can ever persist a quarantined-phantom document.
* 5.1-02: §18.27 audit records (actor/action/capability_id/diff) are
  persisted and survive a restart.
* live capabilities keep their disable->enable round trip across
  restarts with monotonic human ids.
"""
from __future__ import annotations

import pytest

from app.auth.identity import Identity
from app.capabilities.errors import (
    CapabilityConfigurationError,
    CapabilityStateError,
)
from app.capabilities.models import CAPABILITIES_COLLECTION, Capability, CapabilityStatus, ImplementationRef
from app.capabilities.registry import CapabilityRegistry
from app.capabilities.repository import CapabilityRepository
from app.capabilities.service import CapabilityService


def _admin() -> Identity:
    return Identity(subject_id="admin", role="admin", permissions=())


@pytest.fixture()
def cap_repo(db, test_config) -> CapabilityRepository:
    repo = CapabilityRepository(db=db, config=test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    repo.ensure_audit_schema()
    repo.ensure_audit_indexes()
    return repo


@pytest.fixture()
def cap_service(cap_repo) -> CapabilityService:
    svc = CapabilityService(repository=cap_repo, registry=CapabilityRegistry())
    svc.seed_builtins()
    return svc


def _restart_service(cap_repo) -> CapabilityService:
    """Simulate a process restart: fresh repository + fresh in-memory registry."""
    fresh_registry = CapabilityRegistry()
    svc = CapabilityService(repository=cap_repo, registry=fresh_registry)
    svc.reload_from_repository()
    return svc


def test_planned_disable_refused_document_survives_restart_and_recovers(db, cap_service, cap_repo):
    # --- the supported lifecycle must refuse the invalid transition ---
    with pytest.raises(CapabilityStateError):
        cap_service.disable(identity=_admin(), capability_id="cap-waf")

    raw = db[CAPABILITIES_COLLECTION].find_one({"capability_id": "cap-waf"})
    assert raw is not None
    assert raw["status"] == CapabilityStatus.PLANNED.value
    assert raw["implementation_ref"] == ImplementationRef.PLANNED.value

    # --- restart: the document must be readable (NOT quarantined) ---
    svc2 = _restart_service(cap_repo)
    reread = svc2.repository.get("cap-waf")
    assert reread is not None, "5.1-01: document must not be quarantined after restart"
    assert reread.status is CapabilityStatus.PLANNED
    listed = {c.capability_id for c in svc2.repository.find_all()}
    assert "cap-waf" in listed
    assert svc2.get("cap-waf")["status"] == "planned"

    # --- recovery / next legal transition: planned -> retired ---
    retired = svc2.retire(identity=_admin(), capability_id="cap-waf")
    assert retired["status"] == "retired"

    # --- second restart: retired state survives and stays readable ---
    svc3 = _restart_service(cap_repo)
    assert svc3.repository.get("cap-waf").status is CapabilityStatus.RETIRED
    archived = svc3.archive(identity=_admin(), capability_id="cap-waf")
    assert archived["status"] == "archived"
    svc4 = _restart_service(cap_repo)
    assert svc4.repository.get("cap-waf").status is CapabilityStatus.ARCHIVED
    # terminal state is closed
    with pytest.raises(CapabilityStateError):
        svc4.enable(identity=_admin(), capability_id="cap-waf")


def test_invalid_cross_field_state_cannot_be_persisted(db, cap_service, cap_repo):
    """Defense-in-depth: no writer can bypass the model invariant.

    ``model_copy`` skips Pydantic validation, so an invalid Capability
    instance can be crafted in memory; the repository pre-persist guard
    must refuse it BEFORE the Mongo write (5.1-01 root-cause hardening).
    """
    planned = cap_repo.get("cap-iam")
    assert planned is not None and planned.status is CapabilityStatus.PLANNED
    invalid = planned.model_copy(update={"status": CapabilityStatus.DISABLED})
    with pytest.raises(CapabilityConfigurationError):
        cap_repo.save(invalid)
    raw = db[CAPABILITIES_COLLECTION].find_one({"capability_id": "cap-iam"})
    assert raw["status"] == CapabilityStatus.PLANNED.value, "document must be untouched"


def test_live_capability_lifecycle_survives_restart(db, cap_service, cap_repo):
    created = cap_service.create(
        identity=_admin(),
        capability_id="cap-live-it",
        name="Live Integration Probe",
        implementation_ref="simulator",
        status="active",
    )
    assert created["status"] == "active"
    assert created["human_id"].startswith("CAP-")
    disabled = cap_service.disable(identity=_admin(), capability_id="cap-live-it")
    assert disabled["status"] == "disabled"

    svc2 = _restart_service(cap_repo)
    assert svc2.repository.get("cap-live-it").status is CapabilityStatus.DISABLED
    enabled = svc2.enable(identity=_admin(), capability_id="cap-live-it")
    assert enabled["status"] == "active"

    svc3 = _restart_service(cap_repo)
    assert svc3.repository.get("cap-live-it").status is CapabilityStatus.ACTIVE
    # duplicate human-id allocation stays monotonic across restarts
    other = cap_service.create(
        identity=_admin(),
        capability_id="cap-live-it-2",
        name="Live Integration Probe 2",
        implementation_ref="simulator",
        status="active",
    )
    assert other["human_id"] != created["human_id"]


def test_audit_records_persisted_and_survive_restart(db, cap_service, cap_repo):
    cap_service.create(
        identity=_admin(),
        capability_id="cap-audit-it",
        name="Audit Probe",
        implementation_ref="planned",
        status="planned",
    )
    cap_service.update(
        identity=_admin(),
        capability_id="cap-audit-it",
        description="updated description",
        version=2,
    )
    cap_service.retire(identity=_admin(), capability_id="cap-audit-it")

    raw_audit = list(db["capability_audit"].find({"capability_id": "cap-audit-it"}))
    actions = {r["action"] for r in raw_audit}
    assert {"create", "update", "retire"} <= actions
    for rec in raw_audit:
        assert rec["actor"] == "admin"
        assert rec["capability_id"] == "cap-audit-it"
        assert isinstance(rec["changed_fields"], list)

    # restart: the audit trail is still readable through the service view
    svc2 = _restart_service(cap_repo)
    trail = svc2.list_audit("cap-audit-it", limit=50)
    assert trail["count"] >= 3
    read_actions = {r["action"] for r in trail["records"]}
    assert {"create", "update", "retire"} <= read_actions
    update_rec = next(r for r in trail["records"] if r["action"] == "update")
    assert "description" in update_rec["changed_fields"]
    assert update_rec["after"]["version"] == 2


def test_seed_fail_loud_contract(db, cap_repo, monkeypatch):
    """§18.25: a failing capability seed must not be silently swallowed.

    ensure_all_collections (real-Mongo path) must propagate seed failures
    so a deployment never boots with a missing registry.
    """
    from app.persistence.bootstrap import ensure_all_collections

    def _boom(self, *, actor: str = "system"):
        raise CapabilityConfigurationError(safe_message="seed failed", internal_detail="simulated")

    monkeypatch.setattr(CapabilityService, "seed_builtins", _boom)
    with pytest.raises(CapabilityConfigurationError):
        ensure_all_collections(db, cap_repo._config)
