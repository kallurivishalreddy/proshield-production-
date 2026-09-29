"""Phase 5.1 Capability Registry tests.

Covers: model validation, lifecycle/registry transitions, allowlisted
implementation_ref, idempotent seeds, repository validator/indexes,
service CRUD + lifecycle + derived views, SecureProxy authz matrix,
adversarial payloads, and V2 pipeline non-regression.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.auth import Identity
from app.auth.permissions import Permission
from app.auth.session import SessionTokenService, SessionVerifier
from app.auth.identity import InMemoryIdentityStore
from app.capabilities.errors import (
    CapabilityAlreadyExistsError,
    CapabilityAuthorizationError,
    CapabilityConfigurationError,
    CapabilityNotFoundError,
    CapabilityStateError,
)
from app.capabilities.models import (
    CAPABILITIES_COLLECTION,
    Capability,
    CapabilityStatus,
    ImplementationRef,
    MappingProfile,
)
from app.capabilities.registry import CapabilityRegistry, can_transition
from app.capabilities.repository import (
    CAPABILITIES_VALIDATOR,
    CAPABILITY_INDEX_SPECS,
    CapabilityRepository,
)
from app.capabilities.seeds import build_builtin_capabilities
from app.capabilities.service import CapabilityService
from app.config import ProShieldConfig
from app.proxy import ProxyRequest, SecureProxy


def _config() -> ProShieldConfig:
    return ProShieldConfig(auth_signing_key="t" * 32, source_signing_key="s" * 32)


def _admin() -> Identity:
    return Identity(subject_id="admin", role="admin", permissions=())


def _analyst() -> Identity:
    return Identity(subject_id="analyst", role="analyst", permissions=())


def _service(db=None, *, source_service=None, rule_service=None) -> CapabilityService:
    from scripts.proxy_server import FakeDatabase

    database = db if db is not None else FakeDatabase()
    return CapabilityService(
        repository=CapabilityRepository(db=database, config=_config()),
        registry=CapabilityRegistry(),
        source_service=source_service,
        rule_service=rule_service,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _payload(cid="cap-demo", **over):
    base = {
        "capability_id": cid,
        "name": "Demo",
        "description": "d",
        "responsibility": "r",
        "implementation_ref": ImplementationRef.SIMULATOR,
        "version": 1,
        "status": CapabilityStatus.ACTIVE,
        "configuration_schema": {"type": "object"},
        "mapping_profiles": (),
        "created_by": "admin",
        "created_at": _now(),
        "updated_by": "admin",
        "updated_at": _now(),
    }
    base.update(over)
    return base


# ------------------------------------------------------------------ models
def test_model_rejects_bad_id_and_impl_and_code_upload_markers():
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(cid="BAD ID!"))
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(implementation_ref="http://evil/code.py"))
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(configuration_schema={"x": "eval(malicious())"}))
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(
            _payload(mapping_profiles=(MappingProfile(profile_id="p", source_type="nginx", field_map={"a": "eval(x)"}),))
        )


def test_model_rejects_planned_active_mismatch():
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(implementation_ref=ImplementationRef.PLANNED, status=CapabilityStatus.ACTIVE))
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(status=CapabilityStatus.PLANNED))


def test_model_rejects_duplicate_profiles_and_version_bounds():
    p = MappingProfile(profile_id="p", source_type="nginx", field_map={"a": "b"})
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(mapping_profiles=(p, p)))
    with pytest.raises((PydanticValidationError, ValueError)):
        Capability.model_validate(_payload(version=0))


def test_lifecycle_transitions():
    assert can_transition(CapabilityStatus.ACTIVE, CapabilityStatus.DISABLED)
    assert can_transition(CapabilityStatus.DISABLED, CapabilityStatus.ACTIVE)
    assert can_transition(CapabilityStatus.RETIRED, CapabilityStatus.ARCHIVED)
    assert not can_transition(CapabilityStatus.PLANNED, CapabilityStatus.ACTIVE)
    assert not can_transition(CapabilityStatus.ARCHIVED, CapabilityStatus.ACTIVE)
    # 5.1-01 regression: PLANNED->DISABLED was removed from the transition
    # table — persisting impl=planned+status=disabled is model-invalid and
    # used to quarantine the document after restart.
    assert not can_transition(CapabilityStatus.PLANNED, CapabilityStatus.DISABLED)
    assert can_transition(CapabilityStatus.PLANNED, CapabilityStatus.RETIRED)
    assert can_transition(CapabilityStatus.PLANNED, CapabilityStatus.ARCHIVED)


def test_seeds_are_truthful_two_live_four_planned():
    seeds = build_builtin_capabilities()
    assert len(seeds) == 6
    live = [s for s in seeds if s["implementation_ref"] in ("nginx", "simulator")]
    planned = [s for s in seeds if s["implementation_ref"] == "planned"]
    assert len(live) == 2
    assert len(planned) == 4
    assert {s["capability_id"] for s in seeds} == {
        "cap-nginx", "cap-simulator", "cap-waf", "cap-iam", "cap-rate-limit", "cap-network",
    }
    assert all(s["status"] == "planned" for s in planned)
    assert all(s["version"] == 1 for s in seeds)


# ------------------------------------------------------------------ service
def test_seed_builtins_idempotent_and_human_ids_monotonic():
    svc = _service()
    first = svc.seed_builtins()
    assert first == {"created": 6, "existing": 0}
    second = svc.seed_builtins()
    assert second == {"created": 0, "existing": 6}
    ids = [c["capability_id"] for c in svc.list(limit=50)]
    assert len(ids) == 6
    humans = [c["human_id"] for c in svc.list(limit=50)]
    assert all(h and h.startswith("CAP-") for h in humans)
    assert len(set(humans)) == 6


def test_create_duplicate_conflict_and_version_monotonic():
    svc = _service()
    svc.seed_builtins()
    created = svc.create(identity=_admin(), capability_id="cap-demo", name="Demo", implementation_ref="planned", status="planned")
    assert created["capability_id"] == "cap-demo"
    with pytest.raises(CapabilityAlreadyExistsError):
        svc.create(identity=_admin(), capability_id="cap-demo", name="Dup", implementation_ref="planned", status="planned")
    with pytest.raises(CapabilityConfigurationError):
        svc.update(identity=_admin(), capability_id="cap-demo", version=1)
    updated = svc.update(identity=_admin(), capability_id="cap-demo", description="new", version=2)
    assert updated["description"] == "new"
    assert updated["version"] == 2


def test_lifecycle_enable_disable_retire_archive_and_planned_guard():
    svc = _service()
    svc.seed_builtins()
    with pytest.raises(CapabilityStateError):
        svc.enable(identity=_admin(), capability_id="cap-waf")
    assert svc.disable(identity=_admin(), capability_id="cap-nginx")["status"] == "disabled"
    assert svc.enable(identity=_admin(), capability_id="cap-nginx")["status"] == "active"
    # 5.1-01 regression: planned drafts can NEVER be disabled — that
    # transition persisted impl=planned+status=disabled, a model-invalid
    # state that quarantined the document after restart. It must be
    # refused (409) before any write and the draft must stay planned.
    with pytest.raises(CapabilityStateError):
        svc.disable(identity=_admin(), capability_id="cap-waf")
    assert svc.get("cap-waf")["status"] == "planned"
    # enable() on a still-planned draft is also refused (planned cannot
    # activate, and planned->disabled no longer exists to be undone).
    with pytest.raises(CapabilityStateError):
        svc.enable(identity=_admin(), capability_id="cap-waf")
    # the legal planned lifecycle remains: retire -> archive
    assert svc.retire(identity=_admin(), capability_id="cap-waf")["status"] == "retired"
    with pytest.raises(CapabilityStateError):
        svc.archive(identity=_admin(), capability_id="cap-nginx")
    assert svc.retire(identity=_admin(), capability_id="cap-nginx")["status"] == "retired"
    with pytest.raises(CapabilityStateError):
        svc.update(identity=_admin(), capability_id="cap-nginx", description="late")
    assert svc.archive(identity=_admin(), capability_id="cap-nginx")["status"] == "archived"


def test_analyst_cannot_write_but_can_read():
    svc = _service()
    svc.seed_builtins()
    with pytest.raises(CapabilityAuthorizationError):
        svc.create(identity=_analyst(), capability_id="cap-nope", name="Nope", implementation_ref="planned", status="planned")
    assert len(svc.list(limit=50)) == 6
    assert svc.get("cap-nginx")["capability_id"] == "cap-nginx"
    with pytest.raises(CapabilityNotFoundError):
        svc.get("cap-missing")


def test_derived_views_nginx_rules_patterns_sources():
    from app.rules import RuleRegistry, load_rules_from_specs
    from app.rules.management.service import RuleManagementService
    from app.persistence.rule_repository import RuleRepository
    from scripts.proxy_server import FakeDatabase, _seed_managed_rules

    db = FakeDatabase()
    reg = RuleRegistry()
    load_rules_from_specs(reg, ["app.rules._library.nginx"])
    repo = RuleRepository(db=db, config=_config())
    _seed_managed_rules(repo, reg)
    rule_svc = RuleManagementService(repository=repo, registry=reg, config=_config())
    svc = _service(db, rule_service=rule_svc)
    svc.seed_builtins()
    rules = svc.list_rules("cap-nginx")
    assert rules["count"] == 5
    assert {r["rule_id"] for r in rules["rules"]} == {
        "NGINX-ACCESS-DENIED-001", "NGINX-AUTH-BRUTEFORCE-001", "NGINX-AUTH-FAILURE-001",
        "NGINX-RATE-LIMIT-001", "NGINX-STATUS-ANOMALY-001",
    }
    patterns = svc.list_patterns("cap-nginx")
    assert patterns["count"] >= 1
    assert "NGINX-CORR-BRUTEFORCE-001" in [p["pattern_id"] for p in patterns["patterns"]]
    planned_patterns = svc.list_patterns("cap-waf")
    assert planned_patterns == {"capability_id": "cap-waf", "patterns": [], "count": 0}
    sources = svc.list_sources("cap-nginx")
    assert sources["capability_id"] == "cap-nginx"
    assert sources["count"] == 0
    enriched = svc.get("cap-nginx")
    assert set(enriched["rule_ids"]) == {r["rule_id"] for r in rules["rules"]}
    assert "NGINX-CORR-BRUTEFORCE-001" in enriched["pattern_ids"]


def test_repository_validator_and_indexes_documented():
    props = CAPABILITIES_VALIDATOR["$jsonSchema"]["properties"]
    assert CAPABILITIES_VALIDATOR["$jsonSchema"]["additionalProperties"] is False
    assert props["capability_id"]["pattern"] == r"^cap-[a-z][a-z0-9-]{1,47}$"
    assert set(props["implementation_ref"]["enum"]) == {"nginx", "planned", "simulator"}
    names = [s["name"] for s in CAPABILITY_INDEX_SPECS]
    assert "cap_capability_id_unique" in names
    assert "cap_human_id_unique" in names
    assert "cap_status" in names
    assert "cap_implementation_ref" in names
    assert CAPABILITIES_COLLECTION == "capabilities"


def test_adversarial_payloads_rejected():
    svc = _service()
    svc.seed_builtins()
    with pytest.raises(CapabilityConfigurationError):
        svc.create(identity=_admin(), capability_id="cap-x", name="x" * 500, implementation_ref="planned", status="planned")
    with pytest.raises(CapabilityConfigurationError):
        svc.create(identity=_admin(), capability_id="cap-big", name="Big", implementation_ref="simulator",
                   configuration_schema={"blob": "z" * 9000})
    with pytest.raises(CapabilityConfigurationError):
        svc.create(identity=_admin(), capability_id="cap-mm", name="MM", implementation_ref="simulator",
                   mapping_profiles=[{"profile_id": "p", "source_type": "nginx", "field_map": {f"k{i}": "v" for i in range(70)}}])
    with pytest.raises(CapabilityConfigurationError):
        svc.create(identity=_admin(), capability_id="cap-sub", name="Sub", implementation_ref="connector; rm -rf /")


# ------------------------------------------------------------------ proxy
def _wired_proxy():
    from scripts.proxy_server import FakeDatabase, _seed_managed_rules
    from app.rules import RuleRegistry, load_rules_from_specs
    from app.rules.management.service import RuleManagementService
    from app.persistence.rule_repository import RuleRepository

    admin = Identity(subject_id="admin", role="admin", permissions=())
    analyst = Identity(subject_id="analyst", role="analyst", permissions=())
    store = InMemoryIdentityStore(
        identities={"admin": admin, "analyst": analyst},
        credentials={"admin": "pw", "analyst": "pw"},
    )
    cfg = _config()
    proxy = SecureProxy(config=cfg, identity_store=store,
                        session_verifier=SessionVerifier(signing_key=cfg.auth_signing_key, identity_store=store))
    db = FakeDatabase()
    reg = RuleRegistry()
    load_rules_from_specs(reg, ["app.rules._library.nginx"])
    repo = RuleRepository(db=db, config=cfg)
    _seed_managed_rules(repo, reg)
    rule_svc = RuleManagementService(repository=repo, registry=reg, config=cfg)
    svc = CapabilityService(repository=CapabilityRepository(db=db, config=cfg),
                            registry=CapabilityRegistry(), rule_service=rule_svc)
    svc.seed_builtins()
    proxy.attach_capability_service(svc)
    toksvc = SessionTokenService(signing_key=cfg.auth_signing_key)
    return proxy, toksvc.issue(subject_id="admin").token, toksvc.issue(subject_id="analyst").token


def _call(proxy, op, body, tok):
    return proxy.handle(ProxyRequest(operation=op, headers={"X-ProShield-Session": tok}, body=body or {}))


def test_proxy_authz_matrix_and_status_codes():
    proxy, atok, ntok = _wired_proxy()
    assert _call(proxy, "capability.list", {}, atok).status == 200
    assert _call(proxy, "capability.list", {}, ntok).status == 200
    assert _call(proxy, "capability.list", {}, "").status == 401
    assert _call(proxy, "capability.get", {"capability_id": "cap-missing"}, atok).status == 404
    assert _call(proxy, "capability.create", {"capability_id": "cap-x1", "name": "X1",
               "implementation_ref": "planned", "status": "planned"}, ntok).status == 403
    assert _call(proxy, "capability.create", {"capability_id": "cap-x1", "name": "X1",
               "implementation_ref": "planned", "status": "planned"}, atok).status == 200
    assert _call(proxy, "capability.create", {"capability_id": "cap-x1", "name": "Dup",
               "implementation_ref": "planned", "status": "planned"}, atok).status == 409
    assert _call(proxy, "capability.create", {"capability_id": "cap-evil", "name": "E",
               "implementation_ref": "evil.py"}, atok).status == 400
    assert _call(proxy, "capability.get", {}, atok).status == 400
    # full lifecycle over the wire: disable -> enable -> retire -> archive
    assert _call(proxy, "capability.disable", {"capability_id": "cap-simulator"}, atok).status == 200
    assert _call(proxy, "capability.enable", {"capability_id": "cap-simulator"}, atok).status == 200
    assert _call(proxy, "capability.retire", {"capability_id": "cap-simulator"}, atok).status == 200
    assert _call(proxy, "capability.archive", {"capability_id": "cap-simulator"}, atok).status == 200
    # relationship views over the wire
    rules = _call(proxy, "capability.list_rules", {"capability_id": "cap-nginx"}, atok)
    assert rules.status == 200
    assert rules.body["data"]["count"] == 5
    patterns = _call(proxy, "capability.list_patterns", {"capability_id": "cap-nginx"}, atok)
    assert patterns.status == 200
    assert patterns.body["data"]["count"] >= 1
    sources = _call(proxy, "capability.list_sources", {"capability_id": "cap-nginx"}, atok)
    assert sources.status == 200
    #pagination bounded
    bounded = _call(proxy, "capability.list", {"limit": 500}, atok)
    assert bounded.status == 200
    assert bounded.body["data"]["count"] <= 200


def test_v2_pipeline_non_regression_nginx_detection_still_fires():
    from app.rules import RuleRegistry, load_rules_from_specs
    from app.detection.engine import DetectionEngine
    from app.domain.security_event import SecurityEvent, SecurityEventProvenance
    from datetime import timedelta

    reg = RuleRegistry()
    load_rules_from_specs(reg, ["app.rules._library.nginx"])
    engine = DetectionEngine(registry=reg)
    now = _now()
    event = SecurityEvent(
        event_id="0196bf40-1111-7111-8111-111111111111",
        event_time=now,
        ingested_at=now + timedelta(milliseconds=1),
        source="nginx",
        event_type="authentication_failure",
        source_ip="9.9.9.9",
        endpoint="/auth/login",
        details={"status_code": 401},
        provenance=SecurityEventProvenance(collector="nginx", source_event_id="v2-check-1"),
    )
    result = engine.run(event, now=now)
    assert len(result.detections) >= 1
    assert any("NGINX-AUTH" in d.rule_id for d in result.detections)


# --------------------------------------------------- 5.1-01 regressions
def test_planned_disable_refused_before_any_write():
    """5.1-01: planned->disable must be refused and never persisted."""
    svc = _service()
    svc.seed_builtins()
    with pytest.raises(CapabilityStateError):
        svc.disable(identity=_admin(), capability_id="cap-waf")
    # nothing was written: the persisted document is untouched
    doc = svc._repository.get("cap-waf")
    assert doc is not None
    assert doc.status is CapabilityStatus.PLANNED
    assert doc.implementation_ref is ImplementationRef.PLANNED


def test_planned_disable_over_wire_is_409_and_document_survives():
    proxy, atok, _ = _wired_proxy()
    resp = _call(proxy, "capability.disable", {"capability_id": "cap-waf"}, atok)
    assert resp.status == 409
    got = _call(proxy, "capability.get", {"capability_id": "cap-waf"}, atok)
    assert got.status == 200
    assert got.body["data"]["capability"]["status"] == "planned"


def test_lifecycle_revalidation_guard_blocks_invalid_target():
    """The _lifecycle re-validation is the second line of defence: a
    transition that passes the table but violates the model invariant
    (disabled live -> planned status) must be refused before any write."""
    svc = _service()
    svc.seed_builtins()
    assert svc.disable(identity=_admin(), capability_id="cap-nginx")["status"] == "disabled"
    with pytest.raises(CapabilityStateError):
        svc._lifecycle(identity=_admin(), capability_id="cap-nginx", target=CapabilityStatus.PLANNED)
    assert svc._repository.get("cap-nginx").status is CapabilityStatus.DISABLED


def test_pre_persist_guard_rejects_model_invalid_instance():
    """repository.save is the last line of defence (finding 5.1-01 (c))."""
    svc = _service()
    svc.seed_builtins()
    repo = svc._repository
    planned = repo.get("cap-iam")
    assert planned.status is CapabilityStatus.PLANNED
    invalid = planned.model_copy(update={"status": CapabilityStatus.DISABLED})
    with pytest.raises(CapabilityConfigurationError):
        repo.save(invalid)
    assert repo.get("cap-iam").status is CapabilityStatus.PLANNED


# --------------------------------------------------- 5.1-02 audit tests
def test_persisted_audit_trail_actor_action_diff():
    """§18.27: actor/action/capability_id/diff persisted on every write."""
    svc = _service()
    svc.seed_builtins()
    svc.create(identity=_admin(), capability_id="cap-audit", name="A",
               implementation_ref="planned", status="planned")
    svc.update(identity=_admin(), capability_id="cap-audit", description="d2", version=2)
    svc.retire(identity=_admin(), capability_id="cap-audit")
    trail = svc.list_audit("cap-audit", limit=50)
    actions = {r["action"] for r in trail["records"]}
    assert {"create", "update", "retire"} <= actions
    update_rec = next(r for r in trail["records"] if r["action"] == "update")
    assert update_rec["actor"] == "admin"
    assert update_rec["capability_id"] == "cap-audit"
    assert "description" in update_rec["changed_fields"]
    assert update_rec["after"]["version"] == 2
    assert update_rec["before"]["version"] == 1
    # seeds are audited writes too
    nginx_trail = svc.list_audit("cap-nginx", limit=50)
    assert any(r["action"] == "seed" for r in nginx_trail["records"])


def test_capability_audit_proxy_op_authz_and_shape():
    proxy, atok, ntok = _wired_proxy()
    assert _call(proxy, "capability.create", {"capability_id": "cap-a2", "name": "A2",
                 "implementation_ref": "planned", "status": "planned"}, atok).status == 200
    r = _call(proxy, "capability.audit", {"capability_id": "cap-a2"}, atok)
    assert r.status == 200
    records = r.body["data"]["records"]
    assert any(x["action"] == "create" for x in records)
    # missing id -> 400, anon -> 401, analyst read allowed (capability:read)
    assert _call(proxy, "capability.audit", {}, atok).status == 400
    assert _call(proxy, "capability.audit", {"capability_id": "cap-a2"}, "").status == 401
    assert _call(proxy, "capability.audit", {"capability_id": "cap-a2"}, ntok).status == 200
    # unknown capability -> truthful 404 (never a fake-success empty trail)
    assert _call(proxy, "capability.audit", {"capability_id": "cap-missing"}, atok).status == 404
