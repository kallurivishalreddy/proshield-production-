"""Phase 5.2 — Source Architecture 2.0 unit tests.

Covers the Phase 5.2 contract at the owning layers:

* SourceInstance -> Capability binding (model invariants + service gates);
* deterministic, non-fabricating legacy migration (dry-run / idempotency /
  audit);
* per-source token trust isolation and capability cross-checks;
* ingress capability derivation (server-side, never payload-derived);
* rule -> capability dual-read resolution;
* the append-only source audit trail.

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md §19,
docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md §7.1/§12/§29/§38.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest

from app.auth import ADMIN_ROLE, ANALYST_ROLE, Identity
from app.config import ProShieldConfig
from app.sources.audit import SOURCE_AUDIT_COLLECTION, read_audit_records
from app.sources.capability_binding import (
    CAPABILITY_ID_TO_SOURCE_TYPE,
    SOURCE_TYPE_TO_CAPABILITY_ID,
    builtin_capability_index,
    deterministic_mapping_profile,
    resolve_capability_id_for_sources,
    resolve_capability_id_for_type,
    validate_capability_binding,
)
from app.sources.errors import (
    DuplicateSourceCapabilityBindingError,
    SourceCapabilityBindingError,
    SourceCapabilityUnverifiedError,
    SourceInstanceStateError,
)
from app.sources.ingress import InboundIngressProxy, IngressRequest
from app.sources.models import (
    CapabilityBindingStatus,
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.migration import (
    OUTCOME_ALREADY_BOUND,
    OUTCOME_AMBIGUOUS,
    OUTCOME_BOUND,
    OUTCOME_QUARANTINED,
    SourceCapabilityMigration,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    new_development_signing_key,
)
from tests.unit._phase49_fakes import FakeDatabase, FakeSourceCollection

_NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
# Wire form of ``_NOW`` (Batch 1/2 T22: the canonical ``event_time`` the
# trusted ingress now requires on every wire event).
_NOW_ISO = _NOW.isoformat().replace("+00:00", "Z")
_SECRET = "phase52-unit-test-signing-secret"
_ADMIN = Identity(subject_id="user-admin-001", role=ADMIN_ROLE)
_ANALYST = Identity(subject_id="user-analyst-001", role=ANALYST_ROLE)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_phase52_unit",
        mongo_collection_events="security_events",
        source_signing_key=_SECRET,
    )


def _lookup(capability_id: str) -> Optional[Dict[str, Any]]:
    """Capability lookup over the shipped seed catalogue."""
    return builtin_capability_index().get(capability_id)


def _repo() -> SourceRepository:
    return SourceRepository(FakeDatabase(), _config())


def _service_with_persisted(
    *instances: SourceInstance,
    issuer: Optional[SourceIdentityTokenIssuer] = None,
    lookup: Any = _lookup,
    audit: Any = None,
) -> SourceManagementService:
    """Persist instances, then build a service whose registry sees them.

    Mirrors the real startup composition (``reload_from_repository``
    after the repository is populated), so the service's
    ``get_required`` path behaves exactly as it does in production.
    """
    repo = _repo()
    for inst in instances:
        repo.create(inst)
    svc = _service(
        repo=repo, issuer=issuer, lookup=lookup, audit=audit,
    )
    svc.reload_from_repository()
    return svc


def _service(
    *,
    repo: Optional[SourceRepository] = None,
    registry: Optional[SourceRegistry] = None,
    issuer: Optional[SourceIdentityTokenIssuer] = None,
    lookup: Any = _lookup,
    audit: Any = None,
) -> SourceManagementService:
    return SourceManagementService(
        repository=repo if repo is not None else _repo(),
        registry=registry if registry is not None else SourceRegistry(),
        token_issuer=issuer,
        capability_lookup=lookup,
        audit_collection=audit,
    )


def _cfg_payload(**overrides: Any) -> SourceInstanceConfiguration:
    base = dict(
        connection_type=SourceConnectionType.PUSH,
        endpoint="https://ingest.example.test/hook",
        proxy_path="",
        destination="web-api-01",
        asset_tags=(),
        tags=(),
        references=(),
        secret_ref="",
    )
    base.update(overrides)
    return SourceInstanceConfiguration(**base)


def _raw_source_doc(
    *,
    sid: str,
    source_type: str = "nginx",
    state: str = "enabled",
    human_id: str = "",
    capability_id: Any = None,
    binding_status: Any = None,
) -> Dict[str, Any]:
    """A legacy-shaped persisted source document (pre-Phase-5.2 fields)."""
    doc: Dict[str, Any] = {
        "source_instance_id": sid,
        "human_id": human_id,
        "source_type": source_type,
        "source": source_type,
        "display_name": f"legacy-{source_type}",
        "description": "",
        "configuration": {
            "connection_type": "push",
            "endpoint": "https://ingest.example.test/hook",
            "proxy_path": "",
            "destination": "web-api-01",
            "asset_tags": [],
            "tags": [],
            "references": [],
            "secret_ref_set": False,
        },
        "state": state,
        "created_by": "user-admin-001",
        "created_at": _NOW,
        "updated_by": "user-admin-001",
        "updated_at": _NOW,
        "last_validation_at": _NOW,
        "tags": [],
        "asset_tags": [],
        "retired_at": _NOW if state == "retired" else None,
    }
    if capability_id is not None:
        doc["capability_id"] = capability_id
    if binding_status is not None:
        doc["capability_binding_status"] = binding_status
    return doc


def _instance(
    *,
    sid: str,
    source_type: SourceType = SourceType.NGINX,
    state: SourceState = SourceState.ENABLED,
    capability_id: Optional[str] = None,
    capability_version: Optional[int] = None,
    mapping_profile_id: Optional[str] = None,
    binding_status: CapabilityBindingStatus = (
        CapabilityBindingStatus.UNBOUND
    ),
) -> SourceInstance:
    return SourceInstance(
        source_instance_id=sid,
        source_type=source_type,
        source=source_type.value,
        display_name="t",
        description="",
        configuration=_cfg_payload(),
        state=state,
        created_by="user-admin-001",
        created_at=_NOW,
        updated_by="user-admin-001",
        updated_at=_NOW,
        last_validation_at=_NOW,
        tags=(),
        asset_tags=(),
        retired_at=_NOW if state is SourceState.RETIRED else None,
        capability_id=capability_id,
        capability_version=capability_version,
        mapping_profile_id=mapping_profile_id,
        capability_binding_status=binding_status,
    )


_SID_A = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f01-a"
_SID_B = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f02-b"


# ===========================================================================
# 1. Model invariants — capability binding
# ===========================================================================
class TestSourceCapabilityBindingModel:
    def test_bound_requires_capability_id(self) -> None:
        with pytest.raises(ValueError, match="capability_id"):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_version=1,
            )

    def test_bound_requires_version(self) -> None:
        with pytest.raises(ValueError, match="capability_version"):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_id="cap-nginx",
            )

    def test_bound_rejects_zero_version(self) -> None:
        with pytest.raises(ValueError, match=">= 1"):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_id="cap-nginx",
                capability_version=0,
            )

    def test_unbound_must_not_carry_capability_id(self) -> None:
        with pytest.raises(ValueError, match="must not carry capability_id"):
            _instance(sid=_SID_A, capability_id="cap-nginx")

    def test_requires_verification_must_not_carry_capability_id(self) -> None:
        """Never invent ownership: a quarantined row has no owner."""
        with pytest.raises(ValueError, match="must not carry capability_id"):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.REQUIRES_VERIFICATION,
                capability_id="cap-nginx",
            )

    def test_requires_verification_must_not_carry_profile(self) -> None:
        with pytest.raises(ValueError, match="mapping_profile_id"):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.REQUIRES_VERIFICATION,
                mapping_profile_id="nginx-access-default",
            )

    def test_unbound_is_the_default(self) -> None:
        inst = _instance(sid=_SID_A)
        assert inst.capability_binding_status is (
            CapabilityBindingStatus.UNBOUND
        )
        assert inst.capability_id is None
        assert inst.capability_version is None

    def test_bound_round_trips_through_repository(self) -> None:
        """The real persistence path must return the binding intact."""
        inst = _instance(
            sid=_SID_A,
            binding_status=CapabilityBindingStatus.BOUND,
            capability_id="cap-nginx",
            capability_version=1,
            mapping_profile_id="nginx-access-default",
        )
        repo = _repo()
        repo.create(inst)
        reloaded = repo.get(_SID_A)
        assert reloaded is not None
        assert reloaded.capability_id == "cap-nginx"
        assert reloaded.capability_version == 1
        assert reloaded.mapping_profile_id == "nginx-access-default"
        assert reloaded.capability_binding_status is (
            CapabilityBindingStatus.BOUND
        )

    def test_legacy_row_without_binding_loads_as_unbound(self) -> None:
        """A pre-Phase-5.2 row must not be assumed bound."""
        from app.sources.repository import _document_to_instance

        doc = _raw_source_doc(sid=_SID_A)
        loaded = _document_to_instance(doc)
        assert loaded is not None
        assert loaded.capability_id is None
        assert loaded.capability_binding_status is (
            CapabilityBindingStatus.UNBOUND
        )

    def test_bad_capability_id_pattern_rejected(self) -> None:
        with pytest.raises(ValueError):
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_id="NOT-A-CAPABILITY",
                capability_version=1,
            )

    def test_view_omits_nothing_but_carries_binding_truthfully(self) -> None:
        inst = _instance(
            sid=_SID_A,
            binding_status=CapabilityBindingStatus.BOUND,
            capability_id="cap-nginx",
            capability_version=1,
        )
        view = inst.to_view()
        assert view.capability_id == "cap-nginx"
        assert view.capability_version == 1
        assert view.capability_binding_status == "bound"


# ===========================================================================
# 2. Deterministic mapping
# ===========================================================================
class TestDeterministicCapabilityMapping:
    @pytest.mark.parametrize(
        "source_type,expected",
        [
            (SourceType.NGINX, "cap-nginx"),
            (SourceType.SIMULATOR, "cap-simulator"),
            (SourceType.WAF, "cap-waf"),
            (SourceType.IAM, "cap-iam"),
            (SourceType.RATE_LIMIT, "cap-rate-limit"),
            (SourceType.NETWORK, "cap-network"),
        ],
    )
    def test_every_source_type_maps_to_its_planned_capability(
        self, source_type: SourceType, expected: str
    ) -> None:
        assert resolve_capability_id_for_type(source_type) == expected
        assert expected in builtin_capability_index()

    def test_unknown_type_resolves_to_none_not_a_guess(self) -> None:
        assert resolve_capability_id_for_type("mainframe") is None
        assert resolve_capability_id_for_type(None) is None
        assert resolve_capability_id_for_type(1234) is None

    def test_string_form_is_accepted(self) -> None:
        assert resolve_capability_id_for_type("nginx") == "cap-nginx"

    def test_the_map_covers_every_declared_source_type(self) -> None:
        """No declared SourceType may be left unmapped/undefined."""
        assert set(SOURCE_TYPE_TO_CAPABILITY_ID) == set(SourceType)

    def test_rule_sources_single_capability_resolves(self) -> None:
        assert resolve_capability_id_for_sources(("nginx",)) == "cap-nginx"

    def test_rule_sources_cross_source_is_ambiguous(self) -> None:
        assert resolve_capability_id_for_sources(("nginx", "waf")) is None

    def test_rule_sources_unknown_is_unresolvable(self) -> None:
        assert resolve_capability_id_for_sources(("mainframe",)) is None

    def test_rule_sources_empty_is_unresolvable(self) -> None:
        assert resolve_capability_id_for_sources(()) is None


# ===========================================================================
# 2b. 5.2-R-01 regression: the connector-family check runs on BOTH paths
# ===========================================================================
class TestBindingFamilyCheckOnBothPaths:
    """Independent-review finding 5.2-R-01.

    ``validate_capability_binding(..., allow_non_active=True)`` used to skip
    the connector-family check because that check lived *inside* the
    ``if not allow_non_active:`` branch — while its own comment claimed it
    was deliberately outside it. The legacy backfill is precisely the caller
    that passes ``allow_non_active=True``, so the hole was latent rather than
    dead code: the next caller of that mode could bind a source to a
    capability that does not implement its connector. These tests pin the
    check on both paths, and pin the migration's own family carve-out
    (``waf`` -> ``cap-waf``) so the fix cannot over-correct into a backfill
    regression.
    """

    def _bind(self, capability_id: str, source_type: str, *, allow_non_active: bool):
        return validate_capability_binding(
            builtin_capability_index()[capability_id],
            source_type=source_type,
            allow_non_active=allow_non_active,
        )

    def test_planned_capability_refuses_a_foreign_family_when_backfilling(
        self,
    ) -> None:
        """cap-waf owns the waf family; it must not adopt an nginx source."""
        with pytest.raises(SourceCapabilityBindingError) as exc:
            self._bind("cap-waf", "nginx", allow_non_active=True)
        assert "does not implement this source type" in str(
            exc.value.safe_message
        )

    def test_live_capability_refuses_a_foreign_family_when_backfilling(
        self,
    ) -> None:
        """The same hole admitted a LIVE capability (cap-simulator) as well."""
        with pytest.raises(SourceCapabilityBindingError):
            self._bind("cap-simulator", "nginx", allow_non_active=True)

    def test_planned_capability_still_accepts_its_own_family(self) -> None:
        """The migration's waf -> cap-waf backfill must keep working."""
        binding = self._bind("cap-waf", "waf", allow_non_active=True)
        assert binding.capability_id == "cap-waf"
        # A planned capability declares no mapping profiles: honest None.
        assert binding.mapping_profile_id is None

    def test_new_source_path_still_refuses_a_foreign_family(self) -> None:
        with pytest.raises(SourceCapabilityBindingError):
            self._bind("cap-nginx", "simulator", allow_non_active=False)

    def test_new_source_path_still_accepts_its_own_family(self) -> None:
        binding = self._bind("cap-nginx", "nginx", allow_non_active=False)
        assert binding.capability_id == "cap-nginx"

    def test_no_seeded_capability_can_be_bound_outside_its_family(self) -> None:
        """Exhaustive: every seeded capability x every source type."""
        index = builtin_capability_index()
        for capability_id, own_family in CAPABILITY_ID_TO_SOURCE_TYPE.items():
            for source_type in SourceType:
                target = source_type.value
                if target == own_family:
                    binding = self._bind(
                        capability_id, target, allow_non_active=True
                    )
                    assert binding.capability_id == capability_id
                else:
                    with pytest.raises(SourceCapabilityBindingError):
                        self._bind(
                            capability_id, target, allow_non_active=True
                        )
        assert CAPABILITY_ID_TO_SOURCE_TYPE == {
            v: k.value for k, v in SOURCE_TYPE_TO_CAPABILITY_ID.items()
        }

    def test_deterministic_profile_helper_matches_the_binding_path(self) -> None:
        """5.2-R-05: one helper, so the two paths cannot drift."""
        index = builtin_capability_index()
        for capability_id, family in CAPABILITY_ID_TO_SOURCE_TYPE.items():
            via_helper = deterministic_mapping_profile(
                index[capability_id], source_type=family
            )
            via_binding = self._bind(
                capability_id, family, allow_non_active=True
            ).mapping_profile_id
            assert via_helper == via_binding


# ===========================================================================
# 3. register() always produces a valid, validated binding
# ===========================================================================
class TestRegisterBinding:
    def test_nginx_source_is_bound_to_cap_nginx(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-a",
        )
        assert view.capability_id == "cap-nginx"
        assert view.capability_version == 1
        assert view.capability_binding_status == "bound"
        assert view.mapping_profile_id == "nginx-access-default"

    def test_simulator_source_is_bound_to_cap_simulator(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.SIMULATOR,
            display_name="sim-a",
        )
        assert view.capability_id == "cap-simulator"
        assert view.capability_binding_status == "bound"

    def test_unknown_capability_is_refused(self) -> None:
        svc = _service(lookup=lambda cid: None)
        with pytest.raises(SourceCapabilityBindingError):
            svc.register(
                identity=_ADMIN, source_type=SourceType.NGINX,
                display_name="nginx-unknown",
                capability_id="cap-does-not-exist",
            )

    def test_planned_capability_cannot_own_a_source(self) -> None:
        """A planned capability has no connector: binding would be phantom."""
        svc = _service()
        with pytest.raises(SourceCapabilityBindingError):
            svc.register(
                identity=_ADMIN, source_type=SourceType.NGINX,
                display_name="nginx-planned",
                capability_id="cap-waf",
            )

    def test_undeclared_mapping_profile_is_refused(self) -> None:
        svc = _service()
        with pytest.raises(SourceCapabilityBindingError):
            svc.register(
                identity=_ADMIN, source_type=SourceType.NGINX,
                display_name="nginx-bad-profile",
                capability_id="cap-nginx",
                mapping_profile_id="not-a-real-profile",
            )

    def test_declared_mapping_profile_is_accepted(self) -> None:
        svc = _service()
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-profile",
            capability_id="cap-nginx",
            mapping_profile_id="nginx-access-default",
        )
        assert view.mapping_profile_id == "nginx-access-default"

    def test_analyst_cannot_register(self) -> None:
        from app.sources.errors import SourceAuthorizationError

        svc = _service()
        with pytest.raises(SourceAuthorizationError):
            svc.register(
                identity=_ANALYST, source_type=SourceType.NGINX,
                display_name="nginx-analyst",
            )

    def test_registered_source_survives_reload_with_binding(self) -> None:
        repo = _repo()
        svc = _service(repo=repo)
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-reload",
        )
        fresh = _service(repo=repo)
        n = fresh.reload_from_repository()
        assert n == 1
        got = fresh.get(view.source_instance_id)
        assert got.capability_id == "cap-nginx"
        assert got.capability_binding_status == "bound"


# ===========================================================================
# 4. bind_capability — the authoritative admin remediation path
# ===========================================================================
class TestBindCapability:
    def test_rebinding_a_quarantined_source_succeeds_and_audits(self) -> None:
        audit = FakeDatabase()[SOURCE_AUDIT_COLLECTION]
        svc = _service_with_persisted(
            _instance(
                sid=_SID_A,
                state=SourceState.DISABLED,
                binding_status=(
                    CapabilityBindingStatus.REQUIRES_VERIFICATION
                ),
            )
        )
        svc.set_audit_collection(audit)

        view = svc.bind_capability(
            identity=_ADMIN,
            source_instance_id=_SID_A,
            capability_id="cap-nginx",
        )
        assert view.capability_id == "cap-nginx"
        assert view.capability_binding_status == "bound"
        assert any(
            r.get("action") == "source_bind_capability"
            for r in audit.docs
        )

    def test_unknown_capability_is_refused(self) -> None:
        svc = _service_with_persisted(
            _instance(sid=_SID_A), lookup=lambda cid: None,
        )
        with pytest.raises(SourceCapabilityBindingError):
            svc.bind_capability(
                identity=_ADMIN,
                source_instance_id=_SID_A,
                capability_id="cap-nope",
            )

    def test_duplicate_binding_is_a_conflict(self) -> None:
        """An exact repeat of the held binding is a conflict, not a change."""
        svc = _service_with_persisted(
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_id="cap-nginx",
                capability_version=1,
                mapping_profile_id="nginx-access-default",
            )
        )
        with pytest.raises(DuplicateSourceCapabilityBindingError):
            svc.bind_capability(
                identity=_ADMIN,
                source_instance_id=_SID_A,
                capability_id="cap-nginx",
                mapping_profile_id="nginx-access-default",
            )

    def test_rebinding_that_adds_a_profile_is_a_real_change(self) -> None:
        """Filling in a previously-absent mapping profile must persist."""
        svc = _service_with_persisted(
            _instance(
                sid=_SID_A,
                binding_status=CapabilityBindingStatus.BOUND,
                capability_id="cap-nginx",
                capability_version=1,
            )
        )
        view = svc.bind_capability(
            identity=_ADMIN,
            source_instance_id=_SID_A,
            capability_id="cap-nginx",
        )
        assert view.mapping_profile_id == "nginx-access-default"

    def test_retired_source_is_immutable(self) -> None:
        svc = _service_with_persisted(
            _instance(sid=_SID_A, state=SourceState.RETIRED)
        )
        with pytest.raises(SourceInstanceStateError):
            svc.bind_capability(
                identity=_ADMIN,
                source_instance_id=_SID_A,
                capability_id="cap-nginx",
            )

    def test_analyst_cannot_bind(self) -> None:
        from app.sources.errors import SourceAuthorizationError

        svc = _service_with_persisted(_instance(sid=_SID_A))
        with pytest.raises(SourceAuthorizationError):
            svc.bind_capability(
                identity=_ANALYST,
                source_instance_id=_SID_A,
                capability_id="cap-nginx",
            )
# ===========================================================================
# 5. Lifecycle gate — no verified capability, no promotion
# ===========================================================================
class TestLifecycleBindingGate:
    def _quarantined(self) -> SourceManagementService:
        return _service_with_persisted(
            _instance(
                sid=_SID_A,
                state=SourceState.CONFIGURED,
                binding_status=(
                    CapabilityBindingStatus.REQUIRES_VERIFICATION
                ),
            )
        )

    def test_quarantined_source_cannot_be_validated(self) -> None:
        svc = self._quarantined()
        with pytest.raises(SourceCapabilityUnverifiedError):
            svc.validate_connection(
                identity=_ADMIN, source_instance_id=_SID_A,
            )

    def test_quarantined_source_cannot_be_enabled(self) -> None:
        svc = self._quarantined()
        with pytest.raises(SourceCapabilityUnverifiedError):
            svc.enable(identity=_ADMIN, source_instance_id=_SID_A)

    def test_quarantined_source_cannot_issue_a_token(self) -> None:
        svc = self._quarantined()
        svc._token_issuer = (  # noqa: SLF001 - test harness
            SourceIdentityTokenIssuer(secret=_SECRET)
        )
        with pytest.raises(SourceCapabilityUnverifiedError):
            svc.issue_ingress_token(
                identity=_ADMIN, source_instance_id=_SID_A,
            )

    def test_unbound_source_cannot_be_enabled(self) -> None:
        svc = _service_with_persisted(
            _instance(sid=_SID_A, state=SourceState.VALIDATED)
        )
        with pytest.raises(SourceCapabilityUnverifiedError):
            svc.enable(identity=_ADMIN, source_instance_id=_SID_A)

    def test_bound_source_completes_the_full_lifecycle(self) -> None:
        """The happy path: register -> configure -> validate -> enable."""
        svc = _service(
            issuer=SourceIdentityTokenIssuer(secret=_SECRET),
        )
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-happy",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN, source_instance_id=sid,
            configuration=_cfg_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        enabled = svc.enable(identity=_ADMIN, source_instance_id=sid)
        assert enabled.state == "enabled"
        token = svc.issue_ingress_token(
            identity=_ADMIN, source_instance_id=sid,
        )
        assert isinstance(token, str) and token.count(".") == 2

    def test_retired_source_credential_issuance_is_revoked(self) -> None:
        svc = _service(
            issuer=SourceIdentityTokenIssuer(secret=_SECRET),
        )
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-retire",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN, source_instance_id=sid,
            configuration=_cfg_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        svc.retire(identity=_ADMIN, source_instance_id=sid)
        with pytest.raises(SourceInstanceStateError):
            svc.issue_ingress_token(
                identity=_ADMIN, source_instance_id=sid,
            )
        with pytest.raises(SourceInstanceStateError):
            svc.rotate_ingress_token(
                identity=_ADMIN, source_instance_id=sid,
            )

    def test_rotation_issues_a_distinct_fresh_token(self) -> None:
        svc = _service(
            issuer=SourceIdentityTokenIssuer(secret=_SECRET),
        )
        view = svc.register(
            identity=_ADMIN, source_type=SourceType.NGINX,
            display_name="nginx-rotate",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN, source_instance_id=sid,
            configuration=_cfg_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN, source_instance_id=sid,
        )
        first = svc.issue_ingress_token(
            identity=_ADMIN, source_instance_id=sid,
        )
        rotated = svc.rotate_ingress_token(
            identity=_ADMIN, source_instance_id=sid,
        )
        assert first != rotated

# ===========================================================================
# 5b. Lifecycle audit trail — every successful transition is recorded
# ===========================================================================
class TestLifecycleAuditTrail:
    """Regression: enable/disable/retire must append one audit record each."""

    def _configured(self):
        audit = _AuditFakeCollection()
        svc = _service(
            issuer=SourceIdentityTokenIssuer(secret=_SECRET),
            audit=audit,
        )
        view = svc.register(
            identity=_ADMIN,
            source_type=SourceType.NGINX,
            display_name="lifecycle-audit",
        )
        sid = view.source_instance_id
        svc.configure(
            identity=_ADMIN,
            source_instance_id=sid,
            configuration=_cfg_payload(),
        )
        svc.validate_connection(
            identity=_ADMIN,
            source_instance_id=sid,
        )
        return svc, audit, sid

    @staticmethod
    def _rows(audit, sid, action):
        return [
            row for row in audit.docs
            if row.get("source_instance_id") == sid
            and row.get("action") == action
        ]

    def _assert_lifecycle_row(self, row, before, after):
        assert row["actor"] == "user-admin-001"
        assert row["capability_id"] == "cap-nginx"
        assert row["before"]["state"] == before
        assert row["after"]["state"] == after
        assert row["changed_fields"] == ["state"]
        assert row["reason"] == (
            f"lifecycle transition {before.value} -> {after.value}"
        )
        serialized = json.dumps(row, default=str).lower()
        assert "token" not in serialized
        assert "secret" not in serialized

    def _assert_readable(self, audit, sid, action, after):
        records = read_audit_records(audit, sid, limit=50)
        matching = [r for r in records if r.get("action") == action]
        assert len(matching) == 1
        assert matching[0]["source_instance_id"] == sid
        assert matching[0]["after"]["state"] == after

    def test_enable_writes_exactly_one_lifecycle_audit_record(self) -> None:
        svc, audit, sid = self._configured()
        svc.enable(identity=_ADMIN, source_instance_id=sid)
        rows = self._rows(audit, sid, "source_enable")
        assert len(rows) == 1
        self._assert_lifecycle_row(
            rows[0], SourceState.VALIDATED, SourceState.ENABLED,
        )
        self._assert_readable(
            audit, sid, "source_enable", SourceState.ENABLED,
        )

    def test_disable_writes_exactly_one_lifecycle_audit_record(self) -> None:
        svc, audit, sid = self._configured()
        svc.enable(identity=_ADMIN, source_instance_id=sid)
        svc.disable(identity=_ADMIN, source_instance_id=sid)
        rows = self._rows(audit, sid, "source_disable")
        assert len(rows) == 1
        self._assert_lifecycle_row(
            rows[0], SourceState.ENABLED, SourceState.DISABLED,
        )
        self._assert_readable(
            audit, sid, "source_disable", SourceState.DISABLED,
        )

    def test_retire_writes_exactly_one_lifecycle_audit_record(self) -> None:
        svc, audit, sid = self._configured()
        svc.enable(identity=_ADMIN, source_instance_id=sid)
        svc.retire(identity=_ADMIN, source_instance_id=sid)
        rows = self._rows(audit, sid, "source_retire")
        assert len(rows) == 1
        self._assert_lifecycle_row(
            rows[0], SourceState.ENABLED, SourceState.RETIRED,
        )
        self._assert_readable(
            audit, sid, "source_retire", SourceState.RETIRED,
        )

# ===========================================================================
# 6. Token / trust model — per-source isolation
# ===========================================================================
class _ReplayStore:
    """Minimal single-use store mirroring the production contract."""

    def __init__(self) -> None:
        self.seen = set()

    def claim(self, *, token_id: str, expires_at) -> bool:
        if token_id in self.seen:
            return False
        self.seen.add(token_id)
        return True

    def release(self, token_id: str) -> None:
        self.seen.discard(token_id)


def _verifier(resolver, *, replay_store=None):
    from app.sources.trust import (
        SourceIdentityTokenKeyring,
        SourceIdentityTokenVerifier,
    )

    return SourceIdentityTokenVerifier(
        keyring=SourceIdentityTokenKeyring(
            keys={"k1": _SECRET}, active_key_id="k1",
        ),
        source_resolver=resolver,
        replay_store=replay_store,
        replay_store_required=replay_store is not None,
    )


def _issue(sid: str, source_type: SourceType, cap: Optional[str] = None):
    issuer = SourceIdentityTokenIssuer(secret=_SECRET)
    return issuer.pack(
        issuer.issue(
            source_instance_id=sid,
            source_type=source_type,
            capability_id=cap,
        )
    )


class TestTokenTrustIsolation:
    def _bound(self, sid: str, source_type: SourceType, cap: str):
        return _instance(
            sid=sid,
            source_type=source_type,
            binding_status=CapabilityBindingStatus.BOUND,
            capability_id=cap,
            capability_version=1,
        )

    def test_token_for_its_own_source_verifies(self) -> None:
        inst_a = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier = _verifier(lambda sid: inst_a if sid == _SID_A else None)
        token = verifier.verify(
            _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        assert token.source_instance_id == _SID_A
        assert token.capability_id == "cap-nginx"

    def test_token_for_source_a_does_not_authenticate_source_b(self) -> None:
        """A's token resolves to A — B's record is never consulted.

        The token's authority is the ``source_instance_id`` it carries and
        the resolver is asked for *that* id, so a credential minted for A
        can never be evaluated against B's registry record.
        """
        inst_a = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        inst_b = self._bound(_SID_B, SourceType.SIMULATOR, "cap-simulator")
        seen: list = []

        def resolver(sid):
            seen.append(sid)
            return {_SID_A: inst_a, _SID_B: inst_b}.get(sid)

        verifier = _verifier(resolver)
        token = verifier.verify(
            _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        assert token.source_instance_id == _SID_A
        # The resolver was asked for A only — B's record never consulted.
        assert seen == [_SID_A]

    def test_token_for_an_unregistered_peer_is_rejected(self) -> None:
        """B's token cannot ride on A's registration."""
        from app.sources.errors import SourceIdentityTokenError

        inst_a = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier = _verifier(
            lambda sid: inst_a if sid == _SID_A else None
        )
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(_issue(_SID_B, SourceType.NGINX, "cap-nginx"))

    def test_token_for_unregistered_source_is_rejected(self) -> None:
        from app.sources.errors import SourceIdentityTokenError

        verifier = _verifier(lambda sid: None)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(_issue(_SID_A, SourceType.NGINX))

    def test_tampered_source_instance_id_breaks_the_signature(self) -> None:
        from app.sources.errors import SourceIdentityTokenError

        inst_a = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier = _verifier(lambda sid: inst_a)
        packed = _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        token_id, body, sig = packed.split(".")
        import base64
        import json

        raw = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        )
        raw["source_instance_id"] = _SID_B
        forged = base64.urlsafe_b64encode(
            json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(f"{token_id}.{forged}.{sig}")

    def test_token_capability_must_match_the_registered_binding(self) -> None:
        """A stale credential for a different capability is refused."""
        from app.sources.errors import SourceIdentityTokenError

        inst = self._bound(_SID_A, SourceType.NGINX, "cap-simulator")
        verifier = _verifier(lambda sid: inst)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(_issue(_SID_A, SourceType.NGINX, "cap-nginx"))

    def test_unbound_source_token_has_no_capability_claim(self) -> None:
        inst = _instance(sid=_SID_A, source_type=SourceType.NGINX)
        verifier = _verifier(lambda sid: inst)
        token = verifier.verify(_issue(_SID_A, SourceType.NGINX))
        assert token.capability_id is None

    def test_replay_is_rejected_single_use_is_preserved(self) -> None:
        from app.sources.errors import SourceIdentityTokenError

        inst = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier = _verifier(
            lambda sid: inst, replay_store=_ReplayStore()
        )
        packed = _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier.verify(packed)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)

    def test_rotated_token_is_distinct_and_still_accepted(self) -> None:
        inst = self._bound(_SID_A, SourceType.NGINX, "cap-nginx")
        verifier = _verifier(
            lambda sid: inst, replay_store=_ReplayStore()
        )
        first = _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        second = _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        assert first != second
        assert verifier.verify(first).source_instance_id == _SID_A
        assert verifier.verify(second).source_instance_id == _SID_A


# ===========================================================================
# 7. Ingress — capability is derived server-side, never payload-derived
# ===========================================================================
class _RecordingIngestion:
    """Stub ingestion service that records the canonical events it sees."""

    def __init__(self) -> None:
        self.events: list = []

    def ingest(self, event):  # noqa: ANN001
        self.events.append(event)
        return event


def _ingress(*instances, replay_store=None):
    recorder = _RecordingIngestion()
    registry = SourceRegistry()
    for inst in instances:
        registry.register(inst)
    verifier = _verifier(
        lambda sid: registry.get(sid),
        replay_store=replay_store or _ReplayStore(),
    )
    proxy = InboundIngressProxy(
        config=_config(),
        registry=registry,
        token_verifier=verifier,
        ingestion_service=recorder,
    )
    return proxy, recorder, verifier


def _ingest_body(**overrides):
    body = {
        "events": [
            {
                "event_type": "authentication_failure",
                # Batch 1/2 T22: ``event_time`` is a REQUIRED canonical field;
                # the payload below used to omit it and relied on the ingress
                # stamping the server receive clock (which fabricated the
                # source's observation time). The wire payload now has to carry
                # the real, source-attributed instant.
                "event_time": _NOW_ISO,
                "source_ip": "203.0.113.9",
                "details": {"status_code": 401},
            }
        ],
    }
    body.update(overrides)
    return body


def _bound_source(
    sid: str,
    source_type: SourceType,
    cap: str,
    state: SourceState = SourceState.ENABLED,
):
    return _instance(
        sid=sid,
        source_type=source_type,
        state=state,
        binding_status=CapabilityBindingStatus.BOUND,
        capability_id=cap,
        capability_version=1,
    )


def _ingest(proxy, token: str, body=None):  # noqa: ANN001
    return proxy.handle(IngressRequest(
        operation="source.ingest",
        headers={"X-ProShield-Source-Token": token},
        body=body if body is not None else _ingest_body(),
    ))


class TestIngressCapabilityProvenance:
    def test_event_is_stamped_with_the_server_derived_capability(self) -> None:
        proxy, recorder, _ = _ingress(
            _bound_source(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        resp = _ingest(
            proxy, _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        assert resp.status == 200, resp.body
        assert len(recorder.events) == 1
        ev = recorder.events[0]
        assert ev.provenance.capability_id == "cap-nginx"
        assert ev.provenance.source_instance_id == _SID_A

    def test_client_supplied_capability_id_is_ignored(self) -> None:
        """A caller must not be able to choose its capability."""
        proxy, recorder, _ = _ingress(
            _bound_source(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        body = _ingest_body()
        body["capability_id"] = "cap-simulator"
        body["events"][0]["capability_id"] = "cap-simulator"
        resp = _ingest(
            proxy,
            _issue(_SID_A, SourceType.NGINX, "cap-nginx"),
            body=body,
        )
        assert resp.status == 200, resp.body
        assert recorder.events[0].provenance.capability_id == "cap-nginx"

    def test_quarantined_source_ingestion_is_blocked(self) -> None:
        quarantined = _instance(
            sid=_SID_A,
            source_type=SourceType.NGINX,
            state=SourceState.ENABLED,
            binding_status=(
                CapabilityBindingStatus.REQUIRES_VERIFICATION
            ),
        )
        proxy, recorder, _ = _ingress(quarantined)
        resp = _ingest(proxy, _issue(_SID_A, SourceType.NGINX))
        assert resp.status == 409
        assert resp.body["error"]["code"] == "source_capability_unverified"
        assert recorder.events == []

    def test_retired_source_ingestion_is_blocked_with_the_410_contract(
        self,
    ) -> None:
        proxy, recorder, _ = _ingress(
            _bound_source(
                _SID_A, SourceType.NGINX, "cap-nginx",
                state=SourceState.RETIRED,
            )
        )
        resp = _ingest(
            proxy, _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        assert resp.status == 410
        assert resp.body["error"]["code"] == "source_retired"
        assert recorder.events == []

    def test_disabled_source_ingestion_is_blocked(self) -> None:
        proxy, recorder, _ = _ingress(
            _bound_source(
                _SID_A, SourceType.NGINX, "cap-nginx",
                state=SourceState.DISABLED,
            )
        )
        resp = _ingest(
            proxy, _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        )
        assert resp.status == 409
        assert recorder.events == []

    def test_unbound_source_still_ingests_with_no_capability_claim(
        self,
    ) -> None:
        """V2 compatibility: unbound legacy sources keep working, and the
        event carries an honest ``None`` capability rather than a guess."""
        legacy = _instance(
            sid=_SID_A, source_type=SourceType.NGINX,
            state=SourceState.ENABLED,
        )
        proxy, recorder, _ = _ingress(legacy)
        resp = _ingest(proxy, _issue(_SID_A, SourceType.NGINX))
        assert resp.status == 200, resp.body
        assert recorder.events[0].provenance.capability_id is None



# ===========================================================================
# 8. Rule -> Capability resolution (dual-read, capability wins)
# ===========================================================================
def _event(source: str, event_type: str, capability_id=None):
    from app.domain.security_event import (
        SecurityEvent,
        SecurityEventProvenance,
    )
    from app.domain.uuid7 import uuid7

    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=_NOW,
        ingested_at=_NOW,
        source=source,
        event_type=event_type,
        provenance=SecurityEventProvenance(
            collector=source,
            source_event_id="evt-1",
            capability_id=capability_id,
        ),
    )


def _registry_with(*metas):
    from app.rules import RuleRegistry

    from tests.unit._rules_helpers import always_match_rule

    reg = RuleRegistry()
    for meta in metas:
        reg.register(always_match_rule(meta))
    return reg


def _meta(**overrides):
    from app.rules import RuleCategory, RuleMetadata, RuleState

    base = dict(
        rule_id="NGINX-TEST-001",
        version=1,
        name="nginx test rule",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("authentication_failure",),
        state=RuleState.APPROVED,
        enabled=True,
    )
    base.update(overrides)
    return RuleMetadata(**base)


class TestRuleCapabilityResolution:
    def test_legacy_rule_still_matches_by_source_string(self) -> None:
        """V2 behaviour is byte-identical for an un-migrated rule."""
        reg = _registry_with(_meta())
        ev = _event("nginx", "authentication_failure", "cap-nginx")
        assert len(reg.applies_to(ev)) == 1

    def test_capability_owned_rule_matches_its_own_capability(self) -> None:
        reg = _registry_with(_meta(capability_id="cap-nginx"))
        ev = _event("nginx", "authentication_failure", "cap-nginx")
        assert len(reg.applies_to(ev)) == 1

    def test_capability_owned_rule_rejects_a_foreign_capability(self) -> None:
        """Capability ownership is authoritative: a cap-nginx rule must not
        fire for an event derived from cap-simulator."""
        reg = _registry_with(_meta(capability_id="cap-nginx"))
        ev = _event("nginx", "authentication_failure", "cap-simulator")
        assert reg.applies_to(ev) == []

    def test_capability_owned_rule_ignores_source_string_entirely(self) -> None:
        """Ownership alone decides — even with no sources[] declared."""
        reg = _registry_with(
            _meta(
                category=__import__(
                    "app.rules", fromlist=["RuleCategory"]
                ).RuleCategory.COMMON_BEHAVIORAL,
                sources=(),
                capability_id="cap-nginx",
            )
        )
        ev = _event("nginx", "authentication_failure", "cap-nginx")
        assert len(reg.applies_to(ev)) == 1

    def test_dual_read_falls_back_when_the_event_is_unstamped(self) -> None:
        """An event ingested outside the binding-aware ingress still selects
        capability-owned rules through the legacy source match."""
        reg = _registry_with(_meta(capability_id="cap-nginx"))
        ev = _event("nginx", "authentication_failure", None)
        assert len(reg.applies_to(ev)) == 1

    def test_event_type_filter_is_still_enforced(self) -> None:
        reg = _registry_with(_meta(capability_id="cap-nginx"))
        ev = _event("nginx", "rate_limit_exceeded", "cap-nginx")
        assert reg.applies_to(ev) == []

    def test_list_for_event_capability_filter_is_authoritative(self) -> None:
        """The hot path honours capability ownership without an event object."""
        reg = _registry_with(_meta(capability_id="cap-nginx"))
        assert len(reg.list_for_event(
            "nginx", "authentication_failure", "cap-nginx",
        )) == 1
        assert reg.list_for_event(
            "nginx", "authentication_failure", "cap-simulator",
        ) == []
        # Dual-read: an unstamped event falls back to the string match.
        assert len(reg.list_for_event(
            "nginx", "authentication_failure", None,
        )) == 1

    def test_matches_capability_helper_contract(self) -> None:
        owned = _meta(capability_id="cap-nginx")
        assert owned.matches_capability("cap-nginx") is True
        assert owned.matches_capability("cap-simulator") is False
        assert owned.matches_capability(None) is True  # dual-read
        legacy = _meta()
        assert legacy.matches_capability("cap-simulator") is True
        assert owned.capability_authoritative_for("cap-nginx") is True
        assert owned.capability_authoritative_for(None) is False

    def test_replayed_token_cannot_ingest_twice(self) -> None:
        proxy, recorder, _ = _ingress(
            _bound_source(_SID_A, SourceType.NGINX, "cap-nginx"),
            replay_store=_ReplayStore(),
        )
        token = _issue(_SID_A, SourceType.NGINX, "cap-nginx")
        first = _ingest(proxy, token)
        second = _ingest(proxy, token)
        assert first.status == 200
        assert second.status == 401
        assert len(recorder.events) == 1

# ===========================================================================
# 9. Legacy migration contract (dry-run / deterministic / idempotent / audit)
# ===========================================================================
class _AuditFakeCollection(FakeSourceCollection):
    """Audit-trail fake that does NOT enforce source_instance_id uniqueness.

    The shared :class:`FakeSourceCollection` hard-codes a unique
    ``source_instance_id`` rule (correct for the ``source_instances``
    entity collection). The real ``source_audit`` collection is
    append-only: many records legitimately share one
    ``source_instance_id``, and its only uniqueness is the server-managed
    ``_id``. This subclass models that shape faithfully so the migration's
    audit writes can be exercised.
    """

    def __init__(self, name: str = SOURCE_AUDIT_COLLECTION) -> None:
        super().__init__(name)

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        import copy as _copy

        self.docs.append(_copy.deepcopy(dict(doc)))
        return type("R", (), {"inserted_id": "fake"})()


def _legacy_migration(*docs, lookup=None, with_audit=True, rules=None):
    """Build a migration engine over a fake source_instances collection."""
    db = FakeDatabase()
    repo = SourceRepository(db, _config())
    coll = db[repo._collection.name]
    for doc in docs:
        coll.docs.append(dict(doc))
    audit = _AuditFakeCollection() if with_audit else None
    if audit is not None:
        repo.audit_collection = lambda: audit
    engine = SourceCapabilityMigration(
        source_repository=repo,
        capability_lookup=lookup if lookup is not None else _lookup,
        registry=None,
        rule_repository=rules,
        capability_audit_collection=None,
    )
    return engine, repo, audit


_SID_C = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f03-c"
_SID_D = "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f03-d"

_LEGACY_NGINX = _raw_source_doc(
    sid=_SID_A, source_type="nginx", human_id="SRC-000001",
)
_LEGACY_SIM = _raw_source_doc(
    sid=_SID_B, source_type="simulator", human_id="SRC-000002",
)
_LEGACY_UNKNOWN = _raw_source_doc(
    sid=_SID_C, source_type="mainframe", human_id="SRC-000003",
)


class TestMigrationPlan:
    def test_dry_run_writes_nothing(self) -> None:
        engine, repo, audit = _legacy_migration(_LEGACY_NGINX, _LEGACY_SIM)
        before = [dict(d) for d in repo._collection.docs]
        report = engine.run(dry_run=True)
        assert report.dry_run is True
        assert report.sources_scanned == 2
        assert report.sources_bound == 2
        assert report.documents_modified == 0
        assert report.audit_records_written == 0
        assert [dict(d) for d in repo._collection.docs] == before
        assert audit.docs == []

    def test_planned_mapping_matches_the_frozen_design(self) -> None:
        engine, _, _ = _legacy_migration(_LEGACY_NGINX, _LEGACY_SIM)
        report = engine.run(dry_run=True)
        by_sid = {c.source_instance_id: c for c in report.source_changes}
        assert by_sid[_SID_A].capability_id == "cap-nginx"
        assert by_sid[_SID_B].capability_id == "cap-simulator"
        assert all(c.outcome == OUTCOME_BOUND for c in report.source_changes)

    def test_migrated_row_resolves_the_same_mapping_profile_as_a_new_row(
        self,
    ) -> None:
        """5.2-R-05: a migrated row must behave like a native one.

        The backfill used to hard-code ``mapping_profile_id=None`` while the
        new-source path deterministically selected the single profile the
        capability declares for that source type. The two paths now resolve
        through one helper, so here they are asserted equal.
        """
        index = builtin_capability_index()
        engine, _, _ = _legacy_migration(_LEGACY_NGINX, _LEGACY_SIM)
        report = engine.run(dry_run=True)
        by_sid = {c.source_instance_id: c for c in report.source_changes}

        nginx = by_sid[_SID_A]
        assert nginx.mapping_profile_id == "nginx-access-default"
        assert nginx.mapping_profile_id == validate_capability_binding(
            index["cap-nginx"], source_type="nginx", allow_non_active=True
        ).mapping_profile_id

        sim = by_sid[_SID_B]
        assert sim.mapping_profile_id == "simulator-default"
        assert sim.mapping_profile_id == validate_capability_binding(
            index["cap-simulator"], source_type="simulator",
            allow_non_active=True,
        ).mapping_profile_id

    def test_planned_family_migrates_with_no_profile_never_a_guess(self) -> None:
        """A planned capability declares no profile: the honest value is None."""
        legacy_waf = _raw_source_doc(
            sid=_SID_D, source_type="waf", human_id="SRC-000004",
        )
        engine, _, _ = _legacy_migration(legacy_waf)
        report = engine.run(dry_run=True)
        change = report.source_changes[0]
        assert change.outcome == OUTCOME_BOUND
        assert change.capability_id == "cap-waf"
        assert change.mapping_profile_id is None

    def test_unknown_source_type_is_quarantined_never_invented(self) -> None:
        engine, _, _ = _legacy_migration(_LEGACY_UNKNOWN)
        report = engine.run(dry_run=True)
        change = report.source_changes[0]
        assert change.outcome == OUTCOME_QUARANTINED
        assert change.capability_id is None
        assert report.sources_quarantined == 1

    def test_missing_registry_capability_is_quarantined(self) -> None:
        """The map names a capability the registry does not hold."""
        engine, _, _ = _legacy_migration(
            _LEGACY_NGINX, lookup=lambda cid: None,
        )
        report = engine.run(dry_run=True)
        assert report.source_changes[0].outcome == OUTCOME_QUARANTINED
        assert report.source_changes[0].capability_id is None

    def test_plan_is_deterministic_across_engines(self) -> None:
        engine_a, _, _ = _legacy_migration(
            _LEGACY_NGINX, _LEGACY_SIM, _LEGACY_UNKNOWN,
        )
        engine_b, _, _ = _legacy_migration(
            _LEGACY_UNKNOWN, _LEGACY_SIM, _LEGACY_NGINX,
        )
        plan_a = [
            c.as_dict() for c in engine_a.run(dry_run=True).source_changes
        ]
        plan_b = [
            c.as_dict() for c in engine_b.run(dry_run=True).source_changes
        ]
        assert plan_a == plan_b
        ids = [c["source_instance_id"] for c in plan_a]
        assert ids == sorted(ids)

    def test_dry_run_counts_equal_applied_counts(self) -> None:
        engine, _, _ = _legacy_migration(
            _LEGACY_NGINX, _LEGACY_SIM, _LEGACY_UNKNOWN,
        )
        dry = engine.run(dry_run=True)
        engine2, _, _ = _legacy_migration(
            _LEGACY_NGINX, _LEGACY_SIM, _LEGACY_UNKNOWN,
        )
        applied = engine2.run(dry_run=False)
        assert dry.sources_bound == applied.sources_bound
        assert dry.sources_quarantined == applied.sources_quarantined

    def test_already_bound_row_is_counted_and_skipped(self) -> None:
        bound = _raw_source_doc(
            sid=_SID_A, source_type="nginx", human_id="SRC-000001",
            capability_id="cap-nginx", binding_status="bound",
        )
        engine, _, _ = _legacy_migration(bound)
        report = engine.run(dry_run=True)
        assert report.sources_already_bound == 1
        assert report.sources_bound == 0
        assert report.source_changes[0].outcome == OUTCOME_ALREADY_BOUND


class TestMigrationApply:
    def test_apply_binds_the_row_and_writes_an_audit_record(self) -> None:
        engine, repo, audit = _legacy_migration(_LEGACY_NGINX)
        report = engine.run(dry_run=False)
        assert report.sources_bound == 1
        assert report.documents_modified == 1
        assert report.audit_records_written == 1
        row = repo._collection.docs[0]
        assert row["capability_id"] == "cap-nginx"
        assert row["capability_version"] == 1
        assert row["capability_binding_status"] == "bound"
        assert row["capability_bound_at"] is not None
        rec = audit.docs[0]
        assert rec["action"] == "source_capability_bind"
        assert rec["source_instance_id"] == _SID_A
        assert rec["capability_id"] == "cap-nginx"
        assert rec["before"]["capability_id"] is None
        assert rec["after"]["capability_id"] == "cap-nginx"
        assert "capability_id" in rec["changed_fields"]

    def test_apply_quarantines_and_audits_an_unresolvable_row(self) -> None:
        engine, repo, audit = _legacy_migration(_LEGACY_UNKNOWN)
        report = engine.run(dry_run=False)
        assert report.sources_quarantined == 1
        row = repo._collection.docs[0]
        assert row["capability_id"] is None
        assert row["capability_binding_status"] == "requires_verification"
        assert audit.docs[0]["action"] == "source_capability_quarantine"
        assert audit.docs[0]["capability_id"] is None

    def test_second_run_is_a_no_op_and_writes_no_audit(self) -> None:
        engine, repo, audit = _legacy_migration(
            _LEGACY_NGINX, _LEGACY_SIM, _LEGACY_UNKNOWN,
        )
        first = engine.run(dry_run=False)
        assert first.sources_bound == 2
        assert first.sources_quarantined == 1
        audit_after_first = len(audit.docs)
        rows_after_first = [dict(d) for d in repo._collection.docs]

        second = engine.run(dry_run=False)
        assert second.sources_bound == 0
        assert second.sources_quarantined == 0
        assert second.documents_modified == 0
        assert second.is_noop is True
        assert len(audit.docs) == audit_after_first
        assert [dict(d) for d in repo._collection.docs] == rows_after_first

    def test_historical_lineage_is_preserved(self) -> None:
        """The migration must not rewrite unrelated historical fields."""
        engine, repo, _ = _legacy_migration(_LEGACY_NGINX)
        original = dict(repo._collection.docs[0])
        engine.run(dry_run=False)
        row = repo._collection.docs[0]
        for field in (
            "source_instance_id",
            "source_type",
            "source",
            "display_name",
            "description",
            "state",
            "created_by",
            "created_at",
            "updated_by",
            "updated_at",
            "last_validation_at",
            "human_id",
        ):
            assert row[field] == original[field], field

    def test_migrated_binding_survives_a_fresh_engine(self) -> None:
        """Restart safety: a new engine over the same data sees the binding."""
        engine, repo, _ = _legacy_migration(_LEGACY_NGINX)
        engine.run(dry_run=False)
        repo2 = SourceRepository(repo._db, _config())
        engine2 = SourceCapabilityMigration(
            source_repository=repo2,
            capability_lookup=_lookup,
            registry=None,
        )
        report2 = engine2.run(dry_run=True)
        assert report2.sources_already_bound == 1
        assert report2.sources_bound == 0

    def test_bound_row_is_loadable_after_migration(self) -> None:
        engine, repo, _ = _legacy_migration(_LEGACY_NGINX)
        engine.run(dry_run=False)
        reloaded = repo.get(_SID_A)
        assert reloaded is not None
        assert reloaded.capability_id == "cap-nginx"
        assert reloaded.capability_binding_status is (
            CapabilityBindingStatus.BOUND
        )

    def test_report_serialises_to_a_stable_shape(self) -> None:
        engine, _, _ = _legacy_migration(_LEGACY_NGINX)
        payload = engine.run(dry_run=True).as_dict()
        assert set(payload) == {
            "dry_run",
            "migration_version",
            "sources",
            "rules",
            "documents_modified",
            "audit_records_written",
            "registry_reloaded",
            "source_changes",
            "rule_changes",
        }