"""Regression tests: live-detection fidelity for managed library rules.

Reference: docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md
§13 (a rule is real only when its capability/source applicability is
enforceable and its behaviour is testable) and §10.1 (Capability -> Rules).

Defect under test (2026-09-18 baseline audit, reproduced live):
``ManagedRuleLifecycleSync.seed_builtins()`` persists every shipped library
rule as a metadata-only :class:`RuleDefinition` (a Python predicate cannot be
transcribed into the bounded declarative DSL), and
``RuleManagementService.reload_registry()`` used to replace the registry's
predicate-bearing :class:`SimpleRule` with a :class:`GenericDeclarativeRule`.
Because ``_matches_conditions`` returns ``True`` when ``conditions is None``,
the live detector then matched on ``(source, event_type)`` alone: a benign
nginx ``request_blocked`` event with HTTP 200 raised three detections, and a
forged ``authentication_failure`` with HTTP 500 raised the 401 rule.

These tests pin the CORRECT semantics through the real service + sync objects
(fake database, no MongoDB required). The live end-to-end proof lives in
``scripts/verify_phase52_pipeline.py`` and ``scripts/_cline_probe_a.py``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from app.config import ProShieldConfig
from app.detection.engine import DetectionEngine
from app.persistence.rule_repository import RuleRepository
from app.pipeline.managed_rule_sync import ManagedRuleLifecycleSync
from app.rules.management.generic_rule import GenericDeclarativeRule
from app.rules.management.service import RuleManagementService
from app.rules.registry import RuleRegistry
from app.rules.rule import SimpleRule
from tests.unit._phase47_fakes import FakeDatabase


_NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)
_LIBRARY_SPECS = ("app.rules._library.nginx",)

_LIBRARY_RULE_IDS = (
    "NGINX-ACCESS-DENIED-001",
    "NGINX-AUTH-BRUTEFORCE-001",
    "NGINX-AUTH-FAILURE-001",
    "NGINX-RATE-LIMIT-001",
    "NGINX-STATUS-ANOMALY-001",
)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="WARNING",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="test",
        mongo_collection_events="security_events",
    )


def _event(
    *,
    event_type: str,
    status: int,
    endpoint: str = "/api/login",
    source: str = "nginx",
    source_ip: str = "198.51.100.7",
    details: Optional[Dict[str, Any]] = None,
    capability_id: Optional[str] = "cap-nginx",
):
    from app.domain.security_event import (
        SecurityEvent,
        SecurityEventProvenance,
    )
    from app.domain.uuid7 import uuid7

    payload_details: Dict[str, Any] = {"status_code": status}
    if details:
        payload_details.update(details)
    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=_NOW,
        ingested_at=_NOW,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        endpoint=endpoint,
        provenance=SecurityEventProvenance(
            collector=source,
            source_event_id="evt-1",
            capability_id=capability_id,
        ),
        details=payload_details,
    )


def _fire(registry: RuleRegistry, event) -> set:  # noqa: ANN001
    """Return the set of rule_ids that fired for ``event``."""
    result = DetectionEngine(registry).run(event, now=_NOW)
    return {d.rule_id for d in result.detections}


class _Stack:
    """The real managed-rule composition over a fake database."""

    def __init__(self) -> None:
        self.db = FakeDatabase()
        self.config = _config()
        self.repository = RuleRepository(self.db, self.config)
        self.registry = RuleRegistry()
        from app.rules.loader import load_rules_from_specs

        load_rules_from_specs(self.registry, list(_LIBRARY_SPECS))
        self.service = RuleManagementService(
            repository=self.repository,
            registry=self.registry,
            config=self.config,
        )
        self.sync = ManagedRuleLifecycleSync(
            repository=self.repository,
            registry=self.registry,
            config=self.config,
            library_specs=_LIBRARY_SPECS,
        )
        self.seeded = self.sync.seed_builtins()
        self.sync.sync()


def _stack() -> _Stack:
    return _Stack()


# ===========================================================================
# 1. capability ownership is declared by the shipped library rules
# ===========================================================================
def test_library_rules_declare_their_capability_owner() -> None:
    stack = _stack()
    for rule_id in _LIBRARY_RULE_IDS:
        rule = stack.registry.get(rule_id, 1)
        assert rule is not None, rule_id
        assert rule.metadata.capability_id == "cap-nginx", rule_id
        assert rule.metadata.matches_capability("cap-nginx") is True


# ===========================================================================
# 2. the shipped implementation survives the managed-rule reconciliation
# ===========================================================================
def test_reload_keeps_the_shipped_implementation_not_a_declarative_wrapper() -> None:
    stack = _stack()
    # Every shipped library rule is seeded into managed state...
    assert stack.seeded >= len(_LIBRARY_RULE_IDS)
    # ...and the live registry still evaluates the SHIPPED implementation.
    for rule_id in _LIBRARY_RULE_IDS:
        rule = stack.registry.get(rule_id, 1)
        assert isinstance(rule, SimpleRule), (
            f"{rule_id} was replaced by {type(rule).__name__}: the shipped "
            "predicate would be lost"
        )
        assert not isinstance(rule, GenericDeclarativeRule)


def test_persisted_seed_definition_carries_the_capability_owner() -> None:
    stack = _stack()
    seeded = {d.rule_id: d for d in stack.repository.find_all()}
    assert set(_LIBRARY_RULE_IDS) <= set(seeded)
    for rule_id in _LIBRARY_RULE_IDS:
        assert seeded[rule_id].capability_id == "cap-nginx", rule_id


# ===========================================================================
# 3. detection fidelity: benign telemetry must not produce detections
# ===========================================================================
def test_benign_404_on_a_non_sensitive_path_produces_no_detection() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="request_blocked",
            status=404,
            endpoint="/blog/missing-article",
        ),
    )
    assert fired == set(), fired


def test_benign_200_static_asset_produces_no_detection() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="request_blocked",
            status=200,
            endpoint="/index.html",
        ),
    )
    assert fired == set(), fired


def test_forged_authentication_failure_with_wrong_status_is_not_detected() -> None:
    """Defence in depth: the 401 rule re-checks the status code."""
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(event_type="authentication_failure", status=500, endpoint="/api/login"),
    )
    assert fired == set(), fired


# ===========================================================================
# 4. detection fidelity: real signals still fire exactly the right rules
# ===========================================================================
def test_sensitive_path_4xx_fires_only_access_denied() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(event_type="request_blocked", status=404, endpoint="/.env"),
    )
    assert fired == {"NGINX-ACCESS-DENIED-001"}, fired


def test_5xx_fires_only_the_status_anomaly_rule() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="request_blocked",
            status=502,
            endpoint="/app/checkout",
        ),
    )
    assert fired == {"NGINX-STATUS-ANOMALY-001"}, fired


def test_401_on_auth_shaped_path_fires_both_documented_rules() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="authentication_failure",
            status=401,
            endpoint="/api/login",
        ),
    )
    assert fired == {"NGINX-AUTH-FAILURE-001", "NGINX-AUTH-BRUTEFORCE-001"}, fired


def test_429_fires_only_the_rate_limit_rule() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="rate_limit_exceeded",
            status=429,
            endpoint="/api/search",
        ),
    )
    assert fired == {"NGINX-RATE-LIMIT-001"}, fired


# ===========================================================================
# 5. capability ownership isolation (freeze §10.1 / §13)
# ===========================================================================
def test_event_owned_by_another_capability_cannot_fire_nginx_rules() -> None:
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="request_blocked",
            status=404,
            endpoint="/.env",
            capability_id="cap-simulator",
        ),
    )
    assert fired == set(), fired


def test_unstamped_event_still_resolves_by_legacy_source_match() -> None:
    """Dual-read during migration: no derived capability -> string match."""
    stack = _stack()
    fired = _fire(
        stack.registry,
        _event(
            event_type="authentication_failure",
            status=401,
            endpoint="/api/login",
            capability_id=None,
        ),
    )
    assert "NGINX-AUTH-FAILURE-001" in fired, fired


# ===========================================================================
# 6. lifecycle still governs the live detector (V2-01 must not regress)
# ===========================================================================
def test_disabling_a_library_rule_stops_it_firing() -> None:
    stack = _stack()
    event_factory = lambda: _event(  # noqa: E731
        event_type="request_blocked", status=404, endpoint="/.env"
    )
    assert _fire(stack.registry, event_factory()) == {"NGINX-ACCESS-DENIED-001"}

    stack.service.set_enabled("NGINX-ACCESS-DENIED-001", False)
    stack.sync.sync()
    assert _fire(stack.registry, event_factory()) == set()

    stack.service.set_enabled("NGINX-ACCESS-DENIED-001", True)
    stack.sync.sync()
    assert _fire(stack.registry, event_factory()) == {"NGINX-ACCESS-DENIED-001"}


def test_retiring_a_library_rule_unregisters_it() -> None:
    stack = _stack()
    stack.service.retire("NGINX-STATUS-ANOMALY-001")
    stack.sync.sync()
    assert stack.registry.get("NGINX-STATUS-ANOMALY-001", 1) is None
    fired = _fire(
        stack.registry,
        _event(event_type="request_blocked", status=502, endpoint="/app"),
    )
    assert "NGINX-STATUS-ANOMALY-001" not in fired


# ===========================================================================
# 7. operator-authored declarative rules keep working (conditions win)
# ===========================================================================
def _declarative_payload(*, rule_id: str = "CLINE-404-PROBE-001") -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "version": 1,
        "name": "Operator-owned 404 probe rule",
        "description": "Operator-authored declarative rule (regression fixture).",
        "category": "source_specific",
        "type": "detection",
        "state": "approved",
        "enabled": True,
        "severity": "low",
        "sources": ["nginx"],
        "event_types": ["request_blocked"],
        "tags": [],
        "references": [],
        "combinator": "and",
        "conditions": {
            "kind": "atom",
            "atom": {
                "field": "details.status_code",
                "operator": "eq",
                "value": 404,
            },
        },
        "scope": [],
        "evidence_requirements": [],
        "thresholds": {},
        "window_seconds": None,
        "actions": ["alert"],
    }


# ===========================================================================
# 8. catalogue truthfulness: a legacy ownerless row is backfilled
# ===========================================================================
def test_missing_persisted_capability_owner_is_backfilled() -> None:
    """2026-09-18 audit (AUD-CL-05).

    Seeding is insert-only, so a ``managed_rules`` row created before the
    shipped rules declared their capability owner keeps ``capability_id: null``
    forever — the persisted catalogue then contradicts the live registry and
    the Rules page truthfully reports "no capability owner" for a rule the
    detector knows is ``cap-nginx``.
    """
    stack = _stack()
    collection = stack.repository._collection  # noqa: SLF001 - test fixture
    for doc in collection.docs:
        if doc.get("rule_id") == "NGINX-ACCESS-DENIED-001":
            doc["capability_id"] = None
    assert all(
        d.get("capability_id") is None
        for d in collection.docs
        if d.get("rule_id") == "NGINX-ACCESS-DENIED-001"
    )

    stack.sync.seed_builtins()

    restored = [
        d for d in collection.docs
        if d.get("rule_id") == "NGINX-ACCESS-DENIED-001"
    ]
    assert restored and restored[0]["capability_id"] == "cap-nginx", restored


def test_backfill_never_overwrites_an_existing_owner() -> None:
    stack = _stack()
    collection = stack.repository._collection  # noqa: SLF001 - test fixture
    for doc in collection.docs:
        if doc.get("rule_id") == "NGINX-AUTH-FAILURE-001":
            doc["capability_id"] = "cap-simulator"
    stack.sync.seed_builtins()
    kept = [
        d for d in collection.docs
        if d.get("rule_id") == "NGINX-AUTH-FAILURE-001"
    ]
    assert kept and kept[0]["capability_id"] == "cap-simulator", kept


def test_owner_backfill_rejects_a_malformed_capability_id() -> None:
    from app.domain.errors import ValidationError as DomainValidationError

    stack = _stack()
    with pytest.raises(DomainValidationError):
        stack.repository.set_capability_id_if_missing(
            "NGINX-ACCESS-DENIED-001", 1, "conn-nginx"
        )
    with pytest.raises(DomainValidationError):
        stack.repository.set_capability_id_if_missing(
            "NGINX-ACCESS-DENIED-001", 1, ""
        )


# ===========================================================================
# 9. operator-authored declarative rules keep working (conditions win)
# ===========================================================================
def test_operator_declarative_rule_is_evaluated_declaratively() -> None:
    stack = _stack()
    stack.service.create(_declarative_payload())
    rule = stack.registry.get("CLINE-404-PROBE-001", 1)
    assert isinstance(rule, GenericDeclarativeRule)

    assert _fire(
        stack.registry,
        _event(event_type="request_blocked", status=404, endpoint="/anything"),
    ) == {"CLINE-404-PROBE-001"}
    assert _fire(
        stack.registry,
        _event(event_type="request_blocked", status=200, endpoint="/anything"),
    ) == set()
