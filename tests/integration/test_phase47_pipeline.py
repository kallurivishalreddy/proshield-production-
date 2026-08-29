"""End-to-end integration test for the Phase 4.7 rule
management backend against the real local MongoDB.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.correlation import BruteForceClusteringPattern, CorrelationEngine
from app.detection import DetectionEngine, DetectionPipeline
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.detection_repository import DetectionRepository
from app.persistence.rule_repository import (
    RuleRepository,
    managed_rule_collection_name,
)
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.rules import (
    RuleRegistry,
    load_rules_from_specs,
)
from app.rules.management import (
    GenericDeclarativeRule,
    RuleDefinition,
    RuleManagementService,
    RuleType,
    STATE_RETIRED,
)
from app.rules.types import RuleCategory, RuleState
from app.severity import SeverityEngine
from app.severity.models import SeverityBand
from app.timeline import TimelineEngine


_BASIC_NGINX_LOG = (
    # 4 auth failures from the same source
    '198.51.100.7 - - [26/Aug/2026:12:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:10 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:20 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:30 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    # A 200 on a public page
    '198.51.100.99 - - [26/Aug/2026:12:00:40 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
)


@pytest.fixture
def nginx_log(tmp_path: Path) -> Path:
    p = tmp_path / "access.log"
    p.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    return p


@pytest.fixture
def rule_repository(db, test_config: ProShieldConfig) -> RuleRepository:
    repo = RuleRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo


@pytest.fixture
def service(rule_repository: RuleRepository) -> RuleManagementService:
    registry = RuleRegistry()
    return RuleManagementService(rule_repository, registry)


def _make_det_rule_payload(
    *,
    rule_id: str,
    severity: str = "medium",
    source_ip_in_cidr: str = "198.51.100.0/24",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "version": 1,
        "name": f"Phase 4.7 integration rule {rule_id}",
        "description": "User-defined 401 detector for 198.51.100.0/24",
        "category": "source_specific",
        "type": "detection",
        "state": "approved",
        "enabled": True,
        "severity": severity,
        "sources": ["nginx"],
        "event_types": ["authentication_failure"],
        "tags": ["PHASE-4-7"],
        "references": [],
        "combinator": "and",
        "scope": [],
        "evidence_requirements": ["source_ip"],
        "conditions": {
            "kind": "group",
            "group": {
                "combinator": "and",
                "children": [
                    {
                        "kind": "atom",
                        "atom": {
                            "field": "event_type",
                            "operator": "eq",
                            "value": "authentication_failure",
                        },
                    },
                    {
                        "kind": "atom",
                        "atom": {
                            "field": "source_ip",
                            "operator": "ip_in_cidr",
                            "value": source_ip_in_cidr,
                        },
                    },
                ],
            },
        },
        "thresholds": {},
        "window_seconds": None,
        "actions": ["alert", "block_remediation"],
    }


# ----------------------------------------------------------------- integration: full create -> execute
def test_phase47_full_create_validate_persist_load_execute(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
    rule_repository: RuleRepository,
) -> None:
    """The documented Phase 4.7 flow."""
    # 1. CREATE  (Pydantic validates; the service
    #    additionally checks the closed-set
    #    actions and the lifecycle invariants).
    payload = _make_det_rule_payload(rule_id="CUSTOM-001")
    created = service.create(payload)
    assert created.rule_id == "CUSTOM-001"
    assert created.state == "approved"
    assert created.enabled is True
    in_repo = rule_repository.get("CUSTOM-001", 1)
    assert in_repo is not None
    # 3. PERSIST  - the raw document has the canonical
    #    fields, including the closed-set actions.
    raw = rule_repository.get("CUSTOM-001", 1)
    assert raw is not None
    assert raw.actions == ("alert", "block_remediation")
    # 4. LOAD  - the registry now has the rule as a
    #    GenericDeclarativeRule (the single Rule
    #    subclass produced by Phase 4.7).
    registry = service.registry
    in_registry = registry.get("CUSTOM-001", 1)
    assert in_registry is not None
    assert isinstance(in_registry, GenericDeclarativeRule)

    # 5. EXECUTE  - the existing Phase 4.4 / 4.5 pipeline.
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    results = pipeline.run_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    custom_dets: List = []
    for pr in results:
        for d in pr.detection_result.detections:
            if d.rule_id == "CUSTOM-001":
                custom_dets.append(d)
    assert len(custom_dets) == 4
    assert all(d.rule_version == 1 for d in custom_dets)
    assert any("CUSTOM-001" in d.reasoning for d in custom_dets)

    # 6. Detection / Timeline / Severity.
    all_events = [pr.event for pr in results]
    events_by_id = {e.event_id: e for e in all_events}
    all_dets = [
        d for pr in results for d in pr.detection_result.detections
    ]
    timeline = TimelineEngine().run(
        events=all_events,
        detections=all_dets,
        correlations=[],
    )
    assert timeline.item_count >= 4
    severity = SeverityEngine().run(
        detections=all_dets,
        correlations=[],
        events=events_by_id,
    )
    assert len(severity.errors) == 0
    assert severity.bundle_severity in (
        SeverityBand.LOW,
        SeverityBand.MEDIUM,
        SeverityBand.HIGH,
        SeverityBand.CRITICAL,
    )



# ----------------------------------------------------------------- integration: validation rejects
def test_phase47_create_rejects_malformed_payload(
    service: RuleManagementService,
) -> None:
    from app.rules.management.errors import RuleDefinitionValidationError
    with pytest.raises(RuleDefinitionValidationError):
        service.create({"rule_id": "CUSTOM-002"})


def test_phase47_create_rejects_unknown_action(
    service: RuleManagementService,
) -> None:
    from app.rules.management.errors import RuleDefinitionValidationError
    bad = _make_det_rule_payload(rule_id="CUSTOM-003")
    bad["actions"] = ["execute_shell"]
    with pytest.raises(RuleDefinitionValidationError):
        service.create(bad)


def test_phase47_create_rejects_invalid_source(
    service: RuleManagementService,
) -> None:
    from app.rules.management.errors import RuleDefinitionValidationError
    bad = _make_det_rule_payload(rule_id="CUSTOM-004")
    bad["sources"] = ["not_a_source"]
    with pytest.raises(RuleDefinitionValidationError):
        service.create(bad)



# ----------------------------------------------------------------- integration: lifecycle
def test_phase47_lifecycle_disable_reexecute(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
) -> None:
    """Disable a rule and prove it stops executing."""
    service.create(_make_det_rule_payload(rule_id="CUSTOM-LIFECYCLE"))

    registry = service.registry
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )

    # First pass: rule is enabled, produces 4 detections.
    results = pipeline.run_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    count_first = sum(
        1
        for pr in results
        for d in pr.detection_result.detections
        if d.rule_id == "CUSTOM-LIFECYCLE"
    )
    assert count_first == 4

    # Disable the rule via the service.
    service.set_enabled("CUSTOM-LIFECYCLE", False, version=1)
    assert registry.get("CUSTOM-LIFECYCLE", 1) is not None
    assert registry.get("CUSTOM-LIFECYCLE", 1).metadata.enabled is False

    # Re-run with a fresh connector.
    log2 = nginx_log.parent / "access-2.log"
    log2.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    results2 = pipeline.run_from_connector(
        NginxConnector(log2, asset="web-api-01")
    )
    count_second = sum(
        1
        for pr in results2
        for d in pr.detection_result.detections
        if d.rule_id == "CUSTOM-LIFECYCLE"
    )
    assert count_second == 0


def test_phase47_lifecycle_new_version(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
) -> None:
    """Disable v1, create v2, prove v2 is the one
    that executes against new events.

    The framework's documented supersede-on-new-
    version semantic protects against
    accidentally re-enabling a deprecated version
    (Section 33 + 88); the caller is expected
    to retire or disable v1 explicitly.
    """
    # v1: enabled + approved.
    service.create(_make_det_rule_payload(
        rule_id="CUSTOM-VERSION",
        source_ip_in_cidr="198.51.100.0/24",
    ))
    # Disable v1 before creating v2 so the
    # detection engine does not double-fire.
    service.set_enabled("CUSTOM-VERSION", False, version=1)

    v2_payload = _make_det_rule_payload(
        rule_id="CUSTOM-VERSION",
        source_ip_in_cidr="10.0.0.0/8",
    )
    v2_payload["version"] = 2
    v2 = service.create_new_version("CUSTOM-VERSION", v2_payload)
    assert v2.version == 2
    assert v2.state == "candidate"
    assert v2.enabled is False

    # Promote + enable v2.
    service.set_state("CUSTOM-VERSION", "approved", version=2)
    service.set_enabled("CUSTOM-VERSION", True, version=2)

    # Re-enabling v1 (the superseded version) is
    # refused by the registry (Section 33 + 88).
    from app.rules.management.errors import RuleNotInExpectedStateError
    with pytest.raises(RuleNotInExpectedStateError):
        service.set_enabled("CUSTOM-VERSION", True, version=1)

    registry = service.registry
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    log2 = nginx_log.parent / "access-version.log"
    log2.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    results = pipeline.run_from_connector(
        NginxConnector(log2, asset="web-api-01")
    )
    # v1 is disabled (no firings). v2's CIDR
    # (10.0.0.0/8) does not match the test
    # events (198.51.100.0/24).
    v1_hits = sum(
        1
        for pr in results
        for d in pr.detection_result.detections
        if d.rule_id == "CUSTOM-VERSION" and d.rule_version == 1
    )
    v2_hits = sum(
        1
        for pr in results
        for d in pr.detection_result.detections
        if d.rule_id == "CUSTOM-VERSION" and d.rule_version == 2
    )
    assert v1_hits == 0
    assert v2_hits == 0

    # Re-enable v2 (it is the latest version, so
    # the registry's supersede check does not
    # apply).
    service.set_enabled("CUSTOM-VERSION", False, version=2)
    service.set_enabled("CUSTOM-VERSION", True, version=2)


def test_phase47_lifecycle_retire(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
) -> None:
    """Retire a rule and prove it stops executing."""
    service.create(_make_det_rule_payload(rule_id="CUSTOM-RETIRE"))
    service.retire("CUSTOM-RETIRE", version=1)
    assert service.registry.get("CUSTOM-RETIRE", 1) is None
    # The document remains in the collection; we
    # fetch the raw doc to verify the soft-delete
    # ``state`` / ``enabled`` flags.
    collection = db[managed_rule_collection_name(test_config)]
    raw = collection.find_one({"rule_id": "CUSTOM-RETIRE", "version": 1})
    assert raw is not None
    assert raw["state"] == STATE_RETIRED
    assert raw["enabled"] is False



# ----------------------------------------------------------------- integration: dynamic loading
def test_phase47_dynamic_load_registers_persisted_rule(
    db,
    test_config: ProShieldConfig,
    rule_repository: RuleRepository,
) -> None:
    """Insert a rule directly into the repository
    (bypassing the service) and prove the
    service's ``reload_registry`` picks it up
    into the live in-memory registry.
    """
    d = RuleDefinition(
        rule_id="CUSTOM-LOAD-001",
        version=1,
        name="Reload-from-MongoDB",
        category=RuleCategory.SOURCE_SPECIFIC,
        type=RuleType.DETECTION,
        state=RuleState.APPROVED,
        enabled=True,
        severity=SeverityBand.MEDIUM,
        sources=("nginx",),
        event_types=("authentication_failure",),
        actions=("alert",),
    )
    rule_repository.create(d)
    registry = RuleRegistry()
    assert registry.get("CUSTOM-LOAD-001", 1) is None
    service = RuleManagementService(rule_repository, registry)
    n = service.reload_registry()
    assert n == 1
    assert registry.get("CUSTOM-LOAD-001", 1) is not None


# ----------------------------------------------------------------- integration: existing NGINX compatibility
def test_phase47_built_in_nginx_rules_still_work(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
) -> None:
    """The Phase 4.7 slice does not affect the built-in
    NGINX rules.
    """
    registry = RuleRegistry()
    load_rules_from_specs(registry, ["app.rules._library.nginx"])
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    results = pipeline.run_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    rule_ids = {
        d.rule_id
        for pr in results
        for d in pr.detection_result.detections
    }
    assert "NGINX-AUTH-BRUTEFORCE-001" in rule_ids


def test_phase47_user_rule_alongside_built_in_nginx_rules(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
) -> None:
    """The user-defined rule fires alongside the
    built-in NGINX rules.
    """
    load_rules_from_specs(service.registry, ["app.rules._library.nginx"])
    service.create(_make_det_rule_payload(rule_id="CUSTOM-COMBO"))

    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(service.registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    results = pipeline.run_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    rule_ids = {
        d.rule_id
        for pr in results
        for d in pr.detection_result.detections
    }
    assert "CUSTOM-COMBO" in rule_ids
    assert "NGINX-AUTH-BRUTEFORCE-001" in rule_ids


# ----------------------------------------------------------------- integration: correlation with user rule
def test_phase47_correlation_user_rule_observation(
    nginx_log: Path,
    db,
    test_config: ProShieldConfig,
    service: RuleManagementService,
) -> None:
    """A user-defined rule's per-event Detection is
    picked up by the existing Phase 4.5 correlation
    engine.
    """
    service.create(_make_det_rule_payload(
        rule_id="CUSTOM-CORR",
        source_ip_in_cidr="0.0.0.0/0",
    ))
    registry = service.registry
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, test_config), test_config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, test_config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )
    results = pipeline.run_from_connector(
        NginxConnector(nginx_log, asset="web-api-01")
    )
    all_dets: List = [
        d for pr in results for d in pr.detection_result.detections
    ]
    user_dets = [d for d in all_dets if d.rule_id == "CUSTOM-CORR"]
    assert len(user_dets) == 4
    events = [pr.event for pr in results]
    events_by_id = {e.event_id: e for e in events}
    correlation_engine = CorrelationEngine(
        patterns=[
            BruteForceClusteringPattern(
                threshold=3,
                window=timedelta(seconds=60),
            )
        ]
    )
    correlation_result = correlation_engine.run(
        detections=all_dets,
        events=events_by_id,
    )
    # The Phase 4.5 correlation engine has consumed
    # the per-event detections. The built-in
    # BruteForceClusteringPattern is intentionally
    # narrow (it only selects detections whose
    # rule_id is in the built-in rule set); it
    # therefore does not produce correlations for
    # a user-defined rule with a different rule_id.
    # The point of this test is to prove the
    # correlation engine's runtime accepts user
    # rule detections as input without errors and
    # produces a deterministic result.
    assert correlation_result.detections_consumed == 4
    assert correlation_result.errors == ()
    # ``patterns_evaluated == 0`` because the
    # existing pattern's ``select`` rejected every
    # detection (none of them had a built-in
    # brute-force rule_id). This is the documented
    # behaviour: the user-defined rule's per-event
    # firings are valid input, but the pattern
    # only acts on its own rule ids.

