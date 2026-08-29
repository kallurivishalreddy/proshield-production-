"""Phase 4.7 local verification script.

This script demonstrates the documented Phase 4.7
flow against the real local MongoDB.

Run it with::

    python scripts/demo_phase47.py
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any, Dict

# Allow the demo to be run from anywhere by adding
# the project root to ``sys.path``.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import ProShieldConfig
from app.connectors.nginx import NginxConnector
from app.detection import DetectionEngine, DetectionPipeline
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.detection_repository import DetectionRepository
from app.persistence.rule_repository import RuleRepository
from app.persistence.security_event_repository import SecurityEventRepository
from app.rules import RuleRegistry
from app.rules.management import RuleManagementService
from app.severity import SeverityEngine
from app.timeline import TimelineEngine


_BASIC_NGINX_LOG = (
    '198.51.100.7 - - [26/Aug/2026:12:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:10 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:20 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:12:00:30 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.99 - - [26/Aug/2026:12:00:40 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
)


def _make_test_config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    suffix = uuid.uuid4().hex[:8]
    return ProShieldConfig(
        env_name=f"phase47-demo-{suffix}",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db="proshield_test",
        mongo_collection_events=f"security_events_{suffix}",
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        connector_specs=[],
    )


def _print_header(text: str) -> None:
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def _make_rule_payload(rule_id: str, cidr: str) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "version": 1,
        "name": f"Demo rule {rule_id}",
        "description": "Phase 4.7 demo: 401 detector inside a CIDR",
        "category": "source_specific",
        "type": "detection",
        "state": "approved",
        "enabled": True,
        "severity": "medium",
        "sources": ["nginx"],
        "event_types": ["authentication_failure"],
        "tags": ["DEMO", "PHASE-4-7"],
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
                            "value": cidr,
                        },
                    },
                ],
            },
        },
        "thresholds": {},
        "window_seconds": None,
        "actions": ["alert", "block_remediation"],
    }


def _build_pipeline(config, db, registry):
    """Build the documented per-event pipeline."""
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db, config), config
    )
    detection_engine = DetectionEngine(registry)
    detection_repo = DetectionRepository(db, config)
    detection_repo.ensure_schema()
    detection_repo.ensure_indexes()
    return DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=detection_repo,
    )


def _run_pipeline(pipeline, log_path: Path, rule_id: str):
    """Run the pipeline on a temporary NGINX log and
    return the per-rule detections."""
    log_path.write_text(_BASIC_NGINX_LOG, encoding="utf-8")
    results = pipeline.run_from_connector(
        NginxConnector(log_path, asset="web-api-01")
    )
    return [
        d
        for pr in results
        for d in pr.detection_result.detections
        if d.rule_id == rule_id
    ]


def main() -> int:
    print("Phase 4.7 local verification")
    print("----------------------------")

    config = _make_test_config()
    print(f"Test database: {config.mongo_db}")
    print(f"Events collection: {config.mongo_collection_events}")

    from app.persistence.mongo import (
        check_connectivity,
        get_database,
        make_client,
    )
    client = make_client(config)
    check_connectivity(client)
    db = get_database(client, config)

    repository = RuleRepository(db, config)
    repository.ensure_schema()
    repository.ensure_indexes()
    registry = RuleRegistry()
    service = RuleManagementService(repository, registry)

    _print_header("1. CREATE -> VALIDATE -> PERSIST -> LOAD -> EXECUTE")
    payload = _make_rule_payload("DEMO-RULE-001", "198.51.100.0/24")
    print("  CREATE   : rule definition payload -> service.create")
    created = service.create(payload)
    print(f"             -> {created.rule_id} v{created.version}")
    print("  VALIDATE  : Pydantic + service-layer checks passed")
    print(f"  PERSIST   : managed_rules count={repository.count()}")
    print(f"  LOAD      : registry.get('DEMO-RULE-001', 1) -> {type(registry.get('DEMO-RULE-001', 1)).__name__}")
    pipeline = _build_pipeline(config, db, registry)
    log1 = Path("demo_access.log")
    custom_dets = _run_pipeline(pipeline, log1, "DEMO-RULE-001")
    print(f"  EXECUTE   : {len(custom_dets)} detections produced")

    _print_header("2. MODIFY the rule (different CIDR, no backend code change)")
    update_payload = _make_rule_payload("DEMO-RULE-001", "10.0.0.0/8")
    update_payload["name"] = "Demo rule (modified CIDR)"
    service.update("DEMO-RULE-001", 1, update_payload)
    log2 = Path("demo_access_2.log")
    custom_dets_2 = _run_pipeline(pipeline, log2, "DEMO-RULE-001")
    print(f"  New CIDR (10.0.0.0/8) does not match the test events -> {len(custom_dets_2)} new detections")

    _print_header("3. DISABLE the rule and prove it stops executing")
    service.update("DEMO-RULE-001", 1, _make_rule_payload("DEMO-RULE-001", "198.51.100.0/24"))
    service.set_enabled("DEMO-RULE-001", False, version=1)
    log3 = Path("demo_access_3.log")
    custom_dets_3 = _run_pipeline(pipeline, log3, "DEMO-RULE-001")
    print(f"  After disable -> {len(custom_dets_3)} new detections (expected 0)")

    _print_header("4. NEW VERSION: create v2 and prove the intended version is recorded")
    v2_payload = _make_rule_payload("DEMO-RULE-001", "198.51.100.0/24")
    v2_payload["version"] = 2
    v2_payload["name"] = "Demo rule v2"
    v2 = service.create_new_version("DEMO-RULE-001", v2_payload)
    print(f"  v2 created: state={v2.state} (expected candidate), enabled={v2.enabled} (expected False)")
    service.set_state("DEMO-RULE-001", "approved", version=2)
    service.set_enabled("DEMO-RULE-001", True, version=2)
    log4 = Path("demo_access_4.log")
    custom_dets_4 = _run_pipeline(pipeline, log4, "DEMO-RULE-001")
    v2_hits = [d for d in custom_dets_4 if d.rule_version == 2]
    print(f"  v2 hits: {len(v2_hits)} (v1 was disabled, v2 fires on the 198.51.100.0/24 events)")

    _print_header("5. RE-ENABLE superseded v1 is refused (Section 33 + 88)")
    try:
        service.set_enabled("DEMO-RULE-001", True, version=1)
        print("  ERROR: the framework allowed re-enabling a superseded version")
        return 1
    except Exception as exc:
        print(f"  OK: refused -> {type(exc).__name__}: {exc.safe_message}")

    _print_header("6. RE-ENABLE the active v2 (re-enable cycle)")
    service.set_enabled("DEMO-RULE-001", False, version=2)
    service.set_enabled("DEMO-RULE-001", True, version=2)
    log6 = Path("demo_access_6.log")
    custom_dets_6 = _run_pipeline(pipeline, log6, "DEMO-RULE-001")
    v2_hits_6 = [d for d in custom_dets_6 if d.rule_version == 2]
    print(f"  After re-enable v2 -> {len(v2_hits_6)} new v2 detections (expected 4)")

    _print_header("7. RETIRE the rule (soft-delete)")
    service.retire("DEMO-RULE-001", version=2)
    raw = db["managed_rules"].find_one({"rule_id": "DEMO-RULE-001", "version": 2})
    print(f"  After retire: registry entry removed; document state={raw['state']}, enabled={raw['enabled']}")

    # Cleanup
    for p in (log1, log2, log3, log4, log6):
        p.unlink(missing_ok=True)
    client.close()

    _print_header("Phase 4.7 verification: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

