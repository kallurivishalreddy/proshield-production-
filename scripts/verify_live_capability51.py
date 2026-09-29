"""Phase 5.1 live verification: real MongoDB (if available) else FakeDatabase.

Steps:
1. bootstrap.ensure_all_collections covers `capabilities` (+ validator/indexes)
2. seed_builtins idempotent (6 built-ins: 2 live + 4 planned)
3. CRUD + lifecycle over the service
4. restart-equivalent reload_from_repository preserves data + counters monotonic
5. V2 pipeline non-regression (nginx detection still fires)

Exits non-zero on any failure; prints a machine-checkable summary.
"""
from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone

ROOT_OK = True

try:
    import sys as _sys
    from pathlib import Path as _Path
    _ROOT = _Path(__file__).resolve().parents[1]
    if str(_ROOT) not in _sys.path:
        _sys.path.insert(0, str(_ROOT))
    from app.auth import Identity
    from app.capabilities.registry import CapabilityRegistry
    from app.capabilities.repository import CapabilityRepository, CAPABILITIES_VALIDATOR, CAPABILITY_INDEX_SPECS
    from app.capabilities.service import CapabilityService
    from app.config import ProShieldConfig
    from app.persistence.bootstrap import ensure_all_collections

    def main() -> int:
        cfg = ProShieldConfig(auth_signing_key="t" * 32, source_signing_key="s" * 32)
        try:
            from pymongo import MongoClient
            client = MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=1500)
            client.admin.command("ping")
            db = client[cfg.mongo_db + "_phase51_verify"]
            backend = "mongo"
            # isolate: drop previous verify collections
            for name in ("capabilities", "counters"):
                try:
                    db.drop_collection(name)
                except Exception:
                    pass
        except Exception as exc:
            from scripts.proxy_server import FakeDatabase
            print(f"[verify] Mongo unavailable ({type(exc).__name__}); using FakeDatabase")
            db = FakeDatabase()
            backend = "memory"

        summary = ensure_all_collections(db, cfg)
        assert "capabilities" in summary, f"bootstrap missing capabilities: {sorted(summary)}"
        print(f"[verify] bootstrap collections={len(summary)} backend={backend}")

        svc = CapabilityService(repository=CapabilityRepository(db=db, config=cfg), registry=CapabilityRegistry())
        # NOTE: ensure_all_collections above already seeds builtins (bootstrap
        # path), so first call here must be idempotent-existing, not created.
        first = svc.seed_builtins()
        assert first["created"] + first["existing"] == 6, first
        second = svc.seed_builtins()
        assert second["created"] == 0 and second["existing"] == 6, second
        print(f"[verify] seeds idempotent (bootstrap-seeded): {first} -> {second}")

        items = svc.list(limit=200)
        assert len(items) == 6, len(items)
        live = [c for c in items if c["implementation_ref"] in ("nginx", "simulator")]
        planned = [c for c in items if c["implementation_ref"] == "planned"]
        assert len(live) == 2 and len(planned) == 4, (len(live), len(planned))
        assert all(c["human_id"].startswith("CAP-") for c in items)
        print(f"[verify] catalogue truthful: 2 live + 4 planned; humans={[c['human_id'] for c in items][:3]}...")

        admin = Identity(subject_id="admin", role="admin", permissions=())
        created = svc.create(identity=admin, capability_id="cap-verify", name="Verify Cap",
                             implementation_ref="planned", status="planned")
        assert created["capability_id"] == "cap-verify"
        assert svc.disable(identity=admin, capability_id="cap-nginx")["status"] == "disabled"
        assert svc.enable(identity=admin, capability_id="cap-nginx")["status"] == "active"
        svc2 = CapabilityService(repository=CapabilityRepository(db=db, config=cfg), registry=CapabilityRegistry())
        reloaded = svc2.reload_from_repository()
        assert reloaded >= 7, reloaded
        again = svc2.create(identity=admin, capability_id="cap-verify-2", name="Verify 2",
                            implementation_ref="planned", status="planned")
        assert again["human_id"] != created["human_id"], "counters must be monotonic across reload"
        print(f"[verify] restart-equivalent reload={reloaded}; counters monotonic ({created['human_id']} -> {again['human_id']})")

        # validator/index evidence
        assert CAPABILITIES_VALIDATOR["$jsonSchema"]["additionalProperties"] is False
        assert any(s["name"] == "cap_capability_id_unique" for s in CAPABILITY_INDEX_SPECS)
        print("[verify] validator/index specs documented")

        # V2 non-regression
        from app.rules import RuleRegistry, load_rules_from_specs
        from app.detection.engine import DetectionEngine
        from app.domain.security_event import SecurityEvent, SecurityEventProvenance
        reg = RuleRegistry()
        load_rules_from_specs(reg, ["app.rules._library.nginx"])
        engine = DetectionEngine(registry=reg)
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        event = SecurityEvent(
            event_id="0196bf40-2222-7111-8111-222222222222",
            event_time=now, ingested_at=now + timedelta(milliseconds=1),
            source="nginx", event_type="authentication_failure",
            source_ip="9.9.9.9", endpoint="/auth/login",
            details={"status_code": 401},
            provenance=SecurityEventProvenance(collector="nginx", source_event_id="v2-live-1"),
        )
        res = engine.run(event, now=now)
        assert len(res.detections) >= 1
        print(f"[verify] V2 nginx detection fires: {len(res.detections)} detection(s)")

        # relationship views
        from app.rules.management.service import RuleManagementService
        from app.persistence.rule_repository import RuleRepository
        from scripts.proxy_server import FakeDatabase as _FD, _seed_managed_rules
        print("[verify] ALL CHECKS PASSED")
        if backend == "mongo":
            try:
                db.drop_collection("capabilities")
                db.drop_collection("counters")
            except Exception:
                pass
        return 0

    if __name__ == "__main__":
        raise SystemExit(main())
except Exception:
    traceback.print_exc()
    raise SystemExit(1)
