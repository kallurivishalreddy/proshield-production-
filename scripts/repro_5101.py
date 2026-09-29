"""Independent reproduction of DeepSeek finding 5.1-01.

planned capability -> capability.disable -> persisted state -> read/restart.
Real MongoDB. Fresh DB, dropped afterwards.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

from pymongo import MongoClient

from app.auth.identity import Identity
from app.capabilities.models import CAPABILITIES_COLLECTION
from app.capabilities.registry import CapabilityRegistry
from app.capabilities.repository import CapabilityRepository
from app.capabilities.service import CapabilityService
from app.config import ProShieldConfig

DB_NAME = "repro_5101_check"
MONGO = "mongodb://127.0.0.1:27017"


def _config() -> ProShieldConfig:
    return ProShieldConfig(auth_signing_key="t" * 32, source_signing_key="s" * 32)


def _admin() -> Identity:
    return Identity(subject_id="admin", role="admin", permissions=())


def build_service(client) -> CapabilityService:
    db = client[DB_NAME]
    repo = CapabilityRepository(db=db, config=_config())
    repo.ensure_schema()
    repo.ensure_indexes()
    svc = CapabilityService(repository=repo, registry=CapabilityRegistry())
    return svc


def main() -> int:
    client = MongoClient(MONGO)
    client.drop_database(DB_NAME)
    try:
        # 1. seed built-ins (includes planned cap-waf)
        svc = build_service(client)
        result = svc.seed_builtins()
        print("seed:", result)
        assert result["created"] == 6, result

        # 2. attempt disable on a PLANNED capability (5.1-01 exploit path)
        try:
            out = svc.disable(identity=_admin(), capability_id="cap-waf")
            print("disable -> UNEXPECTED SUCCESS:", out["status"])
            return 2
        except Exception as exc:  # noqa: BLE001
            print("disable on planned -> REFUSED:", type(exc).__name__, getattr(exc, "safe_message", exc))

        # 3. the persisted document must be untouched and valid
        raw_doc = client[DB_NAME][CAPABILITIES_COLLECTION].find_one({"capability_id": "cap-waf"})
        print("raw persisted doc status:", raw_doc and raw_doc.get("status"),
              "impl:", raw_doc and raw_doc.get("implementation_ref"))
        if raw_doc is None or raw_doc.get("status") != "planned":
            print("\n*** FAIL: planned capability document was modified ***")
            return 2

        # 4. RESTART: fresh service + registry, read from repository only
        svc2 = build_service(client)
        reread = svc2._repository.get("cap-waf")
        print("after restart repository.get ->", "QUARANTINED (None)" if reread is None else reread.status)
        listed = [c.capability_id for c in svc2._repository.find_all()]
        print("after restart find_all includes cap-waf:", "cap-waf" in listed)
        n = svc2.reload_from_repository()
        print("reload_from_repository registered:", n)

        # 5. recovery: the next LEGAL transition works (planned -> retired)
        recovered = svc2.retire(identity=_admin(), capability_id="cap-waf")
        print("recovery retire ->", recovered["status"])
        svc3 = build_service(client)
        print("second restart read ->", svc3._repository.get("cap-waf").status)

        if reread is not None and recovered["status"] == "retired":
            print("\n*** FINDING 5.1-01 FIXED: invalid transition refused pre-write; document valid across restarts; recovery works ***")
            return 0
        print("\n*** FAIL: unexpected state ***")
        return 2
    finally:
        client.drop_database(DB_NAME)
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
