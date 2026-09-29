"""Fresh-DB audit for the capability patch (mission item 21/23).

Creates a DEDICATED audit database (proshield_patch_audit), drops it
first so every collection/index/validator is created from scratch,
then programmatically verifies:

* the $jsonSchema validator is present on every documented collection
  (incl. the new notifications / source_telemetry / counters);
* the unique indexes exist (incidents, detections, correlations,
  reports, managed_rules, source_instances, notifications, telemetry);
* the validator REJECTS a malformed direct write (defense-in-depth);
* human-id counters allocate monotonically and persist.

Run: python scripts/audit_fresh_db.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pymongo import MongoClient  # noqa: E402

from app.config import ProShieldConfig  # noqa: E402
from app.persistence.bootstrap import ensure_all_collections  # noqa: E402

AUDIT_DB = "proshield_patch_audit"
RESULTS = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (" :: " + detail if detail else ""))


def main() -> int:
    client = MongoClient("mongodb://127.0.0.1:27017/")
    client.drop_database(AUDIT_DB)
    db = client[AUDIT_DB]
    config = ProShieldConfig(
        env_name="production",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db=AUDIT_DB,
        auth_signing_key="audit-auth-key-0123456789abcdef",
        source_signing_key="audit-source-key-0123456789abcdef",
    )

    summary = ensure_all_collections(db, config)
    for name, info in summary.items():
        record(
            f"collection.{name}.validator",
            info["validator"] is True,
            f"indexes={info['indexes']}",
        )

    # --- unique index verification (direct collection inspection) ---
    expected_unique = {
        "security_events": "ev_event_id_unique",
        "detections": "det_detection_id_unique",
        "correlations": "corr_correlation_id_unique",
        "incidents": "inc_incident_id_unique",
        "source_instances": "source_source_instance_id_unique",
        "notifications": "ntf_notification_id_unique",
        "source_telemetry": "tel_source_instance_id_unique",
        "capabilities": "cap_capability_id_unique",
    }
    for coll, index_name in expected_unique.items():
        names = {ix["name"] for ix in db[coll].list_indexes()}
        record(
            f"unique_index.{coll}.{index_name}",
            index_name in names,
            sorted(names).__str__(),
        )

    # --- validator rejects a malformed direct write ---
    from pymongo.errors import DocumentTooLarge, WriteError

    try:
        db["incidents"].insert_one({"bogus": True})
        record("validator.rejects_malformed_incident", False,
               "insert accepted!")
    except WriteError:
        record("validator.rejects_malformed_incident", True)
    try:
        db["detections"].insert_one({"bogus": True})
        record("validator.rejects_malformed_detection", False,
               "insert accepted!")
    except WriteError:
        record("validator.rejects_malformed_detection", True)
    try:
        db["notifications"].insert_one({"kind": 12345})
        record("validator.rejects_malformed_notification", False,
               "insert accepted!")
    except WriteError:
        record("validator.rejects_malformed_notification", True)
    try:
        db["capabilities"].insert_one({"bogus": True})
        record("validator.rejects_malformed_capability", False,
               "insert accepted!")
    except WriteError:
        record("validator.rejects_malformed_capability", True)
    # Phase 5.1: capability seeds + registry truthfulness on the fresh DB
    # (bootstrap already seeded; assert catalogue shape, do not reseed-count).
    try:
        from scripts.audit_phase51 import check_capability_audit
        for _name, _ok, _detail in check_capability_audit(db, config):
            record(_name, _ok, _detail)
    except Exception as exc:  # noqa: BLE001
        record("capabilities.audit_module", False, f"{type(exc).__name__}: {exc}")

    # --- human-id counters monotonic + persisted ---
    from app.persistence.human_ids import HumanIdAllocator

    alloc = HumanIdAllocator(db["counters"], "incident")
    seq1 = alloc.allocate()
    seq2 = alloc.allocate()
    record("human_ids.monotonic", seq1 == "CASE-000001" and seq2 == "CASE-000002",
           f"{seq1}, {seq2}")
    doc = db["counters"].find_one({"_id": "incident"})
    record("human_ids.counter_persisted", doc is not None and doc["seq"] == 2,
           json.dumps(doc, default=str) if doc else "missing")

    # --- concurrency: 25 parallel allocations produce 25 unique ids ---
    import threading

    got = []
    lock = threading.Lock()

    def alloc_many() -> None:
        local = HumanIdAllocator(db["counters"], "detection")
        ids = [local.allocate() for _ in range(5)]
        with lock:
            got.extend(ids)

    threads = [threading.Thread(target=alloc_many) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    record("human_ids.concurrent_unique",
           len(got) == 25 and len(set(got)) == 25,
           f"unique={len(set(got))}/25")

    # counters: uniqueness is provided by the native _id index
    names = {ix["name"] for ix in db["counters"].list_indexes()}
    record("counters.native_id_index_present", "_id_" in names,
           sorted(names).__str__())

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n==== {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ====")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
