"""IST display probe (Batch 1/2 verification) — canonical DB vs expected IST.

Prints the exact canonical (MongoDB, UTC) timestamps of the newest pipeline
case plus the IST strings an *independent* implementation (Python
``zoneinfo``) computes for them. The Playwright pass compares these strings
against what the browser renders, so the browser is never checked against
itself.

Usage:  python scripts/_ist_live_probe.py [--db proshield_ist_verify]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pymongo import MongoClient  # noqa: E402

MONGO_URI = "mongodb://127.0.0.1:27017"
IST = ZoneInfo("Asia/Kolkata")


def _as_utc(value) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def ist(value, with_ms: bool = True) -> str | None:
    """Independent IST rendering: 'YYYY-MM-DD HH:MM:SS(.mmm) IST'."""
    d = _as_utc(value)
    if d is None:
        return None
    local = d.astimezone(IST)
    text = local.strftime("%Y-%m-%d %H:%M:%S")
    if with_ms:
        text += f".{local.microsecond // 1000:03d}"
    return f"{text} IST"


def ist_hm(value) -> str | None:
    d = _as_utc(value)
    if d is None:
        return None
    return d.astimezone(IST).strftime("%H:%M") + " IST"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="proshield_ist_verify")
    args = parser.parse_args()

    db = MongoClient(MONGO_URI)[args.db]
    collections = sorted(db.list_collection_names())
    out: dict = {"db": args.db, "collections": collections}

    # --- newest case -------------------------------------------------------
    case_coll = next((c for c in ("incidents", "cases") if c in collections), None)
    case = None
    if case_coll:
        case = db[case_coll].find_one(sort=[("created_at", -1)])
    if not case:
        print(json.dumps({"error": "no case persisted yet", "collections": collections}, indent=2))
        return 1

    incident_id = case.get("incident_id") or case.get("case_id")
    out["case"] = {
        "collection": case_coll,
        "incident_id": incident_id,
        "human_id": case.get("human_id"),
        "state": case.get("state"),
        "canonical": {
            "created_at": str(case.get("created_at")),
            "updated_at": str(case.get("updated_at")),
            "first_seen": str(case.get("first_seen")),
            "last_seen": str(case.get("last_seen")),
        },
        "expected_ist": {
            "created_at": ist(case.get("created_at")),
            "updated_at": ist(case.get("updated_at")),
            "first_seen": ist(case.get("first_seen")),
            "last_seen": ist(case.get("last_seen")),
            "first_seen_time": ist(case.get("first_seen"), with_ms=False),
            "last_seen_time": ist(case.get("last_seen"), with_ms=False),
        },
    }

    # --- timeline items of that case --------------------------------------
    timeline = []
    if "timeline_items" in collections:
        docs = list(
            db["timeline_items"].find({"incident_id": incident_id}).sort("occurred_at", 1)
        )
        for doc in docs:
            timeline.append(
                {
                    "timeline_item_id": doc.get("timeline_item_id"),
                    "kind": doc.get("kind"),
                    "canonical_occurred_at": str(doc.get("occurred_at")),
                    "expected_ist": ist(doc.get("occurred_at")),
                }
            )
    out["timeline"] = timeline

    # --- detections + correlation of the case -----------------------------
    detections = []
    if "detections" in collections:
        evidence = case.get("evidence") or {}
        det_ids = list(evidence.get("detection_ids") or [])
        if det_ids:
            docs = list(db["detections"].find({"detection_id": {"$in": det_ids}}))
            for doc in docs:
                detections.append(
                    {
                        "detection_id": doc.get("detection_id"),
                        "human_id": doc.get("human_id"),
                        "canonical_detected_at": str(doc.get("detected_at")),
                        "expected_ist": ist(doc.get("detected_at")),
                    }
                )
    out["detections"] = detections

    correlations = []
    if "correlations" in collections:
        for doc in db["correlations"].find().sort("correlated_at", -1).limit(2):
            correlations.append(
                {
                    "correlation_id": doc.get("correlation_id"),
                    "human_id": doc.get("human_id"),
                    "canonical_correlated_at": str(doc.get("correlated_at")),
                    "expected_ist": ist(doc.get("correlated_at")),
                }
            )
    out["correlations"] = correlations

    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
