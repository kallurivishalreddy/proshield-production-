"""STRIX F-2 live idempotency: re-delivering the same events must not
grow detections/correlations/incidents (no duplicate case)."""
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pymongo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.domain.uuid7 import uuid7

PROXY = "http://127.0.0.1:8000/api/proxy"
INGRESS = "http://127.0.0.1:8089/api/ingress"
MONGO = pymongo.MongoClient("mongodb://127.0.0.1:27017/")["proshield"]
SID = ("src-01a06c99-cff7-7ca9-91c1-c1969316ae88-nginx-prod-web-01")


def call(url, payload, headers):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def counts():
    return {c: MONGO[c].count_documents({}) for c in
            ["security_events", "detections", "correlations", "incidents"]}


def main():
    _, ai = call(PROXY, {"operation": "auth.issue", "subject_id": "admin"},
                 {"Content-Type": "application/json",
                  "X-ProShield-Credential": "admin-dev-credential"})
    session = ai["data"]["token"]
    h = {"Content-Type": "application/json", "X-ProShield-Session": session}
    _, it = call(PROXY, {"operation": "source.issue_token",
                         "source_instance_id": SID}, h)
    tok = it["data"]["source_token"]

    fixed = [{
        "event_id": str(uuid7()),
        "event_type": "authentication_failure",
        "source_ip": "10.99.99.99",
        "endpoint": "https://edge.example.com/ingest",
        "details": {"status_code": 401},
    } for _ in range(6)]
    body = {"operation": "source.ingest", "events": fixed}

    before = counts()
    for round_no in (1, 2, 3):
        sc, rb = call(INGRESS, body,
                      {"Content-Type": "application/json",
                       "X-ProShield-Source-Token": tok})
        time.sleep(1.5)
        after = counts()
        print(f"round {round_no}: status={sc} after={after}")
    print("BEFORE", before)
    grew_after_repeat = (
        after["detections"] > before["detections"]
        or after["correlations"] > before["correlations"]
        or after["incidents"] > before["incidents"]
    )
    print("IDEMPOTENCY:", "PASS" if not grew_after_repeat else "FAIL")
    return 0 if not grew_after_repeat else 1


if __name__ == "__main__":
    raise SystemExit(main())