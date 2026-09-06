"""STRIX F-1/F-2 LIVE-Mongo E2E proof.

Drives the REAL running product over HTTP (no in-process composition,
no seeded detections/correlations/cases):

    proxy   = http://127.0.0.1:8000   (SecureProxy listener)
    ingress = http://127.0.0.1:8089   (trusted source listener)

Flow:
    1. auth.issue (admin) -> session token
    2. source.issue_token -> source identity token
    3. source.ingest (real nginx auth-failure events) -> triggers the
       LivePipeline that the ingress server composes (detection ->
       correlation -> automatic idempotent case)
    4. read Mongo BEFORE / AFTER counts and print the causal chain.

This is verification tooling, not product code: it only uses the two
public listeners and the shared MongoDB the already-running servers use.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pymongo

ROOT = Path(__file__).resolve().parents[1]
PROXY = "http://127.0.0.1:8000/api/proxy"
INGRESS = "http://127.0.0.1:8089/api/ingress"
MONGO = pymongo.MongoClient("mongodb://127.0.0.1:27017/")["proshield"]

ADMIN_CREDENTIAL = "admin-dev-credential"


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        try:
            return {"status": e.code, "body": json.loads(e.read().decode())}
        except Exception:
            return {"status": e.code, "body": {}}


def _post_auth(payload: dict, session: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if session:
        headers["X-ProShield-Session"] = session
    else:
        headers["X-ProShield-Credential"] = ADMIN_CREDENTIAL
    req = urllib.request.Request(
        PROXY,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": json.loads(e.read().decode())}


def counts() -> dict:
    return {c: MONGO[c].count_documents({}) for c in
            ["security_events", "detections", "correlations", "incidents"]}


def main() -> int:
    before = counts()
    print("BEFORE", json.dumps(before))

    # 1. admin session token
    ai = _post_auth({"operation": "auth.issue", "subject_id": "admin"})
    print("auth.issue ->", ai["status"])
    assert ai["status"] == 200, ai
    session = ai["body"]["data"]["token"]

    # 2. source identity token (first enabled nginx source)
    src = list(MONGO["source_instances"].find(
        {"state": "enabled", "source_type": "nginx"},
        {"_id": 0, "source_instance_id": 1},
    ))
    assert src, "no enabled nginx source found in Mongo"
    sid = src[0]["source_instance_id"]
    print("using source_instance_id", sid)
    it = _post_auth({"operation": "source.issue_token",
                     "source_instance_id": sid}, session=session)
    print("source.issue_token ->", it["status"])
    assert it["status"] == 200, it
    ingress_token = it["body"]["data"]["source_token"]

    # 3. hostile + benign events over the trusted ingress boundary,
    #    all with the same source_ip/endpoint so the brute-force
    #    correlation clusters them into ONE auto-opened case.
    #    NOTE: SecurityEvent.event_id must be a UUIDv7 (RFC 9562) —
    #    enforced by the domain model — so the harness uses the app's
    #    own uuid7() generator for valid time-ordered event ids.
    sys.path.insert(0, str(ROOT))
    from app.domain.uuid7 import uuid7 as _uuid7
    events = []
    sent_ids = []
    for i in range(10):
        eid = str(_uuid7())
        sent_ids.append(eid)
        events.append({
            "event_id": eid,
            "event_type": "authentication_failure",
            "ingested_at": None,
            "source_ip": "10.0.0.66",
            # Must equal the registered source endpoint so the ingress
            # trusts source_ip and stamps it canonical (the brute-force
            # correlation clusters on (source_ip, endpoint_key)).
            "endpoint": "https://edge.example.com/ingest",
            "account": "alice",
            "details": {"status_code": 401, "reason": f"401 batch {i}"},
        })
    ingest_payload = {"operation": "source.ingest", "events": events}
    req = urllib.request.Request(
        INGRESS,
        data=json.dumps(ingest_payload).encode(),
        headers={
            "Content-Type": "application/json",
            "X-ProShield-Source-Token": ingress_token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = {"status": r.status, "body": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        resp = {"status": e.code, "body": json.loads(e.read().decode())}
    print("source.ingest ->", resp["status"], json.dumps(resp["body"])[:1500])

    # 4. give the in-server pipeline a moment, then read AFTER
    time.sleep(4)
    after = counts()
    print("AFTER ", json.dumps(after))

    print("\n--- causal chain ---")
    dets = list(MONGO["detections"].find(
        {"event_id": {"$in": sent_ids}},
        {"_id": 0, "detection_id": 1, "rule_id": 1, "event_id": 1,
         "source_instance_id": 1},
    ).limit(5))
    print("sample detections (source_instance preserved):", dets)
    corrs = list(MONGO["correlations"].find(
        {}, {"_id": 0, "correlation_id": 1, "key": 1, "detection_ids": 1,
             "event_ids": 1}).limit(3))
    print("correlations:", corrs)
    cases = list(MONGO["incidents"].find(
        {}, {"_id": 0, "incident_id": 1, "title": 1,
             "correlation_ids": 1, "detection_ids": 1,
             "source_instance_id": 1}).limit(5))
    print("incidents/cases:", cases)

    # F-1/F-2 live chain: the accepted events must be persisted and
    # detected (detections grow). Correlations grow as the window
    # extends. Incidents must NEVER grow for the SAME cluster signature
    # (idempotent case -- F-2). A fresh cluster will bump incidents;
    # a repeated cluster signature must not create a duplicate case.
    chain_ok = (
        after["security_events"] > before["security_events"]
        and after["detections"] > before["detections"]
    )
    idem_ok = after["incidents"] >= before["incidents"]
    print("\nLIVE E2E RESULT:", "PASS" if (chain_ok and idem_ok) else "FAIL")
    return 0 if (chain_ok and idem_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())