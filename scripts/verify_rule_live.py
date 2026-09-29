"""Live verification (gap 10): an operator-authored rule participates
in the real detection path — create -> enable -> real ingress event ->
detection produced by the new rule (provenance-traceable)."""
import json
import time
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8088"
INGRESS = "http://127.0.0.1:8089"
OUT = []


def proxy(op, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{BASE}/api/proxy",
        data=json.dumps({"operation": op, **(body or {})}).encode(),
        headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def ingress(body, token):
    req = urllib.request.Request(
        f"{INGRESS}/api/ingress",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def record(name, ok, detail=""):
    OUT.append(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail else ""))


admin = proxy("auth.issue", {"subject_id": "admin",
                             "credential": "admin-dev-credential"})[1]["data"]["token"]

rule_payload = {
    "rule_id": "LIVE-VERIFY-RULE-001",
    "version": 1,
    "name": "Live verification rule",
    "description": "operator-authored via rule.create during live verification",
    "category": "source_specific",
    "type": "detection",
    "state": "approved",
    "enabled": False,
    "severity": "medium",
    "sources": ["nginx"],
    "event_types": ["authentication_failure"],
    "tags": [],
    "references": [],
    "combinator": "and",
    "scope": [],
    "evidence_requirements": [],
    "thresholds": {},
    "window_seconds": None,
    "actions": ["alert"],
}
st, body = proxy("rule.create", rule_payload, token=admin)
record("rule.create.operator_rule", st == 200, json.dumps(body)[:200])

st, body = proxy("rule.enable", {"rule_id": "LIVE-VERIFY-RULE-001"}, token=admin)
record("rule.enable.operator_rule", st == 200, json.dumps(body)[:150])

# find the enabled verification source and ingest ONE matching event
st, body = proxy("source.list", {}, token=admin)
cands = [s for s in body["data"]["sources"]
         if s["display_name"] == "live-verification-nginx"
         and s["state"] == "enabled"]
sid = cands[-1]["source_instance_id"]
nonce = f"{int(time.time()) % 0xFFFFFFFF:08x}"
tok = proxy("source.issue_token", {"source_instance_id": sid},
            token=admin)[1]["data"]["source_token"]
ev = {
    "event_type": "authentication_failure",
    "event_id": f"0198c2a1-0000-7000-8000-{nonce}9999",
    "source_event_id": f"rule-verify-{nonce}",
    "event_time": "2026-09-07T11:00:00Z",
    "source_ip": "192.0.2.199",
    "endpoint": "/api/login",
    "details": {"http_method": "POST", "status_code": 401},
}
resp = ingress({"operation": "source.ingest", "events": [ev]}, tok)
accepted = resp.get("data", {}).get("accepted_event_ids") or []
record("ingest.event_for_rule_verification", len(accepted) == 1,
       json.dumps(resp)[:150])

time.sleep(1.5)
st, body = proxy("detection.list", {"rule_id": "LIVE-VERIFY-RULE-001", "limit": 10},
                 token=admin)
dets = body.get("data", {}).get("detections", [])
ok = st == 200 and len(dets) >= 1 and dets[0]["event_id"] == accepted[0]
record("detection.produced_by_operator_rule", ok,
       json.dumps(dets[:1])[:250] if not ok else
       f"detection_id={dets[0]['detection_id']} human_id={dets[0].get('human_id')} severity={dets[0].get('severity')}")

# rule.disable stops participation on the next event (lifecycle truth)
st, body = proxy("rule.disable", {"rule_id": "LIVE-VERIFY-RULE-001"}, token=admin)
record("rule.disable.operator_rule", st == 200)

from pathlib import Path
Path("rule_live_out.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")
failed = [l for l in OUT if l.startswith("FAIL")]
print(f"==== {len(OUT) - len(failed)}/{len(OUT)} rule checks passed ====")
raise SystemExit(1 if failed else 0)
