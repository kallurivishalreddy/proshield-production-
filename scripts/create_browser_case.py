"""Create one fresh OPEN case through the real pipeline for the
browser verification journey."""
import json
import time
import urllib.request

BASE = "http://127.0.0.1:8088"
INGRESS = "http://127.0.0.1:8089"


def proxy(op, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{BASE}/api/proxy",
        data=json.dumps({"operation": op, **(body or {})}).encode(),
        headers=headers, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


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


admin = proxy("auth.issue", {"subject_id": "admin",
                             "credential": "admin-dev-credential"})["data"]["token"]
body = proxy("source.list", {}, token=admin)
candidates = [s for s in body["data"]["sources"]
              if s["display_name"] == "live-verification-nginx"
              and s["state"] == "enabled"]
if not candidates:
    raise SystemExit("no enabled live-verification source; candidates: "
                     + json.dumps([(s["display_name"], s["state"])
                                   for s in body["data"]["sources"]]))
src = candidates[-1]
sid = src["source_instance_id"]

nonce = f"{int(time.time()) % 0xFFFFFFFF:08x}"
ip = f"203.0.113.{80 + (int(time.time()) % 20)}"
for i in range(6):
    tok = proxy("source.issue_token", {"source_instance_id": sid},
                token=admin)["data"]["source_token"]
    ev = {
        "event_type": "authentication_failure",
        "event_id": f"0198c2a1-0000-7000-8000-{nonce}{i:04d}",
        "source_event_id": f"browser-{nonce}-{i}",
        "event_time": "2026-09-07T10:00:00Z",
        "source_ip": ip,
        "endpoint": "/api/login",
        "asset": "browser-audit",
        "account": {"id": f"u{i % 2}"},
        "details": {"http_method": "POST", "status_code": 401},
    }
    ingress({"operation": "source.ingest", "events": [ev]}, tok)

time.sleep(1.0)
cases = proxy("case.list", {"limit": 50}, token=admin)["data"]["cases"]
case = next(c for c in cases
            if (c.get("attribution") or {}).get("attacker") == ip)
with open("browser_case.txt", "w", encoding="utf-8") as f:
    f.write(json.dumps({
        "human_id": case.get("human_id"),
        "incident_id": case["incident_id"],
        "state": case["state"],
        "attacker": ip,
    }, indent=1))
print("created", case.get("human_id"), case["state"], ip)
