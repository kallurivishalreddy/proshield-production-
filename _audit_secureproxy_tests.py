"""STRIX V2 audit: SecureProxy error-code truth tests (temp infra)."""
import json
import urllib.error
import urllib.request

PROXY = "http://127.0.0.1:8000/api/proxy"
ADMIN = "ps.admin.1788629048.1788632648.3b75a77be7af92ccf6b13646487ada7728e35ce7a654deaa87f72613444d91b9"


def call(body, session=None):
    headers = {"Content-Type": "application/json"}
    if session:
        headers["X-ProShield-Session"] = session
    req = urllib.request.Request(
        PROXY, data=json.dumps(body).encode(),
        headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()[:400]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


print("NO-SESSION case.list:      ", call({"operation": "case.list"}))
print("UNKNOWN-OP:                ", call({"operation": "totally.bogus"}, ADMIN))
print("MALFORMED source.ingest:   ", call({"operation": "source.ingest", "events": [{"event_id": "x"}]}, ADMIN))

# collector login + RBAC
body = json.dumps({"operation": "auth.issue", "subject_id": "collector", "credential": "collector-dev-credential"}).encode()
req = urllib.request.Request(PROXY, data=body, headers={"Content-Type": "application/json"}, method="POST")
resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
ct = resp["data"]["token"]
print("COLLECTOR case.list:       ", call({"operation": "case.list"}, ct))
print("COLLECTOR rule.create:     ", call({"operation": "rule.create", "rule_id": "X-1", "name": "x", "severity": "high"}, ct))

# ingestion boundary: no token / wrong token on ingress
def ingress(body, auth=None):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "Bearer " + auth
    req = urllib.request.Request(
        "http://127.0.0.1:8089/api/ingress", data=json.dumps(body).encode(),
        headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]

print("INGRESS no-token:          ", ingress({"operation": "source.ingest", "events": []}))
print("INGRESS bad-token:         ", ingress({"operation": "source.ingest", "events": []}, "sit-bogus"))
print("INGRESS unknown-op:        ", ingress({"operation": "case.list"}))
print("INGRESS malformed:         ", ingress({"operation": "source.ingest", "events": [{"event_type": "bogus_type"}]}, "sit-bogus"))