"""
End-to-end HTTP test of the ProShield stack.

Boots the FastAPI wrapper in-process via Starlette ``TestClient`` and
exercises every page and the underlying SecureProxy.handle boundary
exactly as the browser would.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # type: ignore

from scripts import proxy_server  # noqa: E402

bundle = proxy_server._build_memory_backend(
    proxy_server._build_config(
        argparse.Namespace(seed_credentials=True)
    )
)
app = proxy_server._build_app(bundle)

client = TestClient(app)

passed = 0
failed = 0


def step(label):
    print(">>>", label, flush=True)


def ok(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS]", label, (":: " + detail) if detail else "")
    else:
        failed += 1
        print("  [FAIL]", label, (":: " + detail) if detail else "")


# ------------------------------------------------------------
# 1. Static asset checks
# ------------------------------------------------------------
step("static asset serving")

for path in [
    "/static/login.html",
    "/static/index.html",
    "/static/cases.html",
    "/static/case.html",
    "/static/rules.html",
    "/static/sources.html",
    "/static/detections.html",
    "/static/correlations.html",
    "/static/timeline.html",
    "/static/health.html",
    "/static/css/app.css",
    "/static/js/services/api.js",
    "/static/js/components/layout.js",
    "/static/js/components/format.js",
    "/static/js/components/overview.js",
    "/static/js/components/sources.js",
    "/static/js/components/rules.js",
    "/static/js/components/cases.js",
    "/static/js/components/case.js",
    "/static/js/components/detections.js",
    "/static/js/components/correlations.js",
    "/static/js/components/timeline.js",
    "/static/js/components/health.js",
]:
    r = client.get(path)
    ok(path, r.status_code == 200, f"{r.status_code}")

# root redirects to login
r = client.get("/", follow_redirects=False)
ok("/ redirects", r.status_code in (307, 308) and
   r.headers.get("location") == "/static/login.html",
   f"status={r.status_code} loc={r.headers.get('location')}")

# ------------------------------------------------------------
# 2. API: health & meta
# ------------------------------------------------------------
step("health & meta")

r = client.get("/health")
ok("/health", r.status_code == 200 and r.json()["status"] == "ok",
   json.dumps(r.json()))

r = client.get("/api/meta")
body = r.json()
ok("/api/meta", r.status_code == 200 and body["backend_kind"] == "memory",
   json.dumps(body)[:200])

# ------------------------------------------------------------
# 3. Auth flow
# ------------------------------------------------------------
step("auth flow")

r = client.post("/api/proxy",
                json={"operation": "auth.issue",
                      "subject_id": "analyst",
                      "credential": "wrong"})
ok("auth.issue bad credential -> 401", r.status_code == 401,
   f"status={r.status_code}")

r = client.post("/api/proxy",
                json={"operation": "auth.issue",
                      "subject_id": "analyst",
                      "credential": "analyst-dev-credential"})
ok("auth.issue analyst", r.status_code == 200)
analyst_token = r.json()["data"]["token"]
analyst_session = r.json()["data"]["token"]
print("  analyst token prefix:", analyst_token[:30])

r = client.post("/api/proxy",
                json={"operation": "auth.issue",
                      "subject_id": "admin",
                      "credential": "admin-dev-credential"})
admin_token = r.json()["data"]["token"]
admin_session = r.json()["data"]["token"]
ok("auth.issue admin", r.status_code == 200)

r = client.post("/api/proxy",
                json={"operation": "auth.issue",
                      "subject_id": "collector",
                      "credential": "collector-dev-credential"})
collector_token = r.json()["data"]["token"]
collector_session = r.json()["data"]["token"]
ok("auth.issue collector", r.status_code == 200)

def proxy(op, body=None, token=None):
    headers = {}
    if token:
        headers["X-ProShield-Session"] = token
    return client.post("/api/proxy",
                       json={"operation": op, **(body or {})},
                       headers=headers)

r = proxy("case.list")
ok("unauth case.list -> 401", r.status_code == 401, f"status={r.status_code}")

r = proxy("case.list", token=collector_session)
ok("collector case.list -> 403", r.status_code == 403, f"status={r.status_code}")

# ------------------------------------------------------------
# 4. rule.list (must include seeded NGINX rules)
# ------------------------------------------------------------
step("rule.list with seeded built-ins")

r = proxy("rule.list", token=analyst_session)
ok("rule.list 200", r.status_code == 200)
rules = r.json()["data"]["rules"]
ids = sorted(rule["rule_id"] for rule in rules)
expected_prefixes = ["NGINX-ACCESS-DENIED-001", "NGINX-AUTH-BRUTEFORCE-001",
                     "NGINX-AUTH-FAILURE-001", "NGINX-RATE-LIMIT-001",
                     "NGINX-STATUS-ANOMALY-001"]
ok("rule.list has 5 rules", len(rules) == 5, f"got {len(rules)}: {ids}")
for prefix in expected_prefixes:
    ok(f"rule.list has {prefix}", any(rule["rule_id"] == prefix for rule in rules))

# ------------------------------------------------------------
# 5. Full source lifecycle
# ------------------------------------------------------------
step("source lifecycle (admin)")

r = proxy("source.list", token=analyst_session)
ok("source.list", r.status_code == 200)

import uuid
r = proxy("source.register",
          {"source_type": "nginx", "display_name": "nginx-e2e-1",
           "description": "e2e test", "tags": ["E2E", "PROD"],
           "asset_tags": ["web"]},
          token=admin_session)
ok("source.register", r.status_code == 200, r.text[:200])
got_id = r.json()["data"]["source"]["source_instance_id"]
print("  registered:", got_id)

r = proxy("source.configure",
          {"source_instance_id": got_id,
           "configuration": {"connection_type": "push",
                             "endpoint": "/ingress/e2e",
                             "asset_tags": ["web"]}},
          token=admin_session)
ok("source.configure", r.status_code == 200, r.text[:200])

r = proxy("source.validate",
          {"source_instance_id": got_id}, token=admin_session)
ok("source.validate", r.status_code == 200, r.text[:200])

r = proxy("source.enable",
          {"source_instance_id": got_id}, token=admin_session)
ok("source.enable", r.status_code == 200, r.text[:200])
ok("state=enabled",
   r.json()["data"]["source"]["state"] == "enabled",
   r.json()["data"]["source"]["state"])

r = proxy("source.get",
          {"source_instance_id": got_id}, token=analyst_session)
ok("source.get (analyst)", r.status_code == 200)

r = proxy("source.issue_token",
          {"source_instance_id": got_id, "lifetime_seconds": 300},
          token=admin_session)
ok("source.issue_token", r.status_code == 200, r.text[:200])

r = proxy("source.disable",
          {"source_instance_id": got_id}, token=admin_session)
ok("source.disable", r.status_code == 200)
ok("state=disabled",
   r.json()["data"]["source"]["state"] == "disabled")

r = proxy("source.retire",
          {"source_instance_id": got_id}, token=admin_session)
ok("source.retire", r.status_code == 200)
ok("state=retired",
   r.json()["data"]["source"]["state"] == "retired")

# ------------------------------------------------------------
# 6. Frontend HTML smoke
# ------------------------------------------------------------
step("frontend HTML content")

r = client.get("/static/index.html")
ok("index.html has #app",
   b'id="app"' in r.content,
   f"len={len(r.content)}")

r = client.get("/static/login.html")
ok("login.html has form",
   b'<form id="login-form"' in r.content,
   f"len={len(r.content)}")

r = client.get("/static/sources.html")
ok("sources.html loads sources.js",
   b"sources.js" in r.content)

r = client.get("/static/css/app.css")
ok("app.css is non-trivial",
   len(r.content) > 5_000,
   f"len={len(r.content)}")

r = client.get("/static/js/components/layout.js")
ok("layout.js has PSUI namespace",
   b"PSUI" in r.content and b"NAV" in r.content)

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
print()
print(f"PASSED: {passed}    FAILED: {failed}")
if failed:
    print("FAILURES PRESENT")
    sys.exit(1)
print("ALL E2E STACK CHECKS PASSED")
