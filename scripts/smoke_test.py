"""Smoke test for the proxy_server (in-memory backend).

Runs the FastAPI app in-process via ``fastapi.testclient.TestClient``
so the full SecureProxy boundary is exercised without spawning a subprocess.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # type: ignore

from scripts.proxy_server import (
    _build_app,
    _build_config,
    _build_memory_backend,
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


import logging
logging.basicConfig(level=logging.INFO)


def main() -> int:
    ns = argparse.Namespace(seed_credentials=True)
    cfg = _build_config(ns)
    bundle = _build_memory_backend(cfg)
    app = _build_app(bundle)
    client = TestClient(app)

    # 1) health
    r = client.get("/health")
    _assert(r.status_code == 200, r.text)
    print("1. health OK:", r.json())

    # 2) meta
    r = client.get("/api/meta")
    _assert(r.status_code == 200, r.text)
    print("2. meta OK:", r.json()["backend_kind"])

    # 3) auth.issue (good credential)
    r = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "analyst",
            "credential": "analyst-dev-credential",
        },
    )
    _assert(r.status_code == 200, r.text)
    token = r.json()["data"]["token"]
    print("3. auth.issue OK; token prefix:", token[:24])

    # 4) auth.issue (bad credential)
    r = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "analyst",
            "credential": "WRONG",
        },
    )
    print("4. bad credential:", r.status_code)
    _assert(r.status_code in (401, 400), r.text)

    # 5) overview.summary
    r = client.post(
        "/api/proxy",
        json={"operation": "overview.summary"},
        headers={"X-ProShield-Session": token},
    )
    _assert(r.status_code == 200, r.text)
    data = r.json()["data"]
    print(
        "5. overview.summary:",
        data.get("open_case_count"),
        data.get("scope"),
    )

    # 6) rule.list
    r = client.post(
        "/api/proxy",
        json={"operation": "rule.list"},
        headers={"X-ProShield-Session": token},
    )
    _assert(r.status_code == 200, r.text)
    rules = r.json()["data"]["rules"]
    print(
        "6. rule.list: count=",
        len(rules),
        "ids=",
        sorted({x["rule_id"] for x in rules}),
    )

    # 7) source.list
    r = client.post(
        "/api/proxy",
        json={"operation": "source.list"},
        headers={"X-ProShield-Session": token},
    )
    _assert(r.status_code == 200, r.text)
    src_data = r.json()["data"]
    print(
        "7. source.list:",
        len(src_data.get("sources", [])),
        "sources;",
        "supported_types=",
        src_data.get("supported_connector_types"),
    )

    # 8) unauth'd case.list -> 401
    r = client.post("/api/proxy", json={"operation": "case.list"})
    print("8. unauth case.list:", r.status_code)
    _assert(r.status_code == 401, r.text)

    # 9) correlation.list (no filters -> empty)
    r = client.post(
        "/api/proxy",
        json={"operation": "correlation.list"},
        headers={"X-ProShield-Session": token},
    )
    _assert(r.status_code == 200, r.text)
    print(
        "9. correlation.list:",
        len(r.json()["data"]["correlations"]),
    )

    # 10) detection.list (no filters)
    r = client.post(
        "/api/proxy",
        json={"operation": "detection.list"},
        headers={"X-ProShield-Session": token},
    )
    _assert(r.status_code == 200, r.text)
    print(
        "10. detection.list:",
        len(r.json()["data"]["detections"]),
    )

    # 11) collector cannot read cases (403)
    r = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "collector",
            "credential": "collector-dev-credential",
        },
    )
    _assert(r.status_code == 200, r.text)
    coll_token = r.json()["data"]["token"]
    r = client.post(
        "/api/proxy",
        json={"operation": "case.list"},
        headers={"X-ProShield-Session": coll_token},
    )
    print("11. collector case.list:", r.status_code)
    _assert(r.status_code == 403, r.text)

    # 12) admin auth
    r = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "admin",
            "credential": "admin-dev-credential",
        },
    )
    _assert(r.status_code == 200, r.text)
    admin_token = r.json()["data"]["token"]
    print("12. admin auth OK")

    # 13) source.register
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.register",
            "source_type": "nginx",
            "display_name": "smoke-nginx-1",
            "description": "smoke test",
            "tags": ["SMOKE"],
            "asset_tags": ["web"],
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    sid = r.json()["data"]["source"]["source_instance_id"]
    print("13. source.register OK:", sid)

    # 14) source.configure
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.configure",
            "source_instance_id": sid,
            "configuration": {
                "connection_type": "push",
                "endpoint": "/ingress/nginx-1",
                "asset_tags": ["web"],
            },
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    print("14. source.configure OK")

    # 15) source.validate
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.validate",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    print("15. source.validate OK")

    # 16) source.enable
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.enable",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    state = r.json()["data"]["source"]["state"]
    _assert(state == "enabled", f"state={state}")
    print("16. source.enable OK; state=", state)

    # 17) source.list_types
    r = client.post(
        "/api/proxy",
        json={"operation": "source.list_types"},
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    print(
        "17. source.list_types:",
        r.json()["data"]["supported_connector_types"],
    )

    # 18) source.get
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.get",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    print("18. source.get OK")

    # 19) source.issue_token
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.issue_token",
            "source_instance_id": sid,
            "lifetime_seconds": 600,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    print("19. source.issue_token OK")

    # 20) source.disable
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.disable",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    _assert(r.json()["data"]["source"]["state"] == "disabled", "")
    print("20. source.disable OK")

    # 21) source.retire
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.retire",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin_token},
    )
    _assert(r.status_code == 200, r.text)
    _assert(r.json()["data"]["source"]["state"] == "retired", "")
    print("21. source.retire OK")

    print("\nALL 21 SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())