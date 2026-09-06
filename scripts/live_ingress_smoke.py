"""Live uvicorn smoke for scripts.ingress_server (D-4 proof).

Boots the REAL ingress listener on a real socket via uvicorn in a
background thread, then exercises /healthz and /api/ingress over
actual HTTP (no TestClient).
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from scripts import ingress_server  # noqa: E402
from app.config import ProShieldConfig  # noqa: E402

PORT = 18099
BASE = f"http://127.0.0.1:{PORT}"


def main() -> int:
    config = ProShieldConfig(
        env_name="test",
        auth_signing_key="live-smoke-auth",
        source_signing_key="live-smoke-source",
        default_subject_credentials={
            "admin": "admin-dev-credential",
        },
    )
    bundle = ingress_server._build_memory_ingress(config)
    app = ingress_server._build_app(bundle)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "uvicorn did not start"

    # 1. health probe over a real socket
    with urllib.request.urlopen(f"{BASE}/api/ingress/health") as r:
        body = json.loads(r.read().decode())
        assert r.status == 200 and body.get("ok") is True, body
    print("healthz:", body)

    # 2. ingest with NO token -> documented 401 over the real wire
    req = urllib.request.Request(
        f"{BASE}/api/ingress",
        data=json.dumps({"operation": "source.ingest", "events": []}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        raise AssertionError("expected 401")
    except urllib.error.HTTPError as exc2:
        body = json.loads(exc2.read().decode())
        assert exc2.code == 401, (exc2.code, body)
        assert (
            body["error"]["message"] == "source identity token missing"
        ), body
        print("no-token ingest ->", exc2.code, body)

    # 3. malformed JSON -> 400 over the real wire
    req = urllib.request.Request(
        f"{BASE}/api/ingress",
        data=b"{not-json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        raise AssertionError("expected 400")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400, exc.code
    print("malformed JSON -> 400 OK")

    server.should_exit = True
    thread.join(timeout=5)
    print("\nLIVE INGRESS LISTENER SMOKE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())