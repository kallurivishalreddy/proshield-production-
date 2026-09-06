"""STRIX V2 audit - controlled LOCAL EXTERNAL-LIKE TEST ENDPOINT (temp infra).

Simulates the external nginx telemetry host ("SOC-TEST-NGINX-01") as a REAL
network endpoint on 127.0.0.1:9091. It is NOT a product connector; it is a
harness used by the human-operator audit to send real HTTP pushes into the
real ProShield ingress listener (port 8089).

Endpoints
---------
GET  /            service descriptor
GET  /requests    dump every inbound request recorded so far
POST /emit        body: {event_type, status_code?, source_ip?, endpoint?,
                         count, detail?}  -> generates COUNT canonical
                         security events and pushes each to the ingress;
                         returns per-event {event_id, status, body}
POST /emit/spec    body: {events: [...]} raw event specs (override most fields)

All inbound requests are appended to ./_audit_external_requests.jsonl.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest

ROOT = os.path.dirname(os.path.abspath(__file__))
REQUEST_LOG = os.path.join(ROOT, "_audit_external_requests.jsonl")

INGRESS_URL = os.environ.get("AUDIT_INGRESS_URL", "http://127.0.0.1:8089/api/ingress")
SOURCE_TOKEN = os.environ.get("AUDIT_SOURCE_TOKEN", "")
TOKEN_FILE = os.path.join(ROOT, "_audit_token.txt")


def _load_token() -> str:
    """Return the token from env/argv or the current token file (fresh
    tokens are written per push because tokens are single-use)."""
    if SOURCE_TOKEN:
        return SOURCE_TOKEN
    try:
        with open(TOKEN_FILE, encoding="utf-8") as fh:
            tok = fh.read().strip()
            if tok:
                return tok
    except OSError:
        pass
    raise RuntimeError("no source token (env, argv, or _audit_token.txt)")


def _uuid7() -> str:
    """Minimal RFC 9562 UUIDv7 (48-bit ms | ver 7 | rand)."""
    import random
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand_a = random.getrandbits(12)
    rand_b = random.getrandbits(62)
    val = (ts << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=val))


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _record(path: str, payload: dict, result: dict) -> None:
    line = {
        "ts": _utc(),
        "path": path,
        "payload_keys": sorted(payload.keys()) if isinstance(payload, dict) else None,
        "result": result,
    }
    with open(REQUEST_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


def _canonical(spec: dict) -> dict:
    return {
        "event_id": spec.get("event_id") or _uuid7(),
        "source": spec.get("source", "nginx"),
        "event_type": spec.get("event_type", "authentication_failure"),
        "schema_version": spec.get("schema_version", "1.0"),
        "source_ip": spec.get("source_ip", "203.0.113.42"),
        "destination": spec.get("destination", "web-01.example.internal"),
        "endpoint": spec.get("endpoint", "/login"),
        "account_id": spec.get("account_id", ""),
        "asset_id": spec.get("asset_id", ""),
        "device_id": spec.get("device_id", ""),
        "timestamp": spec.get("timestamp") or _utc(),
        "provenance": {
            "collector": spec.get("provenance_collector", "soc-test-nginx-01"),
            "source_event_id": spec.get("source_event_id", ""),
        },
        "details": spec.get("details") or {},
    }


def _push_batch(specs: list) -> dict:
    """Push a SEQUENCE of events in ONE source.ingest request."""
    events = [_canonical(s) for s in specs]
    body = {"operation": "source.ingest", "events": events}
    req = urlrequest.Request(
        INGRESS_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + _load_token(),
        },
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            return {
                "count": len(events),
                "ingest_status": resp.status,
                "ingest_body": json.loads(resp_body) if resp_body else {},
            }
    except Exception as exc:  # noqa: BLE001
        body_txt = getattr(exc, "read", lambda: b"")()
        return {
            "count": len(events),
            "ingest_status": getattr(exc, "code", None),
            "error": str(exc),
            "ingest_body": (body_txt.decode("utf-8")[:2000] if body_txt else None),
        }


def _push_event(spec: dict) -> dict:
    """Push one canonical event to the ProShield ingress."""
    event = {
        "event_id": spec.get("event_id") or _uuid7(),
        "source": spec.get("source", "nginx"),
        "event_type": spec.get("event_type", "authentication_failure"),
        "schema_version": spec.get("schema_version", "1.0"),
        "source_ip": spec.get("source_ip", "203.0.113.42"),
        "destination": spec.get("destination", "web-01.example.internal"),
        "endpoint": spec.get("endpoint", "/login"),
        "account_id": spec.get("account_id", ""),
        "asset_id": spec.get("asset_id", ""),
        "device_id": spec.get("device_id", ""),
        "timestamp": spec.get("timestamp") or _utc(),
        "provenance": {
            "collector": spec.get("provenance_collector", "soc-test-nginx-01"),
            "source_event_id": spec.get("source_event_id", ""),
        },
        "details": spec.get("details") or {},
    }
    body = {"operation": "source.ingest", "events": [event]}
    req = urlrequest.Request(
        INGRESS_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + _load_token(),
        },
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=15) as resp:
            resp_body = resp.read().decode("utf-8")
            return {
                "event_id": event["event_id"],
                "ingest_status": resp.status,
                "ingest_body": json.loads(resp_body) if resp_body else {},
            }
    except Exception as exc:  # noqa: BLE001
        body_txt = getattr(exc, "read", lambda: b"")()
        return {
            "event_id": event["event_id"],
            "ingest_status": getattr(exc, "code", None),
            "error": str(exc),
            "ingest_body": (body_txt.decode("utf-8")[:2000] if body_txt else None),
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, obj: dict) -> None:
        payload = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> dict:
        ln = int(self.headers.get("Content-Length") or 0)
        if ln <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(ln).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/requests"):
            lines = []
            if os.path.exists(REQUEST_LOG):
                with open(REQUEST_LOG, encoding="utf-8") as fh:
                    lines = [json.loads(l) for l in fh if l.strip()]
            self._send(200, {"service": self.server.server_name, "requests": lines})
            return
        self._send(200, {
            "service": "SOC-TEST-NGINX-01 external-like nginx telemetry endpoint",
            "role": "controlled local external source (STRIX V2 human audit)",
            "endpoints": ["/emit", "/emit/spec", "/requests"],
            "ingress_target": INGRESS_URL,
        })

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        results = {}
        if self.path.startswith("/emit/batch"):
            # Build N specs and push them ALL in a single source.ingest
            # request (the product requires one token per request,
            # batching events inside it).
            count = int(body.get("count", 5))
            specs = []
            for _ in range(count):
                detail = dict(body.get("detail") or {})
                if body.get("status_code") is not None:
                    detail["status_code"] = body["status_code"]
                specs.append({
                    "event_type": body.get("event_type", "authentication_failure"),
                    "source_ip": body.get("source_ip", "203.0.113.42"),
                    "endpoint": body.get("endpoint", "/login"),
                    "details": detail,
                })
            results["batch"] = _push_batch(specs)
        elif self.path.startswith("/emit/spec"):
            for spec in body.get("events", []):
                results[spec.get("event_id") or _uuid7()] = _push_event(spec)
        elif self.path.startswith("/emit"):
            count = int(body.get("count", 1))
            spec = {
                "event_type": body.get("event_type", "authentication_failure"),
                "status_code": body.get("status_code"),
                "source_ip": body.get("source_ip", "203.0.113.42"),
                "endpoint": body.get("endpoint", "/login"),
            }
            detail = body.get("detail") or {}
            if spec["status_code"] is not None:
                detail["status_code"] = spec["status_code"]
            spec["details"] = detail
            for _ in range(count):
                r = _push_event(spec)
                results[r["event_id"]] = r
        else:
            self._send(404, {"error": "unknown path"})
            return
        _record(self.path, body, {"ok": True, "count": len(results)})
        self._send(200, {"ok": True, "pushed": results})


def main() -> int:
    global SOURCE_TOKEN
    if len(sys.argv) > 1:
        SOURCE_TOKEN = sys.argv[1]
    srv = ThreadingHTTPServer(("127.0.0.1", 9091), Handler)
    print("external-like endpoint listening on http://127.0.0.1:9091", flush=True)
    print("ingress target:", INGRESS_URL, flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())