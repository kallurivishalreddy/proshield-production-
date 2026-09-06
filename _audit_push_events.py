"""STRIX V2 audit: push controlled events through the external endpoint."""
import json
import sys
import urllib.request

sys.path.insert(0, ".")

from _audit_issue_token import issue  # noqa: E402

EXTERNAL = "http://127.0.0.1:9091/emit/spec"


def push(spec: dict) -> None:
    tok = issue()
    body = json.dumps({"events": [spec]}).encode()
    req = urllib.request.Request(
        EXTERNAL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(json.dumps(json.loads(resp.read().decode()), indent=2))


if __name__ == "__main__":
    which = sys.argv[1]
    if which == "no-rule":
        # Valid nginx event type with NO matching rule anywhere.
        push({
            "event_id": "01a0729f-0000-7001-8000-000000000001",
            "source": "nginx",
            "event_type": "tls_anomaly",
            "source_ip": "198.51.100.77",
            "endpoint": "/api/tls",
            "details": {"reason": "certificate_cn_mismatch"},
        })
    elif which == "benign":
        # Close-to-boundary benign auth SUCCESS (must NOT fire).
        push({
            "event_id": "01a0729f-0000-7001-8000-000000000002",
            "source": "nginx",
            "event_type": "authentication_success",
            "source_ip": "203.0.113.42",
            "endpoint": "/login",
            "details": {"status_code": 200, "http_method": "POST"},
        })
    elif which == "attack-new":
        # NEW 401 after NGINX-AUTH-FAILURE-001 was disabled via UI.
        push({
            "event_id": "01a0729f-0000-7001-8000-000000000003",
            "source": "nginx",
            "event_type": "authentication_failure",
            "source_ip": "203.0.113.99",
            "endpoint": "/login",
            "details": {"status_code": 401},
        })
    elif which == "dup-attack":
        # Duplicate event_id of an ALREADY-INGESTED event (idempotency attack).
        push({
            "event_id": "01a0729b-05b2-7271-b029-906ab1ab75eb",
            "source": "nginx",
            "event_type": "authentication_failure",
            "source_ip": "203.0.113.42",
            "endpoint": "/login",
            "details": {"status_code": 401},
        })
    else:
        print("unknown scenario", which)