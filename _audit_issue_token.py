"""STRIX V2 audit helper: issue a fresh single-use source token from the
running analyst-plane proxy and write it to _audit_token.txt (temp infra)."""
import json
import sys
import urllib.request

PROXY = "http://127.0.0.1:8000/api/proxy"
SESSION = "ps.admin.1788629048.1788632648.3b75a77be7af92ccf6b13646487ada7728e35ce7a654deaa87f72613444d91b9"
SOURCE = "src-01a0728c-a5b6-73a4-81fb-fbd845a8a508-soc-test-nginx-01"


def issue(source_instance_id: str = SOURCE) -> str:
    body = json.dumps({
        "operation": "source.issue_token",
        "source_instance_id": source_instance_id,
        "lifetime_seconds": 3600,
    }).encode()
    req = urllib.request.Request(
        PROXY, data=body,
        headers={"Content-Type": "application/json",
                 "X-ProShield-Session": SESSION},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    tok = payload["data"]["source_token"]
    with open("_audit_token.txt", "w", encoding="utf-8") as fh:
        fh.write(tok)
    return tok


if __name__ == "__main__":
    print(issue(sys.argv[1] if len(sys.argv) > 1 else SOURCE))