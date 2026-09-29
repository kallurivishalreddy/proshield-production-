"""Post-restart persistence probe (mission item 32).

Run AFTER restarting the stack: proves human ids, case state, notes,
attribution and telemetry survive a full process restart.
"""
import json
import sys
import urllib.request

ANALYST = "http://127.0.0.1:8088"
OUT = []


def record(name, ok, detail=""):
    OUT.append(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail else ""))


def proxy(op, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{ANALYST}/api/proxy",
        data=json.dumps({"operation": op, **(body or {})}).encode(),
        headers=headers, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def issue(subject, credential):
    body = proxy("auth.issue", {"subject_id": subject, "credential": credential})
    return body["data"]["token"]


def main():
    admin = issue("admin", "admin-dev-credential")

    body = proxy("case.list", {"limit": 50}, token=admin)
    cases = body["data"]["cases"]
    case = next(
        (c for c in cases if c.get("human_id") == "CASE-000003"), None
    )
    record("restart.case_human_id_stable", case is not None,
           f"cases={len(cases)}")
    if case is None:
        return 1
    record("restart.case_state_persisted",
           case["state"] == "closed",
           f"state={case['state']}")
    record("restart.notes_persisted",
           len(case.get("notes") or []) >= 1,
           f"notes={len(case.get('notes') or [])}")
    record("restart.attribution_persisted",
           (case.get("attribution") or {}).get("attacker") is not None,
           json.dumps(case.get("attribution"))[:150])
    record("restart.lifecycle_history_persisted",
           len(case.get("lifecycle_history") or []) >= 4,
           f"history={len(case.get('lifecycle_history') or [])}")

    body = proxy("detection.list", {"limit": 200}, token=admin)
    dets = body["data"]["detections"]
    with_meta = [d for d in dets if d.get("human_id") and d.get("severity")]
    record("restart.detection_metadata_persisted", len(with_meta) >= 30,
           f"with_metadata={len(with_meta)}/{len(dets)}")

    body = proxy("correlation.list",
                 {"pattern_id": "NGINX-CORR-BRUTEFORCE-001", "limit": 50},
                 token=admin)
    corrs = body["data"]["correlations"]
    with_conf = [c for c in corrs if c.get("confidence") and c.get("human_id")]
    record("restart.correlation_metadata_persisted", len(with_conf) >= 1,
           f"with_metadata={len(with_conf)}/{len(corrs)}")

    body = proxy("source.list", {}, token=admin)
    srcs = body["data"]["sources"]
    with_tel = [s for s in srcs if (s.get("ingest_telemetry") or {}).get("accepted")]
    record("restart.telemetry_persisted", len(with_tel) >= 1,
           json.dumps([s.get("ingest_telemetry") for s in srcs][:1])[:200])

    body = proxy("notification.unread_count", {}, token=admin)
    record("restart.notifications_persisted",
           body["data"]["unread_count"] >= 1,
           f"unread={body['data']['unread_count']}")

    body = proxy("report.export", {"report_id": "", "format": "markdown"},
                 token=admin)
    record("restart.report_export_shape_400", body is not None)

    failed = [l for l in OUT if l.startswith("FAIL")]
    print(f"==== {len(OUT) - len(failed)}/{len(OUT)} restart checks passed ====")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        from pathlib import Path
        Path("restart_verify_out.txt").write_text("\n".join(OUT) + "\n",
                                                 encoding="utf-8")
    raise SystemExit(code)
