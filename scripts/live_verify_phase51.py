import sys, json, time, subprocess, os, signal
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import urllib.request

import socket as _sock
def _free_port() -> int:
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
PORT = int(__import__("os").environ.get("LIVE51_PORT", _free_port()))
env = dict(os.environ)
env["PROSHIELD_AUTH_SIGNING_KEY"] = "live51-auth-key-0123456789abcdef"
env["PROSHIELD_SOURCE_SIGNING_KEY"] = "live51-source-key-0123456789abcdef"
env["PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"] = "admin:adminpw,analyst:analystpw"
import time as _t
env["PROSHIELD_MONGO_DB"] = f"proshield_phase51_live_{int(_t.time())}"

def api(op, body, token=None, timeout=10):
    payload = json.dumps({"operation": op, **(body or {})}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/proxy", data=payload,
                                 headers={"Content-Type": "application/json", **({"X-ProShield-Session": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())
    except Exception as e:  # timeout / connection error -> fail the check, never hang the script
        return 0, {"error": {"code": type(e).__name__, "message": str(e)[:200]}}

import urllib.error
_logf = open(ROOT / "scripts" / "live51_last.log", "w", encoding="utf-8")
proc = subprocess.Popen([sys.executable, "-u", "scripts/proxy_server.py", "--port", str(PORT),
                         "--backend", "mongo", "--seed-credentials"],
                        cwd=str(ROOT), env=env, stdout=_logf, stderr=subprocess.STDOUT, text=True, bufsize=1)
try:
    # wait for readiness
    token_admin = token_analyst = None
    deadline = time.time() + 40
    ready = False
    while time.time() < deadline:
        try:
            s, b = api("auth.issue", {"subject_id": "admin", "credential": "adminpw"})
            if s == 200 and b.get("data", {}).get("token"):
                token_admin = b["data"]["token"]
                s2, b2 = api("auth.issue", {"subject_id": "analyst", "credential": "analystpw"})
                token_analyst = b2.get("data", {}).get("token")
                ready = True
                break
        except Exception:
            pass
        time.sleep(1)
    assert ready, "server did not become ready"
    checks = []
    def check(name, cond, detail=""):
        checks.append((name, bool(cond), detail))
        print(f"[live51] {name}: {'PASS' if cond else 'FAIL'} {detail}")
    s, b = api("capability.list", {"limit": 50}, token_admin)
    caps = (b.get("data") or {}).get("capabilities", [])
    check("list_6_seeds", s == 200 and len(caps) == 6, f"status={s} count={len(caps)}")
    live = [c for c in caps if c.get("implementation_ref") in ("nginx", "simulator")]
    check("two_live", len(live) == 2, f"live={len(live)}")
    s, b = api("capability.get", {"capability_id": "cap-nginx"}, token_analyst)
    cap = (b.get("data") or {}).get("capability", {})
    check("analyst_get_nginx", s == 200 and cap.get("capability_id") == "cap-nginx", f"status={s}")
    check("nginx_patterns_live", "NGINX-CORR-BRUTEFORCE-001" in (cap.get("pattern_ids") or []), str(cap.get("pattern_ids")))
    s, b = api("capability.list_rules", {"capability_id": "cap-nginx"}, token_admin)
    check("nginx_5_rules", s == 200 and (b.get("data") or {}).get("count") == 5, f"status={s} body={str(b)[:200]}")
    s, b = api("capability.list_patterns", {"capability_id": "cap-nginx"}, token_admin)
    check("nginx_patterns_view", s == 200 and (b.get("data") or {}).get("count", 0) >= 1, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-live-test", "name": "Live Test",
        "implementation_ref": "planned"}, token_analyst)
    check("analyst_create_403", s == 403, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-live-test", "name": "Live Test",
        "implementation_ref": "planned", "status": "planned"}, token_admin)
    check("admin_create_200", s == 200, f"status={s} body={str(b)[:200]}")
    created_human = ((b.get("data") or {}).get("capability") or {}).get("human_id")
    s, b = api("capability.create", {"capability_id": "cap-live-test", "name": "Dup",
        "implementation_ref": "planned", "status": "planned"}, token_admin)
    check("dup_409", s == 409, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-evil", "name": "Evil",
        "implementation_ref": "evil.py"}, token_admin)
    check("evil_impl_400", s == 400, f"status={s}")
    s, b = api("capability.update", {"capability_id": "cap-live-test", "description": "live-updated", "version": 2}, token_admin)
    check("update_v2", s == 200, f"status={s}")
    # 5.1-01 regression over live HTTP: a planned capability can NEVER be
    # disabled — the old behaviour persisted impl=planned+status=disabled
    # (model-invalid), which quarantined the document after restart.
    s, b = api("capability.disable", {"capability_id": "cap-live-test"}, token_admin)
    check("planned_disable_409", s == 409, f"status={s} body={str(b)[:200]}")
    s, b = api("capability.enable", {"capability_id": "cap-live-test"}, token_admin)
    check("planned_enable_409", s == 409, f"status={s} body={str(b)[:200]}")
    s, b = api("capability.get", {"capability_id": "cap-live-test"}, token_admin)
    check("planned_stays_planned", s == 200 and ((b.get("data") or {}).get("capability") or {}).get("status") == "planned", f"status={s} body={str(b)[:200]}")
    # live capabilities keep the disable -> enable round trip
    s, b = api("capability.disable", {"capability_id": "cap-nginx"}, token_admin)
    check("live_disable_200", s == 200 and ((b.get("data") or {}).get("capability") or {}).get("status") == "disabled", f"status={s} body={str(b)[:200]}")
    s, b = api("capability.enable", {"capability_id": "cap-nginx"}, token_admin)
    check("live_enable_200", s == 200 and ((b.get("data") or {}).get("capability") or {}).get("status") == "active", f"status={s} body={str(b)[:200]}")
    s, b = api("capability.retire", {"capability_id": "cap-live-test"}, token_admin)
    check("retire_200", s == 200, f"status={s} body={str(b)[:300]}")
    # §18.27 persisted audit: create/update/retire must leave records
    s, b = api("capability.audit", {"capability_id": "cap-live-test"}, token_admin)
    _recs = ((b.get("data") or {}).get("records") or [])
    _acts = {r.get("action") for r in _recs}
    check("audit_records_persisted", s == 200 and {"create", "update", "retire"} <= _acts, f"status={s} actions={sorted(_a for _a in _acts if _a)}")
    # persistence across restart handled by caller (restart check below re-lists)
    s, b = api("system.health.deep", {}, token_admin)
    names = [x.get("name") for x in ((b.get("data") or {}).get("health") or {}).get("subsystems", [])]
    check("health_has_capability_probe", "capability_registry" in names, str(names))
    # V2 pipeline still fine
    s, b = api("rule.list", {}, token_admin)
    check("v2_rule_list_ok", s == 200 and len((b.get("data") or {}).get("rules", [])) >= 5, f"status={s}")
    failed = [c for c in checks if not c[1]]
    print(f"[live51] {len(checks)-len(failed)}/{len(checks)} passed; created_human={created_human}")
    rc = 1 if failed else 0
finally:
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        _logf.close()
    except Exception:
        pass
    try:
        sys.exit(rc)
    except NameError:
        sys.exit(1)
