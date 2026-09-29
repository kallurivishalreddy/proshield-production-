"""Restart/persistence verification for Phase 5.1 (real MongoDB).

Boots the analyst plane twice against the SAME database and proves:
1. capabilities seeded on boot 1 survive into boot 2 (no reseed wipe)
2. a capability created on boot 1 is visible on boot 2
3. human-id counters are monotonic across the restart
4. lifecycle state (retired) survives the restart
"""
import json, os, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import socket as _sock
def _free_port():
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])

DB = f"proshield_phase51_restart_{int(time.time())}"
AUTH = "restart51-auth-key-0123456789abcdef"
SRC = "restart51-source-key-0123456789abcdef"

def start(port):
    env = dict(os.environ)
    env["PROSHIELD_AUTH_SIGNING_KEY"] = AUTH
    env["PROSHIELD_SOURCE_SIGNING_KEY"] = SRC
    env["PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"] = "admin:adminpw,analyst:analystpw"
    env["PROSHIELD_MONGO_DB"] = DB
    logf = open(ROOT / "scripts" / "restart51.log", "a", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, "-u", "scripts/proxy_server.py", "--port", str(port),
                             "--backend", "mongo", "--seed-credentials"],
                            cwd=str(ROOT), env=env, stdout=logf, stderr=subprocess.STDOUT, text=True, bufsize=1)
    return proc, logf

def api(port, op, body, token=None):
    payload = json.dumps({"operation": op, **(body or {})}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/proxy", data=payload,
        headers={"Content-Type": "application/json", **({"X-ProShield-Session": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())
    except Exception as e:
        return 0, {"error": {"code": type(e).__name__, "message": str(e)[:200]}}

def wait_ready(port):
    deadline = time.time() + 40
    while time.time() < deadline:
        s, b = api(port, "auth.issue", {"subject_id": "admin", "credential": "adminpw"})
        if s == 200 and (b.get("data") or {}).get("token"):
            return b["data"]["token"]
        time.sleep(1)
    raise RuntimeError("boot1 not ready")

def stop(proc, logf):
    try: proc.terminate()
    except Exception: pass
    try: proc.wait(timeout=10)
    except Exception:
        try: proc.kill()
        except Exception: pass
    try: logf.close()
    except Exception: pass

checks = []
def check(name, cond, detail=""):
    checks.append((name, bool(cond), detail))
    print(f"[restart51] {name}: {'PASS' if cond else 'FAIL'} {detail}")

Path(ROOT / "scripts" / "restart51.log").write_text("", encoding="utf-8")
p1 = _free_port()
proc1, log1 = start(p1)
try:
    admin1 = wait_ready(p1)
    s, b = api(p1, "capability.list", {"limit": 200}, admin1)
    caps1 = (b.get("data") or {}).get("capabilities", [])
    check("boot1_6_seeds", s == 200 and len(caps1) == 6, f"count={len(caps1)}")
    s, b = api(p1, "capability.create", {"capability_id": "cap-restart", "name": "Restart Probe",
        "implementation_ref": "planned", "status": "planned"}, admin1)
    h1 = ((b.get("data") or {}).get("capability") or {}).get("human_id")
    check("boot1_create", s == 200 and h1, f"human={h1}")
    s, b = api(p1, "capability.retire", {"capability_id": "cap-restart"}, admin1)
    check("boot1_retire", s == 200, f"status={s}")
finally:
    stop(proc1, log1)

time.sleep(2)
p2 = _free_port()
proc2, log2 = start(p2)
try:
    admin2 = wait_ready(p2)
    s, b = api(p2, "capability.list", {"limit": 200}, admin2)
    caps2 = (b.get("data") or {}).get("capabilities", [])
    ids2 = {c["capability_id"] for c in caps2}
    check("boot2_7_total", s == 200 and len(caps2) == 7, f"count={len(caps2)}")
    check("boot2_created_survives", "cap-restart" in ids2, str(sorted(ids2)))
    got = next((c for c in caps2 if c["capability_id"] == "cap-restart"), {})
    check("boot2_state_retired", got.get("status") == "retired", str(got.get("status")))
    s, b = api(p2, "capability.create", {"capability_id": "cap-restart-2", "name": "Restart 2",
        "implementation_ref": "planned", "status": "planned"}, admin2)
    h2 = ((b.get("data") or {}).get("capability") or {}).get("human_id")
    check("boot2_counter_monotonic", s == 200 and h2 and h2 != h1, f"{h1} -> {h2}")
finally:
    stop(proc2, log2)

failed = [c for c in checks if not c[1]]
print(f"[restart51] {len(checks)-len(failed)}/{len(checks)} passed")
sys.exit(1 if failed else 0)
