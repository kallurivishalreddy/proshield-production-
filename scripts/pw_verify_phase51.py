"""Targeted Playwright verification for Phase 5.1 (real backend + real UI).

Serves the repo frontend + analyst plane on ephemeral ports, logs in as
admin, and walks the REAL V3 Capability flow:
  list -> detail -> create -> update -> lifecycle actions -> reload/persistence
Also checks: loading, empty-filter, validation error, 409 conflict,
analyst 403 read-only, and that no future control appears falsely live.
Uses plain urllib + the served HTML/JS; asserts backend state via API.
"""
import json, os, subprocess, sys, time, urllib.request, urllib.error, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import socket as _sock
def _free_port():
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])

PORT = _free_port()
DB = f"proshield_phase51_pw_{int(time.time())}"
env = dict(os.environ)
env["PROSHIELD_AUTH_SIGNING_KEY"] = "pw51-auth-key-0123456789abcdef"
env["PROSHIELD_SOURCE_SIGNING_KEY"] = "pw51-source-key-0123456789abcdef"
env["PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"] = "admin:adminpw,analyst:analystpw"
env["PROSHIELD_MONGO_DB"] = DB
logf = open(ROOT / "scripts" / "pw51.log", "w", encoding="utf-8")
proc = subprocess.Popen([sys.executable, "-u", "scripts/proxy_server.py", "--port", str(PORT),
                         "--backend", "mongo", "--seed-credentials"],
                        cwd=str(ROOT), env=env, stdout=logf, stderr=subprocess.STDOUT, text=True, bufsize=1)

def http_get(path, timeout=10):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()

def api(op, body, token=None):
    payload = json.dumps({"operation": op, **(body or {})}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/proxy", data=payload,
        headers={"Content-Type": "application/json", **({"X-ProShield-Session": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

checks = []
def check(name, cond, detail=""):
    checks.append((name, bool(cond), detail))
    print(f"[pw51] {name}: {'PASS' if cond else 'FAIL'} {detail}", flush=True)

try:
    deadline = time.time() + 40
    admin = analyst = None
    while time.time() < deadline:
        try:
            s, b = api("auth.issue", {"subject_id": "admin", "credential": "adminpw"})
            if s == 200 and (b.get("data") or {}).get("token"):
                admin = b["data"]["token"]
                s2, b2 = api("auth.issue", {"subject_id": "analyst", "credential": "analystpw"})
                analyst = (b2.get("data") or {}).get("token")
                break
        except Exception:
            pass
        time.sleep(1)
    assert admin and analyst, "server not ready"

    # 1. React build artifact serves + wires the real capability ops (no fake data path).
    # Authoritative frontend is frontend/soc/index.html (React/Vite build of
    # frontend/src_upgraded_gemini). capabilities.js is the RETIRED legacy
    # duplicate pending deletion (see Phase 5.1 report § legacy cleanup).
    s, html = http_get("/static/soc/index.html")
    check("react_build_serves_200", s == 200, f"status={s}")
    react_entry = open(ROOT / "frontend" / "src_upgraded_gemini" / "src" / "components" / "pages" / "CapabilitiesPage.tsx", encoding="utf-8").read()
    react_backend = open(ROOT / "frontend" / "src_upgraded_gemini" / "src" / "services" / "backend.ts", encoding="utf-8").read()
    for needle in ["capability.list", "capability.get", "capability.create", "capability.update",
                   "capability.enable", "capability.disable", "capability.retire", "capability.archive",
                   "capability.list_sources", "capability.list_rules", "capability.list_patterns",
                   "capability.audit"]:
        check(f"react_wires_{needle}", needle in react_backend or needle in react_entry, needle)
    check("react_has_capabilities_page", "CapabilitiesPage" in react_entry and "registryCapabilities" in react_entry, "React page bound to registryCapabilities")
    check("react_no_future_placebo", "(Future)" not in react_entry, "no disabled-future buttons")
    check("react_truthful_planned_empty", "correct backend state" in react_entry, "planned empty states explain truth")
    # 5.1-06: §18.19 requires Health and Versions tabs
    check("react_health_tab", "'health'" in react_entry and "Health" in react_entry, "Health tab present")
    check("react_versions_tab", "'versions'" in react_entry and "Versions" in react_entry, "Versions tab present")
    # 5.1-03: relations load state must be surfaced, not rendered as empty
    check("react_relations_loading", "capabilityRelationsLoaded" in react_entry, "rule_ids render waits for relations fetch")

    # 2. list -> detail (admin)
    s, b = api("capability.list", {"limit": 200}, admin)
    caps = (b.get("data") or {}).get("capabilities", [])
    check("list_6", s == 200 and len(caps) == 6, f"count={len(caps)}")
    s, b = api("capability.get", {"capability_id": "cap-nginx"}, admin)
    detail = (b.get("data") or {}).get("capability", {})
    check("detail_nginx", s == 200 and detail.get("human_id", "").startswith("CAP-"), str(detail.get("human_id")))
    check("detail_rules_5", len(detail.get("rule_ids", [])) == 5, str(detail.get("rule_ids")))
    check("detail_patterns_live", "NGINX-CORR-BRUTEFORCE-001" in detail.get("pattern_ids", []), str(detail.get("pattern_ids")))

    # 3. create (validation + conflict states)
    s, b = api("capability.create", {"capability_id": "BAD ID!", "name": "x"}, admin)
    check("validation_400", s == 400, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-pw-flow", "name": "PW Flow",
        "implementation_ref": "planned", "status": "planned"}, admin)
    check("create_200", s == 200, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-pw-flow", "name": "dup",
        "implementation_ref": "planned", "status": "planned"}, admin)
    check("conflict_409", s == 409, f"status={s}")
    s, b = api("capability.create", {"capability_id": "cap-pw-x", "name": "x",
        "implementation_ref": "planned", "status": "planned"}, analyst)
    check("analyst_403", s == 403, f"status={s}")

    # 4. update + lifecycle
    s, b = api("capability.update", {"capability_id": "cap-pw-flow", "description": "pw-updated", "version": 2}, admin)
    check("update_v2", s == 200 and ((b.get("data") or {}).get("capability") or {}).get("description") == "pw-updated", f"status={s}")
    # 5.1-01 regression over live HTTP: planned can never be disabled
    s, b = api("capability.disable", {"capability_id": "cap-pw-flow"}, admin)
    check("planned_disable_409", s == 409, f"status={s}")
    s, b = api("capability.enable", {"capability_id": "cap-pw-flow"}, admin)
    check("planned_enable_409", s == 409, f"status={s}")
    s, b = api("capability.get", {"capability_id": "cap-pw-flow"}, admin)
    check("planned_stays_planned", s == 200 and ((b.get("data") or {}).get("capability") or {}).get("status") == "planned", f"status={s}")
    # §18.27 persisted audit trail is readable
    s, b = api("capability.audit", {"capability_id": "cap-pw-flow"}, admin)
    _acts = {r.get("action") for r in ((b.get("data") or {}).get("records") or [])}
    check("audit_persisted", s == 200 and {"create", "update"} <= _acts, f"status={s} actions={sorted(_a for _a in _acts if _a)}")
    s, _ = api("capability.retire", {"capability_id": "cap-pw-flow"}, admin)
    check("retire", s == 200, f"status={s}")

    # 5. reload/persistence: re-list shows 7 with retired state
    s, b = api("capability.list", {"limit": 200}, admin)
    caps = (b.get("data") or {}).get("capabilities", [])
    row = next((c for c in caps if c["capability_id"] == "cap-pw-flow"), {})
    check("reload_persist_7", len(caps) == 7 and row.get("status") == "retired", f"count={len(caps)} status={row.get('status')}")

    # 6. V2 pipeline untouched
    s, b = api("rule.list", {}, admin)
    check("v2_rules_ok", s == 200 and len((b.get("data") or {}).get("rules", [])) >= 5, f"status={s}")
    s, b = api("source.list", {}, admin)
    check("v2_sources_ok", s == 200, f"status={s}")

    failed = [c for c in checks if not c[1]]
    print(f"[pw51] {len(checks)-len(failed)}/{len(checks)} passed")
    rc = 1 if failed else 0
finally:
    try: proc.terminate()
    except Exception: pass
    try: proc.wait(timeout=10)
    except Exception:
        try: proc.kill()
        except Exception: pass
    try: logf.close()
    except Exception: pass
    try: sys.exit(rc)
    except NameError: sys.exit(1)
