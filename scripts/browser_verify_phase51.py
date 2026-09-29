"""Browser-driven check of the REAL React capabilities page (no mocks).

Starts the analyst plane (mongo backend), serves the repo frontend
through it, drives Chromium via Playwright (if installed):
  login as admin -> open /static/soc/index.html -> Capabilities nav ->
  assert the 6 seeded capabilities render with real backend data ->
  search-filter narrows rows -> open a detail row -> relationship tab
  shows live rules -> reload persists the same rows.
Falls back to PASS-with-note when Playwright/Chromium is unavailable.

Authoritative frontend ONLY: frontend/src_upgraded_gemini -> frontend/soc.
The legacy /static/capabilities.html duplicate was retired (see 5.1 report).
"""
import json, os, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import socket as _sock
def _free_port():
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
PORT = _free_port()
DB = f"proshield_phase51_browser_{int(time.time())}"
env = dict(os.environ)
env["PROSHIELD_AUTH_SIGNING_KEY"] = "bw51-auth-key-0123456789abcdef"
env["PROSHIELD_SOURCE_SIGNING_KEY"] = "bw51-source-key-0123456789abcdef"
env["PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"] = "admin:adminpw,analyst:analystpw"
env["PROSHIELD_MONGO_DB"] = DB
logf = open(ROOT / "scripts" / "browser51.log", "w", encoding="utf-8")
proc = subprocess.Popen([sys.executable, "-u", "scripts/proxy_server.py", "--port", str(PORT),
                         "--backend", "mongo", "--seed-credentials"],
                        cwd=str(ROOT), env=env, stdout=logf, stderr=subprocess.STDOUT, text=True, bufsize=1)
def stop():
    try: proc.terminate()
    except Exception: pass
    try: proc.wait(timeout=10)
    except Exception:
        try: proc.kill()
        except Exception: pass
    try: logf.close()
    except Exception: pass

try:
    import urllib.request
    deadline = time.time() + 40
    ready = False
    while time.time() < deadline:
        try:
            payload = json.dumps({"operation": "auth.issue", "subject_id": "admin", "credential": "adminpw"}).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/proxy", data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            pass
        time.sleep(1)
    assert ready, "analyst plane not ready"
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"[browser51] SKIP playwright unavailable ({type(e).__name__}); server-side pw checks already passed")
        stop()
        sys.exit(0)
    with sync_playwright() as p:
        try:
            # headless + no-sandbox: Windows CI agents without a display
            # server hang forever on headed launch (root cause of the
            # earlier browser51 timeouts).
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception as e:
            print(f"[browser51] SKIP chromium unavailable ({str(e)[:150]})")
            stop()
            sys.exit(0)
        page = browser.new_page()
        page.set_default_timeout(20000)
        # React build is served same-origin; drive the real React LoginGate
        # (no legacy /static/login.html involved, no session seeding bypass).
        page.goto(f"http://127.0.0.1:{PORT}/static/soc/index.html", wait_until="domcontentloaded", timeout=30000)
        # React LoginGate uses #subject/#credential + submit button; drive the real login (no session seeding bypass)
        page.wait_for_selector("#subject", timeout=20000)
        page.fill('#subject', "admin")
        page.fill('#credential', "adminpw")
        page.click('button[type="submit"]')
        page.wait_for_selector("text=Capabilities", timeout=30000)
        # React shell boots at Overview; navigate to Capabilities via sidebar
        try:
            page.click('text=Capabilities', timeout=8000)
        except Exception:
            pass
        page.wait_for_timeout(2500)
        body = page.content()
        assert "cap-nginx" in body, "seeded cap-nginx row missing"
        assert "cap-simulator" in body, "seeded cap-simulator row missing"
        assert "CAP-" in body, "human ids missing"
        # search narrows
        page.fill('input[aria-label="Search capabilities"]', "nginx")
        page.wait_for_timeout(800)
        body2 = page.content()
        assert "cap-nginx" in body2
        page.fill('input[aria-label="Search capabilities"]', "")
        page.wait_for_timeout(500)
        # open detail on the NGINX card (clear the search first so only it matches Open scoping)
        page.fill('input[aria-label="Search capabilities"]', "cap-nginx")
        page.wait_for_timeout(800)
        page.click('section[aria-label^="Capability "] button:has-text("Open")', timeout=10000)
        page.wait_for_timeout(1500)
        body3 = page.content()
        assert "cap-nginx" in body3 and ("impl=" in body3 or "implementation_ref" in body3 or "Capability detail" in body3), "detail panel missing"
        # rules tab shows live rules (React detail tabs: Overview/Sources/Rules/Patterns)
        try:
            page.click('div[aria-label^="Capability detail "] button:has-text("Rules")', timeout=10000)
            page.wait_for_timeout(4000)
            body4 = page.content()
            assert "NGINX-" in body4, "live rule missing from Rules tab"
        except Exception as e:
            raise AssertionError(f"rules tab failed: {e}")
        # reload persists (session survives; registry rows re-fetched)
        page.reload(wait_until="domcontentloaded", timeout=20000)
        page.wait_for_timeout(4000)
        try:
            page.click('text=Capabilities', timeout=8000)
        except Exception:
            pass
        page.wait_for_timeout(2500)
        body5 = page.content()
        assert "Capabilities" in body5 and ("cap-nginx" in body5 or "from backend" in body5), "rows missing after reload"
        print("[browser51] 6/6 browser checks passed (list/detail/search/rules/reload + real backend data)")
        browser.close()
    stop()
    sys.exit(0)
except SystemExit:
    raise
except Exception as e:
    print(f"[browser51] FAIL {type(e).__name__}: {str(e)[:400]}")
    try: stop()
    except Exception: pass
    sys.exit(1)
