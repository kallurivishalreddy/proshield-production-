"""F2 - REAL Chromium verification of the Phase 5.2 Source workflow.

Starts the real analyst plane (mongo backend, fresh DB), serves the REAL
React build (frontend/soc/index.html) through it, and drives Chromium via
Playwright as a security analyst would.

Authoritative frontend ONLY: frontend/src_upgraded_gemini -> frontend/soc.
No legacy pages, no session-seeding bypass, no fabricated state.
"""
import json, os, socket, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SHOTS = ROOT / "docs" / "PHASE 5(V3)" / "PHASE 5.2" / "screenshots"
SHOTS.mkdir(parents=True, exist_ok=True)

_ok = []


def check(name, cond, detail=""):
    _ok.append((name, bool(cond)))
    line = f"  [{'PASS' if cond else 'FAIL'}] {name}"
    if detail and not cond:
        line += f"  -- {detail}"
    print(line, flush=True)
    return bool(cond)


with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    PORT = int(s.getsockname()[1])
DB = f"proshield_phase52_browser_{int(time.time())}"
env = dict(os.environ)
env["PROSHIELD_AUTH_SIGNING_KEY"] = "bw52-auth-key-0123456789abcdef"
env["PROSHIELD_SOURCE_SIGNING_KEY"] = "bw52-source-key-0123456789abcdef"
env["PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"] = "admin:adminpw,analyst:analystpw"
env["PROSHIELD_MONGO_DB"] = DB
logf = open(ROOT / "scripts" / "browser52.log", "w", encoding="utf-8")
proc = subprocess.Popen(
    [sys.executable, "-u", "scripts/proxy_server.py", "--port", str(PORT),
     "--backend", "mongo", "--seed-credentials"],
    cwd=str(ROOT), env=env, stdout=logf, stderr=subprocess.STDOUT,
    text=True, bufsize=1,
)


def stop():
    for fn in (lambda: proc.terminate(), lambda: proc.wait(timeout=10), logf.close):
        try:
            fn()
        except Exception:
            pass


def summary():
    passed = sum(1 for _, ok in _ok if ok)
    print(f"\n{passed}/{len(_ok)} browser checks passed", flush=True)
    return 0 if passed == len(_ok) else 1


try:
    import urllib.request

    deadline = time.time() + 45
    ready = False
    while time.time() < deadline:
        try:
            payload = json.dumps({
                "operation": "auth.issue",
                "subject_id": "admin",
                "credential": "adminpw",
            }).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{PORT}/api/proxy", data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            pass
        time.sleep(1)
    if not check("analyst plane + real mongo backend ready", ready):
        stop()
        sys.exit(1)

    try:
        from playwright.sync_api import sync_playwright
        HAVE_PW = True
    except Exception as exc:  # noqa: BLE001
        HAVE_PW = False
        print(f"[browser52] SKIP playwright unavailable ({type(exc).__name__})")
    if not HAVE_PW:
        stop()
        sys.exit(0)

    console_errors = []
    bad_http = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        page = browser.new_page()
        page.set_default_timeout(25000)
        page.on(
            "console",
            lambda m: console_errors.append(m.text)
            if m.type == "error" else None,
        )
        page.on(
            "response",
            lambda r: bad_http.append(f"{r.status} {r.url}")
            if r.status >= 500 else None,
        )
        BASE = f"http://127.0.0.1:{PORT}/static/soc/index.html"

        # ---------------------------------------------------------- login
        page.goto(BASE, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("#subject", timeout=20000)
        page.fill("#subject", "admin")
        page.fill("#credential", "adminpw")
        page.click('button[type="submit"]')
        page.wait_for_selector("text=Sources", timeout=30000)
        check("analyst can log in through the real LoginGate", True)

        page.click("text=Sources")
        page.wait_for_timeout(2500)
        check(
            "Sources navigation renders the Sources page",
            page.locator('[data-testid="add-source-btn"]').count() == 1,
        )
        check(
            "capability filter is populated from the REAL registry",
            "cap-nginx" in page.inner_text('[data-testid="capability-filter"]'),
            page.inner_text('[data-testid="capability-filter"]')[:200],
        )
        page.screenshot(path=str(SHOTS / "01-sources-list.png"), full_page=True)

        # ------------------------------------------------- wizard step 1-2
        page.click('[data-testid="add-source-btn"]')
        page.wait_for_selector('[data-testid="source-wizard"]', timeout=10000)
        check(
            "six-step wizard opens at step 1 (Identity)",
            page.get_attribute('[data-testid="source-wizard"]', "data-wizard-step")
            == "1",
        )
        page.fill('[data-testid="wizard-name"]', "Analyst NGINX Gateway")
        page.screenshot(path=str(SHOTS / "02-wizard-identity.png"))
        page.click('[data-testid="wizard-continue"]')
        page.wait_for_timeout(900)
        step = page.get_attribute('[data-testid="source-wizard"]', "data-wizard-step")
        check("wizard advances to step 2 (Capability)", step == "2", f"step={step}")
        body = page.content()
        check(
            "capability picker uses REAL backend capabilities (capability.list)",
            "cap-nginx" in body and "cap-simulator" in body,
        )
        check(
            "planned capabilities are NOT offered for binding",
            page.locator('[data-testid="wizard-cap-cap-waf"]').count() == 0
            and page.locator('[data-testid="wizard-cap-cap-iam"]').count() == 0,
        )
        page.click('[data-testid="wizard-cap-cap-nginx"]')
        page.wait_for_timeout(700)
        body2 = page.content()
        check(
            "binding preview shows capability_id/version truthfully",
            "cap-nginx" in body2 and "capability_version" in body2,
        )
        page.screenshot(path=str(SHOTS / "03-wizard-capability.png"))
        page.click('[data-testid="wizard-continue"]')
        page.wait_for_timeout(700)

        # ---------------------------------------------------- steps 3-4-5-6
        page.fill(
            'input[placeholder="https://ingest.example.com/hook"]',
            "https://ingest.example.test/hook",
        )
        page.click('[data-testid="wizard-continue"]')
        page.wait_for_timeout(700)
        step4 = page.get_attribute('[data-testid="source-wizard"]', "data-wizard-step")
        check("wizard reaches step 4 (Credentials)", step4 == "4", f"step={step4}")
        body4 = page.content()
        check(
            "credentials step states the credential is backend-issued (no fake token)",
            "backend-issued" in body4.lower() or "HMAC-signed" in body4,
        )
        page.screenshot(path=str(SHOTS / "04-wizard-credentials.png"))
        page.click('[data-testid="wizard-continue"]')
        page.wait_for_timeout(700)
        check(
            "wizard reaches step 5 (Validation) with a truthful summary",
            page.get_attribute('[data-testid="source-wizard"]', "data-wizard-step")
            == "5"
            and "cap-nginx" in page.content(),
        )
        page.screenshot(path=str(SHOTS / "05-wizard-validation.png"))
        page.click('[data-testid="wizard-deploy-enable"]')
        import re as _re
        try:
            # The wizard renders the credential INSIDE the modal (step 6), so
            # wait for its own confirmation copy rather than the SourcesPage
            # credential panel testid.
            page.wait_for_selector(
                "text=SOURCE ENABLED ON THE BACKEND", timeout=40000
            )
            deployed = True
        except Exception:
            deployed = False
        if not deployed:
            page.screenshot(path=str(SHOTS / "06a-deploy-error.png"))
            err_txt = page.inner_text('[data-testid="source-wizard"]')
            safe = err_txt.encode("ascii", "replace").decode("ascii")
            print(f"[browser52] deploy did not reach step 6. Modal text:\n{safe[:900]}")
            check(
                "wizard reaches step 6 (Enable & Verify)",
                False,
                "see modal text above",
            )
            raise SystemExit(summary())
        step6 = page.get_attribute('[data-testid="source-wizard"]', "data-wizard-step")
        check("wizard reaches step 6 (Enable & Verify)", step6 == "6", f"step={step6}")
        modal_txt = page.inner_text('[data-testid="source-wizard"]')
        found = _re.findall(r"sit-[0-9a-f-]{36}\.[A-Za-z0-9_.\-]+", modal_txt)
        tok = found[0] if found else ""
        check(
            "the REAL single-use credential is shown once (sit- token)",
            tok.startswith("sit-"),
            tok[:24],
        )
        check(
            "the issued credential carries the bound capability in its signed claim",
            "jYXBhYmlsaXR5X2lkIjoiY2FwLW5naW54" in tok
            or "cap-nginx" in tok,
            tok[:60],
        )
        page.screenshot(path=str(SHOTS / "06-wizard-token.png"))
        page.click('[data-testid="wizard-close"]')
        page.wait_for_timeout(2500)

        # ------------------------------------------- source detail / truth
        card = page.locator('[data-testid^="source-card-"]').first
        check("the new source instance renders as a card", card.count() == 1)
        check(
            "source detail reports the REAL capability binding",
            card.get_attribute("data-capability-id") == "cap-nginx"
            and card.get_attribute("data-binding-status") == "bound",
            f"cap={card.get_attribute('data-capability-id')} "
            f"binding={card.get_attribute('data-binding-status')}",
        )
        check(
            "source detail reports the persisted lifecycle state",
            card.get_attribute("data-lifecycle-state") in ("enabled", "validated"),
            str(card.get_attribute("data-lifecycle-state")),
        )
        human = (card.get_attribute("data-testid") or "").replace("source-card-", "")
        state_txt = page.inner_text(f'[data-testid="token-state-{human}"]')
        check(
            "credential state is reported truthfully (issuable)",
            "ISSUABLE" in state_txt,
            state_txt[:120],
        )
        check(
            "the UI never renders token material in the card",
            "sit-" not in card.inner_text(),
        )
        page.screenshot(path=str(SHOTS / "07-source-detail.png"), full_page=True)

        # --------------------------------------------------- token rotation
        page.click(f'[data-testid="rotate-token-{human}"]')
        page.wait_for_selector('[data-testid="token-panel"]', timeout=30000)
        tok2 = page.inner_text('[data-testid="token-value"]')
        check(
            "rotation issues a NEW single-use credential (different value)",
            tok2.startswith("sit-") and tok2 != tok,
        )
        page.click('[data-testid="token-panel-close"]')

        # ------------------------------------------------------- migration
        page.click('[data-testid="migration-dry-run-btn"]')
        page.wait_for_selector('[data-testid="migration-result"]', timeout=30000)
        mig = page.inner_text('[data-testid="migration-result"]')
        check(
            "migration dry-run returns real backend state (writes nothing)",
            '"dry_run": true' in mig,
            mig[:160],
        )
        page.screenshot(path=str(SHOTS / "08-migration.png"), full_page=True)

        # ----------------------------------------------------------- audit
        page.click(f'[data-testid="audit-toggle-{human}"]')
        page.wait_for_selector(f'[data-testid="audit-panel-{human}"]', timeout=20000)
        page.wait_for_timeout(2000)
        audit_txt = page.inner_text(f'[data-testid="audit-panel-{human}"]')
        check(
            "audit trail loads real server-side entries (no fabrication)",
            "did not return" not in audit_txt and "No audit entries" not in audit_txt,
            audit_txt[:160],
        )
        page.screenshot(path=str(SHOTS / "09-audit.png"), full_page=True)

        # ------------------------------------------------------- lifecycle
        page.click(f'[data-testid="toggle-source-{human}"]')
        page.wait_for_timeout(2800)
        card = page.locator('[data-testid^="source-card-"]').first
        check(
            "disable is honoured by the backend and reflected truthfully",
            card.get_attribute("data-lifecycle-state") == "disabled",
            str(card.get_attribute("data-lifecycle-state")),
        )
        page.click(f'[data-testid="toggle-source-{human}"]')
        page.wait_for_timeout(2800)
        check(
            "re-enable is honoured by the backend",
            page.locator('[data-testid^="source-card-"]').first.get_attribute(
                "data-lifecycle-state"
            )
            == "enabled",
        )

        # -------------------------------------------------- reload persists
        page.reload(wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("text=Sources", timeout=30000)
        page.click("text=Sources")
        page.wait_for_timeout(3000)
        card = page.locator('[data-testid^="source-card-"]').first
        check(
            "capability binding survives a full page reload",
            card.get_attribute("data-capability-id") == "cap-nginx"
            and card.get_attribute("data-binding-status") == "bound",
            f"cap={card.get_attribute('data-capability-id')}",
        )
        check(
            "lifecycle state survives a full page reload",
            card.get_attribute("data-lifecycle-state") == "enabled",
            str(card.get_attribute("data-lifecycle-state")),
        )
        page.screenshot(path=str(SHOTS / "10-after-reload.png"), full_page=True)

        # ------------------------------- 5.2-R-03 rule -> capability ownership
        # The Rules page used to invent a `conn-*` pseudo-capability from
        # `sources[0]`. It must now render the BACKEND's `rule.capability_id`
        # (or an honest "no capability owner"), and must never fabricate a
        # connector id. Finding 5.2-R-03 was previously never browser-covered.
        page.click("text=Rules")
        page.wait_for_timeout(3500)
        check(
            "Rules navigation renders the Rules page",
            page.locator("text=Create rule").count() >= 1,
        )
        scope_cells = page.locator('[data-testid^="rule-scope-"]')
        n_scopes = scope_cells.count()
        scope_texts = [scope_cells.nth(i).inner_text() for i in range(n_scopes)]
        scope_cap_ids = [
            scope_cells.nth(i).get_attribute("data-capability-id")
            for i in range(n_scopes)
        ]
        check(
            "rules exist to assert ownership against (real seeded library rules)",
            n_scopes > 0,
            f"scopes={n_scopes}",
        )
        check(
            "no rule scope renders a fabricated conn-* capability",
            all("conn-" not in txt for txt in scope_texts),
            str(scope_texts)[:200],
        )
        check(
            "every rule scope is a real cap-* owner or honestly unowned",
            len(scope_texts) == len(scope_cap_ids)
            and all(
                (cid or "").startswith("cap-")
                or "no capability owner" in txt.lower()
                for cid, txt in zip(scope_cap_ids, scope_texts)
            ),
            str(list(zip(scope_cap_ids, scope_texts)))[:300],
        )
        page.screenshot(
            path=str(SHOTS / "13-rules-ownership.png"), full_page=True
        )

        # Return to Sources. The responsive-overflow and retirement checks below
        # both operate on a source card, so this navigation state must be
        # restored — leaving the app on the Rules page made the retirement
        # control unfindable.
        page.click("text=Sources")
        page.wait_for_timeout(3000)
        check(
            "Sources workflow is reachable again after visiting Rules",
            page.locator(f'[data-testid="retire-source-{human}"]').count() == 1,
        )

        # ---------------------------------------------- responsive layouts
        overflow = []
        for w, h in ((1440, 900), (1280, 800), (1024, 768), (768, 1024), (390, 844)):
            page.set_viewport_size({"width": w, "height": h})
            page.wait_for_timeout(800)
            sw = page.evaluate("() => document.documentElement.scrollWidth")
            iw = page.evaluate("() => window.innerWidth")
            if sw > iw + 8:
                overflow.append(f"{w}:{sw}>{iw}")
        check(
            "no horizontal overflow at 1440/1280/1024/768/390",
            not overflow,
            str(overflow),
        )
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_timeout(800)
        page.screenshot(path=str(SHOTS / "11-responsive-390.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.wait_for_timeout(600)

        # ------------------------------------------------- retirement gate
        page.click(f'[data-testid="retire-source-{human}"]')
        page.wait_for_timeout(3200)
        card = page.locator('[data-testid^="source-card-"]').first
        check(
            "retirement is honoured by the backend",
            card.get_attribute("data-lifecycle-state") == "retired",
            str(card.get_attribute("data-lifecycle-state")),
        )
        check(
            "retired source cannot be enabled/disabled (control gated)",
            page.locator(f'[data-testid="toggle-source-{human}"]').is_disabled(),
        )
        check(
            "retired source cannot be retired again (control gated)",
            page.locator(f'[data-testid="retire-source-{human}"]').is_disabled(),
        )
        check(
            "retired source credential state is reported truthfully (RETIRED)",
            "RETIRED" in page.inner_text(f'[data-testid="token-state-{human}"]'),
            page.inner_text(f'[data-testid="token-state-{human}"]')[:120],
        )
        page.screenshot(path=str(SHOTS / "12-retired.png"), full_page=True)

        # ------------------------------------------------ console / network
        check(
            "no unexpected console errors",
            not console_errors,
            str(console_errors[:3])[:300],
        )
        check("no 5xx responses", not bad_http, str(bad_http[:3])[:300])
        browser.close()

    stop()
    sys.exit(summary())
except SystemExit:
    raise
except Exception as exc:  # noqa: BLE001
    print(f"[browser52] FAIL {type(exc).__name__}: {str(exc)[:500]}", flush=True)
    try:
        stop()
    except Exception:
        pass
    sys.exit(summary())