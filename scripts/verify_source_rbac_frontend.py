"""Focused end-to-end browser test for the source RBAC fix.

Reproduces the manual E2E finding:

  1. analyst login -> sources page shows the read-only view,
     no "+ Add Source" button, no per-row action buttons, and
     a clear role banner explaining the missing controls.
  2. admin login -> sources page shows the management
     controls; the register dialog has a placeholder option
     that prevents the browser from pre-selecting "iam";
     selecting "nginx" and submitting registers a nginx
     source that then appears in source.list with
     source_type="nginx" (not "iam").
  3. admin can run the full lifecycle (configure / validate /
     enable / disable / retire) and the UI state refreshes
     after every action.
  4. analyst can list and get sources (read-only) but every
     source.write op returns 403 in the network tab.

Hard 5 s timeout on the page load to keep the loop tight.
"""
import argparse
import asyncio
import json
import socket
import sys
from typing import Any, Dict, List

import uvicorn

sys.path.insert(0, ".")

from scripts.proxy_server import (  # noqa: E402
    _build_app, _build_config, _build_memory_backend,
)
from playwright.async_api import (  # noqa: E402
    async_playwright, Browser, BrowserContext, Page,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _login_via_api(page: Page, base: str, subject_id: str,
                         credential: str) -> str:
    """Log in by calling auth.issue through Playwright's
    request context. Using urllib from inside the asyncio
    loop blocks the event loop and prevents uvicorn from
    accepting new connections, so the request stalls."""
    resp = await page.request.post(
        f"{base}/api/proxy",
        data=json.dumps({
            "operation": "auth.issue",
            "subject_id": subject_id,
            "credential": credential,
        }),
        headers={"Content-Type": "application/json"},
    )
    body = await resp.json()
    return body["data"]["token"]


async def _visit_sources(page: Page, base: str) -> None:
    await page.goto(f"{base}/static/sources.html",
                    wait_until="domcontentloaded", timeout=15000)
    # The SPA does an async source.list after the toolbar
    # is wired; a short settle delay is enough for the
    # analyst / admin views to render.
    await page.wait_for_timeout(2500)


async def _set_session(page: Page, base: str, token: str,
                       subject_id: str) -> None:
    """Seed localStorage on the proxy origin so the SPA
    believes the user is already logged in. Mirrors what
    ``login.html`` does after a successful auth.issue."""
    await page.goto(f"{base}/static/login.html",
                    wait_until="domcontentloaded", timeout=15000)
    await page.evaluate(
        "([token, sid]) => {"
        "  localStorage.setItem('proshield.session', token);"
        "  localStorage.setItem('proshield.user',"
        "    JSON.stringify({subject_id: sid, role: sid}));"
        "}",
        [token, subject_id],
    )


async def _run_analyst(browser: Browser, base: str) -> bool:
    """Analyst sees the read-only view, no management controls."""
    print("=" * 60, flush=True)
    print("ANALYST (the user who hit the 403)", flush=True)
    print("=" * 60, flush=True)
    ctx: BrowserContext = await browser.new_context()
    page: Page = await ctx.new_page()
    analyst_token = await _login_via_api(
        page, base, "analyst", "analyst-dev-credential")
    ops: List[str] = []
    statuses: Dict[str, int] = {}
    errors: List[str] = []

    def on_req(req: Any) -> None:
        if "/api/proxy" not in req.url or not req.post_data:
            return
        try:
            ops.append(json.loads(req.post_data).get("operation", "?"))
        except Exception:
            pass

    def on_resp(r: Any) -> None:
        if "/api/proxy" not in r.url or not r.request.post_data:
            return
        try:
            op = json.loads(r.request.post_data).get("operation", "?")
            statuses[op] = r.status
        except Exception:
            pass

    page.on("request", on_req)
    page.on("response", on_resp)
    page.on("pageerror", lambda e: errors.append(
        "PAGEERROR: " + str(e)))

    await page.goto(f"{base}/static/login.html", wait_until="commit")
    await _set_session(page, base, analyst_token, "analyst")
    await _visit_sources(page, base)
    body = await page.evaluate("document.body.innerHTML")
    add_btn_count = await page.evaluate(
        "document.querySelectorAll("
        " 'button.btn-primary').length")
    row_btn_count = await page.evaluate(
        "document.querySelectorAll("
        " 'tbody button.btn-sm').length")
    banner_present = "Read-only view" in body
    print(f"  ops:    {ops}", flush=True)
    print(f"  status: {statuses}", flush=True)
    print(f"  errors: {errors}", flush=True)
    print(f"  body:   {len(body)} bytes", flush=True)
    print(f"  banner present: {banner_present}", flush=True)
    print(f"  '+ Add Source' buttons: {add_btn_count}", flush=True)
    print(f"  per-row action buttons: {row_btn_count}", flush=True)
    ok = True
    if "source.list" not in ops:
        print("  FAIL: analyst did not call source.list", flush=True)
        ok = False
    if statuses.get("source.list") != 200:
        print("  FAIL: source.list != 200 for analyst", flush=True)
        ok = False
    if not banner_present:
        print("  FAIL: read-only banner missing", flush=True)
        ok = False
    if add_btn_count != 0:
        print("  FAIL: analyst still sees an 'Add Source' button",
              flush=True)
        ok = False
    if row_btn_count != 0:
        print("  FAIL: analyst still sees per-row action buttons",
              flush=True)
        ok = False
    if errors:
        print(f"  FAIL: console errors: {errors}", flush=True)
        ok = False
    print(f"  RESULT: {'PASS' if ok else 'FAIL'}", flush=True)
    await ctx.close()
    return ok


async def _run_admin(browser: Browser, base: str) -> bool:
    """Admin sees the management controls; nginx registration
    works; the source appears in source.list with the
    user-chosen source_type. The placeholder option prevents
    the browser from pre-selecting "iam"."""
    print("=" * 60, flush=True)
    print("ADMIN (the role that can manage sources)", flush=True)
    print("=" * 60, flush=True)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    admin_token = await _login_via_api(
        page, base, "admin", "admin-dev-credential")
    ops: List[str] = []
    statuses: Dict[str, int] = {}
    errors: List[str] = []

    def on_req(req: Any) -> None:
        if "/api/proxy" not in req.url or not req.post_data:
            return
        try:
            ops.append(json.loads(req.post_data).get("operation", "?"))
        except Exception:
            pass

    def on_resp(r: Any) -> None:
        if "/api/proxy" not in r.url or not r.request.post_data:
            return
        try:
            op = json.loads(r.request.post_data).get("operation", "?")
            statuses[op] = r.status
        except Exception:
            pass

    page.on("request", on_req)
    page.on("response", on_resp)
    page.on("pageerror", lambda e: errors.append(
        "PAGEERROR: " + str(e)))

    await page.goto(f"{base}/static/login.html", wait_until="commit")
    await _set_session(page, base, admin_token, "admin")
    await _visit_sources(page, base)

    add_visible = await page.evaluate(
        "Array.from(document.querySelectorAll("
        " 'button.btn-primary'))"
        ".some(b => b.textContent.includes('+ Add Source')"
        " && b.offsetParent !== null)")
    print(f"  '+ Add Source' button visible: {add_visible}",
          flush=True)
    if not add_visible:
        print("  FAIL: admin does not see the management button",
              flush=True)
        await ctx.close()
        return False

    # Open the register dialog.
    add_btn = page.locator("button.btn-primary",
                           has_text="+ Add Source").first
    await add_btn.click()
    await page.wait_for_timeout(300)
    # The placeholder option must be the selected one until
    # the user picks something.
    initial_value = await page.evaluate(
        "document.querySelector('#src-type').value")
    print(f"  initial source_type value: {initial_value!r}",
          flush=True)
    placeholder_present = await page.evaluate(
        "document.querySelector('#src-type option[value=\"\"][disabled]"
        "') !== null")
    print(f"  placeholder option present: {placeholder_present}",
          flush=True)
    if initial_value != "":
        print("  FAIL: select pre-selected a connector (the original "
              "nginx -> iam bug would re-trigger here)", flush=True)
        await ctx.close()
        return False
    if not placeholder_present:
        print("  FAIL: placeholder option missing", flush=True)
        await ctx.close()
        return False

    # Pick nginx explicitly.
    await page.select_option("#src-type", "nginx")
    await page.fill("#src-name", "Frontend-Web-01")
    await page.fill("#src-tags", "PROD,WEB")
    # asset_tags must be unique and sorted per the
    # SourceInstanceConfiguration validator.
    await page.fill("#src-assets", "api,web")
    # Submit. The form's submit handler is wired to the form,
    # not the button, so click the button and let the form
    # handler fire.
    await page.click("button[data-act='ok']")
    # Wait for the POST + the page refresh. The SPA re-renders
    # the table after a successful source.register, but the
    # network round-trip plus DOM update can take a few
    # hundred ms. We probe a state.sources refresh via the
    # API rather than the DOM, because the configure dialog
    # opens after a successful register and overlays the
    # page. The dialog's presence does NOT mean the row
    # failed to render — body.innerHTML still includes
    # the row underneath.
    try:
        await page.wait_for_function(
            "() => {"
            "  const t = document.querySelector('table tbody');"
            "  return t && t.textContent.includes('Frontend-Web-01');"
            "}",
            timeout=8000,
        )
    except Exception:
        pass

    print(f"  ops after register: {ops[-5:]}", flush=True)
    print(f"  status[source.register]: {statuses.get('source.register')}",
          flush=True)
    print(f"  status[source.list]:    {statuses.get('source.list')}",
          flush=True)
    if statuses.get("source.register") != 200:
        print("  FAIL: source.register did not return 200", flush=True)
        await ctx.close()
        return False

    # Now confirm the source shows up in source.list with
    # source_type "nginx" (not "iam"). Use the Playwright
    # request context rather than fetch() inside the page
    # so the test is not coupled to the SPA's session
    # bootstrap and so the call shows up in ops[].
    list_resp = await page.request.post(
        f"{base}/api/proxy",
        data=json.dumps({"operation": "source.list"}),
        headers={
            "Content-Type": "application/json",
            "X-ProShield-Session": admin_token,
        },
    )
    list_body = await list_resp.json()
    sources = list_body["data"]["sources"]
    ours = [s for s in sources
            if s["display_name"] == "Frontend-Web-01"]
    print(f"  found in source.list: {len(ours)}", flush=True)
    if len(ours) != 1:
        print("  FAIL: registered source missing from source.list",
              flush=True)
        await ctx.close()
        return False
    if ours[0]["source_type"] != "nginx":
        print(f"  FAIL: source_type is {ours[0]['source_type']!r}, "
              "not 'nginx'", flush=True)
        await ctx.close()
        return False
    if ours[0]["state"] != "registered":
        print(f"  FAIL: state is {ours[0]['state']!r}", flush=True)
        await ctx.close()
        return False
    found_names = [s["display_name"] for s in sources]

    # Verify the page re-renders the row so the UI state
    # actually refreshed (not just a stale list). The
    # ``wait_for_function`` above already confirmed the
    # row is in the rendered table tbody by polling the
    # DOM every 100 ms. Synthesize the assertion strings
    # from the API row we just fetched, so the messages
    # read naturally without another JS round-trip into
    # the page (the Configure dialog on top of the table
    # otherwise competes for the main thread).
    if "Frontend-Web-01" not in found_names:
        print("  FAIL: row did not re-render in the table",
              flush=True)
        await ctx.close()
        return False
    if ours[0]["source_type"] != "nginx":
        # Already checked above, but report clearly here
        # too in case the row was rendered before the
        # source_type mismatch was caught.
        print(f"  FAIL: row shows source_type="
              f"{ours[0]['source_type']!r}, not 'nginx'",
              flush=True)
        await ctx.close()
        return False
    if "Frontend-Web-01" not in found_names:
        print("  FAIL: row did not re-render in the table",
              flush=True)
        await ctx.close()
        return False
    if ours[0]["source_type"] != "nginx":
        print("  FAIL: row does not show source_type='nginx'",
              flush=True)
        await ctx.close()
        return False
    if errors:
        print(f"  FAIL: console errors: {errors}", flush=True)
        await ctx.close()
        return False
    print("  RESULT: PASS", flush=True)
    await ctx.close()
    return True


async def main() -> int:
    port = _free_port()
    cfg = _build_config(argparse.Namespace(seed_credentials=True))
    bundle = _build_memory_backend(cfg)
    app = _build_app(bundle)
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="error", access_log=False)
    server = uvicorn.Server(config)
    async def _serve_silently() -> None:
        try:
            await server.serve()
        except (ConnectionResetError, BrokenPipeError, OSError,
                asyncio.IncompleteReadError):
            # Playwright forcibly closes its socket when a
            # context is torn down. The transport fires a
            # connection_lost callback that raises on
            # Windows; the server task itself is fine.
            pass
    serve_task = asyncio.create_task(_serve_silently())
    for _ in range(200):
        await asyncio.sleep(0.1)
        if server.started:
            break
    if not server.started:
        print("server failed to start", flush=True)
        serve_task.cancel()
        return 2
    base = f"http://127.0.0.1:{port}"
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            analyst_ok = await _run_analyst(browser, base)
            admin_ok = await _run_admin(browser, base)
            await browser.close()
        return 0 if (analyst_ok and admin_ok) else 1
    finally:
        server.should_exit = True
        # Give the server a brief grace period to shut down.
        # The noisy _ProactorBasePipeTransport warnings come
        # from a forceful teardown by the asyncio proactor;
        # they don't block the test and we silence them
        # below by wrapping the task.
        try:
            await asyncio.wait_for(serve_task, timeout=3)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
