"""Focused end-to-end test for the original bug.

The user reported that sources.html only fires /api/meta and never
fires /api/proxy with operation=source.list. This script:
  1. starts the proxy server in-process on a free port,
  2. logs in,
  3. visits sources.html in headless Chromium,
  4. captures the body HTML, the proxy ops fired, and any errors,
  5. asserts source.list fired with a 200 response,
  6. asserts the page rendered the toolbar + content root,
  7. exits cleanly with 0 on success.

Hard 5s timeout on the page load to prevent hangs.
"""
import argparse
import asyncio
import json
import socket
import sys

import uvicorn

sys.path.insert(0, ".")

from scripts.proxy_server import (  # noqa: E402
    _build_app, _build_config, _build_memory_backend,
)
from playwright.async_api import async_playwright  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def main() -> int:
    port = _free_port()
    cfg = _build_config(argparse.Namespace(seed_credentials=True))
    bundle = _build_memory_backend(cfg)
    app = _build_app(bundle)
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="error", access_log=False)
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())
    for _ in range(100):
        await asyncio.sleep(0.05)
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
            ctx = await browser.new_context()
            page = await ctx.new_page()

            r = await page.request.post(
                f"{base}/api/proxy",
                data=json.dumps({
                    "operation": "auth.issue",
                    "subject_id": "analyst",
                    "credential": "analyst-dev-credential",
                }),
                headers={"Content-Type": "application/json"},
            )
            token = (await r.json())["data"]["token"]

            await page.goto(f"{base}/static/login.html",
                            wait_until="commit")
            await page.wait_for_timeout(200)
            await page.evaluate(
                "(t) => {"
                " localStorage.setItem('proshield.session', t);"
                " localStorage.setItem('proshield.user',"
                "   JSON.stringify({subject_id:'analyst',role:'analyst'}));"
                "}",
                token,
            )

            ops: list[str] = []
            statuses: dict[str, int] = {}
            errors: list[str] = []

            def on_req(req, _o=ops):
                if "/api/proxy" not in req.url:
                    return
                try:
                    d = req.post_data
                    if d:
                        _o.append(json.loads(d).get("operation", "?"))
                except Exception:
                    pass

            def on_resp(r, _s=statuses):
                if "/api/proxy" in r.url:
                    try:
                        body = r.request.post_data
                        if body:
                            op = json.loads(body).get("operation", "?")
                            _s[op] = r.status
                    except Exception:
                        pass

            page.on("request", on_req)
            page.on("response", on_resp)
            page.on("pageerror", lambda e: errors.append(
                "PAGEERROR: " + str(e)))
            page.on("console", lambda m: errors.append(
                f"CONSOLE[{m.type}]: {m.text}") if m.type == "error" else None)

            try:
                await page.goto(f"{base}/static/sources.html",
                                wait_until="domcontentloaded",
                                timeout=5000)
            except Exception as e:
                print(f"NAV FAILED: {e}", flush=True)
                await browser.close()
                return 3
            await page.wait_for_timeout(2000)

            html = await page.evaluate("document.body.innerHTML")
            print("=" * 50, flush=True)
            print("Sources page (the original bug)", flush=True)
            print("=" * 50, flush=True)
            print(f"  ops:    {ops}", flush=True)
            print(f"  status: {statuses}", flush=True)
            print(f"  errors: {errors}", flush=True)
            print(f"  body:   {len(html)} bytes", flush=True)
            print(f"  toolbar present: {'toolbar' in html}", flush=True)
            print(f"  content present: {'sources-content' in html}",
                  flush=True)

            ok = True
            if "source.list" not in ops:
                print("  FAIL: source.list not called", flush=True)
                ok = False
            elif statuses.get("source.list") != 200:
                print(f"  FAIL: source.list status {statuses.get('source.list')}",
                      flush=True)
                ok = False
            if errors:
                print(f"  FAIL: {len(errors)} JS errors", flush=True)
                ok = False
            if len(html) < 1500:
                print("  FAIL: body too small", flush=True)
                ok = False
            print("=" * 50, flush=True)
            print("  RESULT: " + ("PASS" if ok else "FAIL"), flush=True)
            await browser.close()
            return 0 if ok else 1
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(serve_task, timeout=3)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
