"""Reproduce the sources page bug.

Spins up an in-process proxy server, logs in via the API client,
then loads the page in headless Chromium. Captures every request
the page makes, every console message, and the rendered HTML.

Run as a normal Python script — does not require an external
server. Prints a structured report to stdout.
"""
import asyncio
import json
import sys

from playwright.async_api import async_playwright

sys.path.insert(0, ".")

# Import the proxy server machinery and bring up an in-process
# FastAPI app bound to a free port.
import scripts.proxy_server as ps  # noqa: E402
from scripts.proxy_server import _build_config, _build_memory_backend  # noqa: E402

import argparse
import uvicorn  # noqa: E402


async def run_browser(port: int) -> int:
    base = f"http://127.0.0.1:{port}"
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        requests: list[str] = []
        responses: dict[str, int] = {}
        page.on("request", lambda req: requests.append(
            req.method + " " + req.url))
        page.on("response", lambda r: responses.setdefault(
            r.url, r.status))

        errors: list[str] = []
        page.on("pageerror", lambda exc: errors.append(
            "PAGEERROR: " + str(exc)))
        page.on("console", lambda msg: errors.append(
            f"CONSOLE[{msg.type}]: {msg.text}"))

        # 1. log in via the API client
        login = await page.request.post(
            f"{base}/api/proxy",
            data=json.dumps({
                "operation": "auth.issue",
                "subject_id": "analyst",
                "credential": "analyst-dev-credential",
            }),
            headers={"Content-Type": "application/json"},
        )
        body = await login.json()
        token = body["data"]["token"]

        # 2. seed localStorage on the same origin
        await page.goto(f"{base}/static/login.html")
        await page.evaluate(
            "(t) => {"
            " localStorage.setItem('proshield.session', t);"
            " localStorage.setItem('proshield.user',"
            "   JSON.stringify({subject_id:'analyst',role:'analyst'}));"
            "}",
            token,
        )

        # 3. now load the sources page
        requests.clear()
        errors.clear()
        responses.clear()
        bodies: list[tuple[str, str]] = []

        async def on_response(r):
            try:
                t = await r.text()
                bodies.append((r.url, t[:300] if t else ""))
            except Exception:
                pass
        page.on("response", lambda r: asyncio.create_task(on_response(r)))
        await page.goto(
            f"{base}/static/sources.html",
            wait_until="networkidle",
        )
        # Give a generous window for the SPA to issue its calls.
        await page.wait_for_timeout(2000)

        print("=== REQUESTS issued by sources.html ===")
        for r in requests:
            print("  " + r)
        print()
        print("=== RESPONSES (status by URL) ===")
        for url, st in responses.items():
            print(f"  {st}  {url}")
        print()
        print("=== POST BODIES (proxy calls) ===")
        for u, b in bodies:
            if "/api/proxy" in u:
                print(f"  {b}")
        print()
        print("=== ERRORS / CONSOLE ===")
        if not errors:
            print("  (none)")
        for e in errors:
            print("  " + e)
        print()
        body_html = await page.evaluate("document.body.innerHTML")
        print(f"=== BODY HTML length: {len(body_html)} ===")
        # Look for telltale signs of the bug
        if 'id="sources-content"' in body_html:
            print("  sources-content div is present")
        else:
            print("  sources-content div is MISSING")
        if 'class="toolbar"' in body_html:
            print("  toolbar is present")
        else:
            print("  toolbar is MISSING")
        if "No sources match" in body_html:
            print("  empty state shown")
        elif "data-source-id" in body_html or "<tr" in body_html:
            print("  table rows present")
        await browser.close()
    return 0


def main() -> int:
    # Build an in-memory backend with seeded creds.
    ns = argparse.Namespace(seed_credentials=True)
    cfg = _build_config(ns)
    bundle = _build_memory_backend(cfg)
    app = ps._build_app(bundle)
    config = uvicorn.Config(app, host="127.0.0.1", port=0,
                            log_level="warning")
    server = uvicorn.Server(config)

    async def runner() -> int:
        task = asyncio.create_task(server.serve())
        # wait for startup
        for _ in range(50):
            await asyncio.sleep(0.1)
            if server.started:
                break
        if not server.started:
            print("Server failed to start")
            return 2
        port = server.servers[0].sockets[0].getsockname()[1]
        try:
            return await run_browser(port)
        finally:
            server.should_exit = True
            await task
    return asyncio.run(runner())


if __name__ == "__main__":
    sys.exit(main())

