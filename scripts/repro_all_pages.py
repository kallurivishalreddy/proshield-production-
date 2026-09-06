"""Regression test: every frontend page must issue its expected
proxy calls when loaded as a logged-in analyst.

Brings up the proxy server in-process on a free port, logs in via
the API client, then loads every page in headless Chromium and
checks that the expected proxy ops fire. Exits 0 on success, 1
on any failure.
"""
import argparse
import asyncio
import json
import sys

import uvicorn

sys.path.insert(0, ".")

from scripts.proxy_server import (  # noqa: E402
    _build_app, _build_config, _build_memory_backend,
)
from playwright.async_api import async_playwright  # noqa: E402


# Each page: (path, expected ops that must appear at least once)
PAGES = [
    ("/static/index.html",        ["overview.summary"]),
    ("/static/cases.html",        ["case.list"]),
    ("/static/case.html",         []),
    ("/static/rules.html",        ["rule.list"]),
    ("/static/sources.html",      ["source.list"]),
    ("/static/detections.html",   ["detection.list", "rule.list"]),
    ("/static/correlations.html", ["correlation.list", "rule.list"]),
    ("/static/timeline.html",     ["case.list"]),
    ("/static/health.html",       []),
]


async def run_browser(base: str) -> int:
    failures: list[str] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        # 1. log in
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

        for path, expected in PAGES:
            print(f"\n=== {path} ===", flush=True)
            ops: list[str] = []
            errors: list[str] = []

            def on_req(req, _o=ops):
                if "/api/proxy" not in req.url:
                    return
                try:
                    data = req.post_data
                    if data:
                        obj = json.loads(data)
                        _o.append(obj.get("operation", "?"))
                except Exception:
                    pass

            def on_pageerror(e, _e=errors):
                _e.append("PAGEERROR: " + str(e))

            def on_console(m, _e=errors):
                if m.type == "error":
                    _e.append(f"CONSOLE[error]: {m.text}")

            page.on("request", on_req)
            page.on("pageerror", on_pageerror)
            page.on("console", on_console)

            await page.goto(f"{base}{path}", wait_until="domcontentloaded")
            await page.wait_for_timeout(2500)

            html = await page.evaluate("document.body.innerHTML")
            print(f"  ops: {ops}", flush=True)
            print(f"  body length: {len(html)}", flush=True)
            if errors:
                print("  errors:", flush=True)
                for e in errors:
                    print("    " + e, flush=True)
            for op in expected:
                if op not in ops:
                    failures.append(
                        f"{path}: expected op '{op}' not called "
                        f"(saw: {ops})"
                    )
                    print(f"  MISSING: {op}", flush=True)
            if len(html) < 1000:
                failures.append(
                    f"{path}: rendered body too small ({len(html)})"
                )
                print("  BODY TOO SMALL", flush=True)
            page.remove_listener("request", on_req)
            page.remove_listener("pageerror", on_pageerror)
            page.remove_listener("console", on_console)

        await browser.close()
    print()
    if failures:
        print("FAILURES:", flush=True)
        for f in failures:
            print("  " + f, flush=True)
        return 1
    print("ALL PAGES OK", flush=True)
    return 0


def main() -> int:
    ns = argparse.Namespace(seed_credentials=True)
    cfg = _build_config(ns)
    bundle = _build_memory_backend(cfg)
    app = _build_app(bundle)
    config = uvicorn.Config(app, host="127.0.0.1", port=0,
                            log_level="warning")
    server = uvicorn.Server(config)

    async def runner() -> int:
        serve_task = asyncio.create_task(server.serve())
        # Wait for server.started to be true.
        for _ in range(100):
            await asyncio.sleep(0.1)
            if server.started:
                break
        if not server.started:
            print("Server failed to start", flush=True)
            serve_task.cancel()
            return 2
        port = server.servers[0].sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        try:
            return await run_browser(base)
        finally:
            server.should_exit = True
            try:
                await asyncio.wait_for(serve_task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
    return asyncio.run(runner())


if __name__ == "__main__":
    sys.exit(main())
