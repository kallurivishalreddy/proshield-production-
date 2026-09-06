"""Verify a single frontend page issues its expected proxy calls.

Usage: python scripts/repro_one_page.py <path> <expected_op1> ...

Brings up an in-process proxy, logs in, visits the page, prints
the ops fired and PASS/FAIL. Designed to be fast (under 10s) and
to exit cleanly so it can be run per-page.
"""
import argparse
import asyncio
import json
import socket
import sys
import time

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
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("expected", nargs="*")
    ap.add_argument("--no-auth", action="store_true",
                    help="don't seed localStorage; useful for case.html")
    args = ap.parse_args()

    port = _free_port()
    cfg = _build_config(__import__("argparse").Namespace(
        seed_credentials=True))
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

            # log in
            r = await page.request.post(
                f"{base}/api/proxy",
                data=json.dumps({
                    "operation": "auth.issue",
                    "subject_id": "analyst",
                    "credential": "analyst-dev-credential",
                }),
                headers={"Content-Type": "application/json"},
            )
            body = await r.json()
            token = body["data"]["token"]

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
            errors: list[str] = []

            def on_req(req, _o=ops):
                if "/api/proxy" not in req.url:
                    return
                try:
                    d = req.post_data
                    if d:
                        ops.append(json.loads(d).get("operation", "?"))
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

            await page.goto(f"{base}{args.path}", wait_until="commit")
            await page.wait_for_timeout(1500)

            html = await page.evaluate("document.body.innerHTML")
            print(f"  ops:    {ops}", flush=True)
            print(f"  errors: {errors}", flush=True)
            print(f"  body:   {len(html)} bytes", flush=True)
            ok = True
            for op in args.expected:
                if op not in ops:
                    print(f"  MISSING: {op}", flush=True)
                    ok = False
            if len(html) < 1000:
                print("  BODY TOO SMALL", flush=True)
                ok = False
            if errors:
                ok = False
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
