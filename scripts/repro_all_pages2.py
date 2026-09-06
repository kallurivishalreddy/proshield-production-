"""Regression test: every frontend page must issue its expected
proxy calls when loaded as a logged-in analyst.

Each page is tested in its own short-lived uvicorn process so a
stalled page can't hang the whole run. Logs in once via the
proxy, then visits each page in headless Chromium and asserts
the expected ops fire.

Exits 0 on success, 1 on any failure.
"""
import argparse
import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from playwright.async_api import async_playwright  # noqa: E402


PAGES = [
    ("/static/index.html",        ["overview.summary"]),
    ("/static/cases.html",        ["case.list"]),
    ("/static/case.html",         []),  # expects 0 ops; no id in URL
    ("/static/rules.html",        ["rule.list"]),
    ("/static/sources.html",      ["source.list"]),
    ("/static/detections.html",   ["detection.list", "rule.list"]),
    ("/static/correlations.html", ["correlation.list", "rule.list"]),
    ("/static/timeline.html",     ["case.list"]),
    ("/static/health.html",       []),
]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "scripts.proxy_server",
         "--backend", "memory", "--port", str(port),
         "--seed-credentials",
         "--host", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).parent.parent),
    )


def _wait_ready(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


async def _run_one(base: str, path: str, expected: list[str]) -> tuple[
    bool, list[str], list[str]
]:
    """Open the page, capture the proxy ops, check expectations."""
    failures: list[str] = []
    ops: list[str] = []
    errors: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        # Log in
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

        # Seed localStorage on the same origin
        await page.goto(f"{base}/static/login.html")
        await page.evaluate(
            "(t) => {"
            " localStorage.setItem('proshield.session', t);"
            " localStorage.setItem('proshield.user',"
            "   JSON.stringify({subject_id:'analyst',role:'analyst'}));"
            "}",
            token,
        )

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
        await browser.close()
    return (not failures), ops, errors


def main() -> int:
    port = _free_port()
    proc = _start_server(port)
    if not _wait_ready(port):
        print("Server did not start", flush=True)
        proc.kill()
        return 2
    base = f"http://127.0.0.1:{port}"
    print(f"Server up on {base}", flush=True)
    all_failures: list[str] = []
    try:
        for path, expected in PAGES:
            print(f"\n=== {path} ===", flush=True)
            ok, _, _ = asyncio.run(_run_one(base, path, expected))
            if not ok:
                all_failures.append(path)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    print()
    if all_failures:
        print("FAILED PAGES:", flush=True)
        for p in all_failures:
            print("  " + p, flush=True)
        return 1
    print("ALL PAGES OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
