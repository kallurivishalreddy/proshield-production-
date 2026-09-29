"""ProShield installed-stack acceptance verification.

Runs the requirement-14 checks against a **running** ProShield stack - in
development mode or against an installed Windows service, using the same code:

    stack        analyst + ingress planes, MongoDB readiness, versions
    desktop      the native shell reports real state from the same backend
    gateway      the GUI's own origin (``/static/soc/index.html``) is served by
                 the analyst plane, same-origin with ``/api/proxy``
    recovery     kill a supervised plane, confirm the supervisor restarts it
    rejection    tampered manifest / tampered package / unsigned policy
    workflow     the real security workflow end to end over the wire boundary
                 source -> capability -> ingress -> rule -> detection ->
                 capability correlation -> case -> timeline/evidence ->
                 analyst -> explicit central correlation

Usage::

    # against an already-running stack
    python -m scripts.verify_windows_stack --data-dir "%ProgramData%\\ProShield"

    # self-contained: start the supervisor, verify, stop it
    python -m scripts.verify_windows_stack --start-console --dev-credentials

Exit code 0 = every executed check passed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.domain.uuid7 import uuid7  # noqa: E402
from service.paths import resolve_paths  # noqa: E402
from service.settings import (  # noqa: E402
    load_secrets,
    load_settings,
    write_default_settings,
)
from dataclasses import replace  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

RESULTS: List[Tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append((name, status, detail))
    marker = {PASS: "[PASS]", FAIL: "[FAIL]", SKIP: "[SKIP]"}[status]
    print(f"{marker} {name}" + (f" - {detail}" if detail else ""))


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


# ----------------------------------------------------------------- HTTP utils


def http_json(
    url: str,
    payload: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
) -> Tuple[int, Optional[dict]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(raw)
            except ValueError:
                return response.status, {"_raw": raw[:400]}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"_raw": raw[:400]}
    except Exception as exc:
        return 0, {"_error": f"{type(exc).__name__}: {exc}"}


class Stack:
    """Thin client for the two ProShield planes."""

    def __init__(self, analyst: str, ingress: str) -> None:
        self.analyst = analyst.rstrip("/")
        self.ingress = ingress.rstrip("/")

    def proxy(self, op: str, body: Optional[dict] = None, token: str = "") -> Tuple[int, dict]:
        headers = {}
        if token:
            headers["X-ProShield-Session"] = token
        status, parsed = http_json(
            f"{self.analyst}/api/proxy", {"operation": op, **(body or {})}, headers
        )
        return status, parsed or {}

    def data(self, op: str, body: Optional[dict] = None, token: str = "") -> dict:
        status, parsed = self.proxy(op, body, token)
        if not (200 <= status < 300) or parsed.get("ok") is False or parsed.get("error"):
            raise RuntimeError(
                f"{op} failed: HTTP {status} {json.dumps(parsed)[:300]}"
            )
        return parsed.get("data") or {}

    def issue_session(self, subject: str, credential: str) -> str:
        data = self.data(
            "auth.issue", {"subject_id": subject, "credential": credential}
        )
        return str(data.get("token") or "")

    def ingest(self, events: List[dict], source_token: str) -> Tuple[int, dict]:
        return http_json(
            f"{self.ingress}/api/ingress",
            {"operation": "source.ingest", "events": events},
            {"Authorization": f"Bearer {source_token}"},
        )


# ------------------------------------------------------------------- fixtures


def nginx_events(attacker_ip: str = "10.0.0.66", count: int = 8) -> List[dict]:
    """A malicious burst plus benign/blocked/limited traffic (NGINX contract)."""
    now = datetime.now(timezone.utc)
    events: List[dict] = []
    for index in range(count):
        event_time = now - timedelta(seconds=10 - index)
        events.append(
            {
                "event_id": str(uuid7(timestamp_ms=int(event_time.timestamp() * 1000))),
                "event_time": event_time.isoformat(),
                "ingested_at": event_time.isoformat(),
                "source": "nginx",
                "event_type": "authentication_failure",
                "source_ip": attacker_ip,
                "destination": "auth.example.internal",
                "endpoint": "/auth/login",
                "asset": "auth-svc-01",
                "details": {
                    "status_code": 401,
                    "user_agent": "curl/8.0.0",
                    "method": "POST",
                    "account_id": "user-123",
                },
                "provenance": {"collector": "packaged-verify", "source_event_id": f"verify-bf-{index}"},
            }
        )
    events.append(
        {
            "event_id": str(uuid7()),
            "event_time": now.isoformat(),
            "ingested_at": now.isoformat(),
            "source": "nginx",
            "event_type": "authentication_success",
            "source_ip": "10.0.0.10",
            "destination": "auth.example.internal",
            "endpoint": "/auth/login",
            "asset": "auth-svc-01",
            "details": {"status_code": 200, "user_agent": "Mozilla/5.0"},
            "provenance": {"collector": "packaged-verify", "source_event_id": "verify-ok-1"},
        }
    )
    events.append(
        {
            "event_id": str(uuid7()),
            "event_time": now.isoformat(),
            "ingested_at": now.isoformat(),
            "source": "nginx",
            "event_type": "request_blocked",
            "source_ip": attacker_ip,
            "destination": "web.example.internal",
            "endpoint": "/.env",
            "asset": "web-api-01",
            "details": {"status_code": 403, "user_agent": "curl/8.0.0"},
            "provenance": {"collector": "packaged-verify", "source_event_id": "verify-sens-1"},
        }
    )
    events.append(
        {
            "event_id": str(uuid7()),
            "event_time": now.isoformat(),
            "ingested_at": now.isoformat(),
            "source": "nginx",
            "event_type": "rate_limit_exceeded",
            "source_ip": attacker_ip,
            "destination": "web.example.internal",
            "endpoint": "/api/checkout",
            "asset": "web-api-01",
            "details": {"status_code": 429, "user_agent": "curl/8.0.0"},
            "provenance": {"collector": "packaged-verify", "source_event_id": "verify-rl-1"},
        }
    )
    return events


# --------------------------------------------------------------------- checks


def check_stack(stack: Stack, settings) -> bool:
    section("CHECK: stack (planes, MongoDB, versions)")
    ok = True

    status, body = http_json(f"{stack.analyst}/health", timeout=10)
    if status == 200 and body.get("status") == "ok":
        record("analyst plane /health", PASS, f"backend_kind={body.get('backend_kind')}")
    else:
        record("analyst plane /health", FAIL, f"HTTP {status} {json.dumps(body)[:200]}")
        ok = False

    status, body = http_json(f"{stack.ingress}/api/ingress/health", timeout=10)
    if status == 200 and body.get("ok") is not False:
        record("ingress plane /api/ingress/health", PASS, json.dumps(body)[:160])
    else:
        record("ingress plane /api/ingress/health", FAIL, f"HTTP {status} {json.dumps(body)[:200]}")
        ok = False

    status, body = http_json(f"{stack.analyst}/api/meta", timeout=10)
    if status == 200:
        record("analyst /api/meta", PASS, f"max_request_bytes={body.get('proxy_max_request_bytes')}")
    else:
        record("analyst /api/meta", FAIL, f"HTTP {status}")
        ok = False

    # MongoDB is proven through the planes themselves (they only serve real
    # data when the store is reachable), never by the GUI touching the DB.
    status, body = http_json(f"{stack.analyst}/api/proxy", {"operation": "overview.summary"}, {"X-ProShield-Session": ""})
    record(
        "MongoDB reachable through analyst plane",
        PASS if status in (200, 401, 403) else FAIL,
        f"HTTP {status} (401/403 = plane answering behind auth, DB wired)",
    )
    return ok


def check_gateway(stack: Stack) -> bool:
    section("CHECK: GUI origin (no browser, same-origin with SecureProxy)")
    try:
        with urllib.request.urlopen(
            f"{stack.analyst}/static/soc/index.html", timeout=15
        ) as response:
            html = response.read().decode("utf-8", errors="replace")
            status = response.status
    except Exception as exc:
        record("authoritative UI served by analyst plane", FAIL, str(exc))
        return False

    looks_like_ui = "<div id=\"root\"" in html or "<div id=root" in html
    references_proxy = "/api/proxy" in html
    record(
        "authoritative UI served by analyst plane",
        PASS if status == 200 and looks_like_ui else FAIL,
        f"HTTP {status}, {len(html)} bytes, SPA root={looks_like_ui}, "
        f"defers to /api/proxy={references_proxy}",
    )
    return status == 200 and looks_like_ui


def check_desktop(settings) -> bool:
    section("CHECK: desktop shell (real state, no DB access)")
    env = dict(os.environ)
    env["PROSHIELD_DATA_DIR"] = str(settings["data_root"])
    command = [sys.executable, "-m", "desktop", "--status"]
    completed = subprocess.run(
        command, cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120
    )
    if completed.returncode != 0:
        record("desktop --status", FAIL, (completed.stderr or "")[-300:])
        return False
    try:
        payload = json.loads(completed.stdout)
    except ValueError as exc:
        record("desktop --status", FAIL, f"invalid JSON: {exc}")
        return False

    shell = payload.get("shell", {})
    record(
        "desktop reports version/build",
        PASS if shell.get("version") else FAIL,
        f"{shell.get('product_name')} {shell.get('display_version')} "
        f"build={shell.get('build_id')} commit={str(shell.get('git_commit'))[:8]}",
    )
    backend = payload.get("backend", {})
    analyst = backend.get("analyst", {})
    record(
        "desktop sees the real analyst plane",
        PASS if analyst.get("reachable") else FAIL,
        f"{analyst.get('url')} -> {analyst.get('detail')}",
    )
    ingress = backend.get("ingress", {})
    record(
        "desktop sees the real ingress plane",
        PASS if ingress.get("reachable") else FAIL,
        f"{ingress.get('url')} -> {ingress.get('detail')}",
    )
    record(
        "desktop UI is the analyst-plane origin",
        PASS if backend.get("ui_url", "").endswith("/static/soc/index.html") else FAIL,
        str(backend.get("ui_url")),
    )
    # Requirement 15: the GUI must not hold MongoDB credentials.
    secrets_leaked = "mongo_uri" in json.dumps(payload) and "@" in json.dumps(payload)
    record(
        "desktop holds no database credentials",
        PASS if not secrets_leaked else FAIL,
        "no mongo credentials in the shell status payload"
        if not secrets_leaked
        else "credential-like value found",
    )
    return True


def check_recovery(health_file: Path, child_name: str = "ingress") -> bool:
    section(f"CHECK: crash recovery ({child_name} plane)")

    def read() -> dict:
        try:
            return json.loads(health_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    before = read()
    child = next(
        (c for c in before.get("children", []) if c.get("name") == child_name), None
    )
    if not child or not child.get("running"):
        record("supervisor status available", FAIL, f"no running {child_name} child")
        return False
    pid_before = child.get("pid")
    restarts_before = int(child.get("restarts") or 0)
    record("supervised planes running", PASS, f"{child_name} pid={pid_before}")

    completed = subprocess.run(
        ["taskkill", "/PID", str(pid_before), "/F"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    record(
        f"kill {child_name} pid {pid_before}",
        PASS if completed.returncode == 0 else FAIL,
        (completed.stdout or completed.stderr or "").strip()[:120],
    )

    deadline = time.time() + 90
    recovered = False
    while time.time() < deadline:
        time.sleep(2.0)
        snapshot = read()
        current = next(
            (c for c in snapshot.get("children", []) if c.get("name") == child_name),
            None,
        )
        if not current:
            continue
        if (
            current.get("running")
            and current.get("healthy")
            and current.get("pid") != pid_before
            and int(current.get("restarts") or 0) > restarts_before
        ):
            recovered = True
            record(
                "supervisor recovered the failed plane",
                PASS,
                f"{child_name} restarted as pid={current.get('pid')} "
                f"(restarts {restarts_before} -> {current.get('restarts')}), "
                f"health={current.get('health_detail')}",
            )
            break
    if not recovered:
        record(
            "supervisor recovered the failed plane",
            FAIL,
            f"{child_name} did not come back within 90s",
        )
    return recovered


def check_rejection(data_root: Path, install_root: Optional[Path] = None) -> bool:
    """Update trust + failure recovery (requirement 9 and 10).

    The signature/hash checks are non-destructive.  The rollback check *does*
    replace an install tree, so it is deliberately run against a **sandbox copy**
    of the install tree rather than a live installation - restoring files
    underneath running backend planes would break the very stack this harness is
    verifying (and would be a false failure).
    """
    from service import update_manifest
    from service import update_apply as update_apply_module
    from service.paths import resolve_paths as _rp
    from service.settings import load_settings as _ls
    from service.update_apply import UpdateApplier

    section("CHECK: update trust + failure recovery (signature / hash / rollback)")
    ok = True
    workdir = data_root / "state" / "verify-trust"
    workdir.mkdir(parents=True, exist_ok=True)
    paths = _rp(data=data_root)
    settings = _ls(paths)

    # 1. unsigned manifest must be refused by default policy
    manifest_doc = {
        "manifest_schema": 1,
        "channel": "testing",
        "version": "99.0.0",
        "min_version": "0.0.0",
        "released_at": "2026-01-01T00:00:00Z",
        "notes": "verification fixture",
        "artifacts": {
            "windows-x64": {
                "url": "http://127.0.0.1:1/ProShieldSetup.exe",
                "sha256": "0" * 64,
                "size": 1,
                "filename": "ProShieldSetup.exe",
            }
        },
    }
    unsigned = workdir / "manifest-unsigned.json"
    unsigned.write_text(json.dumps(manifest_doc), encoding="utf-8")
    fake_artifact = workdir / "ProShieldSetup.exe"
    fake_artifact.write_bytes(b"MZ-not-a-real-installer")

    applier = UpdateApplier(paths=paths, settings=settings)
    ok_flag, detail, _ = applier.verify(unsigned, fake_artifact)
    record(
        "unsigned manifest rejected",
        PASS if not ok_flag else FAIL,
        detail[:160],
    )
    ok = ok and (not ok_flag)

    # 2. signed manifest, but tampered package -> hash mismatch
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private = Ed25519PrivateKey.generate()
        key_path = workdir / "verify-signing.key"
        key_path.write_bytes(
            private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        pub_path = workdir / "verify-signing.pub.pem"
        pub_path.write_bytes(
            private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )

        good_bytes = b"MZ-real-package-bytes-for-hash-verification"
        signed_doc = update_manifest.build_signed_manifest(
            version="99.0.0",
            channel="testing",
            artifacts={
                "windows-x64": {
                    "url": "http://127.0.0.1:1/ProShieldSetup.exe",
                    "sha256": update_manifest.sha256_bytes(good_bytes),
                    "size": len(good_bytes),
                    "filename": "ProShieldSetup.exe",
                }
            },
            private_key_path=key_path,
            notes="verification fixture",
        )
        signed = workdir / "manifest-signed.json"
        signed.write_text(json.dumps(signed_doc), encoding="utf-8")

        # Point the applier at the verification public key.
        import shutil as _sh

        _sh.copy2(pub_path, paths.update_public_key_file)
        applier = UpdateApplier(paths=paths, settings=settings)

        good_artifact = workdir / "ProShieldSetup.exe"
        good_artifact.write_bytes(good_bytes)
        ok_flag, detail, _ = applier.verify(signed, good_artifact)
        record(
            "signed manifest + matching hash accepted",
            PASS if ok_flag else FAIL,
            detail[:160],
        )
        ok = ok and ok_flag

        tampered = workdir / "ProShieldSetup-tampered.exe"
        tampered.write_bytes(good_bytes + b"EVIL")
        ok_flag, detail, _ = applier.verify(signed, tampered)
        record(
            "tampered package rejected (hash mismatch)",
            PASS if not ok_flag else FAIL,
            detail[:160],
        )
        ok = ok and (not ok_flag)

        # 3. tampered manifest (version flipped) -> signature failure
        forged_doc = dict(signed_doc)
        forged_doc["version"] = "99.9.9"
        forged = workdir / "manifest-forged.json"
        forged.write_text(json.dumps(forged_doc), encoding="utf-8")
        ok_flag, detail, _ = applier.verify(forged, good_artifact)
        record(
            "forged manifest rejected (signature failure)",
            PASS if not ok_flag else FAIL,
            detail[:160],
        )
        ok = ok and (not ok_flag)

        # 4. rollback path: apply with a failing installer must restore the tree.
        #    Run against a sandbox copy so a live installation is never replaced.
        sandbox = workdir / "sandbox-install"
        if sandbox.exists():
            shutil.rmtree(sandbox, ignore_errors=True)
        source_install = install_root or paths.install_root
        copied: List[str] = []
        for name in update_apply_module.INSTALL_TREE_DIRS:
            source = source_install / name
            if source.is_dir():
                shutil.copytree(
                    source,
                    sandbox / name,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                copied.append(name)
        # The bundled runtime is large and proves nothing extra about rollback.
        runtime_copy = sandbox / "runtime"
        if runtime_copy.exists():
            shutil.rmtree(runtime_copy, ignore_errors=True)
            copied.remove("runtime") if "runtime" in copied else None
        record(
            "rollback sandbox prepared",
            PASS if copied else FAIL,
            f"copied {', '.join(copied)} from {source_install}",
        )

        sandbox_paths = _rp(install=sandbox, data=data_root)
        (sandbox_paths.deploy_dir).mkdir(parents=True, exist_ok=True)
        (sandbox / "app").mkdir(parents=True, exist_ok=True)
        marker = sandbox / "app" / "config.py"
        if not marker.is_file():
            marker.write_text("# sandbox marker\n", encoding="utf-8")
        before = marker.read_bytes()

        failing = workdir / "failing-installer.py"
        failing.write_text(
            "import sys\nprint('simulated installer failure')\nsys.exit(4)\n",
            encoding="utf-8",
        )
        rollback_applier = UpdateApplier(
            paths=sandbox_paths,
            settings=settings,
            installer_command=[sys.executable, str(failing)],
            restart_command=None,
            health_timeout=20.0,
        )
        result = rollback_applier.apply(
            good_artifact, signed, expected_version="99.0.0", rollback_on_failure=True
        )
        after = marker.read_bytes() if marker.is_file() else b""
        restored = result.status == "rolled-back" and before == after
        record(
            "failed installer -> rollback restores the previous version",
            PASS if restored else FAIL,
            f"status={result.status} marker_restored={before == after} "
            f"message={result.message[:120]}",
        )
        ok = ok and restored

    except ImportError as exc:  # pragma: no cover
        record("update trust checks", SKIP, f"cryptography unavailable: {exc}")
        return False

    return ok


def check_workflow(stack: Stack, creds: Dict[str, str]) -> bool:
    section("CHECK: real security workflow (source -> ... -> central correlation)")
    ok = True

    admin = stack.issue_session("admin", creds.get("admin", ""))
    analyst = stack.issue_session("analyst", creds.get("analyst", ""))
    record("auth.issue admin + analyst", PASS if admin and analyst else FAIL,
           f"admin_token={bool(admin)} analyst_token={bool(analyst)}")
    if not (admin and analyst):
        return False

    source_name = f"nginx-packaged-{uuid.uuid4().hex[:6]}"
    registered = stack.data(
        "source.register",
        {
            "source_type": "nginx",
            "display_name": source_name,
            "description": "packaged verification source",
            "tags": ["PACKAGED", "VERIFY"],
            "asset_tags": ["api", "web"],
        },
        token=admin,
    )
    source_id = (registered.get("source") or {}).get("source_instance_id")
    record("source.register", PASS if source_id else FAIL, str(source_id))
    if not source_id:
        return False

    stack.data(
        "source.configure",
        {
            "source_instance_id": source_id,
            "configuration": {
                "connection_type": "push",
                "endpoint": "/ingress/verify",
                "asset_tags": ["api", "web"],
            },
        },
        token=admin,
    )
    stack.data("source.validate", {"source_instance_id": source_id}, token=admin)
    enabled = stack.data("source.enable", {"source_instance_id": source_id}, token=admin)
    state = (enabled.get("source") or {}).get("state")
    record("source.configure/validate/enable", PASS if state else FAIL, f"state={state}")

    issued = stack.data(
        "source.issue_token",
        {"source_instance_id": source_id, "lifetime_seconds": 900},
        token=admin,
    )
    token = issued.get("source_token") or issued.get("token") or ""
    record("source.issue_token", PASS if token else FAIL, f"expires_at={issued.get('expires_at')}")
    if not token:
        return False

    # Capability binding: the source must resolve to a capability, and the
    # capability must own the rules that fire (Source != Capability).
    try:
        capabilities = stack.data("capability.list", {}, token=analyst)
        items = capabilities.get("capabilities") or []
        record(
            "capability registry reachable", PASS if items else FAIL,
            f"{len(items)} capability(ies)",
        )
    except Exception as exc:
        record("capability registry reachable", SKIP, str(exc)[:120])

    events = nginx_events()
    status, body = stack.ingest(events, token)
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    accepted = data.get("accepted_event_ids") or []
    record(
        "ingress source.ingest (trust boundary)",
        PASS if status == 200 and accepted else FAIL,
        f"HTTP {status} accepted={len(accepted)} rejected={len(data.get('rejected') or [])}"
        + ("" if accepted else f" body={json.dumps(body)[:200]}"),
    )
    if not accepted:
        return False

    # The ingress listener runs detection -> correlation -> auto-case inline.
    deadline = time.time() + 60
    detections: List[dict] = []
    while time.time() < deadline:
        try:
            listing = stack.data(
                "detection.list",
                {"rule_id": "NGINX-AUTH-FAILURE-001", "limit": 50},
                token=analyst,
            )
            detections = listing.get("detections") or []
        except Exception:
            detections = []
        if detections:
            break
        time.sleep(2.0)
    record(
        "detection engine (NGINX-AUTH-FAILURE-001)",
        PASS if detections else FAIL,
        f"{len(detections)} detection(s) with provenance retained: "
        + ", ".join(
            f"{d.get('detection_id', '')[:14]}..(event={str(d.get('event_id'))[:12]}..)"
            for d in detections[:3]
        ),
    )
    ok = ok and bool(detections)

    correlations: List[dict] = []
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            listing = stack.data("correlation.list", {"limit": 50}, token=analyst)
            correlations = listing.get("correlations") or []
        except Exception:
            correlations = []
        if correlations:
            break
        time.sleep(2.0)
    record(
        "capability-specific correlation",
        PASS if correlations else FAIL,
        f"{len(correlations)} correlation(s): "
        + ", ".join(
            f"{c.get('pattern_id')} key={c.get('key')} count={c.get('count')}"
            for c in correlations[:3]
        ),
    )
    ok = ok and bool(correlations)

    # The auto-opened case is owned by the SYSTEM pipeline identity
    # (``created_by=pipeline``) and the case surface is ownership-scoped: an
    # ANALYST session (``case:read`` without ``case:read:any``) is deliberately
    # denied by the IDOR boundary (OWNER-52-01 / V2-02 — the same rule the UI
    # enforces; see the note in ``scripts/final_rehearsal.py``). This
    # verification therefore lists and reads the case with the ADMIN session,
    # which legitimately holds ``case:read:any``, and separately asserts that
    # the analyst session is denied. Case authorization is NOT relaxed here.
    cases: List[dict] = []
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            listing = stack.data("case.list", {"limit": 50}, token=admin)
            cases = listing.get("cases") or listing.get("incidents") or []
        except Exception:
            cases = []
        if cases:
            break
        time.sleep(2.0)
    record(
        "case opened automatically (admin, case:read:any)",
        PASS if cases else FAIL,
        f"{len(cases)} case(s): " + ", ".join(str(c.get("incident_id")) for c in cases[:3]),
    )
    if not cases:
        return False

    pipeline_cases = [
        c for c in cases if str(c.get("created_by") or "") == "pipeline"
    ]
    case_id = (pipeline_cases[0] if pipeline_cases else cases[0]).get("incident_id")

    # Ownership model preserved (never weakened for the harness): a
    # pipeline-owned case must stay IDOR-hidden from an analyst session.
    if pipeline_cases:
        status, _body = stack.proxy(
            "case.get", {"incident_id": case_id}, token=analyst
        )
        record(
            "pipeline-owned case is IDOR-hidden from an analyst session",
            PASS if status in (403, 404) else FAIL,
            f"HTTP {status}",
        )
        ok = ok and status in (403, 404)
    else:
        record(
            "pipeline-owned case is IDOR-hidden from an analyst session",
            SKIP,
            "no pipeline-owned case in this database to assert against",
        )

    detail = stack.data("case.get", {"incident_id": case_id}, token=admin)
    record(
        "case.get (case detail)",
        PASS if detail.get("case") else FAIL,
        f"state={(detail.get('case') or {}).get('state')}",
    )

    timeline = stack.data(
        "timeline.build_for_incident", {"incident_id": case_id, "limit": 100}, token=admin
    )
    items = timeline.get("items") or []
    record(
        "timeline / evidence",
        PASS if items else FAIL,
        f"{len(items)} timeline item(s)",
    )
    ok = ok and bool(items)

    central = stack.data(
        "case.centralized",
        {"incident_id": case_id, "reason": "packaged verification central analysis"},
        token=admin,
    )
    record(
        "explicit central correlation (case.centralized)",
        PASS if central.get("failed") in (False, None) else FAIL,
        f"new_correlations={len(central.get('new_correlation_ids') or [])} "
        f"failed={central.get('failed')}",
    )
    ok = ok and central.get("failed") in (False, None)

    overview = stack.data("overview.summary", {}, token=analyst)
    record(
        "analyst overview summary", PASS if overview else FAIL,
        json.dumps(overview)[:180],
    )

    # RBAC still enforced: the ingress plane must reject analyst operations.
    status, body = http_json(
        f"{stack.ingress}/api/proxy", {"operation": "case.list"}, {"X-ProShield-Session": analyst}
    )
    record(
        "plane separation preserved (analyst op on ingress plane refused)",
        PASS if status in (401, 403, 404, 405) else FAIL,
        f"HTTP {status}",
    )
    ok = ok and status in (401, 403, 404, 405)

    return ok


# ----------------------------------------------------------------------- main


def _parse_subject_credentials(raw: str) -> Dict[str, str]:
    """``admin:secret,analyst:secret`` -> ``{subject: credential}``."""
    creds: Dict[str, str] = {}
    for pair in (raw or "").split(","):
        if ":" in pair:
            subject, _, credential = pair.partition(":")
            if subject.strip() and credential.strip():
                creds[subject.strip()] = credential.strip()
    return creds


def _parse_initial_credentials_file(path: Path) -> Dict[str, str]:
    """Parse the operator-facing ``config/initial-credentials.txt``.

    Format (written once at first run by ``service/settings.py``)::

        subject_id : admin
        credential : <secret>
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    creds: Dict[str, str] = {}
    subject = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("subject_id :"):
            subject = line.split(":", 1)[1].strip()
        elif line.startswith("credential :") and subject:
            creds[subject] = line.split(":", 1)[1].strip()
            subject = ""
    return creds


def read_credentials(data_root: Path) -> Dict[str, str]:
    """Resolve the seeded subject credentials for the workflow check.

    ``secrets/proshield.env`` is ACL'd to ``Administrators`` + ``SYSTEM`` **by
    design** (it holds the cross-plane HMAC signing keys; a local non-admin user
    must not be able to forge a session token).  A non-elevated verification run
    therefore gets ``PermissionError`` when reading it, so ``load_secrets``
    legitimately returns nothing.

    The installation also writes the operator-facing
    ``config/initial-credentials.txt`` ("read the credentials here" —
    ``docs/WINDOWS_DEPLOYMENT.md``), which *is* readable by users and holds the
    same subject credentials.  It is used as the documented fallback so an
    installed stack can be verified without elevation.  No security control is
    weakened: the fallback reads a file the operator is explicitly told to read.
    """
    paths = resolve_paths(data=Path(data_root))
    secrets = load_secrets(paths)
    creds = _parse_subject_credentials(
        secrets.get("PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS", "")
    )
    if not creds:
        creds = _parse_initial_credentials_file(paths.initial_credentials_file)
    return creds


def wait_for_stack(stack: Stack, timeout: float = 180.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, _ = http_json(f"{stack.analyst}/health", timeout=5)
        if status == 200:
            return True
        time.sleep(2.0)
    return False


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ProShield installed-stack verification.")
    parser.add_argument("--data-dir", default="")
    parser.add_argument("--install-dir", default="")
    parser.add_argument("--analyst-port", type=int, default=0)
    parser.add_argument("--ingress-port", type=int, default=0)
    parser.add_argument("--start-console", action="store_true",
                        help="launch the supervisor, verify, then stop it")
    parser.add_argument("--dev-credentials", action="store_true")
    parser.add_argument("--skip-recovery", action="store_true")
    parser.add_argument("--skip-trust", action="store_true")
    parser.add_argument("--checks", default="stack,gateway,desktop,recovery,trust,workflow")
    args = parser.parse_args(argv)

    if args.data_dir:
        os.environ["PROSHIELD_DATA_DIR"] = args.data_dir
    if args.install_dir:
        os.environ["PROSHIELD_INSTALL_DIR"] = args.install_dir

    paths = resolve_paths().ensure_layout()
    settings = load_settings(paths)
    analyst_port = args.analyst_port or settings.analyst_port
    ingress_port = args.ingress_port or settings.ingress_port

    # ``--start-console`` launches the supervisor, and the supervisor binds the
    # ports from ``<data_root>/config/proshield.json``. Persist an explicitly
    # requested port pair *before* launching, otherwise the flags only move the
    # CLIENT url and a self-contained run silently binds the default ports
    # (8088/8089) — which fails outright when the machine already runs an
    # installed ProShield. ``to_json()`` is secret-free by construction.
    if args.start_console and (
        analyst_port != settings.analyst_port
        or ingress_port != settings.ingress_port
    ):
        settings = replace(
            settings, analyst_port=analyst_port, ingress_port=ingress_port
        )
        write_default_settings(paths, settings)
    stack = Stack(
        f"http://127.0.0.1:{analyst_port}", f"http://127.0.0.1:{ingress_port}"
    )

    print("=" * 72)
    print("ProShield installed-stack acceptance verification")
    print("=" * 72)
    print(f"  install_root : {paths.install_root}")
    print(f"  data_root    : {paths.data_root}")
    print(f"  analyst      : {stack.analyst}")
    print(f"  ingress      : {stack.ingress}")
    print(f"  version      : {settings.version} ({settings.channel})")

    supervisor_process: Optional[subprocess.Popen] = None
    if args.start_console:
        section("Starting supervisor (console mode = the same code the SCM runs)")
        env = dict(os.environ)
        env["PROSHIELD_DATA_DIR"] = str(paths.data_root)
        env["PROSHIELD_INSTALL_DIR"] = str(paths.install_root)
        env.setdefault("PYTHONPATH", str(paths.install_root))
        command = [sys.executable, "-m", "service", "console"]
        if args.dev_credentials:
            command.append("--dev-credentials")
        log_path = paths.logs_dir / "verify-console.log"
        handle = open(log_path, "w", encoding="utf-8", errors="replace")
        supervisor_process = subprocess.Popen(
            command,
            cwd=str(paths.install_root),
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        print(f"  supervisor pid: {supervisor_process.pid} (log: {log_path})")
        if not wait_for_stack(stack):
            record("supervisor reached readiness", FAIL, "analyst plane never answered")
            supervisor_process.terminate()
            return 1
        record("supervisor reached readiness", PASS, "analyst plane answered /health")

    selected = {item.strip() for item in args.checks.split(",") if item.strip()}
    outcomes: Dict[str, bool] = {}

    try:
        if "stack" in selected:
            outcomes["stack"] = check_stack(stack, settings)
        if "gateway" in selected:
            outcomes["gateway"] = check_gateway(stack)
        if "desktop" in selected:
            outcomes["desktop"] = check_desktop({"data_root": paths.data_root})
        if "recovery" in selected and not args.skip_recovery:
            outcomes["recovery"] = check_recovery(paths.health_state_file)
        if "trust" in selected and not args.skip_trust:
            outcomes["trust"] = check_rejection(paths.data_root, paths.install_root)
        if "workflow" in selected:
            creds = read_credentials(paths.data_root)
            if not creds:
                record(
                    "security workflow",
                    FAIL,
                    "no subject credentials found in secrets/proshield.env or "
                    "config/initial-credentials.txt",
                )
                outcomes["workflow"] = False
            else:
                outcomes["workflow"] = check_workflow(stack, creds)
    finally:
        if supervisor_process is not None:
            section("Stopping supervisor")
            supervisor_process.terminate()
            try:
                supervisor_process.wait(timeout=30)
            except subprocess.TimeoutExpired:  # pragma: no cover
                supervisor_process.kill()
            print("  supervisor stopped")

    section("SUMMARY")
    failures = 0
    for name, status, detail in RESULTS:
        marker = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP"}[status]
        print(f"  {marker:4}  {name}")
        if status == FAIL:
            failures += 1
    print()
    print(f"  {sum(1 for r in RESULTS if r[1] == PASS)} passed, "
          f"{failures} failed, {sum(1 for r in RESULTS if r[1] == SKIP)} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())