"""Readiness / liveness probes used by the service, the installer and tests.

Stdlib only (``socket`` + ``urllib``) so the frozen service executable stays
small.  The MongoDB probe upgrades itself to a real ``ping`` handshake when
``pymongo`` is importable, and falls back to a TCP connect otherwise - a TCP
connect alone can succeed while ``mongod`` is still replaying its journal and
not yet serving queries, which is exactly the race the service must survive on
a cold boot.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

DEFAULT_TCP_TIMEOUT = 1.5
DEFAULT_HTTP_TIMEOUT = 5.0


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    detail: str = ""
    payload: Optional[Dict[str, Any]] = None


def tcp_reachable(host: str, port: int, timeout: float = DEFAULT_TCP_TIMEOUT) -> bool:
    """True when something is accepting TCP connections on host:port."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def split_mongo_uri(uri: str, default_port: int = 27017) -> Tuple[str, int]:
    """Extract ``(host, port)`` from a ``mongodb://host:port`` URI."""
    host, port = "127.0.0.1", default_port
    text = (uri or "").strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    # Ignore replica-set style host lists; the first member is representative.
    text = text.split(",", 1)[0]
    if text.startswith("["):  # IPv6 literal
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1 :]
            if rest.startswith(":"):
                port = int(rest[1:] or default_port)
        return host, port
    if ":" in text:
        candidate_host, _, candidate_port = text.rpartition(":")
        if candidate_port.isdigit():
            host = candidate_host or host
            port = int(candidate_port)
        else:
            host = text
    elif text:
        host = text
    return host, port


def mongo_ready(
    uri: str,
    timeout_ms: int = 1500,
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> ProbeResult:
    """Full MongoDB readiness probe.

    Prefers ``pymongo.admin.command("ping")`` (the only check that proves the
    server can actually answer queries).  Degrades to a TCP connect when
    pymongo is unavailable, so the service still starts on a minimal runtime.
    """
    resolved_host, resolved_port = split_mongo_uri(uri)
    resolved_host = host or resolved_host
    resolved_port = int(port or resolved_port)

    try:
        from pymongo import MongoClient  # type: ignore
    except Exception:
        reachable = tcp_reachable(
            resolved_host,
            resolved_port,
            timeout=max(0.2, timeout_ms / 1000.0),
        )
        return ProbeResult(
            ok=reachable,
            detail=(
                f"tcp {resolved_host}:{resolved_port} "
                f"{'reachable' if reachable else 'unreachable'} (pymongo unavailable)"
            ),
        )

    client = None
    try:
        client = MongoClient(
            uri,
            serverSelectionTimeoutMS=max(200, int(timeout_ms)),
            connectTimeoutMS=max(200, int(timeout_ms)),
            socketTimeoutMS=max(200, int(timeout_ms)),
        )
        client.admin.command("ping")
        return ProbeResult(ok=True, detail=f"mongod ping ok ({resolved_host}:{resolved_port})")
    except Exception as exc:
        return ProbeResult(ok=False, detail=f"mongod not ready: {type(exc).__name__}")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover
                pass


def http_probe(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    expect_status: Tuple[int, ...] = (200,),
) -> ProbeResult:
    """GET ``url`` and report readiness plus the parsed JSON body (if any)."""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(64 * 1024)
            status = int(getattr(response, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        return ProbeResult(ok=False, detail=f"HTTP {exc.code} from {url}")
    except Exception as exc:
        return ProbeResult(ok=False, detail=f"{type(exc).__name__} contacting {url}")

    payload: Optional[Dict[str, Any]] = None
    if body:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                payload = parsed
        except ValueError:
            payload = None

    return ProbeResult(ok=status in expect_status, detail=f"HTTP {status}", payload=payload)
