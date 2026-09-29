"""HTTP client for the ProShield testing update channel.

Deliberately small and dependency-free (stdlib ``urllib``) so the frozen
service carries no HTTP stack of its own beyond what the backend already
bundles.

Failure handling required by the update design:

    unavailable update server      -> check fails, no state change
    interrupted download           -> partial file removed, bounded retry
    corrupted package              -> hash/size verification rejects it
    never                          -> anything reaches the install tree

The core ProShield system keeps running regardless: the caller treats every
exception from this module as "no update available right now".
"""
from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger("proshield.update_client")

USER_AGENT = "ProShield-Updater/1.0 (+windows)"
DEFAULT_RETRIES = 3
RETRY_BACKOFF_SECONDS = 3.0


class UpdateClientError(Exception):
    """Raised for any transport-level failure (never for trust failures)."""


def fetch_bytes(
    url: str,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
    etag: Optional[str] = None,
) -> bytes:
    """GET ``url`` and return the body, with bounded retries."""
    last_error: Optional[Exception] = None
    for attempt in range(1, max(1, retries) + 1):
        request = urllib.request.Request(url, method="GET")
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", "application/json, application/octet-stream")
        if etag:
            request.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                raise UpdateClientError("not-modified") from exc
            last_error = exc
            if exc.code in (400, 401, 403, 404):
                # Permanent - retrying cannot help.
                raise UpdateClientError(f"HTTP {exc.code} for {url}") from exc
        except Exception as exc:
            last_error = exc
        if attempt < retries:
            LOGGER.info(
                "fetch %s failed (attempt %d/%d): %s", url, attempt, retries, last_error
            )
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    raise UpdateClientError(f"could not fetch {url}: {last_error}")


def download_artifact(
    url: str,
    destination: Path,
    timeout: float = 300.0,
    expected_size: int = 0,
    retries: int = DEFAULT_RETRIES,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Path:
    """Stream ``url`` into ``destination`` atomically.

    The bytes land in ``<destination>.part`` and are only renamed into place
    after the transfer completes, so an interrupted download can never be
    mistaken for a complete package.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    last_error: Optional[Exception] = None

    for attempt in range(1, max(1, retries) + 1):
        try:
            if part.exists():
                part.unlink()
            request = urllib.request.Request(url, method="GET")
            request.add_header("User-Agent", USER_AGENT)
            received = 0
            with urllib.request.urlopen(request, timeout=timeout) as response:
                declared = int(response.headers.get("Content-Length") or 0) or expected_size
                with open(part, "wb") as handle:
                    while True:
                        chunk = response.read(256 * 1024)
                        if not chunk:
                            break
                        handle.write(chunk)
                        received += len(chunk)
                        if progress is not None:
                            try:
                                progress(received, declared)
                            except Exception:  # pragma: no cover
                                pass
            if expected_size and received != expected_size:
                raise UpdateClientError(
                    f"incomplete download: got {received} of {expected_size} bytes"
                )
            os.replace(part, destination)
            LOGGER.info("downloaded %s (%d bytes)", destination.name, received)
            return destination
        except Exception as exc:
            last_error = exc
            LOGGER.warning(
                "download attempt %d/%d for %s failed: %s", attempt, retries, url, exc
            )
            try:
                if part.exists():
                    part.unlink()
            except OSError:
                pass
            if attempt < retries:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    raise UpdateClientError(f"download failed after {retries} attempts: {last_error}")