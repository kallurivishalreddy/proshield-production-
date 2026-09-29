"""Single source of truth for the ProShield version.

The version is stamped into every shipped artefact:

* ``ProShield.exe``             (desktop shell - via ``packaging/build_info.json``)
* ``ProShieldService.exe``      (service - frozen together with build_info.json)
* ``ProShieldSetup-vX.Y.Z.exe`` (installer - ISCC ``/DAppVersion=``)
* update manifest ``manifest.json``
* About / System information in the desktop shell

Resolution order
----------------
1. ``packaging/build_info.json`` **inside the install root** - authoritative for
   an *installed* ProShield.  Written by ``packaging/build_windows.py`` and it
   also records build metadata (build id, git commit, toolchain versions).
2. ``packaging/version.json`` in the repository - authoritative for
   *development mode* (VS Code / ``python -m scripts.proxy_server``).
3. A hard-coded fallback so this module can never fail to import.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

FALLBACK_VERSION = "0.0.0"

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo_version_file() -> Path:
    return _REPO_ROOT / "deploy" / "version.json"


def _install_build_info_file() -> Optional[Path]:
    override = os.environ.get("PROSHIELD_INSTALL_DIR")
    if override:
        return Path(override) / "deploy" / "build_info.json"
    if getattr(sys, "frozen", False):
        # <install>\service\ProShieldService.exe -> <install>
        exe = Path(sys.executable).resolve()
        return exe.parent.parent / "deploy" / "build_info.json"
    return None


def _load_json(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@dataclass(frozen=True)
class VersionInfo:
    """Immutable, fully-resolved version metadata."""

    product_name: str = "ProShield"
    version: str = FALLBACK_VERSION
    channel: str = "testing"
    publisher: str = "ProShield Security"
    update_mode: str = "automatic"
    update_manifest_url: str = ""
    analyst_port: int = 8088
    ingress_port: int = 8089
    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "proshield"
    build_id: str = "dev"
    git_commit: str = "unknown"
    built_at: str = ""
    source: str = "fallback"
    extra: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ format
    @property
    def display_version(self) -> str:
        return f"{self.version}-{self.channel}" if self.channel else self.version

    @property
    def setup_filename(self) -> str:
        return f"ProShieldSetup-v{self.version}.exe"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "product_name": self.product_name,
            "version": self.version,
            "channel": self.channel,
            "publisher": self.publisher,
            "update_mode": self.update_mode,
            "display_version": self.display_version,
            "build_id": self.build_id,
            "git_commit": self.git_commit,
            "built_at": self.built_at,
            "version_source": self.source,
        }


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_version_info(install_root: Optional[Path] = None) -> VersionInfo:
    """Resolve the effective :class:`VersionInfo` for this process."""
    build_info_path = (
        (install_root / "deploy" / "build_info.json")
        if install_root is not None
        else _install_build_info_file()
    )
    data = _load_json(build_info_path)
    source = "install"
    if not data:
        data = _load_json(_repo_version_file())
        source = "repository"
    if not data:
        data = {}
        source = "fallback"

    return VersionInfo(
        product_name=str(data.get("product_name") or "ProShield"),
        version=str(data.get("version") or FALLBACK_VERSION),
        channel=str(data.get("channel") or "testing"),
        publisher=str(data.get("publisher") or "ProShield Security"),
        update_mode=str(data.get("update_mode") or "automatic"),
        update_manifest_url=str(data.get("update_manifest_url") or ""),
        analyst_port=_coerce_int(data.get("analyst_port"), 8088),
        ingress_port=_coerce_int(data.get("ingress_port"), 8089),
        mongo_uri=str(data.get("mongo_uri") or "mongodb://127.0.0.1:27017"),
        mongo_db=str(data.get("mongo_db") or "proshield"),
        build_id=str(data.get("build_id") or "dev"),
        git_commit=str(data.get("git_commit") or "unknown"),
        built_at=str(data.get("built_at") or ""),
        source=source,
    )


def parse_version(text: str) -> tuple:
    """Parse a dotted numeric version into a comparable tuple.

    Non-numeric suffixes are tolerated (``1.2.3-rc1`` -> ``(1, 2, 3)``) so a
    malformed manifest can never crash the updater.
    """
    parts = []
    for chunk in str(text).strip().split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def is_newer(candidate: str, current: str) -> bool:
    """True when ``candidate`` is strictly newer than ``current``."""
    return parse_version(candidate) > parse_version(current)


VERSION_INFO = load_version_info()
VERSION = VERSION_INFO.version
CHANNEL = VERSION_INFO.channel
