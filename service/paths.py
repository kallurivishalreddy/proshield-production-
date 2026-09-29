"""Windows filesystem layout for ProShield.

Installed layout (machine-wide install, produced by ``ProShieldSetup``)::

    C:\\Program Files\\ProShield\\            install_root  (read-only, replaced by upgrades)
        app\\                               authoritative security implementation
        scripts\\                           proxy_server / ingress_server entry points
        frontend\\soc\\index.html           authoritative React UI (single-file bundle)
        runtime\\python.exe                 relocatable Python used by both planes
        service\\ProShieldService.exe       Windows service host (SCM entry point)
        desktop\\ProShield.exe              native desktop shell (WebView2)
        deploy\\build_info.json             version stamp + update public key

    C:\\ProgramData\\ProShield\\             data_root     (NEVER replaced by upgrades)
        config\\    non-secret settings (users may read)
        secrets\\   signing keys + subject credentials (Administrators only)
        logs\\      service / analyst / ingress / updater / desktop logs
        state\\     supervisor status, update state, WebView2 profile
        updates\\   staged packages + the detached update helper
        backup\\    previous install trees for rollback

The split is deliberate: **nothing the installer replaces may hold runtime
data**, and **nothing that holds runtime data is ever deleted by an upgrade**.
MongoDB lives entirely outside this tree (an independent Windows service on
127.0.0.1:27017) and is never touched by ProShield packaging.

``secrets`` is a separate directory (rather than a file inside ``config``) so
the installer can ACL it to Administrators only: a local non-admin user must
not be able to read the HMAC signing keys, or they could forge a session token
against the loopback analyst plane.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PRODUCT_DIRNAME = "ProShield"

ENV_INSTALL_DIR = "PROSHIELD_INSTALL_DIR"
ENV_DATA_DIR = "PROSHIELD_DATA_DIR"


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _exe_root() -> Path:
    """Install root derived from the running executable.

    ``<install>\\service\\ProShieldService.exe`` and
    ``<install>\\desktop\\ProShield.exe`` both sit exactly one directory
    below the install root.
    """
    exe = Path(sys.executable).resolve()
    return exe.parent.parent


def install_root() -> Path:
    """Absolute path of the ProShield installation directory.

    Resolution order:

    1. ``PROSHIELD_INSTALL_DIR`` (set by the installer / tests).
    2. The parent of the directory holding the frozen executable.
    3. The repository root in development mode (this file is
       ``<root>/service/paths.py``).
    """
    override = _clean(os.environ.get(ENV_INSTALL_DIR))
    if override:
        return Path(override).resolve()
    if getattr(sys, "frozen", False):
        return _exe_root()
    return Path(__file__).resolve().parents[1]


def is_installed() -> bool:
    """True when running from a frozen (installed) ProShield build."""
    return bool(getattr(sys, "frozen", False))


def machine_data_root() -> Path:
    program_data = _clean(os.environ.get("ProgramData"))
    base = Path(program_data) if program_data else Path(r"C:\ProgramData")
    return base / PRODUCT_DIRNAME


def user_data_root() -> Path:
    local = _clean(os.environ.get("LOCALAPPDATA"))
    base = Path(local) if local else Path.home() / "AppData" / "Local"
    return base / PRODUCT_DIRNAME


def data_root(create: bool = True) -> Path:
    """Absolute path of the ProShield runtime-data directory.

    Defaults to ``C:\\ProgramData\\ProShield`` (machine scope, matching the
    machine-wide service).  ``PROSHIELD_DATA_DIR`` overrides it - the
    per-user *test-mode* installer sets this to
    ``%LOCALAPPDATA%\\ProShield`` so a non-elevated install can be validated
    without writing to ProgramData.

    If the machine-scoped directory cannot be created (non-elevated user,
    hardened ProgramData ACL) the per-user location is used as a fallback so
    the desktop shell still has somewhere to keep its own state.
    """
    override = _clean(os.environ.get(ENV_DATA_DIR))
    if override:
        target = Path(override).resolve()
        if create:
            target.mkdir(parents=True, exist_ok=True)
        return target

    target = machine_data_root()
    if create:
        try:
            target.mkdir(parents=True, exist_ok=True)
            probe = target / ".proshield-write-probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return target
        except OSError:
            target = user_data_root()
            target.mkdir(parents=True, exist_ok=True)
    return target


def runtime_python(install: Optional[Path] = None) -> Path:
    """The Python interpreter used to launch the two backend planes.

    An installed ProShield always uses the bundled relocatable runtime so the
    machine does not need a system Python.  Development mode falls back to the
    interpreter running this process.
    """
    root = install or install_root()
    bundled = root / "runtime" / "python.exe"
    if bundled.is_file():
        return bundled
    return Path(sys.executable).resolve()


@dataclass(frozen=True)
class ProShieldPaths:
    """Every path ProShield resolves at runtime."""

    install_root: Path
    data_root: Path

    # ---- install (replaced by upgrades) -------------------------------
    app_dir: Path
    scripts_dir: Path
    frontend_dir: Path
    frontend_ui: Path
    runtime_dir: Path
    runtime_python: Path
    service_dir: Path
    service_exe: Path
    desktop_dir: Path
    desktop_exe: Path
    deploy_dir: Path
    build_info_file: Path
    update_public_key_file: Path

    # ---- data (preserved by upgrades) ---------------------------------
    config_dir: Path
    secrets_dir: Path
    logs_dir: Path
    state_dir: Path
    updates_dir: Path
    backup_dir: Path

    settings_file: Path
    secrets_file: Path
    legacy_secrets_file: Path
    initial_credentials_file: Path
    install_info_file: Path
    update_state_file: Path
    health_state_file: Path

    # ------------------------------------------------------------------ api
    def ensure_layout(self) -> "ProShieldPaths":
        for directory in (
            self.config_dir,
            self.secrets_dir,
            self.logs_dir,
            self.state_dir,
            self.updates_dir,
            self.backup_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def as_dict(self) -> dict:
        return {
            "install_root": str(self.install_root),
            "data_root": str(self.data_root),
            "runtime_python": str(self.runtime_python),
            "service_exe": str(self.service_exe),
            "desktop_exe": str(self.desktop_exe),
            "frontend_ui": str(self.frontend_ui),
            "logs_dir": str(self.logs_dir),
        }


def resolve_paths(
    install: Optional[Path] = None,
    data: Optional[Path] = None,
    create_data: bool = True,
) -> ProShieldPaths:
    """Resolve and (optionally) create the full ProShield layout."""
    root = (install or install_root()).resolve()
    droot = (data or data_root(create=create_data)).resolve()

    config_dir = droot / "config"
    secrets_dir = droot / "secrets"
    state_dir = droot / "state"

    return ProShieldPaths(
        install_root=root,
        data_root=droot,
        app_dir=root / "app",
        scripts_dir=root / "scripts",
        frontend_dir=root / "frontend",
        frontend_ui=root / "frontend" / "soc" / "index.html",
        runtime_dir=root / "runtime",
        runtime_python=runtime_python(root),
        service_dir=root / "service",
        service_exe=root / "service" / "ProShieldService.exe",
        desktop_dir=root / "desktop",
        desktop_exe=root / "desktop" / "ProShield.exe",
        deploy_dir=root / "deploy",
        build_info_file=root / "deploy" / "build_info.json",
        update_public_key_file=root / "deploy" / "proshield-update.pub.pem",
        config_dir=config_dir,
        secrets_dir=secrets_dir,
        logs_dir=droot / "logs",
        state_dir=state_dir,
        updates_dir=droot / "updates",
        backup_dir=droot / "backup",
        settings_file=config_dir / "proshield.json",
        secrets_file=secrets_dir / "proshield.env",
        legacy_secrets_file=config_dir / "proshield.env",
        initial_credentials_file=config_dir / "initial-credentials.txt",
        install_info_file=config_dir / "install-info.json",
        update_state_file=state_dir / "update-state.json",
        health_state_file=state_dir / "health.json",
    )
