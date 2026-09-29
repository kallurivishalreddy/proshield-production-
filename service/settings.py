"""ProShield service / desktop configuration.

Two files, deliberately separated by sensitivity:

``<data_root>/config/proshield.json``
    Non-secret runtime settings: ports, MongoDB endpoint, update channel,
    update mode, restart policy.  Safe to read, safe to ship in logs.

``<data_root>/config/proshield.env``
    Secrets, ``KEY=VALUE`` one per line: the cross-plane signing keys and the
    subject credentials.  These MUST survive every upgrade - they are written
    once at first run and never regenerated, because regenerating the signing
    keys would invalidate every outstanding session and source-identity token
    (see ``scripts/proxy_server.py::_require_explicit_signing_keys``).

Both live under ``data_root`` and therefore outside the installer's file
replacement scope: **an upgrade never touches them**.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, Optional, Tuple

from service.paths import ProShieldPaths, resolve_paths
from service.version import VERSION_INFO, VersionInfo

LOGGER = logging.getLogger("proshield.settings")

ENV_AUTH_SIGNING_KEY = "PROSHIELD_AUTH_SIGNING_KEY"
ENV_SOURCE_SIGNING_KEY = "PROSHIELD_SOURCE_SIGNING_KEY"
ENV_SUBJECT_CREDENTIALS = "PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS"

#: The four subjects the shipped identity store knows about
#: (``scripts/proxy_server.py::_build_identity_store``).
SEED_SUBJECTS = ("admin", "analyst", "collector", "internal")

#: The documented development credentials.  An installed ProShield generates
#: fresh random ones; these are only used when the operator explicitly asks
#: for development parity (``--dev-credentials``).
DEV_CREDENTIALS: Dict[str, str] = {
    "admin": "admin-dev-credential",
    "analyst": "analyst-dev-credential",
    "collector": "collector-dev-credential",
    "internal": "internal-dev-credential",
}

UPDATE_MODES = ("automatic", "notify-only", "manual")


def _parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            values[key] = value.strip()
    return values


def _write_env_file(path: Path, values: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "# ProShield secrets - generated once at first run.",
        "# These values MUST be preserved across upgrades.",
        "# Regenerating the signing keys invalidates all live sessions",
        "# and every issued source-identity token.",
        "",
    ]
    for key in sorted(values):
        body.append(f"{key}={values[key]}")
    body.append("")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(body), encoding="utf-8")
    os.replace(tmp, path)


def load_secrets(paths: ProShieldPaths) -> Dict[str, str]:
    """Read the secrets file, tolerating the pre-1.0 ``config/`` location.

    ``secrets/proshield.env`` is the installed location (Administrators-only
    ACL).  ``config/proshield.env`` is only read when the new file is absent, so
    an existing development or earlier install keeps working.
    """
    values = _parse_env_file(paths.secrets_file)
    if not values:
        values = _parse_env_file(paths.legacy_secrets_file)
    return values


def _parse_credentials(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        subject, _, credential = pair.partition(":")
        subject, credential = subject.strip(), credential.strip()
        if subject and credential:
            out[subject] = credential
    return out


def _format_credentials(creds: Dict[str, str]) -> str:
    return ",".join(f"{k}:{v}" for k, v in creds.items())


@dataclass(frozen=True)
class ServiceSettings:
    """Effective runtime settings for the service and its child planes."""

    # --- child process topology ---------------------------------------
    analyst_host: str = "127.0.0.1"
    analyst_port: int = 8088
    ingress_host: str = "127.0.0.1"
    ingress_port: int = 8089

    # --- MongoDB (existing, external Windows service) -----------------
    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "proshield"
    mongo_host: str = "127.0.0.1"
    mongo_port: int = 27017
    mongo_wait_seconds: int = 300
    mongo_poll_seconds: float = 2.0

    # --- runtime behaviour --------------------------------------------
    env_name: str = "production"
    log_level: str = "INFO"
    health_timeout_seconds: float = 90.0
    health_poll_seconds: float = 1.0
    restart_backoff_seconds: float = 2.0
    restart_backoff_max_seconds: float = 60.0
    restart_stable_seconds: float = 60.0
    max_restart_attempts: int = 0  # 0 = unlimited
    log_rotate_bytes: int = 8 * 1024 * 1024
    log_rotate_keep: int = 5

    # --- versioning / updates -----------------------------------------
    product_name: str = "ProShield"
    version: str = "0.0.0"
    channel: str = "testing"
    update_mode: str = "automatic"
    update_manifest_url: str = ""
    update_check_interval_seconds: int = 3600
    update_initial_delay_seconds: int = 120
    update_download_timeout_seconds: int = 300
    update_apply_timeout_seconds: int = 900
    update_allow_unsigned: bool = False
    #: How to bring the backend back after an update.  Empty means the default
    #: ("sc start ProShieldService").  Configurable because the *testing*
    #: channel may run a per-user install with no Windows Service to start, and
    #: because a future production channel may use a different service name.
    update_restart_command: Tuple[str, ...] = ()

    # --- secrets (never logged, never serialised) ---------------------
    secrets: Dict[str, str] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ api
    @property
    def analyst_base_url(self) -> str:
        return f"http://{self.analyst_host}:{self.analyst_port}"

    @property
    def ingress_base_url(self) -> str:
        return f"http://{self.ingress_host}:{self.ingress_port}"

    @property
    def ui_url(self) -> str:
        """The authoritative React UI, served by the analyst plane.

        Served from ``frontend/soc`` by the analyst plane's ``/static`` mount,
        i.e. **same-origin with ``/api/proxy``** - the desktop shell never
        bypasses SecureProxy and never talks to MongoDB.
        """
        return f"{self.analyst_base_url}/static/soc/index.html"

    @property
    def auth_signing_key(self) -> str:
        return self.secrets.get(ENV_AUTH_SIGNING_KEY, "")

    @property
    def source_signing_key(self) -> str:
        return self.secrets.get(ENV_SOURCE_SIGNING_KEY, "")

    def subject_credentials(self) -> Dict[str, str]:
        return _parse_credentials(self.secrets.get(ENV_SUBJECT_CREDENTIALS, ""))

    def to_child_env(self) -> Dict[str, str]:
        """Environment for the two backend planes.

        These are exactly the variables ``app/config.py`` and
        ``scripts/proxy_server.py`` already understand - the packaged build
        therefore behaves identically to the development implementation.
        """
        env = {
            "PROSHIELD_ENV": self.env_name,
            "PROSHIELD_LOG_LEVEL": self.log_level,
            "PROSHIELD_MONGO_URI": self.mongo_uri,
            "PROSHIELD_MONGO_DB": self.mongo_db,
            "PROSHIELD_INGRESS_REPLAY_STORE_REQUIRED": "1",
            "PROSHIELD_INGRESS_BACKEND": "mongo",
            "PROSHIELD_PROXY_BACKEND": "mongo",
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
            # An installed ProShield lives under Program Files; the planes must
            # not litter it with __pycache__ directories at runtime.
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env.update(self.secrets)
        return env

    def as_dict(self) -> Dict[str, object]:
        """Secret-free view, safe for logs and diagnostics."""
        return {
            "product_name": self.product_name,
            "version": self.version,
            "channel": self.channel,
            "update_mode": self.update_mode,
            "update_manifest_url": self.update_manifest_url,
            "analyst": f"{self.analyst_host}:{self.analyst_port}",
            "ingress": f"{self.ingress_host}:{self.ingress_port}",
            "mongo_uri": self.mongo_uri,
            "mongo_db": self.mongo_db,
            "env_name": self.env_name,
            "log_level": self.log_level,
            "secrets_present": sorted(self.secrets.keys()),
        }

    # ---------------------------------------------------------------- load
    def to_json(self) -> Dict[str, object]:
        """Serialisable settings (no secrets)."""
        return {
            "product_name": self.product_name,
            "version": self.version,
            "channel": self.channel,
            "analyst_host": self.analyst_host,
            "analyst_port": self.analyst_port,
            "ingress_host": self.ingress_host,
            "ingress_port": self.ingress_port,
            "mongo_uri": self.mongo_uri,
            "mongo_db": self.mongo_db,
            "mongo_host": self.mongo_host,
            "mongo_port": self.mongo_port,
            "mongo_wait_seconds": self.mongo_wait_seconds,
            "env_name": self.env_name,
            "log_level": self.log_level,
            "health_timeout_seconds": self.health_timeout_seconds,
            "restart_backoff_seconds": self.restart_backoff_seconds,
            "restart_backoff_max_seconds": self.restart_backoff_max_seconds,
            "max_restart_attempts": self.max_restart_attempts,
            "log_rotate_bytes": self.log_rotate_bytes,
            "log_rotate_keep": self.log_rotate_keep,
            "update_mode": self.update_mode,
            "update_manifest_url": self.update_manifest_url,
            "update_restart_command": list(self.update_restart_command),
            "update_check_interval_seconds": self.update_check_interval_seconds,
            "update_initial_delay_seconds": self.update_initial_delay_seconds,
            "update_allow_unsigned": self.update_allow_unsigned,
        }


def _coerce(value: object, default, caster):
    if value is None or value == "":
        return default
    try:
        return caster(value)
    except (TypeError, ValueError):
        return default


def _tuple_of_str(value: object, default: Tuple[str, ...]) -> Tuple[str, ...]:
    """Read a command-line list from settings JSON.

    Accepts a list (preferred) or a single already-split string, so an operator
    can write either ``["sc", "start", "ProShieldService"]`` or
    ``"sc start ProShieldService"``.
    """
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return tuple(parts) if parts else default
    text = str(value).strip()
    return tuple(text.split()) if text else default


def load_settings(
    paths: Optional[ProShieldPaths] = None,
    version_info: Optional[VersionInfo] = None,
    include_secrets: bool = True,
) -> ServiceSettings:
    """Load settings from disk, layering: defaults < version.json < proshield.json.

    ``include_secrets=False`` is used by the **desktop shell**, which must never
    hold the cross-plane signing keys or the MongoDB-facing plane
    configuration.  The GUI only ever learns non-secret topology (ports,
    channel, update mode) so it cannot become a path around SecureProxy.
    """
    paths = paths or resolve_paths()
    info = version_info or VERSION_INFO

    defaults = ServiceSettings(
        analyst_port=info.analyst_port,
        ingress_port=info.ingress_port,
        mongo_uri=info.mongo_uri,
        mongo_db=info.mongo_db,
        product_name=info.product_name,
        version=info.version,
        channel=info.channel,
        update_mode=info.update_mode,
        update_manifest_url=info.update_manifest_url,
    )

    raw: Dict[str, object] = {}
    if paths.settings_file.is_file():
        try:
            loaded = json.loads(paths.settings_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded
        except (OSError, ValueError) as exc:
            LOGGER.warning(
                "settings file %s unreadable (%s); using defaults",
                paths.settings_file,
                exc,
            )

    # Environment overrides win over the file (operator escape hatch).
    env = os.environ

    settings = replace(
        defaults,
        analyst_host=str(raw.get("analyst_host") or defaults.analyst_host),
        analyst_port=_coerce(env.get("PROSHIELD_ANALYST_PORT") or raw.get("analyst_port"), defaults.analyst_port, int),
        ingress_host=str(raw.get("ingress_host") or defaults.ingress_host),
        ingress_port=_coerce(env.get("PROSHIELD_INGRESS_PORT") or raw.get("ingress_port"), defaults.ingress_port, int),
        mongo_uri=str(env.get("PROSHIELD_MONGO_URI") or raw.get("mongo_uri") or defaults.mongo_uri),
        mongo_db=str(env.get("PROSHIELD_MONGO_DB") or raw.get("mongo_db") or defaults.mongo_db),
        mongo_host=str(raw.get("mongo_host") or defaults.mongo_host),
        mongo_port=_coerce(raw.get("mongo_port"), defaults.mongo_port, int),
        mongo_wait_seconds=_coerce(raw.get("mongo_wait_seconds"), defaults.mongo_wait_seconds, int),
        env_name=str(raw.get("env_name") or defaults.env_name),
        log_level=str(env.get("PROSHIELD_LOG_LEVEL") or raw.get("log_level") or defaults.log_level),
        health_timeout_seconds=_coerce(raw.get("health_timeout_seconds"), defaults.health_timeout_seconds, float),
        restart_backoff_seconds=_coerce(raw.get("restart_backoff_seconds"), defaults.restart_backoff_seconds, float),
        restart_backoff_max_seconds=_coerce(raw.get("restart_backoff_max_seconds"), defaults.restart_backoff_max_seconds, float),
        max_restart_attempts=_coerce(raw.get("max_restart_attempts"), defaults.max_restart_attempts, int),
        log_rotate_bytes=_coerce(raw.get("log_rotate_bytes"), defaults.log_rotate_bytes, int),
        log_rotate_keep=_coerce(raw.get("log_rotate_keep"), defaults.log_rotate_keep, int),
        channel=str(raw.get("channel") or defaults.channel),
        update_mode=str(env.get("PROSHIELD_UPDATE_MODE") or raw.get("update_mode") or defaults.update_mode),
        update_manifest_url=str(env.get("PROSHIELD_UPDATE_URL") or raw.get("update_manifest_url") or defaults.update_manifest_url),
        update_check_interval_seconds=_coerce(raw.get("update_check_interval_seconds"), defaults.update_check_interval_seconds, int),
        update_initial_delay_seconds=_coerce(raw.get("update_initial_delay_seconds"), defaults.update_initial_delay_seconds, int),
        update_download_timeout_seconds=_coerce(raw.get("update_download_timeout_seconds"), defaults.update_download_timeout_seconds, int),
        update_apply_timeout_seconds=_coerce(raw.get("update_apply_timeout_seconds"), defaults.update_apply_timeout_seconds, int),
        update_allow_unsigned=bool(raw.get("update_allow_unsigned", defaults.update_allow_unsigned)),
        update_restart_command=_tuple_of_str(
            raw.get("update_restart_command"), defaults.update_restart_command
        ),
        secrets=load_secrets(paths) if include_secrets else {},
    )
    if settings.update_mode not in UPDATE_MODES:
        LOGGER.warning(
            "unknown update_mode %r; falling back to 'notify-only'",
            settings.update_mode,
        )
        settings = replace(settings, update_mode="notify-only")
    return settings


def bootstrap_secrets(
    paths: Optional[ProShieldPaths] = None,
    dev_credentials: bool = False,
) -> Dict[str, str]:
    """Create the secrets file if it does not exist yet. Idempotent.

    Returns the effective secret mapping.  Existing values are **never**
    rotated: an upgrade or a service restart must not invalidate live
    sessions or outstanding source-identity tokens.
    """
    paths = (paths or resolve_paths()).ensure_layout()
    existing = load_secrets(paths)
    if (
        existing.get(ENV_AUTH_SIGNING_KEY)
        and existing.get(ENV_SOURCE_SIGNING_KEY)
        and existing.get(ENV_SUBJECT_CREDENTIALS)
    ):
        return existing

    credentials = dict(DEV_CREDENTIALS) if dev_credentials else {
        subject: secrets.token_urlsafe(18) for subject in SEED_SUBJECTS
    }

    merged = {
        ENV_AUTH_SIGNING_KEY: existing.get(ENV_AUTH_SIGNING_KEY) or secrets.token_hex(32),
        ENV_SOURCE_SIGNING_KEY: existing.get(ENV_SOURCE_SIGNING_KEY) or secrets.token_hex(32),
        ENV_SUBJECT_CREDENTIALS: existing.get(ENV_SUBJECT_CREDENTIALS) or _format_credentials(credentials),
    }
    _write_env_file(paths.secrets_file, merged)
    LOGGER.info(
        "bootstrapped ProShield secrets at %s (auth+source signing keys pinned)",
        paths.secrets_file,
    )

    if not paths.initial_credentials_file.is_file():
        _write_initial_credentials(paths, _parse_credentials(merged[ENV_SUBJECT_CREDENTIALS]))
    return merged


def _write_initial_credentials(paths: ProShieldPaths, creds: Dict[str, str]) -> None:
    lines = [
        "ProShield - initial analyst credentials",
        "=======================================",
        "",
        "Generated once when ProShield was first started on this machine.",
        "Keep this file private; delete it once the accounts have been rotated.",
        "",
        "These are the subjects known to the shipped identity store:",
        "",
    ]
    for subject in SEED_SUBJECTS:
        if subject in creds:
            lines.append(f"  subject_id : {subject}")
            lines.append(f"  credential : {creds[subject]}")
            lines.append("")
    lines.append("Sign in from the ProShield desktop application.")
    lines.append("")
    try:
        paths.initial_credentials_file.write_text("\n".join(lines), encoding="utf-8")
    except OSError as exc:  # pragma: no cover - best effort
        LOGGER.warning("could not write initial credentials file: %s", exc)


def write_default_settings(
    paths: Optional[ProShieldPaths] = None,
    settings: Optional[ServiceSettings] = None,
) -> Path:
    """Persist the non-secret settings file (idempotent, preserves edits)."""
    paths = (paths or resolve_paths()).ensure_layout()
    current = settings or load_settings(paths)
    paths.settings_file.write_text(
        json.dumps(current.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return paths.settings_file


def ensure_bootstrap(
    paths: Optional[ProShieldPaths] = None,
    dev_credentials: bool = False,
) -> tuple[ServiceSettings, ProShieldPaths]:
    """Prepare the data layout, secrets and settings. Safe to call repeatedly."""
    paths = (paths or resolve_paths()).ensure_layout()
    bootstrap_secrets(paths, dev_credentials=dev_credentials)
    settings = load_settings(paths)
    if not paths.settings_file.is_file():
        write_default_settings(paths, settings)
    return settings, paths
