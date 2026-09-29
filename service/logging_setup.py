"""Logging for the ProShield Windows service.

Installed ProShield never writes logs into the repository or the install
directory (both are replaced by upgrades / are read-only).  Everything lands in
``<data_root>\\logs``:

    C:\\ProgramData\\ProShield\\logs\\service.log   service + supervisor
    C:\\ProgramData\\ProShield\\logs\\updater.log   update channel
    C:\\ProgramData\\ProShield\\logs\\analyst.log   analyst plane stdout/stderr
    C:\\ProgramData\\ProShield\\logs\\ingress.log   ingress plane stdout/stderr
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _level(value: str) -> int:
    return getattr(logging, str(value or "INFO").upper(), logging.INFO)


def configure_logging(
    logs_dir: Path,
    level: str = "INFO",
    filename: str = "service.log",
    max_bytes: int = 8 * 1024 * 1024,
    keep: int = 5,
    console: bool = False,
) -> logging.Logger:
    """Install a rotating file handler on the root logger.

    Idempotent: calling it twice replaces the previous ProShield handler
    instead of stacking duplicates (a real problem for the console/debug mode
    which re-enters ``SvcDoRun``).
    """
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / filename

    root = logging.getLogger()
    root.setLevel(_level(level))

    for handler in list(root.handlers):
        if getattr(handler, "_proshield", False):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover
                pass

    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=max(64 * 1024, int(max_bytes)),
        backupCount=max(1, int(keep)),
        encoding="utf-8",
        delay=False,
    )
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    file_handler._proshield = True  # type: ignore[attr-defined]
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        stream._proshield = True  # type: ignore[attr-defined]
        root.addHandler(stream)

    logging.getLogger("proshield").info(
        "logging initialised (file=%s level=%s)", log_path, level
    )
    return logging.getLogger("proshield")


def child_log_path(logs_dir: Path, name: str) -> Path:
    """Rotating log used for one supervised child plane."""
    return logs_dir / f"{name}.log"


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "proshield")
