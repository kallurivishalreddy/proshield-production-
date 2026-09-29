"""ProShield Windows platform layer.

This package contains the **deployment/productization** code only:

* the Windows Service host (SCM integration),
* the process supervisor that owns the two existing backend planes,
* the versioned update checker/applier with signature + hash verification,
* Windows path/configuration resolution.

It intentionally contains **no security logic**. The authoritative
security implementation remains:

    app/                      (capability, rules, detection, correlation, ...)
    scripts/proxy_server.py   (analyst plane  / SecureProxy wire boundary)
    scripts/ingress_server.py (ingress plane  / trust boundary)

The service merely *supervises* those two processes.
"""
from __future__ import annotations

__all__ = ["__version__"]

from service.version import VERSION as __version__  # noqa: E402
