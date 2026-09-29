"""ProShield Windows deployment / packaging layer.

Nothing here is part of the security implementation.  This package contains the
build orchestration, the installer definition, the update signing tool and the
service registration helpers used to produce and install:

    dist/windows/<version>/
        ProShield.exe                       native desktop shell
        ProShieldService.exe                Windows service host
        ProShieldSetup-v<version>.exe       installer
        manifest.json                       signed update metadata
        checksums.txt                       SHA-256 of every artefact

The directory is named ``deploy`` (not ``packaging``) deliberately: the
repository root is on ``sys.path`` for ``python -m ...`` invocations, and a
top-level ``packaging`` directory would shadow the PyPI ``packaging`` library
that PyInstaller and pip depend on.
"""
from __future__ import annotations

__all__ = ["build_windows"]