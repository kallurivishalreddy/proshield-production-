"""Root conftest: shared pytest configuration.

* Unit tests: zero infrastructure, no MongoDB required.
* Integration tests: require a running local MongoDB on
  127.0.0.1:27017.  Connection failures are reported as a
  collection error so the CI log shows a clean ``blocked`` state
  rather than a hard crash.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _scrub_proshield_environment(monkeypatch):
    """Keep every test hermetic against ambient ``PROSHIELD_*`` variables.

    ``service/settings.py`` deliberately lets the environment override
    ``proshield.json`` (``PROSHIELD_UPDATE_URL``, ``PROSHIELD_DATA_DIR``,
    ``PROSHIELD_MONGO_DB``, ...) because that is exactly what the installer and
    the Windows service rely on.  The same precedence means a developer machine
    that happens to have those variables set silently changes what a test
    observes - and the deployment verification scripts do set them.

    Observed failure without this fixture:
    ``test_engine_without_endpoint_is_disabled_and_harmless`` reported
    ``server-unavailable`` instead of ``no-endpoint``, because a leftover
    ``PROSHIELD_UPDATE_URL`` from an earlier verification run pointed at a
    released test channel.  Tests that *want* an override still set it
    themselves (``monkeypatch.setenv`` runs after this fixture).
    """
    for name in [n for n in os.environ if n.startswith("PROSHIELD_")]:
        monkeypatch.delenv(name, raising=False)


def pytest_collection_modifyitems(config, items):
    """Tag integration tests so they can be selected explicitly."""
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
