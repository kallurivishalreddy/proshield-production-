"""Root conftest: shared pytest configuration.

* Unit tests: zero infrastructure, no MongoDB required.
* Integration tests: require a running local MongoDB on
  127.0.0.1:27017.  Connection failures are reported as a
  collection error so the CI log shows a clean ``blocked`` state
  rather than a hard crash.
"""
from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config, items):
    """Tag integration tests so they can be selected explicitly."""
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
