"""Pytest fixtures for integration tests against the real local MongoDB.

The integration tests REQUIRE a running local MongoDB on
127.0.0.1:27017.  They use a dedicated test database that is
dropped and recreated on every test session so that the suite is
deterministic and self-contained.

Reference: docs/PHASE 3/SECURITY_CONFIGURATION.md (testing
configuration requires an isolated database or namespace).
"""
from __future__ import annotations

import os
import uuid

import pytest
from pymongo import MongoClient

from app.config import ProShieldConfig
from app.persistence.mongo import (
    check_connectivity,
    get_database,
    make_client,
)
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)


TEST_DB_NAME = "proshield_test"


@pytest.fixture(scope="session")
def test_config() -> ProShieldConfig:
    """Per-session test config pointing at a dedicated test database."""
    base = ProShieldConfig.from_env()
    # Force a unique collection per session for total isolation.
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB_NAME,
        mongo_collection_events=f"security_events_{uuid.uuid4().hex[:8]}",
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        connector_specs=[],
    )


@pytest.fixture(scope="session")
def mongo_client(test_config: ProShieldConfig) -> MongoClient:
    client = make_client(test_config)
    check_connectivity(client)
    yield client
    client.close()


@pytest.fixture(scope="session")
def db(mongo_client: MongoClient, test_config: ProShieldConfig):
    return get_database(mongo_client, test_config)


@pytest.fixture(autouse=True)
def clean_collection(db, test_config: ProShieldConfig):
    """Drop and recreate the per-test collection before every test.

    The Phase 4.5 tests introduce additional collections
    (detections, correlations) that also need a clean slate.
    The per-session collection name is unique, so dropping
    every collection is safe.
    """
    for name in db.list_collection_names():
        db.drop_collection(name)
    yield


@pytest.fixture
def repository(db, test_config: ProShieldConfig) -> SecurityEventRepository:
    repo = SecurityEventRepository(db, test_config)
    repo.ensure_schema()
    repo.ensure_indexes()
    return repo
