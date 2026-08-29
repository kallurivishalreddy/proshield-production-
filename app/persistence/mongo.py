"""MongoDB connection management.

The persistence layer is the ONLY place that may import pymongo.
Routes, services, and connectors MUST go through repositories.

Reference: docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001 MongoDB primary,
ADR-002 MongoDB-native document strategy).
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from pymongo import MongoClient
from pymongo.database import Database

from ..config import ProShieldConfig
from ..domain.errors import PersistenceError


def make_client(config: ProShieldConfig) -> MongoClient:
    """Build a MongoClient with a small bounded timeout.

    We deliberately do not configure auto-encryption, retry writes, or
    any advanced features in this slice. ADR-031 leaves transactions
    PROVISIONAL; this slice does not start them.
    """
    return MongoClient(
        config.mongo_uri,
        serverSelectionTimeoutMS=2000,
        connectTimeoutMS=2000,
        socketTimeoutMS=5000,
        appname="proshield-phase4.1",
    )


def get_database(client: MongoClient, config: ProShieldConfig) -> Database:
    return client[config.mongo_db]


def check_connectivity(client: MongoClient) -> None:
    """Raise ``PersistenceError`` if the database is unreachable.

    Performs a server selection ping.  Failures are translated to the
    safe error class so that callers can use a single try/except
    without leaking the underlying driver message.
    """
    try:
        client.admin.command("ping")
    except Exception as exc:  # noqa: BLE001 - we want every driver error here
        raise PersistenceError(
            safe_message="database is unavailable",
            internal_detail=f"ping failed: {type(exc).__name__}",
        ) from exc


@contextmanager
def mongo_session(
    config: ProShieldConfig,
) -> Iterator[tuple[MongoClient, Database]]:
    """Context manager that yields ``(client, db)`` and closes the client on exit.

    Tests and scripts may prefer this over a long-lived module-global
    client so that resources are released deterministically.
    """
    client = make_client(config)
    try:
        yield client, get_database(client, config)
    finally:
        client.close()
