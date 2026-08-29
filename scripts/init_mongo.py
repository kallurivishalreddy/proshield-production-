"""Bootstrap script: create the ProShield database, apply the schema
validator, and create the required indexes for Phase 4.1.

Usage::

    python -m scripts.init_mongo

Reads connection settings from environment variables (see
``.env.example``).  Intended to be run once per environment, but
idempotent: re-running it is a no-op if the database already exists
with the expected schema and indexes.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from pymongo.errors import PyMongoError

from app.config import ProShieldConfig
from app.observability.logging import configure_logging, get_logger
from app.persistence.mongo import (
    check_connectivity,
    get_database,
    make_client,
)
from app.persistence.security_event_repository import (
    INDEX_SPECS,
    SecurityEventRepository,
)


def main() -> int:
    config = ProShieldConfig.from_env()
    configure_logging(config.log_level)
    log = get_logger("init_mongo")
    log.info("init_mongo.start", extra={"config": config.safe_summary()})

    client = make_client(config)
    try:
        check_connectivity(client)
    except Exception as exc:  # noqa: BLE001
        log.error("init_mongo.unreachable", extra={"err": type(exc).__name__})
        print("ERROR: cannot reach MongoDB at", config.mongo_uri, file=sys.stderr)
        return 2

    db = get_database(client, config)
    repo = SecurityEventRepository(db, config)
    try:
        repo.ensure_schema()
        created = repo.ensure_indexes()
    except PyMongoError as exc:
        log.error("init_mongo.failed", extra={"err": type(exc).__name__})
        print("ERROR:", type(exc).__name__, file=sys.stderr)
        return 3

    log.info("init_mongo.done", extra={"indexes": created})
    print("OK")
    print("database:           ", config.mongo_db)
    print("collection:         ", config.mongo_collection_events)
    print("indexes created:    ", ", ".join(created))
    print("expected indexes:   ", len(INDEX_SPECS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
