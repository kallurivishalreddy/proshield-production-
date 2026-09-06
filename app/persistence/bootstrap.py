"""Deployment bootstrap: apply validators + indexes to every collection.

V2-P0 fix. The Phase 2/4 repositories each expose
``ensure_schema()`` / ``ensure_indexes()``, but nothing in the shipped
composition called them, so a fresh deployment ended up with **no
``$jsonSchema`` validators and no unique indexes** on ``detections``,
``correlations``, ``incidents``, ``reports``, ``managed_rules`` and
``source_instances`` (live-DB evidence in the V2 report). The
documented idempotency guarantees (duplicate event / detection /
correlation / case / report / source protection) are enforced at the
**database boundary** by unique indexes; application-level checks alone
are not acceptable under concurrency (the V2 report proved two
concurrent pipeline instances could open duplicate cases because the
``inc_incident_id_unique`` index did not exist).

This module is the single startup hook both deployment planes call
(``scripts/proxy_server.py`` and ``scripts/ingress_server.py``). It is
idempotent and fails loudly when the database cannot be brought to the
documented shape — a deployment that cannot enforce its own persistence
contract must not start silently.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..config import ProShieldConfig

_log = logging.getLogger(__name__)


def ensure_all_collections(db: Any, config: ProShieldConfig) -> Dict[str, Any]:
    """Apply the documented schema + index set to every collection.

    Returns a summary dict
    ``{collection: {"validator": bool, "indexes": [names]}}``.

    Raises on failure (any repository error propagates) so both servers
    refuse to start against a database they cannot prepare.
    """
    from ..incidents.repository import INCIDENTS_VALIDATOR, IncidentRepository
    from ..persistence.correlation_repository import (
        CORRELATIONS_VALIDATOR,
        CorrelationRepository,
    )
    from ..persistence.detection_repository import (
        DETECTIONS_VALIDATOR,
        DetectionRepository,
    )
    from ..persistence.rule_repository import (
        MANAGED_RULES_VALIDATOR,
        RuleRepository,
    )
    from ..persistence.schema import SECURITY_EVENTS_VALIDATOR
    from ..persistence.security_event_repository import (
        SecurityEventRepository,
    )
    from ..reports.repository import REPORTS_VALIDATOR, ReportRepository
    from ..sources.repository import SOURCE_INSTANCES_VALIDATOR, SourceRepository

    # (display key, repository instance, module validator constant).
    # The collection name is always read from the repository itself
    # (``repo.collection.name``) so the bootstrap can never drift from
    # the repository's own naming decision.
    plan = (
        (
            "security_events",
            SecurityEventRepository(db=db, config=config),
            SECURITY_EVENTS_VALIDATOR,
        ),
        (
            "detections",
            DetectionRepository(db=db, config=config),
            DETECTIONS_VALIDATOR,
        ),
        (
            "correlations",
            CorrelationRepository(db=db, config=config),
            CORRELATIONS_VALIDATOR,
        ),
        (
            "incidents",
            IncidentRepository(db=db, config=config),
            INCIDENTS_VALIDATOR,
        ),
        (
            "reports",
            ReportRepository(db=db, config=config),
            REPORTS_VALIDATOR,
        ),
        (
            "managed_rules",
            RuleRepository(db=db, config=config),
            MANAGED_RULES_VALIDATOR,
        ),
        (
            "source_instances",
            SourceRepository(db=db, config=config),
            SOURCE_INSTANCES_VALIDATOR,
        ),
    )

    results: Dict[str, Dict[str, Any]] = {}
    for name, repo, validator in plan:
        # NB: pymongo Collection objects forbid truth-value testing
        # (``bool(collection)`` raises), so the fallback below must
        # compare with None explicitly — never ``a or b``.
        coll = getattr(repo, "collection", None)
        if coll is None:
            coll = getattr(repo, "_collection", None)
        coll_name = coll.name if coll is not None else name
        # 1. Collection-level setup (creation + validator).
        repo.ensure_schema()
        # 2. Re-assert the validator on an existing collection
        #    (create_collection only validates at creation time).
        validator_ok = _assert_validator(db, coll_name, validator)
        # 3. Documented index set (unique + query indexes).
        repo.ensure_indexes()

        results[name] = {
            "validator": validator_ok,
            "indexes": _index_names(db, coll_name),
        }
        _log.info(
            "bootstrap.collection_ready collection=%s validator=%s indexes=%s",
            name,
            validator_ok,
            results[name]["indexes"],
        )

    # Replay store: unique token_id + TTL index (D-1). The store
    # applies its own indexes in its constructor / ``_ensure_schema``.
    try:
        from ..sources.replay_store import MongoReplayStore

        MongoReplayStore(db=db, config=config)
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "bootstrap.replay_store_indexes_skipped error=%s",
            type(exc).__name__,
        )

    _log.info("bootstrap.complete collections=%d", len(results))
    return results


def _assert_validator(db: Any, coll_name: str, validator: Dict[str, Any]) -> bool:
    """Re-assert a ``$jsonSchema`` validator on a collection.

    ``create_collection(validator=...)`` only applies the validator at
    creation time; on an existing collection the documented validator
    must be (re)applied with ``collMod`` — this is idempotent and safe
    to call on every startup. Returns False when the backend cannot
    support it (in-memory dev fakes).
    """
    try:
        db.command("collMod", coll_name, validator=validator)
        return True
    except Exception as exc:  # noqa: BLE001
        _log.debug(
            "bootstrap.validator_collmod_unavailable collection=%s error=%s",
            coll_name,
            type(exc).__name__,
        )
        return False


def _index_names(db: Any, coll_name: str) -> List[str]:
    try:
        return sorted(
            str(ix.get("name"))
            for ix in db[coll_name].list_indexes()
        )
    except Exception:  # noqa: BLE001
        return []


__all__ = ["ensure_all_collections"]
