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
    from ..capabilities.repository import CAPABILITIES_VALIDATOR, CapabilityRepository
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
        (
            "capabilities",
            CapabilityRepository(db=db, config=config),
            CAPABILITIES_VALIDATOR,
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
        # 0. OWNER-52-04: race-tolerant collection creation. BOTH
        #    deployment planes call this hook, and the shipped launcher
        #    starts them together against the same database, so the
        #    repositories' check-then-``create_collection`` pattern is not
        #    atomic: the loser of the race used to abort the whole plane
        #    with ``PersistenceError: could not create <x> collection``
        #    (MongoDB ``NamespaceExists`` / "already exists, but with
        #    different options"). Creating it here first makes the
        #    repository call below a no-op on the winner's collection.
        _ensure_collection(db, coll_name, validator)
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

    # Phase 5.2: the append-only source audit trail. Every binding /
    # lifecycle / token / migration write appends here, so the collection
    # must exist with its validator + indexes on a fresh deployment —
    # otherwise the audit guarantee would depend on the first write path
    # happening to create it.
    try:
        from ..sources.audit import SOURCE_AUDIT_COLLECTION

        _audit_repo = SourceRepository(db=db, config=config)
        _audit_repo.ensure_audit_schema()
        audit_indexes = _audit_repo.ensure_audit_indexes()
        # NB: deliberately NOT added to ``results``. The V2-P0 invariant
        # asserted by the bootstrap audit is "every *entity* collection has
        # a unique id index". An append-only audit trail has no such
        # natural unique key (two identical-looking events at the same
        # instant are both legitimate records); its uniqueness is the
        # server-managed ``_id``. The Phase 5.1 ``capability_audit``
        # collection is prepared the same way, outside the summary.
        _log.info(
            "bootstrap.audit_collection_ready collection=%s indexes=%s",
            SOURCE_AUDIT_COLLECTION,
            audit_indexes,
        )
    except Exception as exc:  # noqa: BLE001
        # Loud, not silent: a deployment that cannot create its audit
        # collection has lost the Phase 5.2 audit guarantee. The
        # ``source_audit_collection`` health probe surfaces the same
        # condition so it cannot hide in a log file.
        _log.error(
            "bootstrap.source_audit_unavailable error=%s: the append-only "
            "source audit collection could not be prepared",
            type(exc).__name__,
        )

    # Phase 5.1: idempotent built-in capability seeds. Seed-only;
    # no legacy rewrite. Failures are LOUD (§18.25 "seed failure blocks
    # boot"): a deployment must never start with a missing registry.
    # (Finding 5.1-04: this block previously swallowed exceptions into a
    # warning, deviating from the fail-loud contract.)
    from ..capabilities.registry import CapabilityRegistry
    from ..capabilities.repository import CapabilityRepository as _CapRepo
    from ..capabilities.service import CapabilityService as _CapService

    _cap_repo = _CapRepo(db=db, config=config)
    _cap_service = _CapService(repository=_cap_repo, registry=CapabilityRegistry())
    _cap_repo.ensure_audit_schema()
    _cap_repo.ensure_audit_indexes()
    _cap_service.reload_from_repository()
    seed_summary = _cap_service.seed_builtins(actor="system")
    _log.info("bootstrap.capabilities_seeded %s", seed_summary)

    # Capability patch additions (gaps 2, 9, 12):
    # * counters — the unique per-entity-kind human-id counters;
    # * notifications — persisted analyst notification feed;
    # * source_telemetry — per-source ingest counters.
    # The ``counters`` collection is keyed on the native unique
    # ``_id`` (one doc per entity kind) — MongoDB maintains that
    # uniqueness automatically, so no extra index is created.
    try:
        from .telemetry import (
            SOURCE_TELEMETRY_COLLECTION,
            SourceTelemetryStore,
        )

        telemetry_store = SourceTelemetryStore(db=db, config=config)
        telemetry_store.ensure_schema()
        results[SOURCE_TELEMETRY_COLLECTION] = {
            "validator": True,
            "indexes": telemetry_store.ensure_indexes(),
        }
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "bootstrap.capability_collections_skipped error=%s",
            type(exc).__name__,
        )
    try:
        from ..notifications import (
            NOTIFICATIONS_COLLECTION,
            NotificationRepository,
        )

        notif_repo = NotificationRepository(db=db, config=config)
        notif_repo.ensure_schema()
        results[NOTIFICATIONS_COLLECTION] = {
            "validator": True,
            "indexes": notif_repo.ensure_indexes(),
        }
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "bootstrap.notifications_skipped error=%s",
            type(exc).__name__,
        )

    _log.info("bootstrap.complete collections=%d", len(results))
    return results


def _ensure_collection(db: Any, coll_name: str, validator: Dict[str, Any]) -> bool:
    """Create ``coll_name`` with its validator if it is not there yet.

    OWNER-52-04 (Phase 5.2 baseline). Both deployment planes call this
    bootstrap hook, and the shipped launcher starts them within the same
    second against the same database. The repositories' existence check
    followed by ``create_collection`` is therefore a check-then-act race:
    the loser is rejected by MongoDB with ``NamespaceExists`` (code 48) or
    "namespace ... already exists, but with different options" (code 85),
    which the repository translates into a fatal ``PersistenceError`` and
    the plane refuses to start.

    Losing that race is not a failure: the caller re-asserts the
    documented validator with ``collMod`` immediately afterwards, so both
    planes converge on the documented shape. This helper creates the
    collection when possible and tolerates a concurrent creator. Any
    other failure still propagates (the bootstrap contract is
    fail-loud).

    Returns ``True`` only when this call created the collection.
    """
    creator = getattr(db, "create_collection", None)
    if creator is None:
        # Backends without an explicit create (in-memory dev doubles)
        # materialise collections lazily; nothing to prepare here.
        return False
    try:
        if coll_name in db.list_collection_names():
            return False
    except Exception:  # noqa: BLE001 - capability probe only
        pass
    try:
        creator(coll_name, validator=validator)
        return True
    except Exception as exc:  # noqa: BLE001 - tolerance decided below
        try:
            exists_now = coll_name in db.list_collection_names()
        except Exception:  # noqa: BLE001
            exists_now = False
        if exists_now:
            _log.info(
                "bootstrap.collection_created_concurrently collection=%s "
                "error=%s",
                coll_name,
                type(exc).__name__,
            )
            return False
        raise


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
