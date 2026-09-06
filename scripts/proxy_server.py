"""HTTP deployment wrapper for ProShield SecureProxy.

This is NOT a backend modification. The Phase 4 backend exposes a
function-level boundary: ``SecureProxy.handle(ProxyRequest) -> ProxyResponse``.
The final backend verification report (PROSHIELD-FINAL-BACKEND-VERIFICATION.md
Section 1 / Section 7 / etc.) explicitly states:

    "A real listener (e.g., FastAPI / uvicorn / gunicorn behind nginx)
     must wrap InboundIngressProxy.handle."

This script is **the deployment-team choice of listener**, wired exactly
as the contract specifies: the FastAPI app has a single ``/api/proxy``
endpoint that constructs a :class:`ProxyRequest` from the inbound HTTP
request and forwards it to :class:`SecureProxy.handle`, then converts
the :class:`ProxyResponse` back to an HTTP response. The proxy itself
(``app.proxy.proxy.SecureProxy``) is untouched.

Two backend choices:

* ``--backend mongo``  - live MongoDB on 127.0.0.1:27017 (default)
* ``--backend memory`` - in-memory FakeDatabase, no MongoDB needed

The proxy is identical in both cases. The frontend cannot tell which
backend is in use; all 39 wired operations behave the same way.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, Request, Response  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from fastapi.responses import RedirectResponse  # type: ignore
import uvicorn  # type: ignore

from app.config import ProShieldConfig
from app.auth import (
    ADMIN_ROLE,
    ANALYST_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
    Identity,
    IdentityStore,
    InMemoryIdentityStore,
)
from app.auth.session import (
    SessionVerifier,
    new_development_signing_key,
)
from app.proxy import (
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    ProxyResponse,
    SecureProxy,
)
from app.proxy.proxy import PROXY_HEADER_CREDENTIAL
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.service import SourceManagementService
from app.rules import RuleRegistry, load_rules_from_specs
from app.detection.service import DetectionReadService
from app.correlation.service import CorrelationReadService
from app.persistence.detection_repository import DetectionRepository
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.security_event_repository import SecurityEventRepository
from app.persistence.rule_repository import RuleRepository
from app.overview.service import OverviewReadService
from app.timeline.service import TimelineReadService
from app.timeline.engine import TimelineEngine
from app.rules.management.service import RuleManagementService
from app.reports.service import ReportService
from app.incidents.service import IncidentService
from app.incidents.repository import IncidentRepository
from app.reports.repository import ReportRepository
from app.routing import RoutingEngine

LOGGER = logging.getLogger("proshield.proxy_server")


# ============================================================ in-memory fakes
# Re-uses the same FakeDatabase / FakeCollection pattern as the
# Phase 4.7 unit tests so the production code paths are exercised
# without a MongoDB dependency.


class FakeCollection:
    def __init__(self) -> None:
        self.docs: List[Dict[str, Any]] = []

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        self.docs.append(dict(doc))
        return type("R", (), {"inserted_id": "fake"})()

    def find_one(
        self,
        query: Dict[str, Any],
        sort: Optional[List[Tuple[str, int]]] = None,
    ) -> Optional[Dict[str, Any]]:
        results = [d for d in self.docs if _match(d, query)]
        if not results:
            return None
        if sort:
            for k, direction in reversed(sort):
                results.sort(
                    key=lambda d, k=k: d.get(k),
                    reverse=(direction == -1),
                )
        return dict(results[0])

    def find(self, query: Dict[str, Any]) -> "FakeCursor":
        return FakeCursor([d for d in self.docs if _match(d, query)])

    def replace_one(
        self,
        query: Dict[str, Any],
        doc: Dict[str, Any],
        upsert: bool = False,
    ) -> Any:
        for d in self.docs:
            if _match(d, query):
                d.clear()
                d.update(doc)
                return type("R", (), {"matched_count": 1, "modified_count": 1})()
        if upsert:
            self.docs.append(dict(doc))
            return type("R", (), {"matched_count": 0, "upserted_id": "fake"})()
        return type("R", (), {"matched_count": 0, "modified_count": 0})()

    def update_one(
        self, query: Dict[str, Any], update: Dict[str, Any]
    ) -> Any:
        for d in self.docs:
            if _match(d, query):
                if "$set" in update:
                    d.update(update["$set"])
                return type("R", (), {"matched_count": 1, "modified_count": 1})()
        return type("R", (), {"matched_count": 0, "modified_count": 0})()

    def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for d in self.docs if _match(d, query))

    def create_index(
        self, key: List[Tuple[str, int]], *, name: str, unique: bool = False
    ) -> Any:
        return name

    def aggregate(self, pipeline: List[Dict[str, Any]]) -> "FakeCursor":
        # Minimal aggregation: support $match / $sort / $group /
        # $replaceRoot / $limit / $project / $unwind.
        docs: List[Dict[str, Any]] = [
            dict(d) for d in self.docs if d is not None
        ]
        for stage in pipeline:
            if "$match" in stage:
                docs = [d for d in docs if d is not None and _match(d, stage["$match"])]
            elif "$sort" in stage:
                for k, direction in reversed(
                    list(stage["$sort"].items())
                ):
                    docs = sorted(
                        [d for d in docs if d is not None],
                        key=lambda x, k=k: (
                            x.get(k) is None,
                            x.get(k),
                        ),
                        reverse=(direction == -1),
                    )
            elif "$group" in stage:
                group_expr = stage["$group"]
                grouped: Dict[Any, List[Dict[str, Any]]] = {}
                for d in docs:
                    key_expr = group_expr.get("_id", None)
                    if isinstance(key_expr, str) and key_expr.startswith("$"):
                        k_val = d.get(key_expr[1:])
                    else:
                        k_val = key_expr
                    grouped.setdefault(k_val, []).append(d)
                out: List[Dict[str, Any]] = []
                for k_val, items in grouped.items():
                    entry: Dict[str, Any] = {"_id": k_val}
                    for out_field, expr in group_expr.items():
                        if out_field == "_id":
                            continue
                        if isinstance(expr, dict):
                            if "$sum" in expr:
                                if expr["$sum"] == 1:
                                    entry[out_field] = len(items)
                                elif isinstance(expr["$sum"], str) and (
                                    expr["$sum"].startswith("$")
                                ):
                                    entry[out_field] = sum(
                                        d.get(expr["$sum"][1:], 0) or 0
                                        for d in items
                                    )
                            elif "$first" in expr and isinstance(
                                expr["$first"], str
                            ) and expr["$first"].startswith("$"):
                                # MongoDB system variables: $$ROOT
                                # (the entire document) and $$CURRENT.
                                if expr["$first"].startswith("$$ROOT"):
                                    entry[out_field] = (
                                        dict(items[0]) if items else None
                                    )
                                elif expr["$first"].startswith(
                                    "$$CURRENT"
                                ):
                                    entry[out_field] = (
                                        dict(items[0]) if items else None
                                    )
                                else:
                                    entry[out_field] = (
                                        items[0].get(
                                            expr["$first"].lstrip("$"),
                                        )
                                        if items
                                        else None
                                    )
                            elif "$max" in expr and isinstance(
                                expr["$max"], str
                            ) and expr["$max"].startswith("$"):
                                vals = [
                                    d.get(expr["$max"][1:]) for d in items
                                ]
                                entry[out_field] = max(
                                    (v for v in vals if v is not None),
                                    default=None,
                                )
                            elif "$push" in expr and isinstance(
                                expr["$push"], str
                            ) and expr["$push"].startswith("$"):
                                entry[out_field] = [
                                    d.get(expr["$push"][1:]) for d in items
                                ]
                    out.append(entry)
                docs = out
            elif "$replaceRoot" in stage:
                new_root = stage["$replaceRoot"].get("newRoot")
                if isinstance(new_root, str) and new_root.startswith("$"):
                    field = new_root[1:]
                    docs = [
                        d.get(field, d) if d is not None else d
                        for d in docs
                    ]
                elif isinstance(new_root, dict):
                    docs = [
                        d.get("doc", d) if d is not None else d
                        for d in docs
                    ]
                else:
                    docs = [
                        d.get("doc", d) if d is not None else d
                        for d in docs
                    ]
                # Final filter to drop any None rows
                docs = [d for d in docs if d is not None]
            elif "$limit" in stage:
                docs = docs[: int(stage["$limit"])]
            elif "$project" in stage:
                keep = stage["$project"]
                docs = [
                    {k: v for k, v in d.items() if keep.get(k, True)}
                    for d in docs
                ]
            elif "$unwind" in stage:
                out2: List[Dict[str, Any]] = []
                field = stage["$unwind"]
                if isinstance(field, str) and field.startswith("$"):
                    field = field[1:]
                preserve = (
                    stage.get("preserveNullAndEmptyArrays", False)
                    if isinstance(stage, dict)
                    else False
                )
                for d in docs:
                    val = d.get(field)
                    if isinstance(val, list):
                        for v in val:
                            nd = dict(d)
                            nd[field] = v
                            out2.append(nd)
                    elif val is None and preserve:
                        out2.append(d)
                    elif val is not None:
                        nd = dict(d)
                        nd[field] = val
                        out2.append(nd)
                docs = out2
            elif "$addFields" in stage or "$set" in stage:
                fields = stage.get("$addFields") or stage.get("$set")
                for d in docs:
                    for fname, fexpr in fields.items():
                        if isinstance(fexpr, str) and fexpr.startswith("$"):
                            d[fname] = d.get(fexpr[1:])
                        else:
                            d[fname] = fexpr
        return FakeCursor(docs)


class FakeCursor:
    def __init__(self, docs: List[Dict[str, Any]]) -> None:
        self.docs = docs

    def sort(
        self, key: Any, direction: Optional[int] = None
    ) -> "FakeCursor":
        if direction is not None:
            k = key
            d = direction
            self.docs = sorted(
                self.docs, key=lambda x, k=k: x.get(k), reverse=(d == -1)
            )
            return self
        for k, d in reversed(list(key)):
            self.docs = sorted(
                self.docs, key=lambda x, k=k: x.get(k), reverse=(d == -1)
            )
        return self

    def limit(self, n: int) -> "FakeCursor":
        self.docs = self.docs[:n]
        return self

    def __iter__(self):
        return iter(self.docs)


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for k, v in query.items():
        if doc.get(k) != v:
            return False
    return True


class FakeDatabase:
    def __init__(self) -> None:
        self.collections: Dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self.collections:
            self.collections[name] = FakeCollection()
        return self.collections[name]

    def command(self, *args: Any, **kwargs: Any) -> Any:
        return {"ok": 1}

    def list_collection_names(self) -> List[str]:
        return list(self.collections.keys())


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _build_config(args: argparse.Namespace) -> ProShieldConfig:
    """Build a runtime config from env + CLI args.

    If signing keys are not provided via env (development convenience)
    we generate ephemeral ones and seed the default subject credentials
    so the frontend can log in immediately.
    """
    base = ProShieldConfig.from_env()
    auth_key = os.environ.get("PROSHIELD_AUTH_SIGNING_KEY", "")
    source_key = os.environ.get("PROSHIELD_SOURCE_SIGNING_KEY", "")
    if not auth_key:
        auth_key = new_development_signing_key()
        LOGGER.warning(
            "PROSHIELD_AUTH_SIGNING_KEY was empty; generated ephemeral "
            "development key."
        )
    if not source_key:
        source_key = new_development_signing_key()
        LOGGER.warning(
            "PROSHIELD_SOURCE_SIGNING_KEY was empty; generated ephemeral "
            "development key."
        )

    seed_credentials = dict(base.default_subject_credentials)
    if args.seed_credentials and not seed_credentials:
        seed_credentials = {
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
            "collector": "collector-dev-credential",
            "internal": "internal-dev-credential",
        }

    return ProShieldConfig(
        env_name=base.env_name or "development",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=base.mongo_db,
        mongo_collection_events=base.mongo_collection_events,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        ingest_rate_limit_per_minute=base.ingest_rate_limit_per_minute,
        auth_signing_key=auth_key,
        auth_token_lifetime_seconds=base.auth_token_lifetime_seconds,
        proxy_rate_limit_per_minute=base.proxy_rate_limit_per_minute,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=(
            base.proxy_centralized_rate_limit_per_minute
        ),
        source_signing_key=source_key,
        source_token_lifetime_seconds=base.source_token_lifetime_seconds,
        ingress_rate_limit_per_minute=base.ingress_rate_limit_per_minute,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_event_rate_limit_per_minute=(
            base.ingress_event_rate_limit_per_minute
        ),
        ingress_max_events_per_request=base.ingress_max_events_per_request,
        ingress_replay_store_required=base.ingress_replay_store_required,
        ingress_replay_collection=base.ingress_replay_collection,
        secret_store_configured=base.secret_store_configured,
        default_subject_credentials=seed_credentials,
        connector_specs=base.connector_specs,
    )


class _BackendBundle:
    """Holds every service the SecureProxy needs to operate."""

    def __init__(
        self,
        config: ProShieldConfig,
        proxy: SecureProxy,
        backend_kind: str,
        identity_store: IdentityStore,
        source_management: SourceManagementService,
        incident_service: IncidentService,
        report_service: ReportService,
        rule_registry: RuleRegistry,
        detection_repo: DetectionRepository,
        correlation_repo: CorrelationRepository,
        event_repo: SecurityEventRepository,
    ) -> None:
        self.config = config
        self.proxy = proxy
        self.backend_kind = backend_kind
        self.identity_store = identity_store
        self.source_management = source_management
        self.incident_service = incident_service
        self.report_service = report_service
        self.rule_registry = rule_registry
        self.detection_repo = detection_repo
        self.correlation_repo = correlation_repo
        self.event_repo = event_repo
        self.rule_repo_for_test: Optional[RuleRepository] = None


def _attach_services(proxy: SecureProxy, bundle: _BackendBundle) -> None:
    """Wire every read/write service into the SecureProxy."""
    proxy.attach_incident_service(bundle.incident_service)
    proxy.attach_source_management_service(bundle.source_management)

    detection_service = DetectionReadService(
        repository=bundle.detection_repo,
    )
    proxy.attach_detection_service(detection_service)

    correlation_service = CorrelationReadService(
        repository=bundle.correlation_repo,
    )
    proxy.attach_correlation_service(correlation_service)

    proxy.attach_overview_service(
        OverviewReadService(
            incident_service=bundle.incident_service,
            detection_service=detection_service,
            correlation_service=correlation_service,
        )
    )

    proxy.attach_timeline_service(
        TimelineReadService(
            engine=TimelineEngine(),
            security_event_repository=bundle.event_repo,
            detection_service=detection_service,
            correlation_service=correlation_service,
        ),
        security_event_repository=bundle.event_repo,
    )

    rule_repo = RuleRepository(
        db=FakeDatabase() if bundle.backend_kind == "memory"
        else _mongo_db_for_collection("managed_rules", bundle),
        config=bundle.config,
    )
    bundle.rule_repo_for_test = rule_repo
    # Persist built-in rules so ``rule.list`` returns the 5 documented
    # NGINX rules (and so any later ``rule.create`` knows about them).
    _seed_managed_rules(rule_repo, bundle.rule_registry)

    proxy.attach_rule_management_service(
        RuleManagementService(
            repository=rule_repo,
            registry=bundle.rule_registry,
            config=bundle.config,
        )
    )

    proxy.attach_report_service(bundle.report_service)


def _mongo_db_for_collection(coll_name: str, bundle: _BackendBundle):  # noqa: ANN001
    """Return a Mongo Database wrapper for a single collection."""
    if hasattr(bundle, "_mongo_db") and bundle._mongo_db is not None:
        return bundle._mongo_db
    return FakeDatabase()


def _seed_managed_rules(
    rule_repo: RuleRepository,
    registry: RuleRegistry,
) -> None:
    """Persist the built-in NGINX rules into the managed-rule repository.

    The repository is the canonical read source for ``rule.list``;
    the registry is the in-memory evaluator. Both must agree on the
    available rules for the UI to display the 5 documented NGINX
    rules plus any rule created via ``rule.create``.

    This is idempotent: rules already present in the repository are
    skipped so a restart never duplicates entries.
    """
    from app.rules.loader import load_rules_from_specs
    from app.rules.management.definition import (
        RuleDefinition,
        RuleState,
    )
    from app.rules.types import RuleState as _RuleStateMeta
    from app.severity.models import SeverityBand
    from datetime import datetime, timezone

    # Only load if the registry is empty (avoid duplicate registration
    # when this is called twice during bundle construction).
    if not registry.list_all():
        try:
            load_rules_from_specs(
                registry, ["app.rules._library.nginx"]
            )
        except Exception as exc:  # pragma: no cover - best effort
            LOGGER.warning("Could not load nginx rules: %s", exc)

    existing = {
        (d.rule_id, d.version) for d in rule_repo.find_all()
    }

    for rule in registry.list_all():
        metadata = rule.metadata
        rule_id = metadata.rule_id
        version = metadata.version
        if (rule_id, version) in existing:
            continue

        # Map the loaded (built-in) metadata into the strict
        # managed-rule definition. The mapping is one-way (built-in
        # -> managed) so the production detector's evaluable set is
        # unchanged.
        raw_severity = getattr(metadata, "severity", "medium")
        try:
            severity = SeverityBand(str(raw_severity).lower())
        except (ValueError, AttributeError):
            severity = SeverityBand.MEDIUM

        try:
            state_value = (
                _RuleStateMeta(metadata.state).value
                if hasattr(metadata.state, "value")
                else str(metadata.state)
            )
        except (ValueError, AttributeError):
            state_value = RuleState.APPROVED.value
        if state_value not in (
            RuleState.APPROVED.value,
            RuleState.CANDIDATE.value,
        ):
            state_value = RuleState.APPROVED.value

        # severity / state must be the correct type / value for the
        # RuleDefinition validator (frozen, extra=forbid).
        try:
            definition = RuleDefinition(
                rule_id=rule_id,
                version=version,
                name=metadata.name,
                description=getattr(metadata, "description", ""),
                category=metadata.category,
                sources=tuple(metadata.sources),
                event_types=tuple(metadata.event_types),
                tags=tuple(metadata.tags),
                references=tuple(getattr(metadata, "references", ())),
                state=state_value,
                enabled=bool(getattr(metadata, "enabled", True)),
                severity=severity,
            )
        except Exception as exc:  # pragma: no cover - validation gate
            LOGGER.warning(
                "Could not build managed definition for %s: %s",
                rule_id,
                exc,
            )
            continue
        try:
            rule_repo.create(definition)
        except Exception as exc:  # pragma: no cover - best effort
            LOGGER.warning("Could not seed rule %s: %s", rule_id, exc)


def _build_identity_store(config: ProShieldConfig) -> IdentityStore:
    """Build an identity store populated with the dev seed subjects.

    Each subject's role maps to the documented RBAC defaults; we
    pass credentials so ``auth.issue`` can issue a session token.
    """
    identities: Dict[str, Identity] = {}
    creds: Dict[str, str] = dict(config.default_subject_credentials)
    seed = [
        ("admin", ADMIN_ROLE),
        ("analyst", ANALYST_ROLE),
        ("collector", COLLECTOR_ROLE),
        ("internal", INTERNAL_SERVICE_ROLE),
    ]
    for subject_id, role in seed:
        if subject_id in creds:
            identities[subject_id] = Identity(
                subject_id=subject_id,
                role=role,
                display_name=subject_id.title(),
                permissions=(),
            )
    return InMemoryIdentityStore(
        identities=identities,
        credentials=creds,
    )


def _build_memory_backend(config: ProShieldConfig) -> _BackendBundle:
    """Build an in-memory backend (FakeDatabase everywhere)."""
    db = FakeDatabase()
    identity_store = _build_identity_store(config)

    session_verifier = SessionVerifier(
        signing_key=config.auth_signing_key,
        identity_store=identity_store,
    )

    source_registry = SourceRegistry()
    from app.sources.trust import SourceIdentityTokenIssuer
    token_issuer = SourceIdentityTokenIssuer(
        secret=config.source_signing_key,
        lifetime_seconds=config.source_token_lifetime_seconds,
        max_lifetime_seconds=config.source_token_lifetime_seconds,
    )
    source_management = SourceManagementService(
        repository=SourceRepository(db=db, config=config),
        registry=source_registry,
        token_issuer=token_issuer,
    )
    # F-6 durability: recover persisted sources into the in-memory
    # registry at startup so a restarted proxy still sees the enabled
    # sources that live in the store (otherwise a restart silently 404s
    # previously-registered sources).
    try:
        reloaded = source_management.reload_from_repository()
        LOGGER.info(
            "source registry recovered %d persisted source(s) at startup",
            reloaded,
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("source registry recovery failed: %s", exc)

    rule_registry = RuleRegistry()
    try:
        load_rules_from_specs(
            rule_registry,
            ["app.rules._library.nginx"],
        )
    except Exception as exc:  # pragma: no cover - best effort
        LOGGER.warning("Could not load rules: %s", exc)

    proxy = SecureProxy(
        config=config,
        identity_store=identity_store,
        session_verifier=session_verifier,
    )

    detection_repo = DetectionRepository(db=db, config=config)
    correlation_repo = CorrelationRepository(db=db, config=config)
    event_repo = SecurityEventRepository(db=db, config=config)
    incident_repo = IncidentRepository(db=db, config=config)
    incident_service = IncidentService(repository=incident_repo)

    report_repo = ReportRepository(db=db, config=config)
    report_service = ReportService(
        repository=report_repo,
        incident_service=incident_service,
    )

    bundle = _BackendBundle(
        config=config,
        proxy=proxy,
        backend_kind="memory",
        identity_store=identity_store,
        source_management=source_management,
        incident_service=incident_service,
        report_service=report_service,
        rule_registry=rule_registry,
        detection_repo=detection_repo,
        correlation_repo=correlation_repo,
        event_repo=event_repo,
    )
    bundle._mongo_db = None  # type: ignore[attr-defined]
    _attach_services(proxy, bundle)
    return bundle


def _require_explicit_signing_keys(config: ProShieldConfig) -> None:
    """V2-21: fail fast on unpinned cross-plane signing keys.

    ``source.issue_token`` (analyst plane) signs source-identity tokens
    with ``PROSHIELD_SOURCE_SIGNING_KEY``; the ingress plane verifies
    them with the *same* key. When the variable is unset each plane
    derives its own ephemeral secret, and every token 401s with no
    diagnostic beyond per-request failures. The same applies to
    ``PROSHIELD_AUTH_SIGNING_KEY`` for sessions across analyst-plane
    workers. A Mongo-backed (deployment-grade) start must therefore
    pin both keys explicitly.
    """
    missing = []
    if not config.auth_signing_key:
        missing.append("PROSHIELD_AUTH_SIGNING_KEY")
    if not config.source_signing_key:
        missing.append("PROSHIELD_SOURCE_SIGNING_KEY")
    if missing:
        raise SystemExit(
            "FATAL: refusing to start the analyst plane against MongoDB "
            "without explicit cross-plane signing keys: "
            + ", ".join(missing)
            + ". Set them in the environment so both planes derive the "
            "same secrets (V2-21)."
        )


def _build_mongo_backend(config: ProShieldConfig) -> _BackendBundle:
    """Build a backend wired to a real MongoDB on 127.0.0.1:27017."""
    from pymongo import MongoClient  # type: ignore

    client = MongoClient(config.mongo_uri)
    db = client[config.mongo_db]

    # V2-21: refuse to start a Mongo-backed deployment whose cross-plane
    # signing keys are not pinned. Without an explicit key both planes
    # would derive *different* ephemeral secrets and every source token
    # / session would fail verification with opaque 401s at runtime.
    _require_explicit_signing_keys(config)

    # V2-P0: apply the documented $jsonSchema validators + unique
    # indexes to every collection on the real startup path. The
    # repositories exposed ensure_schema()/ensure_indexes() but nothing
    # called them, so fresh deployments silently lost the database-level
    # idempotency guarantees (duplicate case / report / source races).
    from app.persistence.bootstrap import ensure_all_collections

    bootstrap = ensure_all_collections(db, config)
    LOGGER.info(
        "persistence bootstrap complete (collections=%d)",
        len(bootstrap),
    )

    identity_store = _build_identity_store(config)
    session_verifier = SessionVerifier(
        signing_key=config.auth_signing_key,
        identity_store=identity_store,
    )

    source_registry = SourceRegistry()
    from app.sources.trust import SourceIdentityTokenIssuer
    token_issuer = SourceIdentityTokenIssuer(
        secret=config.source_signing_key,
        lifetime_seconds=config.source_token_lifetime_seconds,
        max_lifetime_seconds=config.source_token_lifetime_seconds,
    )
    source_management = SourceManagementService(
        repository=SourceRepository(db=db, config=config),
        registry=source_registry,
        token_issuer=token_issuer,
    )
    # F-6 durability: recover persisted sources into the in-memory
    # registry at startup so a restarted proxy still sees the enabled
    # sources that live in the store (otherwise a restart silently 404s
    # previously-registered sources).
    try:
        reloaded = source_management.reload_from_repository()
        LOGGER.info(
            "source registry recovered %d persisted source(s) at startup",
            reloaded,
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("source registry recovery failed: %s", exc)

    rule_registry = RuleRegistry()
    try:
        load_rules_from_specs(
            rule_registry,
            ["app.rules._library.nginx"],
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("Could not load rules: %s", exc)

    proxy = SecureProxy(
        config=config,
        identity_store=identity_store,
        session_verifier=session_verifier,
    )

    detection_repo = DetectionRepository(db=db, config=config)
    correlation_repo = CorrelationRepository(db=db, config=config)
    event_repo = SecurityEventRepository(db=db, config=config)
    incident_repo = IncidentRepository(db=db, config=config)
    incident_service = IncidentService(repository=incident_repo)

    report_repo = ReportRepository(db=db, config=config)
    report_service = ReportService(
        repository=report_repo,
        incident_service=incident_service,
    )

    bundle = _BackendBundle(
        config=config,
        proxy=proxy,
        backend_kind="mongo",
        identity_store=identity_store,
        source_management=source_management,
        incident_service=incident_service,
        report_service=report_service,
        rule_registry=rule_registry,
        detection_repo=detection_repo,
        correlation_repo=correlation_repo,
        event_repo=event_repo,
    )
    bundle._mongo_db = db  # type: ignore[attr-defined]
    _attach_services(proxy, bundle)
    return bundle


def _build_app(bundle: _BackendBundle) -> FastAPI:
    app = FastAPI(
        title="ProShield Proxy Server",
        description=(
            "Thin HTTP wrapper around app.proxy.SecureProxy."
        ),
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    @app.get("/health")
    async def liveness() -> Dict[str, str]:
        return {"status": "ok", "backend_kind": bundle.backend_kind}

    @app.get("/")
    async def root_redirect() -> RedirectResponse:
        # Always go to the login page first. The login page itself
        # bounces the user to /static/index.html once a session
        # token is established.
        return RedirectResponse(url="/static/login.html", status_code=307)

    @app.get("/api/meta")
    async def meta() -> Dict[str, Any]:
        return {
            "backend_kind": bundle.backend_kind,
            "proxy_max_request_bytes": bundle.config.proxy_max_request_bytes,
            "proxy_max_response_bytes": (
                bundle.config.proxy_max_response_bytes
            ),
            "proxy_rate_limit_per_minute": (
                bundle.config.proxy_rate_limit_per_minute
            ),
            "proxy_centralized_rate_limit_per_minute": (
                bundle.config.proxy_centralized_rate_limit_per_minute
            ),
            "default_subjects": list(
                bundle.identity_store.all_subject_ids()
                if hasattr(bundle.identity_store, "all_subject_ids")
                else []
            ),
        }

    @app.post("/api/proxy")
    async def proxy_endpoint(request: Request) -> Response:
        body_bytes = await request.body()
        if len(body_bytes) > bundle.config.proxy_max_request_bytes:
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "code": "request_too_large",
                            "message": "request body exceeds limit",
                        }
                    }
                ),
                status_code=400,
                media_type="application/json",
            )

        try:
            payload: Dict[str, Any] = (
                json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            )
        except json.JSONDecodeError:
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "code": "invalid_json",
                            "message": "request body is not valid JSON",
                        }
                    }
                ),
                status_code=400,
                media_type="application/json",
            )

        operation = payload.pop("operation", None)
        if not operation:
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "code": "missing_operation",
                            "message": (
                                "request must include 'operation' field"
                            ),
                        }
                    }
                ),
                status_code=400,
                media_type="application/json",
            )

        headers: Dict[str, str] = {}
        for header_name, header_value in request.headers.items():
            headers[header_name] = header_value

        if operation == "auth.issue":
            # AUTH-001: accept the credential from either the
            # canonical ``X-ProShield-Credential`` header OR a
            # body-level ``credential`` field (see app/proxy/
            # proxy.py OP_AUTH_ISSUE handling).
            credential = payload.pop("credential", None)
            if credential and PROXY_HEADER_CREDENTIAL not in headers:
                headers[PROXY_HEADER_CREDENTIAL] = credential
            # STRIX D-3 fix: real HTTP listeners lowercase header
            # keys, so a header-supplied credential would otherwise
            # be invisible to SecureProxy._handle_auth_issue.  Promote
            # the lowercased key (if present) to the canonical case
            # so the proxy auto-sees it.  The secret stays in the
            # header (never re-inserted into the request body), which
            # preserves the documented "keep the secret out of any
            # body dump / replay log" property.
            header_credential = headers.get(PROXY_HEADER_CREDENTIAL) or headers.get(
                PROXY_HEADER_CREDENTIAL.lower()
            )
            if isinstance(header_credential, str) and header_credential:
                headers[PROXY_HEADER_CREDENTIAL] = header_credential

        proxy_request = ProxyRequest(
            operation=operation,
            headers=headers,
            body=payload,
        )
        try:
            proxy_response: ProxyResponse = bundle.proxy.handle(
                proxy_request
            )
        except Exception as exc:
            LOGGER.exception("proxy.handle raised")
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "code": "internal_error",
                            "message": str(exc),
                        }
                    }
                ),
                status_code=500,
                media_type="application/json",
            )

        response_body = json.dumps(proxy_response.body)
        if len(response_body.encode("utf-8")) > (
            bundle.config.proxy_max_response_bytes
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "code": "response_too_large",
                            "message": "response exceeded 1 MiB cap",
                        }
                    }
                ),
                status_code=500,
                media_type="application/json",
            )

        return Response(
            content=response_body,
            status_code=proxy_response.status,
            media_type="application/json",
        )

    @app.get("/")
    async def index() -> Response:
        index_path = ROOT / "frontend" / "index.html"
        if index_path.exists():
            return Response(
                content=index_path.read_text(encoding="utf-8"),
                media_type="text/html",
            )
        return Response(
            content=(
                "<html><body><h1>ProShield Proxy Server</h1>"
                "<p>Frontend not found. Run from the repo root and "
                "ensure <code>frontend/</code> exists.</p></body></html>"
            ),
            media_type="text/html",
        )

    # Serve every file under frontend/ at its basename so the
    # multi-page app can fetch its CSS / JS / HTML directly.
    from fastapi.staticfiles import StaticFiles  # type: ignore
    frontend_dir = ROOT / "frontend"
    if frontend_dir.exists():
        app.mount(
            "/static",
            StaticFiles(directory=str(frontend_dir)),
            name="frontend-static",
        )

    return app


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "HTTP deployment wrapper around ProShield SecureProxy."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument(
        "--backend",
        choices=["memory", "mongo"],
        default=os.environ.get("PROSHIELD_PROXY_BACKEND", "memory"),
    )
    parser.add_argument(
        "--seed-credentials",
        action="store_true",
        help=(
            "Seed the in-memory identity store with admin/analyst/"
            "collector/internal subjects using dev-only credentials."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    _configure_logging("INFO")
    config = _build_config(args)
    LOGGER.info(
        "Proxy server starting (backend=%s, mongo_db=%s)",
        args.backend,
        config.mongo_db,
    )
    if args.backend == "mongo":
        bundle = _build_mongo_backend(config)
    else:
        bundle = _build_memory_backend(config)
    app = _build_app(bundle)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())