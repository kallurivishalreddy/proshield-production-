"""Production HTTP ingress listener for ProShield (deployment wrapper).

This is the deployment listener for the trusted inbound plane
(Phase 4.9 ``InboundIngressProxy``), shipped to close the
STRIX D-4 deployment gap ("No ingress HTTP listener in the
deployment wrapper").  It is intentionally parallel to
``scripts/proxy_server.py`` (analyst plane) and shares the same
configuration helpers so both planes stay consistent.

Plane separation is preserved:

* **Analyst plane**  - ``scripts/proxy_server.py``  - gated by
  session tokens, carries no raw source telemetry.
* **Ingress plane**    - this file - gated by HMAC source-identity
  tokens (R-1 single-use replay protection is enforced via the
  configured replay store); accepts only ``source.ingest`` and
  ``source.health``.  It NEVER serves the frontend and NEVER
  exposes analyst ops.

Wire boundary
---------------
``POST /api/ingress``
    Headers (all case-insensitive; real HTTP servers lowercase keys):
    * ``Authorization: Bearer <source-identity-token>`` or
    * ``X-ProShield-Source-Token: <source-identity-token>``
    Body: ``{"operation": "source.ingest", "events": [...]}``

``GET /api/ingress/health`` - health probe (no auth required).

Replay-store wiring (D-1):
* ``--backend mongo`` (default production choice) wires the real
  ``MongoReplayStore`` (cross-process, TTL-aware; see
  ``app/sources/replay_store.py``).
* ``--backend memory`` wires a process-local dev-only double so the
  listener can be exercised without MongoDB; it is NOT cross-process
  safe and therefore NOT a production substitute.

Run
-----
``bash
python -m scripts.ingress_server --host 127.0.0.1 --port 8089
                                  --backend mongo
``
The source signing key MUST be supplied via
``PROSHIELD_SOURCE_SIGNING_KEY`` for any production-like env

(``PROSHIELD_ENV=production``).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, Request, Response  # type: ignore
from fastapi.responses import JSONResponse  # type: ignore
import uvicorn  # type: ignore

from app.config import ProShieldConfig
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import SecurityEventRepository
from app.persistence.telemetry import SourceTelemetryStore
from app.sources.ingress import (
    OP_HEALTH,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
    IngressResponse,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.replay_store import MongoReplayStore
from app.sources.trust import SourceIdentityTokenVerifier

LOGGER = logging.getLogger("proshield.ingress_server")
# ========================================================== dev fakes
class _MemoryReplayStore:
    """Dev-only, process-local single-use store (NOT production).

    The production D-1 requirement is satisfied by
    ``MongoReplayStore``; this double exists so the ingress
    listener can be smoke-tested with ``--backend memory``
    without MongoDB.
    """

    def __init__(self) -> None:
        self._used: Dict[str, Any] = {}

    def claim(self, *, token_id: str, expires_at: Any) -> bool:
        if token_id in self._used:
            return False
        self._used[token_id] = expires_at
        return True

    def release(self, token_id: str) -> None:
        self._used.pop(token_id, None)

    def gc(self, now: Any) -> int:
        from datetime import datetime, timezone
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        expired = [t for t, e in self._used.items() if e <= now]
        for t in expired:
            self._used.pop(t, None)
        return len(expired)


class FakeCollection:
    """Minimal in-memory collection (mirrors proxy_server fakes)."""

    def __init__(self) -> None:
        self.docs: List[Dict[str, Any]] = []

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        self.docs.append(dict(doc))
        return type("R", (), {"inserted_id": "fake"})()

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return dict(d)
        return None

    def find(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [dict(d) for d in self.docs if all(
            d.get(k) == v for k, v in query.items()
        )]

    def delete_one(self, query: Dict[str, Any]) -> Any:
        for i, d in enumerate(self.docs):
            if all(d.get(k) == v for k, v in query.items()):
                self.docs.pop(i)
                return type("R", (), {"deleted_count": 1})()
        return type("R", (), {"deleted_count": 0})()

    def delete_many(self, query: Dict[str, Any]) -> Any:
        before = len(self.docs)
        if "$lte" in str(query):
            field = next(iter(query))
            self.docs = [
                d for d in self.docs
                if not (
                    d.get(field) is not None
                    and d[field] <= query[field]["$lte"]
                )
            ]
        else:
            self.docs = [
                d for d in self.docs
                if not all(d.get(k) == v for k, v in query.items())
            ]
        return type(
            "R", (), {"deleted_count": before - len(self.docs)}
        )()

    def count_documents(self, query: Dict[str, Any]) -> int:
        return len(self.find(query))

    def create_index(
        self,
        key: Any,
        *,
        name: str,
        unique: bool = False,
        expireAfterSeconds: Optional[int] = None,
    ) -> Any:
        return name


class FakeDatabase:
    """Minimal in-memory database."""

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
# ============================================================ config / bundle


def _build_config(args: argparse.Namespace) -> ProShieldConfig:
    """Build runtime config from env + CLI (mirrors proxy_server)."""
    from scripts.proxy_server import _build_config as _proxy_build_config
    return _proxy_build_config(
        argparse.Namespace(
            backend=args.backend,
            seed_credentials=True,
        )
    )


class _IngressBundle:
    """Services the ingress listener needs.

    Since the STRIX F-1 / F-2 fix, the bundle also carries a
    ``pipeline`` (:class:`app.pipeline.service.LivePipeline`) that
    runs detection -> correlation -> auto-case after each accepted
    event, closing the missing-composition gap.
    """

    def __init__(
        self,
        config: ProShieldConfig,
        ingress: InboundIngressProxy,
        backend_kind: str,
        pipeline: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.ingress = ingress
        self.backend_kind = backend_kind
        self.pipeline = pipeline


def _build_mongo_ingress(config: ProShieldConfig) -> _IngressBundle:
    """Wire the ingress to real MongoDB; the replay store is the
    cross-process MongoReplayStore (D-1 fix).

    """
    from pymongo import MongoClient  # type: ignore

    client = MongoClient(config.mongo_uri)
    db = client[config.mongo_db]

    # V2-21: refuse to start a Mongo-backed ingress whose source signing
    # key is not pinned; otherwise the ingress derives an ephemeral key
    # that cannot match the analyst plane and every token 401s.
    if not config.source_signing_key:
        raise SystemExit(
            "FATAL: refusing to start the ingress plane against MongoDB "
            "without an explicit PROSHIELD_SOURCE_SIGNING_KEY. The "
            "analyst plane signs source-identity tokens with the same "
            "key; split secrets would fail every token at runtime (V2-21)."
        )

    # V2-P0: apply the documented validators + unique indexes on the
    # real startup path (duplicates/cases/reports protection at the
    # database boundary). Idempotent; mirrors the analyst plane.
    from app.persistence.bootstrap import ensure_all_collections

    bootstrap = ensure_all_collections(db, config)
    LOGGER.info(
        "persistence bootstrap complete (collections=%d)",
        len(bootstrap),
    )

    registry = SourceRegistry()
    repo = SourceRepository(db=db, config=config)
    replay_store = MongoReplayStore(db=db, config=config)
    verifier = SourceIdentityTokenVerifier.from_secret(
        config.source_signing_key,
        max_lifetime_seconds=config.source_token_lifetime_seconds,
        source_resolver=lambda sid: repo.get(sid),
        replay_store=replay_store,
    )
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db=db, config=config), config,
    )
    # Capability patch gap 9: per-source ingest telemetry, maintained
    # at THIS boundary and persisted for the analyst plane.
    telemetry = SourceTelemetryStore(db=db, config=config)
    telemetry.ensure_ready()
    ingress = InboundIngressProxy(
        config=config,
        registry=registry,
        token_verifier=verifier,
        ingestion_service=ingestion,
        authoritative_source_resolver=lambda sid: repo.get(sid),
        telemetry_recorder=telemetry,
    )
    pipeline = _build_ingress_pipeline(config, db, ingestion)
    return _IngressBundle(
        config=config,
        ingress=ingress,
        backend_kind="mongo",
        pipeline=pipeline,
    )


def _build_ingress_pipeline(config, db, ingestion_service) -> Any:
    """Build the live detection->correlation->case pipeline (F-1/F-2).

    This is the **product** composition that the deployment was missing:
    after an event is accepted, it runs the detection engine, then
    correlation over the recent persisted window, and opens an
    idempotent case per correlation. It reuses the same
    repositories/engines the rest of the app uses.
    """
    from app.pipeline import build_live_pipeline
    from app.incidents.repository import IncidentRepository
    from app.incidents.service import IncidentService
    from app.persistence.rule_repository import RuleRepository
    from app.pipeline.managed_rule_sync import ManagedRuleLifecycleSync
    from app.rules import RuleRegistry, load_rules_from_specs

    rule_registry = RuleRegistry()
    try:
        load_rules_from_specs(
            rule_registry,
            ["app.rules._library.nginx"],
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.warning("Could not load rules for pipeline: %s", exc)

    # V2-01: the live detector must be governed by the managed-rule
    # lifecycle. Seed the built-in library rules into ``managed_rules``
    # (idempotent, mirrors the analyst plane) and reconcile the registry
    # against the persisted state before every detection pass, so
    # rule.disable / rule.enable / rule.retire made in the UI take
    # effect on the next event — no restart required.
    rule_repo = RuleRepository(db=db, config=config)
    rule_sync = ManagedRuleLifecycleSync(
        repository=rule_repo,
        registry=rule_registry,
        config=config,
    )
    try:
        governed = rule_sync.seed_builtins()
        LOGGER.info(
            "managed rule lifecycle seeded (governed rules=%d)", governed
        )
        rule_sync.sync()
    except Exception as exc:  # pragma: no cover - best effort
        LOGGER.warning("managed rule lifecycle seed failed: %s", exc)

    return build_live_pipeline(
        config=config,
        db=db,
        rule_registry=rule_registry,
        incident_service=IncidentService(
            repository=IncidentRepository(db=db, config=config),
        ),
        rule_repository=rule_repo,
    )


def _build_memory_ingress(config: ProShieldConfig) -> _IngressBundle:
    """Wire the ingress to in-memory fakes (dev option)."""
    db = FakeDatabase()
    registry = SourceRegistry()
    repo = SourceRepository(db=db, config=config)
    replay_store = _MemoryReplayStore()
    verifier = SourceIdentityTokenVerifier.from_secret(
        config.source_signing_key,
        max_lifetime_seconds=config.source_token_lifetime_seconds,
        source_resolver=lambda sid: repo.get(sid),
        replay_store=replay_store,
    )
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db=db, config=config), config,
    )
    # Capability patch gap 9: per-source ingest telemetry, maintained
    # at THIS boundary and persisted for the analyst plane.
    telemetry = SourceTelemetryStore(db=db, config=config)
    telemetry.ensure_ready()
    ingress = InboundIngressProxy(
        config=config,
        registry=registry,
        token_verifier=verifier,
        ingestion_service=ingestion,
        authoritative_source_resolver=lambda sid: repo.get(sid),
        telemetry_recorder=telemetry,
    )
    pipeline = _build_ingress_pipeline(config, db, ingestion)
    return _IngressBundle(
        config=config,
        ingress=ingress,
        backend_kind="memory",
        pipeline=pipeline,
    )


def _build_ingress_bundle(
    config: ProShieldConfig, backend: str
) -> _IngressBundle:
    if backend == "mongo":
        return _build_mongo_ingress(config)
    return _build_memory_ingress(config)
# ================================================================= FastAPI app


def _run_live_pipeline_after_ingest(
    bundle: _IngressBundle, op: str, proxy_response: IngressResponse,
) -> None:
    """Run the live detection->correlation->case pipeline on accepted
    events (STRIX F-1/F-2).

    Invoked by the listener after a *successful* ``source.ingest``. It
    loads each accepted canonical event from the shared event store and
    runs :meth:`app.pipeline.LivePipeline.process`, which persists
    detections, runs the correlation engine over the recent window, and opens
    an idempotent case per correlation.

    An event is never silently dropped between ingestion and detection:
    if the pipeline raises, the failure is logged (the event remains
    persisted and visible; the log documents the failure). The HTTP
    response is NOT altered into a fake success — it already reflects the
    accepted ingest.
    """
    if op != OP_INGEST:
        return
    if getattr(bundle, "pipeline", None) is None:
        return
    if proxy_response.status != 200:
        return
    body = proxy_response.body
    if not isinstance(body, dict):
        return
    # The ingress response nests accepted ids under ``data``
    # (``{"ok": true, "data": {"source_instance_id", "accepted_event_ids",
    # "rejected", "request_id"}}``). Reading them from the top level
    # silently produced ``accepted=0`` so the pipeline never ran — the
    # STRIX F-1/F-2 composition was bypassed in the live path.
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    accepted = data.get("accepted_event_ids") or []
    for event_id in (list(accepted) if accepted else []):
        if not isinstance(event_id, str) or not event_id:
            continue
        try:
            event = bundle.pipeline.event_repository.get_by_event_id(event_id)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning(
                "pipeline.load_event_failed",
                extra={"event_id": event_id, "error": type(exc).__name__},
            )
            continue
        if event is None:
            LOGGER.warning(
                "pipeline.event_not_found",
                extra={"event_id": event_id},
            )
            continue
        try:
            # event_persisted=True (V2-23): the event was just loaded
            # from the event store — re-running ingestion would insert
            # a second copy whenever the unique index is absent.
            outcome = bundle.pipeline.process(event, event_persisted=True)
            LOGGER.info(
                "pipeline.processed_event",
                extra={
                    "event_id": event_id,
                    "detections": len(outcome.detections),
                    "correlations": len(outcome.correlations),
                    "case_id": getattr(outcome.case, "incident_id", None),
                    "errors": len(outcome.errors),
                },
            )
            for err in outcome.errors:
                LOGGER.warning(
                    "pipeline.processing_error event_id=%s error=%s",
                    event_id,
                    err,
                )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception(
                "pipeline.process_failed",
                extra={"event_id": event_id},
            )

def _build_app(bundle: _IngressBundle) -> FastAPI:
    """Build the ASGI listener around ``InboundIngressProxy.handle``.

    No business logic lives here: it normalises HTTP -> IngressRequest
    and translates IngressResponse -> HTTP, exactly as the contract
    requires.  Authentication / trust semantics are entirely inside
    the real proxy class.
    """
    app = FastAPI(
        title="ProShield Ingress Server",
        description=(
            "Trusted inbound telemetry boundary around "
            "InboundIngressProxy.handle."
        ),
    )

    @app.post("/api/ingress")
    async def ingress_endpoint(request: Request) -> Response:
        raw = await request.body()
        if len(raw) > getattr(
            bundle.config, "ingress_max_request_bytes", 32_768
        ):
            return JSONResponse(
                {
                    "error": {
                        "code": "request_too_large",
                        "message": (
                            "ingress request exceeds the documented "
                            "size limit"
                        ),
                    }
                },
                status_code=400,
            )
        try:
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                {
                    "error": {
                        "code": "validation_error",
                        "message": "request body must be JSON",
                    }
                },
                status_code=400,
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                {
                    "error": {
                        "code": "validation_error",
                        "message": "request body must be a JSON object",
                    }
                },
                status_code=400,
            )
        # Real HTTP servers lowercase header keys; ``_extract_token``
        # handles both cases (D-2 fix).
        headers: Dict[str, str] = dict(request.headers.items())
        op = payload.get("operation", "")
        proxy_response: IngressResponse = bundle.ingress.handle(
            IngressRequest(
                operation=op,
                headers=headers,
                body=payload,
                body_bytes=len(raw),
            )
        )
        # STRIX F-1 / F-2: once events are accepted, run the live
        # detection -> correlation -> auto-case pipeline over them.
        # This is the production composition the deployment was missing.
        _run_live_pipeline_after_ingest(bundle, op, proxy_response)
        return JSONResponse(
            content=proxy_response.body,
            status_code=proxy_response.status,
        )

    @app.get("/api/ingress/health")
    @app.get("/healthz")
    async def health() -> Response:
        proxy_response: IngressResponse = bundle.ingress.handle(
            IngressRequest(operation=OP_HEALTH, headers={}, body=None)
        )
        body = dict(proxy_response.body)
        body.setdefault("backend_kind", bundle.backend_kind)
        return JSONResponse(
            content=body, status_code=proxy_response.status
        )

    @app.get("/")
    async def index() -> dict:
        return {
            "service": "ProShield Ingress Server",
            "boundary": "trusted inbound telemetry",
            "operations": ["source.ingest", "source.health"],
            "backend_kind": bundle.backend_kind,
        }

    return app


# =================================================================== runnable


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP ingress listener around InboundIngressProxy.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument(
        "--backend",
        choices=["memory", "mongo"],
        default=os.environ.get("PROSHIELD_INGRESS_BACKEND", "memory"),
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    logging.basicConfig(
        level="INFO",
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = _build_config(args)
    LOGGER.info(
        "Ingress server starting (backend=%s, mongo_db=%s)",
        args.backend,
        config.mongo_db,
    )
    bundle = _build_ingress_bundle(config, args.backend)
    app = _build_app(bundle)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())