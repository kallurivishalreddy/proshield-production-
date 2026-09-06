"""Trusted inbound integration boundary (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

The :class:`InboundIngressProxy` is the **trusted inbound
boundary** between an external security system and the
existing ProShield pipeline. It is intentionally distinct
from the client-facing :class:`app.proxy.SecureProxy`:

* ``SecureProxy`` accepts analyst / admin requests on the
  client side; it is permission-gated, rate-limited per
  subject, and never carries raw source telemetry.
* ``InboundIngressProxy`` accepts **trusted source
  telemetry** from registered external systems; it is gated
  by an HMAC-signed :class:`SourceIdentityToken`, rate-limited
  per source instance, and translates every external event
  into a canonical :class:`SecurityEvent` for the existing
  ingestion service.

Security controls (documented in the report):

* Token verification: missing / malformed / expired /
  tampered tokens are rejected with safe 4xx responses.
* Source integrity: the inbound payload's
  ``(source_instance_id, source_type, source)`` triple must
  match the registered source instance. A mismatch is a
  ``SourceIntegrityError`` (403).
* State enforcement: only ``ENABLED`` source instances are
  accepted. ``DISABLED`` / ``RETIRED`` instances return
  documented errors.
* Rate limit: per-source-instance sliding-window budget;
  burst traffic returns 429.
* Size limit: inbound payloads are bounded by
  ``config.ingress_max_request_bytes``; oversized payloads
  return 400.
* Idempotency: the existing ingestion service's idempotent
  path is reused so a retried telemetry batch produces the
  same canonical event.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from ..config import ProShieldConfig
from ..domain.errors import (
    DomainError,
    PersistenceError,
    ValidationError as DomainValidationError,
)
from ..domain.security_event import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SOURCES,
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventProvenance,
    to_canonical_dict,
    validate_size_constraints,
)
from ..domain.uuid7 import uuid7
from ..ingestion.service import SecurityEventIngestionService
from ..observability.logging import get_request_id
from .errors import SourceIdentityTokenError
from .models import (
    SourceInstance,
    SourceInstanceId,
    SourceState,
)
from .registry import SourceRegistry
from .trust import SourceIdentityTokenVerifier


_log = logging.getLogger(__name__)


INGRESS_HEADER_AUTHORIZATION = "Authorization"
INGRESS_HEADER_TOKEN = "X-ProShield-Source-Token"


class _IngressShapeError(DomainError):
    """Internal: a request-shape validation failure.

    Carries a per-call ``code`` so the safe-error envelope
    returned to the client distinguishes ``missing_operation``
    from ``unknown_operation`` from ``request_too_large``.
    """

    code = "validation_error"
    http_status = 400

    def __init__(
        self,
        *,
        safe_message: str,
        internal_detail: str,
        code: str,
        http_status: int,
    ) -> None:
        super().__init__(
            safe_message=safe_message,
            internal_detail=internal_detail,
        )
        self.code = code
        self.http_status = http_status

OP_INGEST = "source.ingest"
OP_HEALTH = "source.health"

ALLOWED_OPERATIONS: frozenset = frozenset({
    OP_INGEST,
    OP_HEALTH,
})

MAX_INGRESS_REQUEST_BYTES_DEFAULT = 32_768
MAX_INGRESS_RESPONSE_BYTES_DEFAULT = 1_048_576
MAX_INGRESS_RATE_BUCKETS = 4096


@dataclass(frozen=True)
class IngressRequest:
    """The wire-shape inbound request."""

    operation: str
    headers: Mapping[str, str]
    body: Optional[Dict[str, Any]]
    body_bytes: int = 0


@dataclass(frozen=True)
class IngressResponse:
    """The wire-shape inbound response."""

    status: int
    body: Dict[str, Any]


@dataclass
class _RateLimiter:
    """Per-source-instance sliding-window rate limiter."""

    window_seconds: int = 60
    budget: int = 600

    def __post_init__(self) -> None:
        self._buckets: Dict[str, Dict[str, List[float]]] = {}

    def allow(
        self,
        *,
        key: str,
        now: Optional[float] = None,
    ) -> bool:
        if not isinstance(key, str) or not key:
            raise DomainValidationError(
                safe_message="rate-limit key missing",
                internal_detail="non-string key",
            )
        if now is None:
            now = datetime.now(timezone.utc).timestamp()
        bucket = self._buckets.setdefault(key, {"ts": []})
        bucket["ts"] = [
            t for t in bucket["ts"]
            if (now - t) < self.window_seconds
        ]
        if len(bucket["ts"]) >= self.budget:
            return False
        bucket["ts"].append(now)
        if len(self._buckets) > MAX_INGRESS_RATE_BUCKETS:
            oldest = sorted(
                self._buckets.items(),
                key=lambda kv: kv[1]["ts"][0] if kv[1]["ts"] else 0,
            )
            for k, _ in oldest[: max(0, len(oldest) - MAX_INGRESS_RATE_BUCKETS)]:
                self._buckets.pop(k, None)
        return True

    def consume(
        self,
        *,
        key: str,
        count: int = 1,
        now: Optional[float] = None,
    ) -> bool:
        """ST-01: decrement the budget by ``count``.

        Returns ``True`` iff the budget was successfully
        decremented. Returns ``False`` (without mutating)
        when the charge would exceed the per-window budget
        — the caller MUST respond 429 and NOT persist any
        of the in-flight events.

        ``count=0`` is a no-op: no budget is charged and
        ``True`` is returned. This lets callers use a
        single ``consume`` call regardless of the batch
        size (e.g. an empty ``events`` list still has a
        request to authorise).

        ``count=N`` charges ``N`` units in a single atomic
        step so a request carrying N events cannot amplify
        the per-event rate limit.
        """
        if not isinstance(count, int):
            raise DomainValidationError(
                safe_message="rate-limit count must be an int",
                internal_detail=f"count={count!r}",
            )
        if count < 0:
            raise DomainValidationError(
                safe_message="rate-limit count must be non-negative",
                internal_detail=f"count={count!r}",
            )
        if not isinstance(key, str) or not key:
            raise DomainValidationError(
                safe_message="rate-limit key missing",
                internal_detail="non-string key",
            )
        if count == 0:
            return True
        if now is None:
            now = datetime.now(timezone.utc).timestamp()
        bucket = self._buckets.setdefault(key, {"ts": []})
        bucket["ts"] = [
            t for t in bucket["ts"]
            if (now - t) < self.window_seconds
        ]
        if (len(bucket["ts"]) + count) > self.budget:
            return False
        # Each unit is recorded as a fresh timestamp so the
        # sliding window rolls them out independently. We
        # only stamp the *first* unit with the real ``now``
        # so the whole batch ages out as a single logical
        # ``now`` to keep the window semantics simple.
        bucket["ts"].append(now)
        # Extra units beyond the first share ``now``; this
        # is intentional — they remain valid for the full
        # window alongside the leading unit and roll out
        # together.
        for _ in range(count - 1):
            bucket["ts"].append(now)
        if len(self._buckets) > MAX_INGRESS_RATE_BUCKETS:
            oldest = sorted(
                self._buckets.items(),
                key=lambda kv: kv[1]["ts"][0] if kv[1]["ts"] else 0,
            )
            for k, _ in oldest[: max(0, len(oldest) - MAX_INGRESS_RATE_BUCKETS)]:
                self._buckets.pop(k, None)
        return True


class InboundIngressProxy:
    """The trusted inbound integration boundary.

    D-3 (multi-process consistency):
        When ``authoritative_source_resolver`` is provided, it is
        consulted for every ingest call. This makes the **persisted
        source state in MongoDB** the single source of truth for
        the ENABLE / DISABLE / RETIRE check, even when a process's
        in-memory :class:`SourceRegistry` is stale.

    R-1 (replay protection) is delegated to the
    :class:`SourceIdentityTokenVerifier`; see ``trust.py``.
    """

    def __init__(
        self,
        *,
        config: ProShieldConfig,
        registry: SourceRegistry,
        token_verifier: SourceIdentityTokenVerifier,
        ingestion_service: SecurityEventIngestionService,
        authoritative_source_resolver: Optional[Any] = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._token_verifier = token_verifier
        self._ingestion_service = ingestion_service
        self._authoritative_resolver = authoritative_source_resolver
        self._rate_limiter = _RateLimiter(
            window_seconds=60,
            budget=config.ingress_rate_limit_per_minute,
        )

    def handle(self, request: IngressRequest) -> IngressResponse:
        """Dispatch a single inbound request."""
        try:
            self._validate_request_shape(request)
        except _IngressShapeError as exc:
            return _error_response(
                exc.code, exc.safe_message, status=exc.http_status,
            )
        if request.operation == OP_HEALTH:
            return self._handle_health(request)
        if request.operation == OP_INGEST:
            return self._handle_ingest(request)
        return _error_response(
            "unknown_operation",
            "unknown ingress operation",
            status=400,
        )

    def _handle_health(
        self, request: IngressRequest,
    ) -> IngressResponse:
        return IngressResponse(
            status=200,
            body={
                "ok": True,
                "data": {
                    "status": "ok",
                    "boundary": "ingress",
                    "supported_operations": sorted(ALLOWED_OPERATIONS),
                },
            },
        )

    def _handle_ingest(
        self, request: IngressRequest,
    ) -> IngressResponse:
        try:
            token = _extract_token(request.headers, request.body)
        except SourceIdentityTokenError as exc:
            return _error_response(
                exc.code, exc.safe_message, status=exc.http_status,
            )
        try:
            verified = self._token_verifier.verify(token)
        except SourceIdentityTokenError as exc:
            return _error_response(
                exc.code, exc.safe_message, status=exc.http_status,
            )
        except PersistenceError as exc:  # fail-closed: an unavailable
            # replay store must NOT degrade into accept-without-replay-
            # protection; it is a 503 so the caller may retry later.
            return _error_response(
                "replay_store_unavailable",
                "source identity replay store unavailable",
                status=503,
            )
        # D-3: prefer the authoritative resolver (MongoDB) over the
        # in-memory registry. A stale registry must NOT be able to
        # authorize an ingest that the persisted state forbids.
        source = None
        if self._authoritative_resolver is not None:
            try:
                source = self._authoritative_resolver(
                    verified.source_instance_id
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "ingress.authoritative_resolver.failed",
                    extra={
                        "source_instance_id": (
                            verified.source_instance_id
                        ),
                        "error_type": type(exc).__name__,
                    },
                )
                return _error_response(
                    "source_state_unavailable",
                    "source state could not be verified",
                    status=503,
                )
        if source is None:
            source = self._registry.get(verified.source_instance_id)
        if source is None:
            return _error_response(
                "source_instance_not_found",
                "source instance is not registered",
                status=404,
            )
        if source.state is SourceState.RETIRED:
            return _error_response(
                "source_retired",
                "source instance is retired",
                status=410,
            )
        if source.state is not SourceState.ENABLED:
            return _error_response(
                "source_not_enabled",
                "source instance is not enabled",
                status=409,
            )
        if (
            source.source != verified.source
            or source.source_type.value != verified.source_type
        ):
            return _error_response(
                "source_integrity_error",
                "token source identity does not match the "
                "registered source instance",
                status=403,
            )
        now = datetime.now(timezone.utc).timestamp()
        # ST-01: count events against the per-source budget
        # so a single request carrying N events cannot amplify
        # the documented per-event rate limit by N×. We also
        # enforce a per-request event cap.
        body = request.body or {}
        events_raw = body.get("events", [])
        if not isinstance(events_raw, list):
            return _error_response(
                "validation_error",
                "events must be a list",
                status=400,
            )
        max_per_request = getattr(
            self._config, "ingress_max_events_per_request", 100
        )
        if len(events_raw) > max_per_request:
            return _error_response(
                "validation_error",
                (
                    f"too many events per request: "
                    f"{len(events_raw)} > {max_per_request}"
                ),
                status=400,
            )
        # Per-request + per-event budget check (ST-01).
        # The sliding window is charged ``1 + len(events)``
        # units atomically:
        #   * the leading ``1`` is the documented
        #     per-request charge (one budget unit per call,
        #     regardless of the batch size — preserves the
        #     pre-Phase-4.9 burst behaviour where
        #     ``rate_limit_blocks_after_budget`` expects 3
        #     back-to-back requests to consume 3 units);
        #   * the ``len(events)`` term is the new ST-01
        #     per-event charge so a request carrying N
        #     events cannot amplify the per-event limit by
        #     N× in a single request.
        if not self._rate_limiter.consume(
            key=str(verified.source_instance_id),
            count=1 + len(events_raw),
            now=now,
        ):
            return _error_response(
                "source_rate_limited",
                "source instance event rate limit exceeded",
                status=429,
            )
        accepted: List[str] = []
        rejected: List[Dict[str, Any]] = []
        for raw in events_raw:
            if not isinstance(raw, dict):
                rejected.append({
                    "reason": "not-a-dict",
                    "raw_type": type(raw).__name__,
                })
                continue
            try:
                ev = self._build_security_event(
                    raw, source=source,
                )
                persisted = self._ingestion_service.ingest(ev)
                accepted.append(persisted.event_id)
            except DomainError as exc:
                rejected.append({
                    "reason": exc.code,
                    "message": exc.safe_message,
                })
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "ingress.event.unexpected",
                    extra={
                        "source_instance_id": (
                            verified.source_instance_id
                        ),
                        "error_type": type(exc).__name__,
                    },
                )
                rejected.append({
                    "reason": "ingest_failed",
                    "message": "event rejected by ingestion service",
                })
        return IngressResponse(
            status=200,
            body={
                "ok": True,
                "data": {
                    "source_instance_id": (
                        verified.source_instance_id
                    ),
                    "accepted_event_ids": accepted,
                    "rejected": rejected,
                    "request_id": get_request_id(),
                },
            },
        )

    def _validate_request_shape(self, request: IngressRequest) -> None:
        if not isinstance(request.operation, str) or not request.operation:
            raise _IngressShapeError(
                safe_message="operation missing",
                internal_detail="non-string operation",
                code="missing_operation",
                http_status=400,
            )
        if request.operation not in ALLOWED_OPERATIONS:
            raise _IngressShapeError(
                safe_message="unknown ingress operation",
                internal_detail=f"got {request.operation!r}",
                code="unknown_operation",
                http_status=400,
            )
        if request.body_bytes > self._config.ingress_max_request_bytes:
            raise _IngressShapeError(
                safe_message="ingress request exceeds the documented size limit",
                internal_detail=(
                    f"body_bytes={request.body_bytes} > "
                    f"{self._config.ingress_max_request_bytes}"
                ),
                code="request_too_large",
                http_status=400,
            )

    def _build_security_event(
        self,
        raw: Dict[str, Any],
        *,
        source: SourceInstance,
    ) -> SecurityEvent:
        if not isinstance(raw, dict):
            raise DomainValidationError(
                safe_message="event must be a dict",
                internal_detail=f"got {type(raw).__name__}",
                code="validation_error",
                http_status=400,
            )
        event_type = raw.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            raise DomainValidationError(
                safe_message="event_type missing",
                internal_detail="non-string event_type",
                code="validation_error",
                http_status=400,
            )
        if event_type not in ALLOWED_EVENT_TYPES:
            raise DomainValidationError(
                safe_message="event_type not in allowed set",
                internal_detail=f"got {event_type!r}",
                code="validation_error",
                http_status=400,
            )
        event_time_raw = raw.get("event_time")
        if isinstance(event_time_raw, str):
            try:
                et = datetime.fromisoformat(
                    event_time_raw.replace("Z", "+00:00")
                )
            except Exception as exc:  # noqa: BLE001
                raise DomainValidationError(
                    safe_message="event_time malformed",
                    internal_detail=str(exc)[:256],
                    code="validation_error",
                    http_status=400,
                )
        elif isinstance(event_time_raw, datetime):
            et = event_time_raw
        else:
            et = datetime.now(timezone.utc)
        if et.tzinfo is None:
            et = et.replace(tzinfo=timezone.utc)
        provenance = SecurityEventProvenance(
            collector=source.source_type.value,
            source_event_id=str(
                raw.get("source_event_id")
                or raw.get("id")
                or f"ingress-{uuid7()}"
            )[:256],
            source_instance_id=source.source_instance_id,
        )
        account = None
        account_raw = raw.get("account")
        if isinstance(account_raw, dict):
            aid = account_raw.get("id")
            if isinstance(aid, str) and aid:
                account = SecurityEventAccount(id=aid[:128])
        elif isinstance(account_raw, str) and account_raw:
            account = SecurityEventAccount(id=account_raw[:128])
        details = raw.get("details") or {}
        if not isinstance(details, dict):
            details = {"_raw_details": str(details)[:256]}
        # ST-04 remediation: source-reported identity is
        # untrusted. The wire endpoint / asset / source_ip
        # are stamped onto the event ONLY when they match
        # the registered source configuration; mismatches
        # are recorded under ``details._untrusted_*`` and
        # NOT promoted to canonical SecurityEvent fields.
        registered_endpoint = (
            source.configuration.endpoint or None
        )
        client_endpoint = _opt_str(raw.get("endpoint"), 512)
        reconciled_endpoint = (
            client_endpoint
            if client_endpoint is not None
            and client_endpoint == registered_endpoint
            else registered_endpoint
        )
        registered_asset = (
            source.asset_tags[0] if source.asset_tags else None
        )
        client_asset = _opt_str(raw.get("asset"), 128)
        reconciled_asset = (
            client_asset
            if client_asset is not None
            and client_asset == registered_asset
            else registered_asset
        )
        client_source_ip = _opt_str(raw.get("source_ip"), 64)
        # V2-19 fix: ``source_ip`` is the *attacker* attribution field
        # observed by the authenticated external source — it does not
        # describe the source system, so it is NOT reconciled against
        # the registered endpoint of the source instance. The previous
        # implementation nulled ``source_ip`` whenever the wire
        # endpoint disagreed with the registered configuration
        # endpoint, which silently broke every correlation that groups
        # by ``source_ip`` (BruteForceClusteringPattern) for realistic
        # telemetry whose wire path differs from the configured one —
        # a systematic false-negative. The endpoint mismatch itself is
        # still recorded under ``details._untrusted_endpoint`` for the
        # analyst; the attacker IP is preserved as evidence.
        if client_asset is not None and reconciled_asset is None:
            details["_untrusted_asset"] = client_asset
        if (
            client_endpoint is not None
            and registered_endpoint is not None
            and client_endpoint != registered_endpoint
        ):
            details["_untrusted_endpoint"] = client_endpoint
        ev = SecurityEvent(
            event_id=str(
                raw.get("event_id") or uuid7()
            )[:64],
            event_time=et,
            ingested_at=datetime.now(timezone.utc),
            source=source.source,
            event_type=event_type,
            source_ip=client_source_ip,
            destination=_opt_str(raw.get("destination"), 256),
            endpoint=reconciled_endpoint,
            asset=reconciled_asset,
            account=account,
            details=dict(details),
            provenance=provenance,
        )
        payload = to_canonical_dict(ev)
        validate_size_constraints(
            payload,
            max_body_bytes=self._config.ingest_max_body_bytes,
            max_details_bytes=self._config.ingest_max_details_bytes,
        )
        return ev


def _first_ci_header(
    headers: Mapping[str, str], *names: str,
) -> Optional[str]:
    """Return the first value among ``names`` matched case-insensitively.

    HTTP/1.1 field names are case-insensitive; a conforming server
    (Starlette / FastAPI / uvicorn / any reverse proxy) lowercases
    them, but a direct client may preserve any casing.  Scanning
    with a case-folded compare is the robust way to honour both.
    """
    wanted = {name.lower() for name in names}
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() in wanted:
            return value
    return None


def _extract_token(
    headers: Mapping[str, str],
    body: Optional[Dict[str, Any]],
) -> str:
    """Extract the source-identity token from headers / body.

    STRIX D-2 fix: real HTTP listeners (Starlette / FastAPI /
    uvicorn / gunicorn / every reverse proxy) lowercase header
    keys per HTTP/1.1, and direct clients may preserve any casing.
    The lookup is therefore case-insensitive for both supported
    header names, mirroring ``SecureProxy._extract_session_token``
    (app/proxy/proxy.py).
    """
    auth = _first_ci_header(
        headers, INGRESS_HEADER_AUTHORIZATION, INGRESS_HEADER_TOKEN,
    )
    if isinstance(auth, str) and auth:
        if auth.lower().startswith("bearer "):
            return auth[len("bearer "):].strip()
        return auth.strip()
    if isinstance(body, dict):
        token = body.get("source_token") or body.get("token")
        if isinstance(token, str) and token:
            return token.strip()
    raise SourceIdentityTokenError(
        safe_message="source identity token missing",
        internal_detail="no token header or body field",
    )


def _opt_str(value: Any, max_length: int) -> Optional[str]:
    if value is None:
        return None
    s = str(value)
    if len(s) > max_length:
        s = s[:max_length]
    return s


def _error_response(
    code: str, message: str, *, status: int,
) -> IngressResponse:
    return IngressResponse(
        status=status,
        body={
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


__all__ = [
    "ALLOWED_OPERATIONS",
    "INGRESS_HEADER_AUTHORIZATION",
    "INGRESS_HEADER_TOKEN",
    "InboundIngressProxy",
    "IngressRequest",
    "IngressResponse",
    "MAX_INGRESS_REQUEST_BYTES_DEFAULT",
    "MAX_INGRESS_RESPONSE_BYTES_DEFAULT",
    "OP_HEALTH",
    "OP_INGEST",
]