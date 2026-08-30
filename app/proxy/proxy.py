"""The secure application proxy / gateway.

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md.

The proxy is the **security boundary** between the client
and the core backend.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from ..auth.identity import Identity, InMemoryIdentityStore
from ..auth.permissions import Permission, has_permission
from ..auth.session import (
    SessionTokenService,
    SessionVerifier,
)
from ..config import ProShieldConfig
from ..domain.errors import (
    AuthenticationRequiredError,
    AuthorizationError,
    DomainError,
    NotFoundError,
    ValidationError as DomainValidationError,
)
from ..incidents import IncidentService, authorize_case_access
from ..reports import ReportService
from ..routing import RoutingEngine
from .errors import (
    InvalidProxyRequestError,
    ProxyRateLimitedError,
    ProxyUnauthorizedError,
)


_log = logging.getLogger(__name__)


# ----------------------------------------------------------------- constants
PROXY_HEADER_AUTHORIZATION = "Authorization"
PROXY_HEADER_SESSION = "X-ProShield-Session"

OP_HEALTH = "health"
OP_GET_CASE = "case.get"
OP_CREATE_CASE = "case.create"
OP_LIST_CASES = "case.list"
OP_CLOSE_CASE = "case.close"
OP_REQUEST_CENTRALIZED = "case.centralized"
OP_GET_REPORT = "report.get"
OP_LIST_REPORTS = "report.list"
OP_GENERATE_NORMAL_REPORT = "report.generate_normal"
OP_GENERATE_CENTRALIZED_REPORT = "report.generate_centralized"
OP_ROUTE_CASE = "routing.compute"
OP_AUTH_ISSUE = "auth.issue"

ALLOWED_OPERATIONS: frozenset = frozenset({
    OP_HEALTH,
    OP_GET_CASE,
    OP_CREATE_CASE,
    OP_LIST_CASES,
    OP_CLOSE_CASE,
    OP_REQUEST_CENTRALIZED,
    OP_GET_REPORT,
    OP_LIST_REPORTS,
    OP_GENERATE_NORMAL_REPORT,
    OP_GENERATE_CENTRALIZED_REPORT,
    OP_ROUTE_CASE,
    OP_AUTH_ISSUE,
})

MAX_PROXY_REQUEST_BYTES = 32_768
MAX_PROXY_RESPONSE_BYTES = 1_048_576  # 1 MiB
MAX_RATE_LIMIT_BUCKETS = 4096


# ----------------------------------------------------------------- request / response
@dataclass(frozen=True)
class ProxyRequest:
    """The wire-shape request."""

    operation: str
    headers: Mapping[str, str]
    body: Optional[Dict[str, Any]]
    body_bytes: int = 0


@dataclass(frozen=True)
class ProxyResponse:
    """The wire-shape response."""

    status: int
    body: Dict[str, Any]

    def to_wire(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "body": self.body,
        }


# ----------------------------------------------------------------- rate limit
@dataclass
class _RateLimiter:
    """Per-subject sliding-window rate limiter."""

    window_seconds: int = 60
    budget: int = 120
    centralized_budget: int = 5

    def __post_init__(self) -> None:
        self._buckets: Dict[str, Dict[str, List[float]]] = {}

    def allow(
        self,
        *,
        subject_id: str,
        now: Optional[float] = None,
        window_name: str = "general",
    ) -> bool:
        if not isinstance(subject_id, str) or not subject_id:
            raise InvalidProxyRequestError(
                safe_message="subject_id required",
                internal_detail=f"got {type(subject_id).__name__}",
                field="subject_id",
            )
        ts = float(time.time()) if now is None else float(now)
        budget = (
            self.centralized_budget
            if window_name == "centralized"
            else self.budget
        )
        bucket = self._buckets.setdefault(subject_id, {})
        entries = bucket.setdefault(window_name, [])
        cutoff = ts - self.window_seconds
        i = 0
        while i < len(entries) and entries[i] < cutoff:
            i += 1
        if i > 0:
            del entries[:i]
        if len(entries) >= budget:
            return False
        entries.append(ts)
        if len(entries) > MAX_RATE_LIMIT_BUCKETS:
            del entries[: len(entries) - MAX_RATE_LIMIT_BUCKETS]
        return True


# ----------------------------------------------------------------- proxy
class SecureProxy:
    """The documented secure application proxy."""

    def __init__(
        self,
        *,
        config: ProShieldConfig,
        identity_store: Optional[InMemoryIdentityStore] = None,
        session_verifier: Optional[SessionVerifier] = None,
        session_token_service: Optional[SessionTokenService] = None,
        incident_service: Optional[IncidentService] = None,
        report_service: Optional[ReportService] = None,
        routing_engine: Optional[RoutingEngine] = None,
    ) -> None:
        if not isinstance(config, ProShieldConfig):
            raise ValueError("config must be a ProShieldConfig")
        if not isinstance(config.auth_signing_key, str) or not config.auth_signing_key:
            raise ValueError(
                "config.auth_signing_key must be a non-empty str; "
                "see Phase 3 secret-handling rules"
            )
        self._config = config
        self._identity_store = identity_store or InMemoryIdentityStore()
        self._session_verifier = session_verifier or SessionVerifier(
            signing_key=config.auth_signing_key,
            identity_store=self._identity_store,
        )
        self._session_token_service = session_token_service or SessionTokenService(
            signing_key=config.auth_signing_key,
        )
        self._incident_service = incident_service
        self._report_service = report_service
        self._routing_engine = routing_engine or RoutingEngine()
        self._rate_limiter = _RateLimiter(
            window_seconds=60,
            budget=int(config.proxy_rate_limit_per_minute),
            centralized_budget=int(
                config.proxy_centralized_rate_limit_per_minute
            ),
        )

    @property
    def config(self) -> ProShieldConfig:
        return self._config

    @property
    def identity_store(self) -> InMemoryIdentityStore:
        return self._identity_store

    @property
    def session_verifier(self) -> SessionVerifier:
        return self._session_verifier

    @property
    def session_token_service(self) -> SessionTokenService:
        return self._session_token_service

    @property
    def incident_service(self) -> Optional[IncidentService]:
        return self._incident_service

    @property
    def report_service(self) -> Optional[ReportService]:
        return self._report_service

    @property
    def routing_engine(self) -> RoutingEngine:
        return self._routing_engine

    def attach_incident_service(self, service: IncidentService) -> None:
        if not isinstance(service, IncidentService):
            raise ValueError("service must be an IncidentService")
        self._incident_service = service

    def attach_report_service(self, service: ReportService) -> None:
        if not isinstance(service, ReportService):
            raise ValueError("service must be a ReportService")
        self._report_service = service

    # ----- request dispatch
    def handle(self, request: ProxyRequest) -> ProxyResponse:
        if not isinstance(request, ProxyRequest):
            raise InvalidProxyRequestError(
                safe_message="invalid proxy request",
                internal_detail=f"got {type(request).__name__}",
            )
        try:
            self._validate_request_shape(request)
        except InvalidProxyRequestError as exc:
            return self._shape(exc)
        try:
            return self._dispatch(request)
        except InvalidProxyRequestError as exc:
            return self._shape(exc)
        except ProxyUnauthorizedError as exc:
            return self._shape(exc)
        except ProxyRateLimitedError as exc:
            return self._shape(exc)
        except NotFoundError as exc:
            return self._shape(exc)
        except AuthorizationError as exc:
            return self._shape(exc)
        except AuthenticationRequiredError as exc:
            return self._shape(exc)
        except DomainValidationError as exc:
            return self._shape(exc)
        except DomainError as exc:
            _log.warning(
                "proxy.domain_error",
                extra={
                    "operation": request.operation,
                    "error_code": getattr(exc, "code", "domain_error"),
                    "error_type": type(exc).__name__,
                },
            )
            return self._shape(exc)
        except Exception as exc:  # noqa: BLE001 - proxy fail-safe boundary
            _log.exception(
                "proxy.unexpected_error",
                extra={"operation": request.operation},
            )
            safe = ProxyUnauthorizedError(
                safe_message="internal error",
                internal_detail=f"{type(exc).__name__}: {exc}",
            )
            return self._shape(safe)

    def _validate_request_shape(self, request: ProxyRequest) -> None:
        if not isinstance(request.operation, str) or not request.operation:
            raise InvalidProxyRequestError(
                safe_message="operation required",
                internal_detail=f"got {request.operation!r}",
                field="operation",
            )
        if request.operation not in ALLOWED_OPERATIONS:
            raise InvalidProxyRequestError(
                safe_message="unknown operation",
                internal_detail=f"operation={request.operation!r}",
                field="operation",
            )
        if request.body_bytes > self._config.proxy_max_request_bytes:
            raise InvalidProxyRequestError(
                safe_message="request too large",
                internal_detail=(
                    f"body_bytes={request.body_bytes} > "
                    f"max={self._config.proxy_max_request_bytes}"
                ),
                field="body",
            )
        if not isinstance(request.headers, Mapping):
            raise InvalidProxyRequestError(
                safe_message="invalid headers",
                internal_detail=f"got {type(request.headers).__name__}",
            )
        if request.body is not None and not isinstance(request.body, dict):
            raise InvalidProxyRequestError(
                safe_message="invalid body",
                internal_detail=f"got {type(request.body).__name__}",
                field="body",
            )

    def _shape(self, exc: DomainError) -> ProxyResponse:
        status = int(getattr(exc, "http_status", 500))
        # IDOR defense: a CaseAccessDeniedError is translated to
        # 404 at the wire boundary so the response does not leak
        # the existence of a case the caller is not authorized
        # to see. The internal log keeps the original 403 signal.
        from ..incidents.errors import CaseAccessDeniedError
        code = getattr(exc, "code", "domain_error")
        message = getattr(exc, "safe_message", "internal error")
        if isinstance(exc, CaseAccessDeniedError):
            status = 404
            code = "case_not_found"
            message = "case not found"
        body: Dict[str, Any] = {
            "error": {
                "code": code,
                "message": message,
            }
        }
        return ProxyResponse(status=status, body=body)

    def _shape_ok(
        self, payload: Dict[str, Any]
    ) -> ProxyResponse:
        size = len(json.dumps(payload, separators=(",", ":")))
        if size > self._config.proxy_max_response_bytes:
            return ProxyResponse(
                status=500,
                body={
                    "error": {
                        "code": "response_too_large",
                        "message": "response exceeded cap",
                    }
                },
            )
        return ProxyResponse(status=200, body={"ok": True, "data": payload})

    def _extract_session_token(
        self, request: ProxyRequest
    ) -> Optional[str]:
        auth = request.headers.get(PROXY_HEADER_AUTHORIZATION) or request.headers.get(
            PROXY_HEADER_AUTHORIZATION.lower()
        )
        if isinstance(auth, str) and auth:
            parts = auth.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1].strip()
            return None
        sess = request.headers.get(PROXY_HEADER_SESSION) or request.headers.get(
            PROXY_HEADER_SESSION.lower()
        )
        if isinstance(sess, str) and sess:
            return sess.strip()
        return None

    def _verify_identity(self, request: ProxyRequest) -> Identity:
        token = self._extract_session_token(request)
        if not token:
            raise ProxyUnauthorizedError(
                safe_message="missing session token",
                internal_detail="no Authorization / X-ProShield-Session",
            )
        try:
            result = self._session_verifier.verify(token)
        except AuthenticationRequiredError as exc:
            raise ProxyUnauthorizedError(
                safe_message=exc.safe_message,
                internal_detail=exc.internal_detail,
            ) from exc
        return result.identity

    def _require(
        self, identity: Identity, permission: str
    ) -> None:
        perms = tuple(identity.permissions)
        if not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=permission,
        ):
            raise AuthorizationError(
                safe_message="operation forbidden",
                internal_detail=f"missing {permission}",
            )

    # ----- dispatch
    def _dispatch(self, request: ProxyRequest) -> ProxyResponse:
        op = request.operation
        if op == OP_HEALTH:
            return self._handle_health()
        if op == OP_AUTH_ISSUE:
            return self._handle_auth_issue(request)
        identity = self._verify_identity(request)
        if not self._rate_limiter.allow(subject_id=identity.subject_id):
            raise ProxyRateLimitedError(
                safe_message="rate limit exceeded",
                internal_detail=(
                    f"budget={self._rate_limiter.budget} per "
                    f"{self._rate_limiter.window_seconds}s"
                ),
            )
        if op == OP_GET_CASE:
            return self._handle_get_case(request, identity)
        if op == OP_CREATE_CASE:
            return self._handle_create_case(request, identity)
        if op == OP_LIST_CASES:
            return self._handle_list_cases(request, identity)
        if op == OP_CLOSE_CASE:
            return self._handle_close_case(request, identity)
        if op == OP_REQUEST_CENTRALIZED:
            return self._handle_request_centralized(
                request, identity
            )
        if op == OP_GET_REPORT:
            return self._handle_get_report(request, identity)
        if op == OP_LIST_REPORTS:
            return self._handle_list_reports(request, identity)
        if op == OP_GENERATE_NORMAL_REPORT:
            return self._handle_generate_normal_report(
                request, identity
            )
        if op == OP_GENERATE_CENTRALIZED_REPORT:
            return self._handle_generate_centralized_report(
                request, identity
            )
        if op == OP_ROUTE_CASE:
            return self._handle_route_case(request, identity)
        raise InvalidProxyRequestError(
            safe_message="unknown operation",
            internal_detail=f"operation={op!r}",
            field="operation",
        )

    # ----- handlers
    def _handle_health(self) -> ProxyResponse:
        return self._shape_ok({"status": "ok"})

    def _handle_auth_issue(
        self, request: ProxyRequest
    ) -> ProxyResponse:
        body = request.body or {}
        subject_id = body.get("subject_id")
        if not isinstance(subject_id, str) or not subject_id:
            raise InvalidProxyRequestError(
                safe_message="subject_id required",
                internal_detail="missing subject_id",
                field="subject_id",
            )
        identity = self._identity_store.get(subject_id)
        if identity is None:
            raise ProxyUnauthorizedError(
                safe_message="unknown subject",
                internal_detail=f"subject_id={subject_id!r}",
            )
        token = self._session_token_service.issue(
            subject_id=identity.subject_id,
            lifetime_seconds=int(
                self._config.auth_token_lifetime_seconds
            ),
        )
        return self._shape_ok({
            "token": token.token,
            "subject_id": identity.subject_id,
            "role": identity.role,
            "expires_at": token.expires_at,
        })

    def _handle_get_case(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CASE_READ)
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=incident_id
        )
        return self._shape_ok({"case": case.to_dict()})

    def _handle_create_case(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        """Phase 4.8 boundary: the proxy does NOT construct
        evidence. Case creation is the IncidentService
        responsibility; the wire boundary always rejects
        ``case.create`` with a documented 400.

        The future slice either (a) promotes this to a
        full evidence-payload create handler, or (b)
        removes the operation entirely. Phase 4.8
        documents the boundary, not the implementation.
        """
        self._require(identity, Permission.CASE_READ)
        raise InvalidProxyRequestError(
            safe_message="case.create is not exposed at the wire boundary",
            internal_detail=(
                "Phase 4.8 boundary: the proxy does not "
                "construct evidence. Use IncidentService."
            ),
            field="operation",
        )

    def _handle_list_cases(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CASE_READ)
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        state = body.get("state") if isinstance(body, dict) else None
        limit = int(body.get("limit", 50)) if isinstance(body, dict) else 50
        cases = self._incident_service.list_cases(
            identity=identity, state=state, limit=limit
        )
        return self._shape_ok({
            "cases": [c.to_dict() for c in cases],
        })

    def _handle_close_case(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CASE_READ)
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        reason = body.get("reason") or ""
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        case = self._incident_service.close_case(
            identity=identity, incident_id=incident_id,
            reason=str(reason),
        )
        return self._shape_ok({"case": case.to_dict()})

    def _handle_request_centralized(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CASE_CENTRALIZED_REQUEST)
        if not self._rate_limiter.allow(
            subject_id=identity.subject_id, window_name="centralized"
        ):
            raise ProxyRateLimitedError(
                safe_message="centralized rate limit exceeded",
                internal_detail="centralized budget exhausted",
            )
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        reason = body.get("reason") or ""
        detections_payload = body.get("detections") or []
        events_payload = body.get("events") or []
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        # The proxy accepts detections / events as
        # payload-shaped references (id + minimal
        # attributes). It NEVER accepts raw pymongo
        # documents or backend internals.
        detections = _payload_to_detections(detections_payload)
        events = _payload_to_events(events_payload)
        outcome = self._incident_service.request_centralized_analysis(
            identity=identity,
            incident_id=incident_id,
            detections=detections,
            events=events,
            reason=str(reason),
        )
        return self._shape_ok({
            "case": outcome.case.to_dict(),
            "failed": outcome.failed,
            "failure_reason": outcome.failure_reason,
            "new_correlation_ids": list(outcome.new_correlation_ids),
        })

    def _handle_get_report(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.REPORT_READ)
        if self._report_service is None:
            raise InvalidProxyRequestError(
                safe_message="report service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        report_id = body.get("report_id")
        if not isinstance(report_id, str) or not report_id:
            raise InvalidProxyRequestError(
                safe_message="report_id required",
                internal_detail="missing report_id",
                field="report_id",
            )
        report = self._report_service.get_report(
            identity=identity, report_id=report_id
        )
        return self._shape_ok({"report": report.to_dict()})

    def _handle_list_reports(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.REPORT_READ)
        if self._report_service is None or self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=incident_id
        )
        reports = self._report_service.list_for_incident(
            identity=identity, case=case
        )
        return self._shape_ok({
            "reports": [r.to_dict() for r in reports],
        })

    def _handle_generate_normal_report(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.REPORT_GENERATE)
        if self._report_service is None or self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        title = body.get("title") or ""
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        # The proxy delegates to the report service which
        # builds the report from the case + the supplied
        # evidence payload. The case is fetched via the
        # incident service; the report service never
        # talks to the persistence layer directly.
        case = self._incident_service.get_case(
            identity=identity, incident_id=incident_id
        )
        evidence = _payload_to_evidence(body)
        report = self._report_service.generate_normal_report(
            identity=identity,
            case=case,
            events=evidence["events"],
            detections=evidence["detections"],
            correlations=evidence["correlations"],
            timeline=evidence.get("timeline"),
            severity=evidence.get("severity"),
            title=str(title),
        )
        return self._shape_ok({"report": report.to_dict()})

    def _handle_generate_centralized_report(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.REPORT_GENERATE)
        if self._report_service is None or self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        incident_id = body.get("incident_id")
        title = body.get("title") or ""
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=incident_id
        )
        evidence = _payload_to_evidence(body)
        centralized_evidence = _payload_to_evidence(body, prefix="centralized_")
        report = self._report_service.generate_centralized_report(
            identity=identity,
            case=case,
            events=evidence["events"],
            detections=evidence["detections"],
            correlations=evidence["correlations"],
            centralized_correlations=centralized_evidence["correlations"],
            centralized_events=centralized_evidence["events"],
            centralized_detections=centralized_evidence["detections"],
            centralized_severity=centralized_evidence.get("severity"),
            centralized_timeline=centralized_evidence.get("timeline"),
            title=str(title),
        )
        return self._shape_ok({"report": report.to_dict()})

    def _handle_route_case(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.ROUTING_READ)
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        from ..routing import RoutingContext
        body = request.body or {}
        incident_id = body.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=incident_id
        )
        ctx = RoutingContext(
            incident=case,
            severity_band=body.get("severity_band"),
            confidence_band=body.get("confidence_band"),
            complexity=body.get("complexity"),
        )
        result = self._routing_engine.route_for_identity(
            identity=identity, context=ctx
        )
        return self._shape_ok({"routing": result.to_dict()})


# ----------------------------------------------------------------- payload helpers
def _payload_to_events(payload: Any) -> List[Any]:
    """Translate a JSON-shaped events payload into
    :class:`SecurityEvent` instances.

    The wire shape is intentionally minimal so the proxy
    never echoes backend internals back through the
    response.
    """
    from datetime import datetime as _dt
    from ..domain.security_event import SecurityEvent as _SE
    out: List[_SE] = []
    if not isinstance(payload, list):
        return out
    for item in payload:
        if not isinstance(item, dict):
            continue
        ev_id = item.get("event_id")
        if not isinstance(ev_id, str) or not ev_id:
            continue
        try:
            et_raw = item.get("event_time")
            if isinstance(et_raw, str):
                event_time = _dt.fromisoformat(et_raw.replace("Z", "+00:00"))
            elif isinstance(et_raw, _dt):
                event_time = et_raw
            else:
                event_time = _dt.now(_dt.now().astimezone().tzinfo)
            ingested_at = _dt.now(event_time.tzinfo)
        except Exception:
            continue
        try:
            ev = _SE(
                event_id=ev_id,
                source=str(item.get("source", "nginx")),
                event_type=str(item.get("event_type", "authentication_failure")),
                event_time=event_time,
                ingested_at=ingested_at,
                endpoint=item.get("endpoint"),
                source_ip=item.get("source_ip"),
                asset=item.get("asset"),
                account=item.get("account"),
                provenance=item.get("provenance") or {
                    "collector": str(item.get("source", "nginx")),
                    "source_event_id": ev_id,
                },
            )
            out.append(ev)
        except Exception:
            continue
    return out


def _payload_to_detections(payload: Any) -> List[Any]:
    """Translate a JSON-shaped detections payload into
    :class:`Detection` instances."""
    from datetime import datetime as _dt
    from ..detection.models import Detection as _D
    out: List[_D] = []
    if not isinstance(payload, list):
        return out
    for item in payload:
        if not isinstance(item, dict):
            continue
        did = item.get("detection_id")
        if not isinstance(did, str) or not did:
            continue
        try:
            da = item.get("detected_at")
            if isinstance(da, str):
                detected_at = _dt.fromisoformat(da.replace("Z", "+00:00"))
            elif isinstance(da, _dt):
                detected_at = da
            else:
                detected_at = _dt.now(_dt.now().astimezone().tzinfo)
        except Exception:
            continue
        try:
            d = _D(
                detection_id=did,
                rule_id=str(item.get("rule_id", "CUSTOM")),
                rule_version=int(item.get("rule_version", 1)),
                category=str(item.get("category", "source_specific")),
                event_id=str(item.get("event_id", did)),
                evidence_refs=tuple(
                    r for r in item.get("evidence_refs", ()) if isinstance(r, str)
                ),
                reasoning=str(item.get("reasoning", "")),
                detected_at=detected_at,
                extra=tuple(
                    tuple(map(str, p))
                    for p in item.get("extra", ())
                    if isinstance(p, (list, tuple)) and len(p) == 2
                ),
            )
            out.append(d)
        except Exception:
            continue
    return out


def _payload_to_correlations(payload: Any) -> List[Any]:
    """Translate a JSON-shaped correlations payload into
    :class:`Correlation` instances."""
    from datetime import datetime as _dt
    from ..correlation.models import (
        Correlation as _C,
        CorrelationKey as _CK,
        CorrelationTrigger as _CT,
    )
    out: List[_C] = []
    if not isinstance(payload, list):
        return out
    for item in payload:
        if not isinstance(item, dict):
            continue
        cid = item.get("correlation_id")
        if not isinstance(cid, str) or not cid:
            continue
        try:
            ws = item.get("window_start")
            we = item.get("window_end")
            ca = item.get("correlated_at")
            if isinstance(ws, str):
                ws_dt = _dt.fromisoformat(ws.replace("Z", "+00:00"))
            else:
                ws_dt = _dt.now(_dt.now().astimezone().tzinfo)
            if isinstance(we, str):
                we_dt = _dt.fromisoformat(we.replace("Z", "+00:00"))
            else:
                we_dt = ws_dt
            if isinstance(ca, str):
                ca_dt = _dt.fromisoformat(ca.replace("Z", "+00:00"))
            else:
                ca_dt = _dt.now(_dt.now().astimezone().tzinfo)
        except Exception:
            continue
        try:
            key_parts = tuple(
                str(p) for p in item.get("key", []) if isinstance(p, (str, int))
            )
            c = _C(
                correlation_id=cid,
                pattern_id=str(item.get("pattern_id", "CUSTOM")),
                pattern_version=int(item.get("pattern_version", 1)),
                trigger=_CT(str(item.get("trigger", "brute_force_count_threshold"))),
                key=_CK(parts=key_parts),
                detection_ids=tuple(
                    r for r in item.get("detection_ids", ()) if isinstance(r, str)
                ),
                event_ids=tuple(
                    r for r in item.get("event_ids", ()) if isinstance(r, str)
                ),
                window_start=ws_dt,
                window_end=we_dt,
                count=int(item.get("count", 0)),
                reasoning=str(item.get("reasoning", "")),
                correlated_at=ca_dt,
                extra=tuple(
                    tuple(map(str, p))
                    for p in item.get("extra", ())
                    if isinstance(p, (list, tuple)) and len(p) == 2
                ),
            )
            out.append(c)
        except Exception:
            continue
    return out


def _payload_to_evidence(
    body: Dict[str, Any], *, prefix: str = ""
) -> Dict[str, Any]:
    """Translate a JSON-shaped request body into a dict
    of typed evidence lists."""
    out: Dict[str, Any] = {
        "events": _payload_to_events(body.get(prefix + "events", [])),
        "detections": _payload_to_detections(
            body.get(prefix + "detections", [])
        ),
        "correlations": _payload_to_correlations(
            body.get(prefix + "correlations", [])
        ),
    }
    if prefix + "timeline" in body:
        out["timeline"] = body[prefix + "timeline"]
    if prefix + "severity" in body:
        out["severity"] = body[prefix + "severity"]
    return out


__all__ = [
    "ALLOWED_OPERATIONS",
    "MAX_PROXY_REQUEST_BYTES",
    "MAX_PROXY_RESPONSE_BYTES",
    "MAX_RATE_LIMIT_BUCKETS",
    "OP_AUTH_ISSUE",
    "OP_CLOSE_CASE",
    "OP_CREATE_CASE",
    "OP_GENERATE_CENTRALIZED_REPORT",
    "OP_GENERATE_NORMAL_REPORT",
    "OP_GET_CASE",
    "OP_GET_REPORT",
    "OP_HEALTH",
    "OP_LIST_CASES",
    "OP_LIST_REPORTS",
    "OP_REQUEST_CENTRALIZED",
    "OP_ROUTE_CASE",
    "PROXY_HEADER_AUTHORIZATION",
    "PROXY_HEADER_SESSION",
    "ProxyRequest",
    "ProxyResponse",
    "SecureProxy",
]