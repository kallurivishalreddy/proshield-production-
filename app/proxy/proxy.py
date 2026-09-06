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
from ..correlation.service import CorrelationReadService
from ..detection.service import DetectionReadService
from ..domain.errors import (
    AuthenticationRequiredError,
    AuthorizationError,
    DomainError,
    NotFoundError,
    ValidationError as DomainValidationError,
)
from ..incidents import IncidentService, authorize_case_access
from ..overview.service import OverviewReadService
from ..reports import ReportService
from ..reports.models import Report
from ..routing import RoutingEngine
from ..rules.management.service import RuleManagementService
from ..timeline.service import TimelineReadService
from .errors import (
    InvalidProxyRequestError,
    ProxyInternalError,
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
OP_REPORT_EXPORT = "report.export"
OP_ROUTE_CASE = "routing.compute"
OP_AUTH_ISSUE = "auth.issue"

# Phase 4.9: source-management wire operations (client-facing
# boundary; the trusted-inbound boundary lives in
# :mod:`app.sources.ingress` and is gated by source-identity
# tokens, not session tokens).
OP_SOURCE_LIST = "source.list"
OP_SOURCE_GET = "source.get"
OP_SOURCE_LIST_TYPES = "source.list_types"
OP_SOURCE_REGISTER = "source.register"
OP_SOURCE_CONFIGURE = "source.configure"
OP_SOURCE_VALIDATE = "source.validate"
OP_SOURCE_ENABLE = "source.enable"
OP_SOURCE_DISABLE = "source.disable"
OP_SOURCE_RETIRE = "source.retire"
OP_SOURCE_ISSUE_TOKEN = "source.issue_token"

# Phase 3 frontend-required operations: detection, correlation,
# overview aggregate, timeline, rule management.
OP_EVENT_LIST = "event.list"
OP_DETECTION_LIST = "detection.list"
OP_DETECTION_GET = "detection.get"
OP_DETECTION_LIST_FOR_INCIDENT = "detection.list_for_incident"
OP_CORRELATION_LIST = "correlation.list"
OP_CORRELATION_GET = "correlation.get"
OP_CORRELATION_LIST_FOR_INCIDENT = "correlation.list_for_incident"
OP_OVERVIEW_SUMMARY = "overview.summary"
OP_TIMELINE_BUILD_FOR_INCIDENT = "timeline.build_for_incident"
OP_RULE_LIST = "rule.list"
OP_RULE_GET = "rule.get"
OP_RULE_CREATE = "rule.create"
OP_RULE_UPDATE = "rule.update"
OP_RULE_VERSION = "rule.version"
OP_RULE_ENABLE = "rule.enable"
OP_RULE_DISABLE = "rule.disable"
OP_RULE_RETIRE = "rule.retire"

# AUTH-001 credential header: the credential can be supplied
# via the ``X-ProShield-Credential`` header OR in the body as
# the ``credential`` field. The header is preferred so a
# logged-in browser / agent can keep the secret out of any
# body dump / replay log.
PROXY_HEADER_CREDENTIAL = "X-ProShield-Credential"

ALLOWED_OPERATIONS: frozenset = frozenset({
    OP_HEALTH,
    OP_EVENT_LIST,
    OP_GET_CASE,
    OP_CREATE_CASE,
    OP_LIST_CASES,
    OP_CLOSE_CASE,
    OP_REQUEST_CENTRALIZED,
    OP_GET_REPORT,
    OP_LIST_REPORTS,
    OP_GENERATE_NORMAL_REPORT,
    OP_GENERATE_CENTRALIZED_REPORT,
    OP_REPORT_EXPORT,
    OP_ROUTE_CASE,
    OP_AUTH_ISSUE,
    OP_SOURCE_LIST,
    OP_SOURCE_GET,
    OP_SOURCE_LIST_TYPES,
    OP_SOURCE_REGISTER,
    OP_SOURCE_CONFIGURE,
    OP_SOURCE_VALIDATE,
    OP_SOURCE_ENABLE,
    OP_SOURCE_DISABLE,
    OP_SOURCE_RETIRE,
    OP_SOURCE_ISSUE_TOKEN,
    OP_DETECTION_LIST,
    OP_DETECTION_GET,
    OP_DETECTION_LIST_FOR_INCIDENT,
    OP_CORRELATION_LIST,
    OP_CORRELATION_GET,
    OP_CORRELATION_LIST_FOR_INCIDENT,
    OP_OVERVIEW_SUMMARY,
    OP_TIMELINE_BUILD_FOR_INCIDENT,
    OP_RULE_LIST,
    OP_RULE_GET,
    OP_RULE_CREATE,
    OP_RULE_UPDATE,
    OP_RULE_VERSION,
    OP_RULE_ENABLE,
    OP_RULE_DISABLE,
    OP_RULE_RETIRE,
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
        source_management_service: Optional[Any] = None,
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
        self._source_management_service = source_management_service
        # Phase 4.10 wire-promotion: each is attached lazily
        # via ``attach_*`` (mirrors the source-management
        # pattern). Keeping them optional preserves the
        # ``proxy-without-services`` test fixtures.
        self._detection_service: Optional[DetectionReadService] = None
        self._correlation_service: Optional[CorrelationReadService] = None
        self._overview_service: Optional[OverviewReadService] = None
        self._timeline_service: Optional[TimelineReadService] = None
        self._rule_management_service: Optional[RuleManagementService] = None
        self._security_event_repository: Optional[Any] = None
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

    def attach_source_management_service(self, service: Any) -> None:
        """Attach the Phase 4.9 source-management service.

        Accepts the duck-typed
        :class:`app.sources.SourceManagementService` to avoid
        a circular import (the proxy does not import
        :mod:`app.sources`).
        """
        if service is None:
            self._source_management_service = None
            return
        # We deliberately accept any object that exposes the
        # documented public methods. Importing
        # :class:`SourceManagementService` for ``isinstance``
        # would couple the two packages at import time.
        required = {
            "list_all",
            "get",
            "register",
            "configure",
            "validate_connection",
            "enable",
            "disable",
            "retire",
            "issue_ingress_token",
            "list_supported_connector_types",
        }
        missing = [
            name for name in required
            if not hasattr(service, name)
        ]
        if missing:
            raise ValueError(
                f"source management service is missing methods: "
                f"{missing}"
            )
        self._source_management_service = service

    def attach_detection_service(
        self, service: Optional[DetectionReadService],
    ) -> None:
        """Attach the Phase 4.10 detection read service.

        Accepts ``None`` to detach (handy for tests that want to
        assert the stub envelope). When ``service`` is not ``None``
        it must be a :class:`DetectionReadService`.
        """
        if service is None:
            self._detection_service = None
            return
        if not isinstance(service, DetectionReadService):
            raise ValueError(
                f"service must be a DetectionReadService, "
                f"got {type(service).__name__}"
            )
        self._detection_service = service

    def attach_correlation_service(
        self, service: Optional[CorrelationReadService],
    ) -> None:
        """Attach the Phase 4.10 correlation read service."""
        if service is None:
            self._correlation_service = None
            return
        if not isinstance(service, CorrelationReadService):
            raise ValueError(
                f"service must be a CorrelationReadService, "
                f"got {type(service).__name__}"
            )
        self._correlation_service = service

    def attach_overview_service(
        self, service: Optional[OverviewReadService],
    ) -> None:
        """Attach the Phase 4.10 overview read service."""
        if service is None:
            self._overview_service = None
            return
        if not isinstance(service, OverviewReadService):
            raise ValueError(
                f"service must be an OverviewReadService, "
                f"got {type(service).__name__}"
            )
        self._overview_service = service

    def attach_timeline_service(
        self, service: Optional[TimelineReadService],
        *,
        security_event_repository: Optional[Any] = None,
    ) -> None:
        """Attach the Phase 4.10 timeline read service.

        The timeline service needs an event repository to resolve
        ``case.evidence.event_ids`` to :class:`SecurityEvent`
        instances. Pass ``security_event_repository`` at attach
        time so the proxy can hand it to the service.
        """
        if service is None:
            self._timeline_service = None
            self._security_event_repository = None
            return
        if not isinstance(service, TimelineReadService):
            raise ValueError(
                f"service must be a TimelineReadService, "
                f"got {type(service).__name__}"
            )
        self._timeline_service = service
        self._security_event_repository = security_event_repository

    def attach_rule_management_service(
        self, service: Optional[RuleManagementService],
    ) -> None:
        """Attach the Phase 4.10 rule management service.

        The service is the Phase 4.7
        :class:`app.rules.management.service.RuleManagementService`;
        all 8 rule ops (`rule.list`, `rule.get`, `rule.create`,
        `rule.update`, `rule.version`, `rule.enable`,
        `rule.disable`, `rule.retire`) are routed through it.

        Accepts ``None`` to detach.
        """
        if service is None:
            self._rule_management_service = None
            return
        if not isinstance(service, RuleManagementService):
            raise ValueError(
                f"service must be a RuleManagementService, "
                f"got {type(service).__name__}"
            )
        self._rule_management_service = service

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
            safe = ProxyInternalError(
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

    def _coerce_iso(self, value: Any, field_name: str) -> Optional[datetime]:
        """Convert a wire payload value to a UTC datetime.

        Accepts a ``datetime`` (returned as-is), an ISO 8601
        string (``...Z`` suffix normalised to ``+00:00``), or
        ``None``. A malformed string raises
        :class:`InvalidProxyRequestError` so the wire does not
        leak the underlying parser error.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise InvalidProxyRequestError(
                    safe_message=(
                        f"invalid {field_name} (must be ISO 8601)"
                    ),
                    internal_detail=str(exc),
                    field=field_name,
                )
        raise InvalidProxyRequestError(
            safe_message=f"invalid {field_name}",
            internal_detail=(
                f"{field_name} must be ISO 8601 string or None"
            ),
            field=field_name,
        )

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
        # AUTH-001 / AUTH-002 remediation: ``auth.issue`` is now
        # routed through the per-caller rate limiter (AUTH-002)
        # and MUST present a valid credential before a token is
        # issued. The credential is supplied either via the
        # ``X-ProShield-Credential`` header or in the request
        # body as the ``credential`` field.
        if op == OP_AUTH_ISSUE:
            self._enforce_auth_issue_rate_limit(request)
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
        if op == OP_SOURCE_LIST:
            return self._handle_source_list(request, identity)
        if op == OP_SOURCE_GET:
            return self._handle_source_get(request, identity)
        if op == OP_SOURCE_LIST_TYPES:
            return self._handle_source_list_types(request, identity)
        if op == OP_SOURCE_REGISTER:
            return self._handle_source_register(request, identity)
        if op == OP_SOURCE_CONFIGURE:
            return self._handle_source_configure(request, identity)
        if op == OP_SOURCE_VALIDATE:
            return self._handle_source_validate(request, identity)
        if op == OP_SOURCE_ENABLE:
            return self._handle_source_enable(request, identity)
        if op == OP_SOURCE_DISABLE:
            return self._handle_source_disable(request, identity)
        if op == OP_SOURCE_RETIRE:
            return self._handle_source_retire(request, identity)
        if op == OP_SOURCE_ISSUE_TOKEN:
            return self._handle_source_issue_token(request, identity)
        if op == OP_EVENT_LIST:
            return self._handle_event_list(request, identity)
        if op == OP_DETECTION_LIST:
            return self._handle_detection_list(request, identity)
        if op == OP_DETECTION_GET:
            return self._handle_detection_get(request, identity)
        if op == OP_DETECTION_LIST_FOR_INCIDENT:
            return self._handle_detection_list_for_incident(
                request, identity
            )
        if op == OP_CORRELATION_LIST:
            return self._handle_correlation_list(request, identity)
        if op == OP_CORRELATION_GET:
            return self._handle_correlation_get(request, identity)
        if op == OP_CORRELATION_LIST_FOR_INCIDENT:
            return self._handle_correlation_list_for_incident(
                request, identity
            )
        if op == OP_OVERVIEW_SUMMARY:
            return self._handle_overview_summary(request, identity)
        if op == OP_TIMELINE_BUILD_FOR_INCIDENT:
            return self._handle_timeline_build_for_incident(
                request, identity
            )
        if op == OP_RULE_LIST:
            return self._handle_rule_list(request, identity)
        if op == OP_RULE_GET:
            return self._handle_rule_get(request, identity)
        if op == OP_RULE_CREATE:
            return self._handle_rule_create(request, identity)
        if op == OP_RULE_UPDATE:
            return self._handle_rule_update(request, identity)
        if op == OP_RULE_VERSION:
            return self._handle_rule_version(request, identity)
        if op == OP_RULE_ENABLE:
            return self._handle_rule_enable(request, identity)
        if op == OP_RULE_DISABLE:
            return self._handle_rule_disable(request, identity)
        if op == OP_RULE_RETIRE:
            return self._handle_rule_retire(request, identity)
        if op == OP_REPORT_EXPORT:
            return self._handle_report_export(request, identity)
        raise InvalidProxyRequestError(
            safe_message="unknown operation",
            internal_detail=f"operation={op!r}",
            field="operation",
        )

    # ----- handlers
    def _handle_health(self) -> ProxyResponse:
        return self._shape_ok({"status": "ok"})

    def _enforce_auth_issue_rate_limit(
        self, request: ProxyRequest
    ) -> None:
        """AUTH-002: rate-limit ``auth.issue`` per (subject_id, caller).

        ``auth.issue`` is reached before identity verification, so
        we cannot key the limiter on the verified subject_id alone
        (an attacker can churn through unknown subject_ids to
        escape the budget). Instead the limiter is keyed on a
        composite ``subject_id || caller_ip`` string. ``caller_ip``
        is the optional ``X-ProShield-Caller-IP`` header (real
        HTTP deployments would source this from the trusted edge
        proxy / mTLS peer).
        """
        body = request.body or {}
        subject_id = body.get("subject_id")
        if not isinstance(subject_id, str) or not subject_id:
            subject_id = "<unknown>"
        caller_ip = (
            request.headers.get("X-ProShield-Caller-IP") or "<anon>"
        )
        key = f"auth_issue::{subject_id}::{caller_ip}"
        if not self._rate_limiter.allow(
            subject_id=key, window_name="auth_issue"
        ):
            raise ProxyRateLimitedError(
                safe_message="auth.issue rate limit exceeded",
                internal_detail=(
                    f"budget={self._rate_limiter.budget} per "
                    f"{self._rate_limiter.window_seconds}s"
                ),
            )

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
        # AUTH-001: require a credential that matches the
        # identity store. Acceptable sources: ``X-ProShield-
        # Credential`` header OR ``credential`` field in the body.
        # STRIX D-3: real HTTP servers lowercase header keys, so
        # the credential header lookup must be case-insensitive.
        credential = (
            request.headers.get(PROXY_HEADER_CREDENTIAL)
            or request.headers.get(PROXY_HEADER_CREDENTIAL.lower())
            or body.get("credential")
        )
        if not isinstance(credential, str) or not credential:
            raise ProxyUnauthorizedError(
                safe_message="credential required",
                internal_detail="no credential in header or body",
            )
        if not self._identity_store.verify_credential(
            subject_id, credential
        ):
            raise ProxyUnauthorizedError(
                safe_message="credential rejected",
                internal_detail=(
                    "credential does not match identity store"
                ),
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
        # V2-05 fix: the correlation engine must analyse the case's
        # REAL evidence, not whatever (typically empty) payload the UI
        # happened to send. The previous handler derived
        # ``detections=[]``/``events=[]`` from the request payload,
        # ran the engine over zero inputs and reported a misleading
        # success ("0 new correlations"). The server resolves the
        # case's persisted evidence itself (same resolution the
        # timeline uses); the payload evidence is only a fallback for
        # callers that explicitly supply it.
        if self._timeline_service is not None:
            case = self._incident_service.get_case(
                identity=identity, incident_id=incident_id,
            )
            resolved_events, resolved_detections, _ = (
                self._timeline_service.resolve_case_evidence(case)
            )
        else:  # pragma: no cover - timeline service is always wired
            resolved_events, resolved_detections = [], []
        if detections_payload or events_payload:
            # The proxy accepts detections / events as
            # payload-shaped references (id + minimal
            # attributes). It NEVER accepts raw pymongo
            # documents or backend internals.
            detections = _payload_to_detections(detections_payload)
            events = _payload_to_events(events_payload)
        else:
            detections = resolved_detections
            events = resolved_events
        if not detections and not events:
            # Truthful refusal: analysing zero evidence cannot
            # succeed. The case is left untouched.
            raise InvalidProxyRequestError(
                safe_message=(
                    "case has no evidence to analyse"
                ),
                internal_detail=(
                    "centralized analysis requested with zero resolvable "
                    f"evidence for incident_id={incident_id!r}"
                ),
                field="incident_id",
            )
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
        # V2-02 (report content) fix: the report must describe the
        # case's REAL evidence. The UI sends only {incident_id}; the
        # old handler passed the (empty) payload evidence straight
        # through, so every generated report had empty
        # what_was_detected / sources / detections / specialized
        # correlation sections even when the case held a full cluster.
        # The server resolves the case's persisted evidence itself
        # (same resolution the timeline uses); a caller-supplied
        # payload is honoured only when it actually carries evidence.
        evidence = _payload_to_evidence(body)
        if (
            not evidence["events"]
            and not evidence["detections"]
            and not evidence["correlations"]
            and self._timeline_service is not None
        ):
            (
                resolved_events,
                resolved_detections,
                resolved_correlations,
            ) = self._timeline_service.resolve_case_evidence(case)
            evidence["events"] = resolved_events
            evidence["detections"] = resolved_detections
            evidence["correlations"] = resolved_correlations
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

    # --------------------------------------------------------------- source ops
    def _require_source_service(self) -> Any:
        svc = self._source_management_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="source management service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _view_to_dict(self, view: Any) -> Dict[str, Any]:
        if hasattr(view, "model_dump"):
            # ``mode="json"`` stringifies datetimes so the
            # response is wire-shape JSON-safe.
            return view.model_dump(mode="json")
        return dict(view)

    def _handle_source_list(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        # PROXY-001 / vuln-0002 remediation: source read ops
        # gate on RULE_READ (analyst / admin / internal_service),
        # NOT on EVENT_READ (which collector also holds). The
        # in-service ``list_all``/``get`` methods remain
        # defence-in-depth.
        self._require(identity, Permission.RULE_READ)
        svc = self._require_source_service()
        views = svc.list_all()
        return self._shape_ok({
            "sources": [self._view_to_dict(v) for v in views],
            "supported_connector_types": [
                t.value for t in svc.list_supported_connector_types()
            ],
        })

    def _handle_source_list_types(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        # PROXY-001: same rule_read gate as ``source.list``.
        self._require(identity, Permission.RULE_READ)
        svc = self._require_source_service()
        return self._shape_ok({
            "supported_connector_types": [
                t.value for t in svc.list_supported_connector_types()
            ],
        })

    def _handle_source_get(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        # PROXY-001: source.get requires RULE_READ.
        self._require(identity, Permission.RULE_READ)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        view = svc.get(sid)
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_register(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        # Defence-in-depth: a non-admin token cannot even
        # reach the in-service ``_require_role`` gate. The
        # service-layer ADMIN check remains.
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        source_type_str = body.get("source_type")
        display_name = body.get("display_name")
        if not isinstance(source_type_str, str) or not source_type_str:
            raise InvalidProxyRequestError(
                safe_message="source_type required",
                internal_detail="missing source_type",
                field="source_type",
            )
        if not isinstance(display_name, str) or not display_name:
            raise InvalidProxyRequestError(
                safe_message="display_name required",
                internal_detail="missing display_name",
                field="display_name",
            )
        from ..sources.models import SourceType
        try:
            source_type = SourceType(source_type_str)
        except ValueError as exc:
            raise InvalidProxyRequestError(
                safe_message="unknown source_type",
                internal_detail=str(exc)[:256],
                field="source_type",
            )
        svc = self._require_source_service()
        # STRIX F-5 / N-3: normalize tag ordering/duplicates server-side
        # so a registry with legitimately sorted-unique tags is the ONLY
        # accepted shape, and escape a Pydantic ValidationError to 400
        # (not the 401 internal-error path) if anything else is invalid.
        try:
            view = svc.register(
                identity=identity,
                source_type=source_type,
                display_name=display_name,
                description=str(body.get("description", "")),
                tags=_normalize_tags(body.get("tags")),
                asset_tags=_normalize_tags(body.get("asset_tags")),
            )
        except DomainValidationError:
            raise
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "proxy.source_register_validation",
                extra={"error_type": type(exc).__name__},
            )
            raise InvalidProxyRequestError(
                safe_message="source registration validation failed",
                internal_detail=f"{type(exc).__name__}: {exc}"[:256],
                field="tags",
            )
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_configure(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        cfg = body.get("configuration") or {}
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        if not isinstance(cfg, dict):
            raise InvalidProxyRequestError(
                safe_message="configuration must be a dict",
                internal_detail=f"got {type(cfg).__name__}",
                field="configuration",
            )
        from ..sources.models import SourceConnectionType
        conn_str = cfg.get("connection_type")
        try:
            connection_type = SourceConnectionType(conn_str)
        except (ValueError, TypeError) as exc:
            raise InvalidProxyRequestError(
                safe_message="unknown connection_type",
                internal_detail=str(exc)[:256],
                field="connection_type",
            )
        from ..sources.models import SourceInstanceConfiguration
        try:
            configuration = SourceInstanceConfiguration(
                connection_type=connection_type,
                endpoint=str(cfg.get("endpoint", "")),
                proxy_path=str(cfg.get("proxy_path", "")),
                destination=str(cfg.get("destination", "")),
                asset_tags=_normalize_tags(cfg.get("asset_tags")),
                tags=_normalize_tags(cfg.get("tags")),
                references=tuple(cfg.get("references") or ()),
                secret_ref=str(cfg.get("secret_ref", "")),
            )
        except Exception as exc:  # noqa: BLE001
            raise InvalidProxyRequestError(
                safe_message="configuration validation failed",
                internal_detail=str(exc)[:256],
                field="configuration",
            )
        svc = self._require_source_service()
        view = svc.configure(
            identity=identity,
            source_instance_id=sid,
            configuration=configuration,
        )
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_validate(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        view = svc.validate_connection(
            identity=identity,
            source_instance_id=sid,
        )
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_enable(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        view = svc.enable(identity=identity, source_instance_id=sid)
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_disable(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        view = svc.disable(identity=identity, source_instance_id=sid)
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_retire(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        view = svc.retire(identity=identity, source_instance_id=sid)
        return self._shape_ok({"source": self._view_to_dict(view)})

    def _handle_source_issue_token(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.SOURCE_WRITE)
        body = request.body or {}
        sid = body.get("source_instance_id")
        if not isinstance(sid, str) or not sid:
            raise InvalidProxyRequestError(
                safe_message="source_instance_id required",
                internal_detail="missing source_instance_id",
                field="source_instance_id",
            )
        svc = self._require_source_service()
        packed = svc.issue_ingress_token(
            identity=identity, source_instance_id=sid,
        )
        return self._shape_ok({
            "source_instance_id": sid,
            "source_token": packed,
        })

    # ============================================================
    # Phase 4.9 — Frontend-required operation handlers
    # ------------------------------------------------------------
    # These 25 handlers cover the 8 UI components required by the
    # Phase 4 frontend contract. Each is a documented STUB that
    # returns a safe 501 not-implemented envelope so a Phase 4
    # UI can surface "not yet implemented" without crashing.
    # The wiring map classifies these as MISSING; each will be
    # promoted to WIRED when the corresponding service is
    # attached.
    # ============================================================

    def _not_implemented_stub(
        self, op: str, detail: str,
    ) -> ProxyResponse:
        """Documented 501 envelope for STUB handlers.

        Used by the Phase 4.9 STUB handlers so the proxy
        does NOT raise an ``AttributeError`` (which would
        become a 500 ``internal error`` envelope) when a
        UI component calls one of the 25 new operations.
        """
        return ProxyResponse(
            status=501,
            body={
                "ok": False,
                "error": {
                    "code": "not_implemented",
                    "message": (
                        f"operation {op!r} is declared but not "
                        "implemented in the current backend slice"
                    ),
                    "internal_detail": detail,
                },
                "data": {"operation": op},
            },
        )

    # ----- detection / correlation / overview / timeline
    def _require_detection_service(self) -> DetectionReadService:
        svc = self._detection_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="detection service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _require_correlation_service(self) -> CorrelationReadService:
        svc = self._correlation_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="correlation service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _require_overview_service(self) -> OverviewReadService:
        svc = self._overview_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="overview service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _require_timeline_service(self) -> TimelineReadService:
        svc = self._timeline_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="timeline service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _require_rule_management_service(self) -> RuleManagementService:
        svc = self._rule_management_service
        if svc is None:
            raise InvalidProxyRequestError(
                safe_message="rule management service unavailable",
                internal_detail="proxy not wired",
            )
        return svc

    def _handle_event_list(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        """V2-06: analyst visibility for persisted SecurityEvents.

        A valid, trusted event that matched **no** rule was previously
        invisible to the analyst (persisted in Mongo but unreachable by
        any wire op or page). This bounded read surface returns the
        most recent events; with ``unmatched=true`` it returns only the
        events that produced no detection — the documented human-review
        obligation for unmatched-but-valid events. No severity or
        escalation is invented: unmatched events are surfaced as
        evidence for analyst review, which is what the specification
        requires of the MVP.
        """
        self._require(identity, Permission.EVENT_READ)
        repo = self._security_event_repository
        if repo is None:
            raise InvalidProxyRequestError(
                safe_message="event repository unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        limit = body.get("limit")
        unmatched = body.get("unmatched")
        source_instance_id = body.get("source_instance_id")
        bounded_limit = (
            limit if isinstance(limit, int) and 0 < limit <= 200 else 50
        )
        events = repo.find_recent(
            limit=bounded_limit,
            source_instance_id=(
                source_instance_id
                if isinstance(source_instance_id, str)
                and source_instance_id
                else None
            ),
        )
        matched_event_ids: set = set()
        if unmatched:
            if self._detection_service is not None:
                recent = self._detection_service.repository.find_latest(
                    limit=500,
                )
                matched_event_ids = {
                    d.event_id for d in recent if d.event_id
                }
            events = [e for e in events if e.event_id not in matched_event_ids]
        return self._shape_ok({
            "events": [
                {
                    "event_id": e.event_id,
                    "event_time": e.event_time.isoformat(),
                    "source": e.source,
                    "event_type": e.event_type,
                    "source_ip": e.source_ip,
                    "endpoint": e.endpoint,
                    "asset": e.asset,
                    "source_instance_id": (
                        getattr(e.provenance, "source_instance_id", None)
                        if e.provenance is not None
                        else None
                    ),
                }
                for e in events
            ],
            "count": len(events),
        })

    def _handle_detection_list(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.DETECTION_READ)
        svc = self._require_detection_service()
        body = request.body or {}
        rule_id = body.get("rule_id")
        event_id = body.get("event_id")
        limit = body.get("limit")
        detections = svc.list(
            rule_id=rule_id if isinstance(rule_id, str) else None,
            event_id=event_id if isinstance(event_id, str) else None,
            limit=limit if isinstance(limit, int) else None,
        )
        return self._shape_ok({
            "detections": [d.to_dict() for d in detections],
        })

    def _handle_detection_get(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.DETECTION_READ)
        svc = self._require_detection_service()
        body = request.body or {}
        did = body.get("detection_id")
        if not isinstance(did, str) or not did:
            raise InvalidProxyRequestError(
                safe_message="detection_id required",
                internal_detail="missing detection_id",
                field="detection_id",
            )
        d = svc.get(did)
        return self._shape_ok({"detection": d.to_dict()})

    def _handle_detection_list_for_incident(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.DETECTION_READ)
        svc = self._require_detection_service()
        body = request.body or {}
        iid = body.get("incident_id")
        if not isinstance(iid, str) or not iid:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=iid,
        )
        limit = body.get("limit")
        detections = svc.list_for_incident(
            incident_event_ids=tuple(case.evidence.event_ids),
            limit=limit if isinstance(limit, int) else None,
        )
        return self._shape_ok({
            "detections": [d.to_dict() for d in detections],
        })

    def _handle_correlation_list(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CORRELATION_READ)
        svc = self._require_correlation_service()
        body = request.body or {}
        pattern_id = body.get("pattern_id")
        since = body.get("since")
        until = body.get("until")
        limit = body.get("limit")
        rows = svc.list(
            pattern_id=pattern_id if isinstance(pattern_id, str) else None,
            since=self._coerce_iso(since, "since"),
            until=self._coerce_iso(until, "until"),
            limit=limit if isinstance(limit, int) else None,
        )
        return self._shape_ok({
            "correlations": [c.to_dict() for c in rows],
        })

    def _handle_correlation_get(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CORRELATION_READ)
        svc = self._require_correlation_service()
        body = request.body or {}
        cid = body.get("correlation_id")
        if not isinstance(cid, str) or not cid:
            raise InvalidProxyRequestError(
                safe_message="correlation_id required",
                internal_detail="missing correlation_id",
                field="correlation_id",
            )
        c = svc.get(cid)
        return self._shape_ok({"correlation": c.to_dict()})

    def _handle_correlation_list_for_incident(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.CORRELATION_READ)
        svc = self._require_correlation_service()
        body = request.body or {}
        iid = body.get("incident_id")
        if not isinstance(iid, str) or not iid:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=iid,
        )
        # Combine normal + centralized correlation ids.
        corr_ids = tuple(case.evidence.correlation_ids) + tuple(
            case.centralized_correlation_ids
        )
        limit = body.get("limit")
        rows = svc.list_for_incident(
            incident_correlation_ids=corr_ids,
            limit=limit if isinstance(limit, int) else None,
        )
        return self._shape_ok({
            "correlations": [c.to_dict() for c in rows],
        })

    def _handle_overview_summary(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.OVERVIEW_READ)
        svc = self._require_overview_service()
        summary = svc.summary(identity)
        return self._shape_ok(summary)

    def _handle_timeline_build_for_incident(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.TIMELINE_READ)
        svc = self._require_timeline_service()
        body = request.body or {}
        iid = body.get("incident_id")
        if not isinstance(iid, str) or not iid:
            raise InvalidProxyRequestError(
                safe_message="incident_id required",
                internal_detail="missing incident_id",
                field="incident_id",
            )
        if self._incident_service is None:
            raise InvalidProxyRequestError(
                safe_message="incident service unavailable",
                internal_detail="proxy not wired",
            )
        case = self._incident_service.get_case(
            identity=identity, incident_id=iid,
        )
        result = svc.build_for_incident(case=case)
        return self._shape_ok(result.to_dict())

    # ----- rule management (Phase 4.9 frontend)
    def _handle_rule_list(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_READ)
        svc = self._require_rule_management_service()
        body = request.body or {}
        # The wire contract documents a simple ``rule.list`` with
        # no required filter; the service exposes both
        # ``list_all`` and ``list_latest``. By default we return
        # the latest version of every rule (analyst-friendly).
        latest_only = bool(body.get("latest_only", True))
        if latest_only:
            rules = svc.list_latest()
        else:
            rules = svc.list_all()
        return self._shape_ok({
            "rules": [r.to_canonical_dict() for r in rules],
        })

    def _handle_rule_get(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_READ)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        version = body.get("version")
        if version is not None and not isinstance(version, int):
            raise InvalidProxyRequestError(
                safe_message="invalid version",
                internal_detail=(
                    f"version must be int, got {type(version).__name__}"
                ),
                field="version",
            )
        rule = svc.get(
            rid,
            version=version if isinstance(version, int) else None,
        )
        if rule is None:
            raise NotFoundError(
                safe_message="rule not found",
                internal_detail=(
                    f"rule_id={rid!r} version={version!r}"
                ),
            )
        return self._shape_ok({"rule": rule.to_canonical_dict()})

    def _handle_rule_create(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        if not isinstance(body, dict):
            raise InvalidProxyRequestError(
                safe_message="invalid body",
                internal_detail="body must be an object",
                field="body",
            )
        payload = dict(body)
        if "rule_id" not in payload:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id in payload",
                field="rule_id",
            )
        definition = svc.create(payload)
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_rule_update(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        version = body.get("version")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        if not isinstance(version, int):
            raise InvalidProxyRequestError(
                safe_message="version required",
                internal_detail=(
                    f"version must be int, got {type(version).__name__}"
                ),
                field="version",
            )
        payload = {
            k: v for k, v in body.items()
            if k not in ("rule_id", "version")
        }
        definition = svc.update(rid, version, payload)
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_rule_version(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        payload = {
            k: v for k, v in body.items() if k != "rule_id"
        }
        definition = svc.create_new_version(rid, payload)
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_rule_enable(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        version = body.get("version")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        definition = svc.set_enabled(
            rid, True,
            version=version if isinstance(version, int) else None,
        )
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_rule_disable(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        version = body.get("version")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        definition = svc.set_enabled(
            rid, False,
            version=version if isinstance(version, int) else None,
        )
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_rule_retire(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        self._require(identity, Permission.RULE_WRITE)
        svc = self._require_rule_management_service()
        body = request.body or {}
        rid = body.get("rule_id")
        version = body.get("version")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="rule_id required",
                internal_detail="missing rule_id",
                field="rule_id",
            )
        definition = svc.set_state(
            rid, "retired",
            version=version if isinstance(version, int) else None,
        )
        return self._shape_ok({"rule": definition.to_canonical_dict()})

    def _handle_report_export(
        self, request: ProxyRequest, identity: Identity
    ) -> ProxyResponse:
        """``report.export`` Phase 4.10.

        The wire contract documents a JSON-serialised export
        built from the report payload returned by ``report.get``.
        We do NOT implement a binary PDF / CSV / text encoder
        here (the contract documents the JSON format and notes
        that the frontend can serialize other formats
        client-side). Future slices can add binary export via
        a ``ReportExporter`` service; the security boundary is
        unaffected because the report payload already
        redacts secrets.
        """
        self._require(identity, Permission.REPORT_READ)
        if self._report_service is None:
            raise InvalidProxyRequestError(
                safe_message="report service unavailable",
                internal_detail="proxy not wired",
            )
        body = request.body or {}
        rid = body.get("report_id")
        fmt = body.get("format", "json")
        if not isinstance(rid, str) or not rid:
            raise InvalidProxyRequestError(
                safe_message="report_id required",
                internal_detail="missing report_id",
                field="report_id",
            )
        if not isinstance(fmt, str) or fmt != "json":
            raise InvalidProxyRequestError(
                safe_message=(
                    "unsupported export format; only 'json' is "
                    "supported in Phase 4.10"
                ),
                internal_detail=f"format={fmt!r}",
                field="format",
            )
        report: Report = self._report_service.get_report(
            identity=identity, report_id=rid,
        )
        return self._shape_ok({
            "report_id": report.report_id,
            "format": fmt,
            "payload": report.to_dict(),
        })


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


def _normalize_tags(value: Any) -> Tuple[str, ...]:
    """Normalize arbitrary client tag input to a sorted-unique tuple.

    STRIX F-5 / N-3: the source model requires unique, sorted tags. A
    client may send them in any order (or with duplicates); normalizing
    at the wire boundary keeps the model authoritative while removing a
    spurious 401-vs-400 classification. Non-string, empty members are
    dropped; bounds are enforced by the model itself.
    """
    if not isinstance(value, (list, tuple)):
        return ()
    seen: set = set()
    out: List[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return tuple(sorted(out))


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
    "OP_EVENT_LIST",
    "OP_ROUTE_CASE",
    "OP_SOURCE_CONFIGURE",
    "OP_SOURCE_DISABLE",
    "OP_SOURCE_ENABLE",
    "OP_SOURCE_GET",
    "OP_SOURCE_ISSUE_TOKEN",
    "OP_SOURCE_LIST",
    "OP_SOURCE_LIST_TYPES",
    "OP_SOURCE_REGISTER",
    "OP_SOURCE_RETIRE",
    "OP_SOURCE_VALIDATE",
    "PROXY_HEADER_AUTHORIZATION",
    "PROXY_HEADER_SESSION",
    "ProxyRequest",
    "ProxyResponse",
    "SecureProxy",
]