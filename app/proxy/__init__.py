"""ProShield secure application proxy / gateway (Phase 4.8).

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md,
docs/PHASE 3/SECURE_FOUNDATION.md (Section 55 Production-MVP
Security Boundary), docs/PHASE 3/SECURITY_CONFIGING.md,
docs/PHASE 2/API_CONTRACTS.md.

The proxy is the **only client-facing integration
boundary** for the ProShield backend. It is the
security boundary, not merely a convenience router.

The slice ships a request/response abstraction over a
single :class:`SecureProxy` that:

* validates every inbound request (request size,
  required headers, presence of the session token),
* delegates session verification to the
  :class:`SessionVerifier`,
* delegates authorization to the per-operation
  permission checks,
* invokes the relevant backend service (incident /
  report / routing / centralized-analysis),
* shapes responses so internal secrets and stack traces
  never reach the client,
* applies a per-subject rate limit so a malicious
  client cannot flood the backend,
* keeps a per-subject centralized-analysis budget so
  expensive correlation runs cannot be triggered without
  authorization + rate control.

The proxy never directly imports
:mod:`app.persistence` (the persistence layer remains
behind the orchestrators / repositories it depends on)
and never exposes internal MongoDB or collector
endpoints to the client.

What this package does NOT do
----------------------------

* It does NOT introduce a parallel IAM system. It
  reuses the Phase 4.8 :mod:`app.auth` foundation so a
  future IAM replacement only has to swap the
  :class:`SessionVerifier` and the identity store.
* It does NOT route HTTP traffic itself. The slice
  ships an in-process request/response API so the
  perimeter can be unit-tested; production wiring is
  the deployment team's choice (FastAPI / WSGI / gRPC
  / etc.).
* It does NOT trust client-supplied identity. Every
  operation re-derives the :class:`Identity` from the
  verified session token server-side.
"""
from __future__ import annotations

from .errors import (
    InvalidProxyRequestError,
    ProxyError,
    ProxyRateLimitedError,
    ProxyUnauthorizedError,
)
from .proxy import (
    ALLOWED_OPERATIONS,
    MAX_PROXY_REQUEST_BYTES,
    OP_AUTH_ISSUE,
    OP_CLOSE_CASE,
    OP_CORRELATION_GET,
    OP_CORRELATION_LIST,
    OP_CORRELATION_LIST_FOR_INCIDENT,
    OP_CREATE_CASE,
    OP_DETECTION_GET,
    OP_DETECTION_LIST,
    OP_DETECTION_LIST_FOR_INCIDENT,
    OP_GENERATE_CENTRALIZED_REPORT,
    OP_GENERATE_NORMAL_REPORT,
    OP_GET_CASE,
    OP_GET_REPORT,
    OP_HEALTH,
    OP_LIST_CASES,
    OP_LIST_REPORTS,
    OP_OVERVIEW_SUMMARY,
    OP_REPORT_EXPORT,
    OP_REQUEST_CENTRALIZED,
    OP_ROUTE_CASE,
    OP_RULE_CREATE,
    OP_RULE_DISABLE,
    OP_RULE_ENABLE,
    OP_RULE_GET,
    OP_RULE_LIST,
    OP_RULE_RETIRE,
    OP_RULE_UPDATE,
    OP_RULE_VERSION,
    OP_SOURCE_CONFIGURE,
    OP_SOURCE_DISABLE,
    OP_SOURCE_ENABLE,
    OP_SOURCE_GET,
    OP_SOURCE_ISSUE_TOKEN,
    OP_SOURCE_BIND_CAPABILITY,
    OP_SOURCE_ROTATE_TOKEN,
    OP_SOURCE_AUDIT,
    OP_SOURCE_MIGRATION_STATUS,
    OP_SOURCE_MIGRATE,
    OP_SOURCE_LIST,
    OP_SOURCE_LIST_TYPES,
    OP_SOURCE_REGISTER,
    OP_SOURCE_RETIRE,
    OP_SOURCE_VALIDATE,
    OP_TIMELINE_BUILD_FOR_INCIDENT,
    OP_CASE_ACKNOWLEDGE,
    OP_CASE_INVESTIGATE,
    OP_CASE_ADD_NOTE,
    OP_CASE_CREATE_FROM_CORRELATION,
    OP_CORRELATION_LIST_PATTERNS,
    OP_SYSTEM_HEALTH_DEEP,
    OP_NOTIFICATION_LIST,
    OP_NOTIFICATION_MARK_READ,
    OP_NOTIFICATION_UNREAD_COUNT,
    OP_TIMELINE_GLOBAL_QUERY,
    OP_OVERVIEW_TIMESERIES,
    OP_CAPABILITY_LIST,
    OP_CAPABILITY_GET,
    OP_CAPABILITY_CREATE,
    OP_CAPABILITY_UPDATE,
    OP_CAPABILITY_ENABLE,
    OP_CAPABILITY_DISABLE,
    OP_CAPABILITY_DEPRECATE,
    OP_CAPABILITY_RETIRE,
    OP_CAPABILITY_ARCHIVE,
    OP_CAPABILITY_LIST_SOURCES,
    OP_CAPABILITY_LIST_RULES,
    OP_CAPABILITY_LIST_PATTERNS,
    OP_CAPABILITY_AUDIT,
    PROXY_HEADER_AUTHORIZATION,
    PROXY_HEADER_SESSION,
    ProxyRequest,
    ProxyResponse,
    SecureProxy,
)

__all__ = [
    "ALLOWED_OPERATIONS",
    "InvalidProxyRequestError",
    "MAX_PROXY_REQUEST_BYTES",
    "OP_AUTH_ISSUE",
    "OP_CLOSE_CASE",
    "OP_CORRELATION_GET",
    "OP_CORRELATION_LIST",
    "OP_CORRELATION_LIST_FOR_INCIDENT",
    "OP_CREATE_CASE",
    "OP_DETECTION_GET",
    "OP_DETECTION_LIST",
    "OP_DETECTION_LIST_FOR_INCIDENT",
    "OP_GENERATE_CENTRALIZED_REPORT",
    "OP_GENERATE_NORMAL_REPORT",
    "OP_GET_CASE",
    "OP_GET_REPORT",
    "OP_HEALTH",
    "OP_LIST_CASES",
    "OP_LIST_REPORTS",
    "OP_OVERVIEW_SUMMARY",
    "OP_REPORT_EXPORT",
    "OP_REQUEST_CENTRALIZED",
    "OP_ROUTE_CASE",
    "OP_RULE_CREATE",
    "OP_RULE_DISABLE",
    "OP_RULE_ENABLE",
    "OP_RULE_GET",
    "OP_RULE_LIST",
    "OP_RULE_RETIRE",
    "OP_RULE_UPDATE",
    "OP_RULE_VERSION",
    "OP_SOURCE_CONFIGURE",
    "OP_SOURCE_DISABLE",
    "OP_SOURCE_ENABLE",
    "OP_SOURCE_GET",
    "OP_SOURCE_ISSUE_TOKEN",
    "OP_SOURCE_BIND_CAPABILITY",
    "OP_SOURCE_ROTATE_TOKEN",
    "OP_SOURCE_AUDIT",
    "OP_SOURCE_MIGRATION_STATUS",
    "OP_SOURCE_MIGRATE",
    "OP_SOURCE_LIST",
    "OP_SOURCE_LIST_TYPES",
    "OP_SOURCE_REGISTER",
    "OP_SOURCE_RETIRE",
    "OP_SOURCE_VALIDATE",
    "OP_CAPABILITY_LIST",
    "OP_CAPABILITY_GET",
    "OP_CAPABILITY_CREATE",
    "OP_CAPABILITY_UPDATE",
    "OP_CAPABILITY_ENABLE",
    "OP_CAPABILITY_DISABLE",
    "OP_CAPABILITY_DEPRECATE",
    "OP_CAPABILITY_RETIRE",
    "OP_CAPABILITY_ARCHIVE",
    "OP_CAPABILITY_LIST_SOURCES",
    "OP_CAPABILITY_LIST_RULES",
    "OP_CAPABILITY_LIST_PATTERNS",
    "OP_CAPABILITY_AUDIT",
    "OP_TIMELINE_BUILD_FOR_INCIDENT",
    "PROXY_HEADER_AUTHORIZATION",
    "PROXY_HEADER_SESSION",
    "ProxyError",
    "ProxyRateLimitedError",
    "ProxyRequest",
    "ProxyResponse",
    "ProxyUnauthorizedError",
    "SecureProxy",
]