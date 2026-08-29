"""Map a parsed NGINX log line to a canonical SecurityEvent.

This module is the only place in the codebase that decides
"NGINX status 401 means a canonical ``authentication_failure``
event", "NGINX status 403 means ``request_blocked``", etc. The
connector calls it for every successfully parsed line.

Design contract
---------------

The mapping is **observation-only**. A canonical SecurityEvent
records *what the source observed*; it does NOT record a
detection conclusion. Mapping rules therefore look like:

    observation --> canonical event_type

not like:

    observation --> "is this an attack?" --> detection

"Brute-force" / "credential stuffing" / "scanner" are
*detections*, not *observations*, and they live in the rule
layer (``app/rules/_library/nginx/``), not here.

The mapping for the NGINX ``combined`` log:

* HTTP 200/201/204 on an auth-shaped endpoint with a known
  ``remote_user`` --> ``authentication_success``.
* HTTP 401 on any endpoint --> ``authentication_failure``.
* HTTP 403 on any endpoint --> ``request_blocked``.
* HTTP 429 --> ``rate_limit_exceeded`` (the documented NGINX
  ``limit_req`` / ``limit_conn`` status code).
* HTTP 5xx --> ``request_blocked`` (server-side error: a
  security control that returns 5xx is a security-relevant
  block, not a successful request).
* HTTP 4xx (other than 401, 403, 429) --> ``request_blocked``.
* HTTP 1xx --> ``None`` (informational, not security-relevant).
* HTTP 2xx/3xx that is NOT an auth-success --> ``None`` (the
  rule layer is the right place to draw conclusions from
  normal-traffic patterns; the connector does not pre-judge).

So the mapping is a partial function from observation to
canonical event_type. ``None`` means "no security-relevant
event for this line". The connector NEVER silently drops lines
that DO carry a security signal; a returned ``None`` is a
documented contract decision, not a per-line failure.
"""
from __future__ import annotations

import re
from typing import Optional

from ...domain.security_event import (
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventProvenance,
)
from .parser import ParsedNginxLine


# ------------------------------------------------------------------ vocabulary
# HTTP status --> canonical event_type (or None for "do not emit").
# The mapping is documented inline so future audits can verify it
# against the canonical SecurityEvent catalogue
# (docs/PHASE 0/INITIAL_SECURITY_EVENTS.md, Section 17).
_STATUS_MAP: dict = {
    401: "authentication_failure",
    403: "request_blocked",
    404: "request_blocked",
    405: "request_blocked",
    408: "request_blocked",
    409: "request_blocked",
    410: "request_blocked",
    412: "request_blocked",
    413: "request_blocked",
    415: "request_blocked",
    418: "request_blocked",
    422: "request_blocked",
    429: "rate_limit_exceeded",
    500: "request_blocked",
    501: "request_blocked",
    502: "request_blocked",
    503: "request_blocked",
    504: "request_blocked",
}

# Endpoints that strongly imply an authentication interaction.
# Matched case-insensitively against the path; substring-based
# because real endpoints embed the auth segment at any depth.
_AUTH_PATH_HINTS = (
    "/login", "/signin", "/auth", "/oauth", "/sso",
    "/token", "/session", "/password", "/mfa", "/2fa",
    "/authenticate", "/verify",
)
_AUTH_PATH_RE = re.compile(
    "|".join(re.escape(s) for s in _AUTH_PATH_HINTS),
    re.IGNORECASE,
)


def _is_auth_path(path: str) -> bool:
    return bool(_AUTH_PATH_RE.search(path))


# ------------------------------------------------------------------ public
def map_parsed_record_to_event(
    record: ParsedNginxLine,
    *,
    line_number: int,
    source_event_id: str,
    event_id: str,
    asset: Optional[str] = None,
) -> Optional[SecurityEvent]:
    """Map one parsed NGINX log line to a canonical SecurityEvent.

    Parameters
    ----------
    record:
        The structured record produced by
        :func:`app.connectors.nginx.parser.parse_combined_line`.
    line_number:
        The 1-based line number in the source log. Stored in the
        ``details`` subdocument for traceability, but never used
        as the sole ``source_event_id`` (a line number alone is
        not unique across log rotations).
    source_event_id:
        A deterministic, unique per-line identifier. The
        connector constructs this as a stable hash of (log path,
        line number, line content) so identical re-deliveries of
        the same line produce the same id (and therefore
        idempotently hit the documented Boundary 2 dedup path).
    event_id:
        A deterministic UUIDv7-formatted per-line identifier.
        The connector derives this from a hash of the same
        inputs as ``source_event_id`` (so two reads of the
        same line produce the same event_id). This is the
        field that the repository's ``insert_one`` dedup
        path keys on, so determinism here is what makes
        re-ingestion a no-op.
    asset:
        Optional asset label to attach to the canonical event
        (e.g. ``web-api-01``). If not supplied the canonical
        event simply omits the field.

    Returns
    -------
    Optional[SecurityEvent]
        A canonical SecurityEvent ready to hand to the
        ingestion service, or ``None`` when the line carries no
        security-relevant signal (informational 1xx, normal 2xx
        GET on a public endpoint). The connector skips lines
        for which the mapping returns ``None``.
    """
    # Decide the canonical event_type. 1xx is informational.
    if 100 <= record.status < 200:
        return None
    # 2xx/3xx: only emit if the request authenticated an
    # auth-shaped endpoint with a known remote_user.
    if 200 <= record.status < 400:
        if (
            200 <= record.status < 300
            and record.remote_user is not None
            and _is_auth_path(record.path)
        ):
            event_type = "authentication_success"
        else:
            return None
    else:
        event_type = _STATUS_MAP.get(record.status, "request_blocked")

    # Compose the canonical account (never the password: the
    # combined log does not carry it; the field is bounded by
    # the canonical SecurityEvent).
    account: Optional[SecurityEventAccount] = None
    if record.remote_user:
        account = SecurityEventAccount(id=record.remote_user)

    # Compose the structured ``details`` subdocument. We carry
    # the documented observable fields; we do NOT carry the
    # response body or the request body (the combined log does
    # not include them, and the canonical model forbids them).
    details: dict = {
        "http_method": record.method,
        "status_code": record.status,
        "protocol": record.protocol,
        "body_bytes_sent": record.body_bytes_sent,
    }
    if record.referer is not None:
        details["referer"] = record.referer
    if record.user_agent is not None:
        details["user_agent"] = record.user_agent
    # Line number is a useful breadcrumb for analysts. Bounded
    # and does not leak the line content.
    details["log_line_number"] = line_number

    # The connector does NOT set ``ingested_at``: the
    # ingestion service stamps it server-side. The
    # SecurityEvent model requires it, so we set it to the
    # event_time; the service overwrites. (Same pattern as
    # the Phase 4.1 SimulatedConnector.)
    return SecurityEvent(
        event_id=event_id,
        event_time=record.event_time,
        ingested_at=record.event_time,
        source="nginx",
        event_type=event_type,
        source_ip=record.remote_addr,
        destination=asset,
        endpoint=record.path,
        asset=asset,
        account=account,
        details=details,
        provenance=SecurityEventProvenance(
            collector="nginx",
            source_event_id=source_event_id,
        ),
    )
