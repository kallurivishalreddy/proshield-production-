"""First production rule for the NGINX connector.

The rule is intentionally small and conservative. It detects a
well-known NGINX-observable pattern: an HTTP 401 (``Unauthorized``)
or 403 (``Forbidden``) response on an authentication-shaped
endpoint. These observations correspond to failed authentication
attempts and authorization denials; they are the building blocks
of brute-force and credential-stuffing attacks.

Why this rule is the right first rule
------------------------------------

1. It is **source-specific**: the rule's applicability is
   ``(source=nginx, event_type in (authentication_failure,
   request_blocked))``. The NGINX connector emits both of
   these event types for HTTP 401/403 respectively, so the
   rule's applicability filter is the documented fast path
   (DET-04).
2. It is **observation-only on the input side**. The
   connector's mapping already produced a canonical
   ``authentication_failure`` for 401s and ``request_blocked``
   for 403s; the rule simply looks for the 401/403 status
   code in the canonical event's structured ``details`` and
   the ``authentication_*`` path hint.
3. It is **deterministic**: a single canonical event either
   matches (status 401/403 on an auth-shaped endpoint) or
   does not. No thresholds, no windows, no state.
4. It is **NOT** a brute-force detection. A brute-force rule
   needs a time window and a count of failures, both of
   which are out of scope for this slice (the correlation
   engine is not yet implemented). The rule fires on each
   individual authentication failure, so a downstream
   correlation rule can later count rule firings. The
   decision to scope this rule to "single 401/403 on an
   auth-shaped endpoint" is documented and intentional.

What the rule does NOT do
-------------------------

* It does NOT count failures over a window (correlation).
* It does NOT enrich the detection with prior context
  (timeline).
* It does NOT assign severity or confidence (the severity
  and confidence engines are not yet implemented).
* It does NOT decide incident ownership or routing.

Those are the documented responsibilities of later slices.
This rule is the *smallest defensible* first rule.
"""
from __future__ import annotations

from typing import Tuple

from ....domain.security_event import SecurityEvent
from ....detection.redact import redact_endpoint
from ...rule import SimpleRule
from ...types import RuleCategory, RuleMetadata, RuleState


_RULE_ID = "NGINX-AUTH-BRUTEFORCE-001"
_AUTH_PATH_HINTS: Tuple[str, ...] = (
    "/login", "/signin", "/auth", "/oauth", "/sso",
    "/token", "/session", "/password", "/mfa", "/2fa",
    "/authenticate", "/verify",
)
_AUTH_PATH_LOWER = tuple(s.lower() for s in _AUTH_PATH_HINTS)


def _predicate(event: SecurityEvent) -> bool:
    """True when the event is a 401 or 403 on an auth-shaped endpoint.

    The connector already maps:
        HTTP 401 -> authentication_failure
        HTTP 403 -> request_blocked

    and stores the HTTP status in ``details["status_code"]``.
    The path hint is matched case-insensitively as a
    substring so real endpoints (e.g. ``/api/v1/auth/login``)
    are recognised without a glob.
    """
    if event.source != "nginx":
        return False
    if event.event_type not in ("authentication_failure", "request_blocked"):
        return False
    status = event.details.get("status_code")
    if status not in (401, 403):
        return False
    if event.endpoint is None:
        return False
    ep = event.endpoint.lower()
    return any(hint in ep for hint in _AUTH_PATH_LOWER)


def _reasoner(event: SecurityEvent) -> str:
    """Build a short, analyst-friendly reasoning string.

    The ``endpoint`` is passed through :func:`redact_endpoint` so
    any query string (e.g. ``?token=...``, ``?code=...`` on
    OAuth callbacks), fragment, or oversized path is stripped
    before being put into the persisted ``Detection.reasoning``
    field. The canonical event is unchanged; only the analyst-
    facing string is redacted. See ``app/detection/redact.py``
    and the Phase 4.4 review (defect D-1).
    """
    status = event.details.get("status_code")
    return (
        f"nginx HTTP {status} on auth-shaped endpoint "
        f"{redact_endpoint(event.endpoint)!r} from {event.source_ip!r}"
    )


def _make_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id=_RULE_ID,
        version=1,
        name="NGINX 401/403 on auth endpoint",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("authentication_failure", "request_blocked"),
        # Phase 5.2: capability ownership (see NGINX-AUTH-FAILURE-001).
        capability_id="cap-nginx",
        state=RuleState.APPROVED,
        enabled=True,
        description=(
            "Detects HTTP 401 (Unauthorized) and 403 (Forbidden) "
            "responses on authentication-shaped NGINX endpoints. "
            "Each individual observation fires the rule; a future "
            "correlation rule can count firings into a brute-force "
            "or credential-stuffing detection."
        ),
        tags=("AUTH", "BRUTEFORCE-CANDIDATE", "NGINX"),
        references=(
            "docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories",
        ),
    )


def build_nginx_auth_brute_force_rule() -> SimpleRule:
    """Factory: build a fresh rule instance.

    The factory pattern (over a class-level singleton) keeps
    the rule's mutable instance attributes (e.g. ``enabled``)
    isolated from other tests' instances and from the rule
    loader's per-process state.
    """
    return SimpleRule(_make_metadata(), _predicate, _reasoner)
