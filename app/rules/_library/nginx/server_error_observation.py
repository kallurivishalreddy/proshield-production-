"""Per-event rule: NGINX 5xx server-error observation.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 13, 18, 23, 28, 32, 49, 59, 87-91)

This is the **per-event** detection for the NGINX-observable pattern
of an HTTP 5xx (server-side error) response. The NGINX connector
maps 5xx to ``request_blocked`` (see
``app/connectors/nginx/mapping.py``), so the rule distinguishes
itself from ``NGINX-ACCESS-DENIED-001`` by checking the status
code.

Observable pattern
------------------

A 5xx response from the application / upstream is a candidate
signal for:

* forced-error probing (an attacker intentionally triggering
  unhandled exceptions to map internal state)
* resource exhaustion / DoS
* upstream failure (which may itself be a security-relevant event
  such as a WAF back-end going down or a dependency compromise)
* auth-state corruption (a session store that returns 5xx is a
  security-relevant failure even if the 5xx is unintentional)

The per-event rule fires on every 5xx observation. Whether the
event joins a "service degradation" or "scanner" incident is a
correlation decision (out of scope for Phase 4.4).

Why this is NOT the only rule for 5xx
-------------------------------------

* A single, isolated 5xx is often a benign application bug.
* A burst of 5xx from one IP is a candidate "forced-error scan"
  signal (correlation).
* A burst of 5xx from many IPs is a candidate "service degradation"
  signal (correlation).
* A 5xx on an auth-shaped endpoint is a candidate "auth-store
  failure" signal (correlation).

All of the above are correlation / context-dependent. The
per-event rule is intentionally the minimum: an observation that
the source recorded a 5xx.

What the rule does NOT do
-------------------------

* It does NOT count 5xx over a window.
* It does NOT distinguish between upstream failure and client
  error. The 5xx status is the only signal it uses.
* It does NOT cover 4xx (handled by other rules).
* It does NOT cover 429 (handled by ``NGINX-RATE-LIMIT-001``).
"""
from __future__ import annotations

from typing import FrozenSet

from ....domain.security_event import SecurityEvent
from ....detection.redact import redact_endpoint
from ...rule import SimpleRule
from ...types import RuleCategory, RuleMetadata, RuleState


_RULE_ID = "NGINX-STATUS-ANOMALY-001"

# The 5xx statuses the connector maps to ``request_blocked``.
# (See app/connectors/nginx/mapping.py ``_STATUS_MAP``.)
_5XX_STATUSES: FrozenSet[int] = frozenset({500, 501, 502, 503, 504})


def _predicate(event: SecurityEvent) -> bool:
    """True iff the event is a NGINX-observed 5xx response."""
    if event.source != "nginx":
        return False
    if event.event_type != "request_blocked":
        return False
    status = event.details.get("status_code")
    return status in _5XX_STATUSES


def _reasoner(event: SecurityEvent) -> str:
    """Build the analyst-facing reasoning string.

    The ``endpoint`` is passed through :func:`redact_endpoint` so
    any query string, fragment, or oversized path is stripped
    before being put into the persisted ``Detection.reasoning``
    field. The canonical event is unchanged; only the analyst-
    facing string is redacted. See ``app/detection/redact.py``
    and the Phase 4.4 review (defect D-1).
    """
    status = event.details.get("status_code")
    return (
        f"nginx HTTP {status} server error on "
        f"{redact_endpoint(event.endpoint)!r} "
        f"from {event.source_ip!r}"
    )


def _make_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id=_RULE_ID,
        version=1,
        name="NGINX 5xx server-error observation",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("request_blocked",),
        state=RuleState.APPROVED,
        enabled=True,
        description=(
            "Per-event detection: each NGINX-observed HTTP 5xx is a "
            "candidate signal for forced-error probing, upstream "
            "failure, resource exhaustion, or auth-state corruption. "
            "Correlation rules are responsible for counting and "
            "grouping; this rule is intentionally the minimum "
            "observation."
        ),
        tags=("ANOMALY", "HTTP-5XX", "NGINX", "PER-EVENT", "SERVER-ERROR"),
        references=(
            "docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories",
        ),
    )


def build_nginx_server_error_observation_rule() -> SimpleRule:
    """Factory: build a fresh rule instance."""
    return SimpleRule(_make_metadata(), _predicate, _reasoner)
