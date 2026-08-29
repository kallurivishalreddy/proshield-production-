"""Per-event rule: NGINX rate-limit-exceeded observation.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 13, 18, 23, 28, 32, 49, 59, 87-91)

This is the **per-event** detection for the NGINX-observable pattern
of an HTTP 429 (``Too Many Requests``) response. The NGINX
connector maps 429 to the canonical
``rate_limit_exceeded`` event type (see
``app/connectors/nginx/mapping.py``), so the rule fires on every
such event.

Observable pattern
------------------

A 429 response is the documented "you are exceeding the
documented rate limit" signal. It is a candidate signal for:

* abusive scraper / loader
* brute-force tool
* runaway retry storm (often a benign client bug, sometimes a
  misconfigured legitimate integration, occasionally an attacker)
* credential-stuffing / carding bot
* API quota exhaustion (legitimate, but security-relevant)

A single 429 is a low-quality signal on its own (a legitimate
client's retry loop will produce a 429). The detection is a
**candidate signal** at the per-event layer; correlation is
responsible for joining a 429 burst with a brute-force
classification or with an "abusive client" incident.

What the rule does NOT do
-------------------------

* It does NOT count 429s over a window.
* It does NOT distinguish between benign retry and malicious
  loader. That is a correlation decision.
* It does NOT cover 4xx (handled by other rules).
* It does NOT cover 5xx (handled by ``NGINX-STATUS-ANOMALY-001``).
* It does NOT cover 401 (handled by ``NGINX-AUTH-FAILURE-001``).
"""
from __future__ import annotations

from ....domain.security_event import SecurityEvent
from ....detection.redact import redact_endpoint
from ...rule import SimpleRule
from ...types import RuleCategory, RuleMetadata, RuleState


_RULE_ID = "NGINX-RATE-LIMIT-001"


def _predicate(event: SecurityEvent) -> bool:
    """True iff the event is a NGINX-observed rate-limit-exceeded."""
    if event.source != "nginx":
        return False
    if event.event_type != "rate_limit_exceeded":
        return False
    # Defense in depth: confirm the status code in case a future
    # connector / manual test event misuses the event_type.
    if event.details.get("status_code") != 429:
        return False
    return True


def _reasoner(event: SecurityEvent) -> str:
    """Build the analyst-facing reasoning string.

    The ``endpoint`` is passed through :func:`redact_endpoint` so
    any query string, fragment, or oversized path is stripped
    before being put into the persisted ``Detection.reasoning``
    field. The canonical event is unchanged; only the analyst-
    facing string is redacted. See ``app/detection/redact.py``
    and the Phase 4.4 review (defect D-1).
    """
    return (
        f"nginx HTTP 429 rate_limit_exceeded on "
        f"{redact_endpoint(event.endpoint)!r} "
        f"from {event.source_ip!r}"
    )


def _make_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id=_RULE_ID,
        version=1,
        name="NGINX rate-limit-exceeded (429)",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("rate_limit_exceeded",),
        state=RuleState.APPROVED,
        enabled=True,
        description=(
            "Per-event detection: each NGINX-observed HTTP 429 is a "
            "candidate rate-limit-exceeded signal. Correlation rules "
            "are responsible for counting and grouping into "
            "brute-force, scraper, or runaway-retry detections."
        ),
        tags=("ABUSE-CANDIDATE", "HTTP-429", "NGINX", "PER-EVENT", "RATE-LIMIT"),
        references=(
            "docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories",
        ),
    )


def build_nginx_rate_limit_observation_rule() -> SimpleRule:
    """Factory: build a fresh rule instance."""
    return SimpleRule(_make_metadata(), _predicate, _reasoner)
