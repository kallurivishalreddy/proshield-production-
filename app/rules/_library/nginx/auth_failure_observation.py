"""Per-event rule: NGINX single authentication failure observation.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 13, 18, 23, 28, 32, 49, 59, 87-91)

This is the **per-event** detection for the well-known NGINX-observable
pattern: a single HTTP 401 (Unauthorized) response from the NGINX
connector. Each individual observation fires the rule; a future
correlation rule (out of scope for Phase 4.4) can count firings into a
brute-force or credential-stuffing detection.

Why this is the right per-event rule
------------------------------------

1. **Source-specific.** Applicability is ``(source=nginx,
   event_type=authentication_failure)``. The NGINX connector emits
   ``authentication_failure`` for HTTP 401 (see
   ``app/connectors/nginx/mapping.py``), so the rule's applicability
   filter is the documented fast path (DET-04).
2. **Observation-only on the input side.** A 401 is one
   *observation*; whether it joins a brute-force incident is a
   correlation decision (not Phase 4.4).
3. **Deterministic.** A single canonical event either matches
   (nginx + authentication_failure) or does not. No thresholds, no
   windows, no state.

Why this is NOT the only rule for this attack class
---------------------------------------------------

The single-401 detection by itself is low signal: an honest user
typoing their password produces the same event. The detection is a
**candidate signal** in the per-event layer. Deciding whether the
candidate is part of a brute-force attack is a correlation problem
(see DETECTION_ENGINEERING Section 18: "1 Attack != 1 Rule"; one
attack behaviour may produce multiple observable patterns, and
counting repeated failures over a window is correlation). The
correlation engine, the incident engine, the routing engine, and
the analyst are responsible for promoting candidates into
investigation cases.

What the rule does NOT do
-------------------------

* It does NOT count failures over a window.
* It does NOT enrich the detection with prior context.
* It does NOT assign severity or confidence.
* It does NOT decide incident ownership or routing.
* It does NOT require the ``endpoint`` to be auth-shaped. The
  decision to restrict to auth-shaped endpoints is a higher-quality
  signal but a *narrower* rule; the broad per-event observation
  belongs here, and the auth-shaped scoping belongs in the
  existing ``NGINX-AUTH-BRUTEFORCE-001`` (Phase 4.3) and in the
  future correlation rule.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from ....domain.security_event import SecurityEvent
from ....detection.redact import redact_endpoint
from ...rule import SimpleRule
from ...types import RuleCategory, RuleMetadata, RuleState


_RULE_ID = "NGINX-AUTH-FAILURE-001"


def _predicate(event: SecurityEvent) -> bool:
    """True iff the event is a NGINX-observed authentication failure.

    The connector maps HTTP 401 -> ``authentication_failure`` and
    stores the HTTP status in ``details["status_code"]``. We
    double-check the status as defense in depth so a future
    connector (or a manual test event) that uses the event_type
    but the wrong status code does not fire the rule.
    """
    if event.source != "nginx":
        return False
    if event.event_type != "authentication_failure":
        return False
    if event.details.get("status_code") != 401:
        return False
    return True


def _reasoner(event: SecurityEvent) -> str:
    """Short, analyst-friendly reasoning string.

    The ``endpoint`` is passed through :func:`redact_endpoint` so
    any query string, fragment, or oversized path is stripped
    before being put into the persisted ``Detection.reasoning``
    field. The canonical event is unchanged; only the analyst-
    facing string is redacted. See ``app/detection/redact.py``
    and the Phase 4.4 review (defect D-1).
    """
    return (
        f"nginx HTTP 401 authentication_failure on "
        f"{redact_endpoint(event.endpoint)!r} "
        f"from {event.source_ip!r}"
    )


def _make_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id=_RULE_ID,
        version=1,
        name="NGINX single authentication failure (401)",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("authentication_failure",),
        # Phase 5.2: capability ownership. This rule IS the NGINX
        # capability's detection logic, so it declares its owner rather
        # than relying on the legacy ``sources[]`` string match.
        capability_id="cap-nginx",
        state=RuleState.APPROVED,
        enabled=True,
        description=(
            "Per-event detection: each NGINX-observed HTTP 401 is a "
            "candidate authentication-failure signal. A future "
            "correlation rule can count firings into a brute-force "
            "or credential-stuffing detection; this rule does not "
            "perform correlation or windowed counting."
        ),
        tags=("AUTH", "AUTH-FAILURE", "NGINX", "PER-EVENT"),
        references=(
            "docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#18-why-we-do-not-create-one-rule-per-attack",
        ),
    )


def build_nginx_auth_failure_observation_rule() -> SimpleRule:
    """Factory: build a fresh rule instance.

    The factory pattern (over a class-level singleton) keeps the
    rule's mutable instance attributes (e.g. ``enabled``) isolated
    from other tests' instances and from the rule loader's
    per-process state.
    """
    return SimpleRule(_make_metadata(), _predicate, _reasoner)
