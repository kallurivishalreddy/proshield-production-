"""Shared helpers for rule-framework tests.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5)

This helper module is intentionally placed under ``tests/unit/`` so
it is never imported by product code. It provides:

* A small catalogue of reusable :class:`RuleMetadata` factories.
* A :func:`make_event` factory for canonical events with sensible
  defaults (so each test only has to override what it cares about).
* A few :class:`SimpleRule` constructors for the common shapes.
* A minimal :class:`NoopRule` for cross-source rules (which
  :class:`SimpleRule` refuses by construction).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.domain.security_event import (
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules import (
    Rule,
    RuleCategory,
    RuleEvaluation,
    RuleMetadata,
    RuleState,
    SimpleRule,
)


# ---------------------------------------------------------------------------
# Event factory
# ---------------------------------------------------------------------------
def make_event(
    *,
    source: str = "simulator",
    event_type: str = "request_blocked",
    source_ip: Optional[str] = "203.0.113.10",
    endpoint: Optional[str] = "/api/login",
    account_id: Optional[str] = "user-1",
    details: Optional[Dict[str, Any]] = None,
) -> SecurityEvent:
    """Build a valid canonical :class:`SecurityEvent` with sensible
    defaults. ``event_time`` and ``ingested_at`` are both set to
    ``2026-01-01T00:00:00Z``.
    """
    et = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    kwargs: Dict[str, Any] = dict(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source=source,
        event_type=event_type,
        provenance=SecurityEventProvenance(
            collector="test", source_event_id=f"src-{source}-1"
        ),
    )
    if source_ip is not None:
        kwargs["source_ip"] = source_ip
    if endpoint is not None:
        kwargs["endpoint"] = endpoint
    if account_id is not None:
        kwargs["account"] = SecurityEventAccount(id=account_id)
    if details is not None:
        kwargs["details"] = details
    return SecurityEvent(**kwargs)


# ---------------------------------------------------------------------------
# Metadata factories
# ---------------------------------------------------------------------------
def waf_metadata(
    *,
    rule_id: str = "WAF-001",
    version: int = 1,
    name: str = "WAF test rule",
    event_types: tuple = ("waf_attack_detected",),
    state: RuleState = RuleState.APPROVED,
    enabled: bool = True,
    description: str = "",
) -> RuleMetadata:
    """A WAF source-specific rule metadata."""
    return RuleMetadata(
        rule_id=rule_id,
        version=version,
        name=name,
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("waf",),
        event_types=event_types,
        state=state,
        enabled=enabled,
        description=description,
    )


def auth_metadata(
    *,
    rule_id: str = "AUTH-BRUTEFORCE-001",
    version: int = 1,
    name: str = "auth bruteforce (common)",
    event_types: tuple = ("authentication_failure",),
    sources: tuple = ("iam", "nginx", "waf"),
    state: RuleState = RuleState.APPROVED,
    enabled: bool = True,
) -> RuleMetadata:
    """A common behavioral rule metadata."""
    return RuleMetadata(
        rule_id=rule_id,
        version=version,
        name=name,
        category=RuleCategory.COMMON_BEHAVIORAL,
        sources=sources,
        event_types=event_types,
        state=state,
        enabled=enabled,
    )


def correlation_metadata(
    *,
    rule_id: str = "CORR-WEB-001",
    version: int = 1,
    name: str = "WAF + NGINX + rate-limit burst",
    sources: tuple = ("nginx", "rate_limiter", "waf"),
    state: RuleState = RuleState.APPROVED,
    enabled: bool = True,
) -> RuleMetadata:
    # Sources are required to be sorted alphabetically (deterministic
    # applicability_signature + deterministic registration order).
    return RuleMetadata(
        rule_id=rule_id,
        version=version,
        name=name,
        category=RuleCategory.CROSS_SOURCE_CORRELATION,
        sources=sources,
        event_types=(),
        state=state,
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# Rule factories
# ---------------------------------------------------------------------------
def always_match_rule(meta: RuleMetadata) -> SimpleRule:
    return SimpleRule(meta, predicate=lambda e: True)


def never_match_rule(meta: RuleMetadata) -> SimpleRule:
    return SimpleRule(meta, predicate=lambda e: False)


class NoopRule(Rule):
    """A trivial rule that always returns ``matched=False``.

    Used by tests that need a concrete :class:`Rule` instance for
    categories that :class:`SimpleRule` does not accept (e.g.,
    :class:`RuleCategory.CROSS_SOURCE_CORRELATION`).
    """

    def __init__(self, metadata: RuleMetadata) -> None:
        self.metadata = metadata

    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        return self.make_evaluation(event, matched=False)
