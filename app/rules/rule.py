"""The ``Rule`` base class and a tiny ``SimpleRule`` helper.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md (Sections
9, 13, 87) and docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5).
"""
from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from ..domain.security_event import SecurityEvent
from .types import RuleEvaluation, RuleMetadata


class Rule(abc.ABC):
    """Abstract base class for a ProShield rule.

    Subclasses MUST:

    * Expose an authoritative :class:`RuleMetadata` via :attr:`metadata`
      as an **instance attribute** (typically assigned in
      ``__init__``). The registry validates and indexes on it, and
      lifecycle transitions mutate the instance attribute, so a
      class-level ``metadata`` would silently drift out of sync
      with the registry's view.
    * Implement :meth:`evaluate` to return a :class:`RuleEvaluation`.
      Implementations must be deterministic: equal inputs must produce
      equal outputs (Section 49, "validated detection logic").

    Subclasses MUST NOT:

    * Talk to pymongo, FastAPI, the network, or any other rule's logic.
      Cross-rule coupling is forbidden (Section 87).
    * Carry state that varies between calls in a way that produces
      non-deterministic evaluations.
    * Declare ``metadata`` as a class attribute unless the
      subclass guarantees that all instances share a single
      frozen metadata that is never mutated (in which case the
      rule's lifecycle state is effectively read-only).
    """

    metadata: RuleMetadata  # subclasses set this as an INSTANCE attribute

    @abc.abstractmethod
    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        """Run the rule against a single canonical SecurityEvent.

        Implementations MUST be deterministic. They MUST NOT raise
        under normal operating conditions: an unmatched event is
        ``RuleEvaluation(matched=False, ...)``.
        """

    def make_evaluation(
        self,
        event: SecurityEvent,
        *,
        matched: bool,
        reasoning: str = "",
        extra: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> RuleEvaluation:
        """Build a :class:`RuleEvaluation` anchored to this rule's
        metadata. Convenience for subclasses.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        extra_t = tuple(sorted((extra or {}).items()))
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            rule_version=self.metadata.version,
            matched=bool(matched),
            target_event_id=event.event_id,
            detected_at=now,
            reasoning=reasoning,
            extra=extra_t,
        )


# ---------------------------------------------------------------------------
# SimpleRule: tiny concrete rule for tests and trivial one-liners.
# ---------------------------------------------------------------------------
SimplePredicate = Callable[[SecurityEvent], bool]
SimpleReasoner = Callable[[SecurityEvent], str]


class SimpleRule(Rule):
    """A minimal rule whose entire logic is a pure ``predicate(event)``.

    Intended for tests and trivially-declarative rules. The default
    ``reasoning`` is the empty string; pass a ``reasoner`` to
    customise it. Both callables MUST be pure.
    """

    def __init__(
        self,
        metadata: RuleMetadata,
        predicate: SimplePredicate,
        reasoner: Optional[SimpleReasoner] = None,
    ) -> None:
        if not isinstance(metadata, RuleMetadata):
            raise TypeError(
                f"metadata must be a RuleMetadata, got {type(metadata).__name__}"
            )
        if metadata.category.value == "cross_source_correlation":
            raise ValueError(
                "SimpleRule cannot implement CROSS_SOURCE_CORRELATION; "
                "correlation rules need access to multiple events"
            )
        if not callable(predicate):
            raise TypeError("predicate must be callable")
        self.metadata = metadata
        self._predicate = predicate
        self._reasoner = reasoner

    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        try:
            matched = bool(self._predicate(event))
        except Exception as exc:  # noqa: BLE001
            raise RuleEvaluationError(
                rule_id=self.metadata.rule_id,
                rule_version=self.metadata.version,
                event_id=event.event_id,
                cause=exc,
            ) from exc
        reasoning = ""
        if matched and self._reasoner is not None:
            reasoning = self._reasoner(event)
        return self.make_evaluation(
            event, matched=matched, reasoning=reasoning
        )


class RuleEvaluationError(RuntimeError):
    """A rule's ``evaluate`` raised an unexpected exception.

    This is a framework-level signal that the rule is misbehaving and
    should be quarantined by the detection engine. The framework
    itself does NOT catch and swallow this error; the rule's
    ``evaluate`` is supposed to be total.
    """

    def __init__(
        self,
        *,
        rule_id: str,
        rule_version: int,
        event_id: str,
        cause: BaseException,
    ) -> None:
        super().__init__(
            f"rule {rule_id} v{rule_version} raised on event {event_id}: "
            f"{type(cause).__name__}: {cause}"
        )
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.event_id = event_id
        self.cause = cause