"""The generic, declarative rule evaluator.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.

A :class:`GenericDeclarativeRule` is a single, hand-written
:class:`app.rules.rule.Rule` subclass that knows how to
evaluate **any** :class:`RuleDefinition` that has passed
server-side validation. It is the runtime side of the
"data-driven rule" promise: creating a new rule does NOT
require writing a new Python class.

The class is intentionally small:

* It carries a :class:`RuleDefinition` as an instance
  attribute (the same contract the framework requires
  of every :class:`Rule`).
* Its :meth:`evaluate` implementation walks the
  definition's combinator + conditions tree using the
  closed-set :mod:`app.rules.management.conditions`
  evaluator. The evaluator never invokes ``eval`` /
  ``exec`` / ``subprocess`` / ``importlib``; it only
  walks the allow-listed operator / combinator
  vocabulary.
* It is **deterministic** like every other rule. The
  same input event + the same definition produce the same
  output. ``now`` is injected via the framework's
  :meth:`Rule.make_evaluation` helper.

Why a single class is the right design
---------------------------------------

The Phase 4.2 framework is a deliberate split between
*what* a rule does (a :class:`Rule` instance with a
metadata and an ``evaluate`` method) and *how* the rule
*is expressed* (a subclass that hard-codes the logic). A
built-in rule like :class:`NGINX-AUTH-FAILURE-001` is
expressed as a ``SimpleRule`` predicate; the framework
treats the predicate as an opaque callable. A
user-defined rule can be expressed as data instead - and
the runtime needs exactly one class that interprets
that data.

The lifecycle semantics (:class:`RuleMetadata`,
:class:`RuleState`, ``enabled``) are still owned by the
:attr:`definition` field and the framework's
:class:`RuleRegistry`. The class is the executor; the
metadata is the catalogue entry.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...domain.security_event import SecurityEvent
from ...rules.rule import Rule
from ...rules.types import RuleEvaluation
from .conditions import (
    ConditionCombinator,
    evaluate_expression,
)
from .definition import (
    RuleDefinition,
    RuleType,
)


def _truncate(s: Any, n: int) -> str:
    """Defensive bound used to build a short, analyst-facing string."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + "..."


class GenericDeclarativeRule(Rule):
    """A :class:`Rule` that evaluates a :class:`RuleDefinition`.

    The class is the only Rule subclass produced by the
    Phase 4.7 rule management layer. The framework's
    :class:`RuleRegistry` registers instances of this class
    for every persisted user-defined rule. The class itself
    is shared by every rule, so creating a new normal rule
    NEVER requires writing a new Python class.
    """

    def __init__(self, definition: RuleDefinition) -> None:
        if not isinstance(definition, RuleDefinition):
            raise TypeError(
                f"definition must be a RuleDefinition, got {type(definition).__name__}"
            )
        self._definition = definition
        self.metadata = definition.to_metadata()
        self._conditions = definition.conditions
        self._combinator = definition.combinator



    # ----------------------------------------------------------------- helpers
    @property
    def definition(self) -> RuleDefinition:
        """Return the bound :class:`RuleDefinition` (read-only)."""
        return self._definition

    def _evidence_complete(self, event: SecurityEvent) -> bool:
        """Check the rule's ``evidence_requirements`` against ``event``."""
        reqs = self._definition.evidence_requirements
        if not reqs:
            return True
        for path in reqs:
            head, _, rest = path.partition(".")
            if head == "details":
                details = event.details or {}
                if not rest:
                    if not isinstance(details, dict):
                        return False
                    continue
                if rest not in details:
                    return False
                continue
            value = getattr(event, head, None)
            if value is None:
                return False
        return True

    def _matches_conditions(self, event: SecurityEvent) -> bool:
        """Apply the rule's ``combinator`` over the ``conditions`` tree."""
        if self._conditions is None:
            return True
        return evaluate_expression(self._conditions, event)



    def _thresholds_observed(self, event: SecurityEvent) -> bool:
        """Apply the rule's ``thresholds`` to ``event``."""
        thresholds = self._definition.thresholds
        if not thresholds:
            return True
        for key, value in thresholds.items():
            details = event.details or {}
            actual = details.get(key)
            if actual is None:
                return False
            if not isinstance(actual, (int, float)) or isinstance(actual, bool):
                return False
            if actual < value:
                return False
        return True

    def _build_reasoning(self, event: SecurityEvent) -> str:
        """Build a short, redacted, analyst-facing reasoning string."""
        rule_id = self.metadata.rule_id
        rule_version = self.metadata.version
        rule_type = self._definition.type.value
        actions = ", ".join(a.value for a in self._definition.actions) or "none"
        endpoint = _truncate(getattr(event, "endpoint", None) or "<none>", 128)
        source_ip = _truncate(getattr(event, "source_ip", None) or "<none>", 64)
        return (
            f"declarative {rule_type} rule {rule_id} v{rule_version} "
            f"matched event_id={event.event_id} endpoint={endpoint!r} "
            f"source_ip={source_ip!r} actions={actions}"
        )



    # ----------------------------------------------------------------- evaluate
    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        """Run the rule against a single canonical :class:`SecurityEvent`.

        Returns a :class:`RuleEvaluation` with
        ``matched=True`` iff:

        * the rule's evidence requirements are satisfied,
        * the rule's conditions evaluate to ``True`` under
          the rule's combinator, and
        * the rule's per-event threshold check (if any)
          is satisfied.
        """
        # Capture ``now`` once so the function is
        # deterministic on a single call and the
        # ``detected_at`` is the same for every branch.
        now = datetime.now(timezone.utc)
        if not isinstance(event, SecurityEvent):
            # Build the evaluation by hand because the
            # ``make_evaluation`` helper would dereference
            # ``event.event_id`` and crash on a non-event.
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                rule_version=self.metadata.version,
                matched=False,
                target_event_id="<non-event>",
                detected_at=now,
                reasoning="non-SecurityEvent input ignored",
                extra=(),
            )
        if not self._evidence_complete(event):
            return self.make_evaluation(
                event,
                matched=False,
                reasoning="evidence_requirements not satisfied",
                now=now,
            )
        if not self._matches_conditions(event):
            return self.make_evaluation(
                event,
                matched=False,
                reasoning="conditions did not match",
                now=now,
            )
        if not self._thresholds_observed(event):
            return self.make_evaluation(
                event,
                matched=False,
                reasoning="threshold not observed on event",
                now=now,
            )
        return self.make_evaluation(
            event,
            matched=True,
            reasoning=self._build_reasoning(event),
            extra={
                "rule_type": self._definition.type.value,
                "severity": self._definition.severity.value,
                "actions": ",".join(
                    a.value for a in self._definition.actions
                ),
            },
            now=now,
        )


__all__ = [
    "GenericDeclarativeRule",
]

