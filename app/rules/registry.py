"""The authoritative ProShield Rule Registry.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md (Sections
10, 88, 89, 90, 91) and docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5).

The registry is the **single source of truth** for "which rules exist,
in which state, and which are eligible to run". It enforces the
documented candidate-vs-approved governance gate (§89) and provides
the efficient applicability filter the detection engine will use
(§90, DET-04).

Design rules:

* **In-memory only in Phase 4.2.** Persistence of the rule catalogue
  to a Mongo collection is a future slice; the registry here is
  authoritative for the running process.
* **No mutation outside the documented methods.** The registry is
  the only thing that flips a rule's ``state`` or ``enabled`` flag.
* **Idempotent lookups.** Lookup methods never raise for "not
  found"; they return ``None`` or an empty list.
* **Deterministic iteration.** ``list_*`` methods return results in
  stable order (rule_id, then version) so tests, audit, and HTTP
  endpoints are reproducible.
* **Strict on the candidate -> approved transition (§59).** A
  CANDIDATE rule cannot be ``enabled``; flipping to ``enabled`` while
  CANDIDATE is rejected with a domain error.
"""
from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Optional, Tuple

from ..domain.errors import DomainError
from ..domain.security_event import SecurityEvent
from .rule import Rule
from .types import (
    RuleCategory,
    RuleMetadata,
    RuleState,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class RuleRegistryError(DomainError):
    """Base class for registry-level domain errors."""

    code = "rule_registry_error"
    http_status = 500


class DuplicateRuleError(RuleRegistryError):
    """A rule with the same ``rule_id`` is already registered.

    Two rules with the same id are treated as one rule, regardless of
    whether they were intended as different versions. Re-registering
    the same ``(rule_id, version)`` is the only allowed update path.
    """

    code = "duplicate_rule"
    http_status = 409


class RuleValidationError(RuleRegistryError):
    """A rule failed the documented metadata validation gates (§9, 90)."""

    code = "rule_validation_error"
    http_status = 400


class CandidateNotPromotableError(RuleRegistryError):
    """An attempt was made to enable a CANDIDATE rule.

    The candidate -> approved -> enabled pipeline (§59, §89) is
    enforced by the registry.
    """

    code = "candidate_not_promotable"
    http_status = 409


class SupersededVersionNotReenablableError(RuleRegistryError):
    """An attempt was made to re-enable a version that is not the
    latest registered for its ``rule_id``.

    Versioning is a "history + supersedes" model: when a newer
    version of a rule is registered, the older version is
    superseded. Re-enabling a superseded version would put a
    deprecated rule back into the live evaluation set, causing
    duplicate detections on every matching event. The registry
    rejects this state by design.

    Disable the rule entirely (or enable the latest version)
    instead.
    """

    code = "superseded_version_not_reenablable"
    http_status = 409


class UnknownRuleError(RuleRegistryError):
    """A lookup / update targeted a rule_id that is not registered."""

    code = "unknown_rule"
    http_status = 404


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class RuleRegistry:
    """Authoritative in-memory rule catalogue.

    The registry is *not* a detection engine. It holds rule *metadata*
    + a reference to the rule *implementation object*; it does not
    call ``evaluate``.

    Concurrency
    -----------
    Read methods (``get``, ``list_*``, ``applies_to``) are safe to call
    from multiple threads. Mutations (``register``, ``set_state``,
    ``set_enabled``) are serialised by an internal lock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # (rule_id, version) -> Rule
        self._by_version: Dict[Tuple[str, int], Rule] = {}
        # rule_id -> highest registered version
        self._latest_version: Dict[str, int] = {}

    # ------------------------------------------------------------ registration
    def register(self, rule: Rule) -> None:
        """Register a rule.

        * Re-registration of the same ``(rule_id, version)`` with the
          same object is a no-op.
        * Re-registration of the same ``(rule_id, version)`` with a
          different implementation is rejected.
        * Registering a NEW version of an existing ``rule_id`` is
          allowed; the new version must be strictly greater than the
          previous one (Section 33: rule versioning).
        """
        if not isinstance(rule, Rule):
            raise RuleValidationError(
                safe_message="only Rule instances may be registered",
                internal_detail=f"got {type(rule).__name__}",
            )
        meta = rule.metadata
        if not isinstance(meta, RuleMetadata):
            raise RuleValidationError(
                safe_message="rule.metadata must be a RuleMetadata",
                internal_detail=f"got {type(meta).__name__}",
            )
        # An enabled rule must be APPROVED (Section 90 + 59).
        if meta.enabled and meta.state is not RuleState.APPROVED:
            raise CandidateNotPromotableError(
                safe_message=(
                    "rule cannot be enabled while it is in the "
                    "CANDIDATE state; promote it to APPROVED first"
                ),
                internal_detail=(
                    f"rule_id={meta.rule_id!r} v{meta.version} "
                    f"state={meta.state.value} enabled={meta.enabled}"
                ),
            )

        key = (meta.rule_id, meta.version)
        with self._lock:
            existing = self._by_version.get(key)
            if existing is not None:
                if existing is rule:
                    return
                raise DuplicateRuleError(
                    safe_message=(
                        f"rule {meta.rule_id} v{meta.version} is already "
                        "registered with a different implementation"
                    ),
                    internal_detail=(
                        f"existing={type(existing).__name__} "
                        f"new={type(rule).__name__}"
                    ),
                )
            prev = self._latest_version.get(meta.rule_id)
            if prev is not None and meta.version <= prev:
                raise RuleValidationError(
                    safe_message=(
                        f"new version of {meta.rule_id} must be > "
                        f"{prev} (Section 33)"
                    ),
                    internal_detail=f"attempted version {meta.version}",
                )
            self._by_version[key] = rule
            self._latest_version[meta.rule_id] = meta.version

    # ----------------------------------------------------------------- lookup
    def get(self, rule_id: str, version: Optional[int] = None) -> Optional[Rule]:
        """Return the registered rule for ``rule_id``.

        * If ``version`` is ``None``, the latest registered version is
          returned.
        * If no such rule exists, returns ``None`` (does not raise).
        """
        if not isinstance(rule_id, str) or not rule_id:
            return None
        with self._lock:
            if version is None:
                version = self._latest_version.get(rule_id)
                if version is None:
                    return None
            return self._by_version.get((rule_id, version))

    def has(self, rule_id: str, version: Optional[int] = None) -> bool:
        return self.get(rule_id, version) is not None

    def latest_version(self, rule_id: str) -> Optional[int]:
        with self._lock:
            return self._latest_version.get(rule_id)

    def list_all(self) -> List[Rule]:
        """Return all registered rules in stable ``(rule_id, version)`` order."""
        with self._lock:
            return [
                self._by_version[k]
                for k in sorted(self._by_version.keys())
            ]

    def list_for_category(self, category: RuleCategory) -> List[Rule]:
        return [
            r for r in self.list_all() if r.metadata.category is category
        ]

    def list_enabled(self) -> List[Rule]:
        """Return APPROVED + enabled rules only.

        These are the rules the detection engine is allowed to invoke
        (Section 90, DET-04).
        """
        return [r for r in self.list_all() if r.metadata.is_evaluable()]

    def list_for_event(
        self, source: str, event_type: str
    ) -> List[Rule]:
        """Return evaluable rules whose applicability covers the given
        ``(source, event_type)``.

        This is the **hot path** of the detection engine. The result
        is sorted by ``(rule_id, version)`` for determinism.
        """
        if not isinstance(source, str) or not source:
            return []
        if not isinstance(event_type, str) or not event_type:
            return []
        out: List[Rule] = []
        for r in self.list_all():
            meta = r.metadata
            if not meta.is_evaluable():
                continue
            if not meta.applies_to_source(source):
                continue
            if not meta.applies_to_event_type(event_type):
                continue
            out.append(r)
        return out

    def applies_to(self, event: SecurityEvent) -> List[Rule]:
        """Applicability filter for a concrete SecurityEvent.

        This is the documented "rule selection" step (Section 12):
        ``SecurityEvent -> identify source -> identify event type ->
        select applicable rules -> run relevant rules``.
        """
        return self.list_for_event(event.source, event.event_type)

    def is_empty(self) -> bool:
        with self._lock:
            return not self._by_version

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_version)

    def __contains__(self, rule_id: object) -> bool:
        return (
            isinstance(rule_id, str)
            and self.get(rule_id) is not None
        )

    # ----------------------------------------------------------- state mutation
    def set_state(
        self,
        rule_id: str,
        new_state: RuleState,
        *,
        version: Optional[int] = None,
    ) -> Rule:
        """Transition a rule's ``state`` (CANDIDATE <-> APPROVED).

        The CANDIDATE -> APPROVED transition is the documented
        promotion gate (§59, §89). Demotion is also allowed and
        resets ``enabled`` to ``False`` to keep the invariant
        "enabled implies APPROVED" intact.
        """
        if not isinstance(new_state, RuleState):
            raise RuleValidationError(
                safe_message="new_state must be a RuleState enum value",
                internal_detail=f"got {type(new_state).__name__}",
            )
        with self._lock:
            rule = self.get(rule_id, version)
            if rule is None:
                raise UnknownRuleError(
                    safe_message=f"rule {rule_id!r} is not registered",
                    internal_detail=(
                        f"requested version={version} "
                        f"known versions={sorted(self._versions_for(rule_id))}"
                    ),
                )
            old = rule.metadata
            if old.state is new_state:
                return rule
            # Pydantic models are frozen; replace metadata with a new
            # frozen instance. The rule object's ``metadata`` attribute
            # is also rebound. This is the documented
            # "promote in place" pattern: the implementation object is
            # preserved across lifecycle changes.
            new_meta = old.model_copy(
                update={
                    "state": new_state,
                    # Demoting must NOT leave an enabled-but-CANDIDATE
                    # rule behind.
                    "enabled": (
                        old.enabled
                        if new_state is RuleState.APPROVED
                        else False
                    ),
                }
            )
            rule.metadata = new_meta
            return rule

    def set_enabled(
        self,
        rule_id: str,
        enabled: bool,
        *,
        version: Optional[int] = None,
    ) -> Rule:
        """Toggle a rule's ``enabled`` flag.

        * Enabling a CANDIDATE rule is rejected
          (:class:`CandidateNotPromotableError`).
        * Re-enabling a superseded version (i.e. a version that is
          not the latest registered for the same ``rule_id``) is
          rejected
          (:class:`SupersededVersionNotReenablableError`).
        * Disabling is always allowed.
        """
        if not isinstance(enabled, bool):
            raise RuleValidationError(
                safe_message="enabled must be a bool",
                internal_detail=f"got {type(enabled).__name__}",
            )
        with self._lock:
            rule = self.get(rule_id, version)
            if rule is None:
                raise UnknownRuleError(
                    safe_message=f"rule {rule_id!r} is not registered",
                    internal_detail=(
                        f"requested version={version} "
                        f"known versions={sorted(self._versions_for(rule_id))}"
                    ),
                )
            if enabled and rule.metadata.state is not RuleState.APPROVED:
                raise CandidateNotPromotableError(
                    safe_message=(
                        f"rule {rule_id!r} cannot be enabled in state "
                        f"{rule.metadata.state.value}; promote to "
                        "APPROVED first"
                    ),
                    internal_detail=(
                        f"rule_id={rule_id!r} v{rule.metadata.version} "
                        f"state={rule.metadata.state.value}"
                    ),
                )
            # Re-enabling a superseded version would put a deprecated
            # rule back into the live evaluation set, producing
            # duplicate detections on every matching event. The
            # registry is the single source of truth for "which
            # rules are live" (Section 88) and refuses this state.
            # The check is only meaningful when the targeted version
            # is not the latest AND there is at least one other
            # version registered.
            if (
                enabled
                and not rule.metadata.enabled
                and self._latest_version.get(rule_id) is not None
                and rule.metadata.version
                != self._latest_version[rule_id]
            ):
                raise SupersededVersionNotReenablableError(
                    safe_message=(
                        f"rule {rule_id!r} v{rule.metadata.version} is "
                        f"superseded by v{self._latest_version[rule_id]}; "
                        "a superseded version cannot be re-enabled"
                    ),
                    internal_detail=(
                        f"rule_id={rule_id!r} "
                        f"targeted_version={rule.metadata.version} "
                        f"latest_version={self._latest_version[rule_id]}"
                    ),
                )
            if rule.metadata.enabled is enabled:
                return rule
            new_meta = rule.metadata.model_copy(update={"enabled": enabled})
            rule.metadata = new_meta
            return rule

    # --------------------------------------------------------------- internals
    def _versions_for(self, rule_id: str) -> Iterable[int]:
        for (rid, ver) in self._by_version.keys():
            if rid == rule_id:
                yield ver