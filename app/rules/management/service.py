"""The rule management service: the Phase 4.7 backend orchestrator.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md
           docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 10, 13, 59, 87-91).

The :class:`RuleManagementService` is the only orchestrator
in the Phase 4.7 layer. It is responsible for:

* **Validation.** Every rule definition passes through
  the :class:`RuleDefinition` model validator before
  anything else happens. Pydantic is the source of truth
  for what a valid rule looks like; the service layer
  adds the *governance* checks.

* **Persistence.** The service uses
  :class:`app.persistence.rule_repository.RuleRepository`
  as its only MongoDB boundary.

* **Dynamic loading.** The service reconciles persisted
  rules into the framework's
  :class:`app.rules.registry.RuleRegistry` as
  :class:`GenericDeclarativeRule` instances. There is
  exactly one class for every persisted rule.

* **Lifecycle.** ``create``, ``read``, ``update``,
  ``version`` (a new version of an existing rule),
  ``enable`` / ``disable``, ``retire`` (soft-delete).

* **Security.** The service NEVER invokes ``eval``,
  ``exec``, ``subprocess``, ``os.system``, or
  ``importlib`` on user-controlled bytes.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from ...persistence.rule_repository import RuleRepository

from pydantic import ValidationError as PydanticValidationError

from ...config import ProShieldConfig
from ...rules.registry import (
    CandidateNotPromotableError,
    DuplicateRuleError,
    RuleRegistry,
    RuleValidationError,
    SupersededVersionNotReenablableError,
    UnknownRuleError,
)
from ...rules.types import RuleState
from .definition import RuleDefinition
from .errors import (
    DuplicateManagedRuleError,
    ManagedRuleRetiredError,
    RuleDefinitionValidationError,
    RuleManagementError,
    RuleNotInExpectedStateError,
    RuleVersionConflictError,
    UnknownManagedRuleError,
)
from .generic_rule import GenericDeclarativeRule


_log = logging.getLogger(__name__)


# The persisted "retired" state is a soft-delete: the
# runtime loader never surfaces retired rules, but the
# document remains for audit traceability. The
# :class:`RuleState` enum has only CANDIDATE / APPROVED,
# so we add the third state as a string constant.
STATE_RETIRED = "retired"


class RuleManagementService:
    """The Phase 4.7 rule management service."""

    def __init__(
        self,
        repository: RuleRepository,
        registry: RuleRegistry,
        *,
        config: Optional[ProShieldConfig] = None,
    ) -> None:
        if repository is None:
            raise ValueError("repository is required")
        if registry is None:
            raise ValueError("registry is required")
        self._repository = repository
        self._registry = registry
        self._config = config
        # Track the (rule_id, version) pairs the service
        # has ever registered so the dynamic loader can
        # unregister rules whose persisted state has
        # disappeared (e.g. a hard delete by an
        # operator). Built-in rules are never in this
        # set, so the loader does not touch them.
        self._known_persisted_ids: Set[Tuple[str, int]] = set()

    # ------------------------------------------------------------- properties
    @property
    def repository(self) -> RuleRepository:
        return self._repository

    @property
    def registry(self) -> RuleRegistry:
        return self._registry



    # ------------------------------------------------------------ validation
    @staticmethod
    def _validate_definition_payload(payload: Dict[str, Any]) -> RuleDefinition:
        """Build a :class:`RuleDefinition` from a raw payload.

        Translates Pydantic validation errors into the
        framework's :class:`RuleDefinitionValidationError`
        so a future HTTP API can return a uniform 400
        with a structured ``field`` path.
        """
        if not isinstance(payload, dict):
            raise RuleDefinitionValidationError(
                safe_message="rule definition must be a JSON object",
                internal_detail=f"got {type(payload).__name__}",
            )
        try:
            return RuleDefinition.model_validate(payload)
        except PydanticValidationError as exc:
            errors = exc.errors()
            field = None
            if errors and isinstance(errors, list):
                first = errors[0]
                loc = first.get("loc", ())
                if loc:
                    field = ".".join(str(p) for p in loc)
            detail = "; ".join(
                f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg')}"
                for e in errors[:3]
            ) or "validation failed"
            raise RuleDefinitionValidationError(
                safe_message="rule definition is invalid",
                internal_detail=detail,
                field=field,
            )



    # ------------------------------------------------------------ create
    def create(self, payload: Dict[str, Any]) -> RuleDefinition:
        """Create a new rule from a raw payload."""
        definition = self._validate_definition_payload(payload)
        if not definition.actions:
            raise RuleDefinitionValidationError(
                safe_message="rule must declare at least one action",
                internal_detail=(
                    f"rule_id={definition.rule_id!r} v{definition.version}"
                ),
                field="actions",
            )
        if definition.enabled and definition.state != RuleState.APPROVED.value:
            raise RuleNotInExpectedStateError(
                safe_message=(
                    "rule cannot be enabled while it is in the "
                    "CANDIDATE state; promote to APPROVED first"
                ),
                internal_detail=(
                    f"rule_id={definition.rule_id!r} v{definition.version}"
                ),
            )
        try:
            self._repository.create(definition)
        except DuplicateManagedRuleError as exc:
            raise DuplicateManagedRuleError(
                safe_message=exc.safe_message,
                internal_detail=exc.internal_detail,
            ) from exc
        self._register_in_registry(definition)
        return definition

    # ------------------------------------------------------------ read
    def get(
        self, rule_id: str, version: Optional[int] = None
    ) -> Optional[RuleDefinition]:
        return self._repository.get(rule_id, version)

    def list_all(
        self, *, state: Optional[RuleState] = None
    ) -> List[RuleDefinition]:
        """List every persisted rule (optionally filtered by state)."""
        return self._repository.find_all(state=state)

    def list_latest(
        self, *, state: Optional[RuleState] = None
    ) -> List[RuleDefinition]:
        """List the latest version of every ``rule_id`` (optionally filtered)."""
        return self._repository.find_latest_versions(state=state)

    def list_evaluable(self) -> List[RuleDefinition]:
        """Return the latest version of every APPROVED + enabled rule."""
        rows = self._repository.find_latest_versions(state=RuleState.APPROVED)
        return [d for d in rows if d.enabled]



    # ------------------------------------------------------------ update
    def update(
        self, rule_id: str, version: int, payload: Dict[str, Any]
    ) -> RuleDefinition:
        """Update an existing rule's content (in place).

        Lifecycle fields (``state``, ``enabled``) are
        NOT changed by this method; use
        :meth:`set_state` / :meth:`set_enabled` instead.
        """
        existing = self._repository.get(rule_id, version)
        if existing is None:
            raise UnknownManagedRuleError(
                safe_message=f"rule {rule_id!r} v{version} is not registered",
                internal_detail=f"requested rule_id={rule_id!r} version={version}",
            )
        if existing.state == STATE_RETIRED:
            raise ManagedRuleRetiredError(
                safe_message=(
                    f"rule {rule_id!r} v{version} is retired; "
                    "retired rules cannot be updated"
                ),
                internal_detail=(
                    f"rule_id={rule_id!r} v{version} state=retired"
                ),
            )
        payload = dict(payload)
        payload["rule_id"] = rule_id
        payload["version"] = version
        payload["state"] = existing.state
        payload["enabled"] = bool(existing.enabled)
        new_definition = self._validate_definition_payload(payload)
        if not new_definition.actions:
            raise RuleDefinitionValidationError(
                safe_message="rule must declare at least one action",
                internal_detail=(
                    f"rule_id={rule_id!r} v{version}"
                ),
                field="actions",
            )
        self._repository.update(new_definition)
        self._reregister_in_registry(new_definition)
        return new_definition



    # ------------------------------------------------------------ versioning
    def create_new_version(
        self, rule_id: str, payload: Dict[str, Any]
    ) -> RuleDefinition:
        """Create a new version of an existing rule."""
        latest = self._repository.get(rule_id)
        if latest is not None and latest.state == STATE_RETIRED:
            raise ManagedRuleRetiredError(
                safe_message=(
                    f"rule {rule_id!r} is retired; "
                    "retired rules cannot be re-versioned"
                ),
                internal_detail=f"rule_id={rule_id!r}",
            )
        payload = dict(payload)
        if "version" not in payload:
            raise RuleDefinitionValidationError(
                safe_message="new version payload must declare a version",
                internal_detail=(
                    f"rule_id={rule_id!r} latest_version="
                    f"{latest.version if latest else None}"
                ),
                field="version",
            )
        if latest is not None:
            new_version = int(payload["version"])
            if new_version <= latest.version:
                raise RuleVersionConflictError(
                    safe_message=(
                        f"new version {new_version} for rule {rule_id!r} "
                        f"must be strictly greater than the latest "
                        f"version {latest.version}"
                    ),
                    internal_detail=(
                        f"rule_id={rule_id!r} "
                        f"requested={new_version} latest={latest.version}"
                    ),
                )
        payload["rule_id"] = rule_id
        # A new version always starts in CANDIDATE /
        # disabled regardless of what the payload
        # says. The documented CANDIDATE -> APPROVED
        # funnel applies (Section 59, 89).
        payload["state"] = "candidate"
        payload["enabled"] = False
        new_definition = self._validate_definition_payload(payload)
        if not new_definition.actions:
            raise RuleDefinitionValidationError(
                safe_message="rule must declare at least one action",
                internal_detail=(
                    f"rule_id={rule_id!r} v{new_definition.version}"
                ),
                field="actions",
            )
        self._repository.create(new_definition)
        self._register_in_registry(new_definition)
        return new_definition



    # ------------------------------------------------------------ lifecycle
    def set_state(
        self, rule_id: str, new_state: str, *, version: Optional[int] = None
    ) -> RuleDefinition:
        """Promote / demote / retire a rule."""
        if new_state not in ("candidate", "approved", STATE_RETIRED):
            raise RuleNotInExpectedStateError(
                safe_message=f"unknown state {new_state!r}",
                internal_detail=(
                    f"rule_id={rule_id!r} requested_state={new_state!r}"
                ),
            )
        existing = self._repository.get(rule_id, version)
        if existing is None:
            raise UnknownManagedRuleError(
                safe_message=f"rule {rule_id!r} v{version} is not registered",
                internal_detail=(
                    f"rule_id={rule_id!r} version={version}"
                ),
            )
        if existing.state == STATE_RETIRED and new_state != STATE_RETIRED:
            raise ManagedRuleRetiredError(
                safe_message=(
                    f"rule {rule_id!r} v{existing.version} is retired; "
                    "retired rules cannot change state"
                ),
                internal_detail=(
                    f"rule_id={rule_id!r} v{existing.version} state=retired"
                ),
            )
        if new_state == STATE_RETIRED:
            self._repository.soft_delete(rule_id, existing.version)
            self._unregister_from_registry(rule_id, existing.version)
            refreshed = self._repository.get(rule_id, existing.version)
            assert refreshed is not None
            return refreshed
        if new_state == "approved" and existing.state == RuleState.CANDIDATE.value:
            try:
                self._registry.set_state(
                    rule_id, RuleState.APPROVED, version=existing.version
                )
            except (RuleValidationError, CandidateNotPromotableError) as exc:
                raise RuleNotInExpectedStateError(
                    safe_message=exc.safe_message,
                    internal_detail=exc.internal_detail,
                ) from exc
            self._repository.set_state_field(
                rule_id, existing.version, "approved"
            )
            return self._repository.get(rule_id, existing.version)  # type: ignore[return-value]
        if new_state == "candidate" and existing.state == RuleState.APPROVED.value:
            try:
                self._registry.set_state(
                    rule_id, RuleState.CANDIDATE, version=existing.version
                )
            except (RuleValidationError, CandidateNotPromotableError) as exc:
                raise RuleNotInExpectedStateError(
                    safe_message=exc.safe_message,
                    internal_detail=exc.internal_detail,
                ) from exc
            self._repository.set_state_field(
                rule_id, existing.version, "candidate"
            )
            return self._repository.get(rule_id, existing.version)  # type: ignore[return-value]
        return existing



    def set_enabled(
        self,
        rule_id: str,
        enabled: bool,
        *,
        version: Optional[int] = None,
    ) -> RuleDefinition:
        """Toggle a rule's ``enabled`` flag."""
        if not isinstance(enabled, bool):
            raise RuleNotInExpectedStateError(
                safe_message="enabled must be a bool",
                internal_detail=f"got {type(enabled).__name__}",
            )
        existing = self._repository.get(rule_id, version)
        if existing is None:
            raise UnknownManagedRuleError(
                safe_message=f"rule {rule_id!r} v{version} is not registered",
                internal_detail=(
                    f"rule_id={rule_id!r} version={version}"
                ),
            )
        if existing.state == STATE_RETIRED:
            raise ManagedRuleRetiredError(
                safe_message=(
                    f"rule {rule_id!r} v{existing.version} is retired"
                ),
                internal_detail=(
                    f"rule_id={rule_id!r} v{existing.version} state=retired"
                ),
            )
        target_version = existing.version
        try:
            self._registry.set_enabled(
                rule_id, enabled, version=target_version
            )
        except (
            RuleValidationError,
            CandidateNotPromotableError,
            SupersededVersionNotReenablableError,
            UnknownRuleError,
        ) as exc:
            raise RuleNotInExpectedStateError(
                safe_message=exc.safe_message,
                internal_detail=exc.internal_detail,
            ) from exc
        self._repository.set_enabled_field(
            rule_id, target_version, enabled
        )
        return self._repository.get(rule_id, target_version)  # type: ignore[return-value]

    def retire(
        self, rule_id: str, *, version: Optional[int] = None
    ) -> RuleDefinition:
        """Soft-delete a rule. One-way operation."""
        return self.set_state(rule_id, STATE_RETIRED, version=version)



    # ------------------------------------------------------------ loading
    def reload_registry(self) -> int:
        """Reconcile every persisted rule into the in-memory registry."""
        latest = self._repository.find_latest_versions()
        persisted_ids: set = set()
        for definition in latest:
            persisted_ids.add((definition.rule_id, definition.version))
            if definition.state == STATE_RETIRED:
                self._safe_unregister(definition.rule_id, definition.version)
                continue
            self._reregister_in_registry(definition)
        for key in list(self._known_persisted_ids):
            if key not in persisted_ids:
                rid, ver = key
                self._safe_unregister(rid, ver)
                self._known_persisted_ids.discard(key)
        return len(persisted_ids)

    # ------------------------------------------------------------ internals
    def _implementation_for(self, definition: RuleDefinition) -> Optional[Any]:
        """The shipped rule IMPLEMENTATION that must stay authoritative.

        Returns the currently-registered rule instance for
        ``(rule_id, version)`` when all of the following hold:

        * the persisted definition declares no ``conditions`` of its own;
        * an instance is registered (so the implementation is a rule that
          actually ships, never an invention);
        * it is NOT a :class:`GenericDeclarativeRule` (the declarative
          wrapper, which carries no compiled predicate);
        * it exposes ``with_metadata`` so it can be rebound to the persisted
          lifecycle view.

        Why this exists
        ---------------
        A capability-owned **library** rule is seeded into ``managed_rules``
        as a metadata-only definition (``conditions=None``), because a Python
        predicate cannot be transcribed into the bounded declarative DSL.
        Re-registering such a definition as a declarative wrapper would
        silently discard the predicate: the rule would then match on
        applicability metadata alone — e.g. every ``request_blocked`` event
        would fire all three ``request_blocked`` rules regardless of status
        code or path, and a forged ``authentication_failure`` with any status
        would fire the 401 rule. Returning the implementation keeps the
        shipped detection logic authoritative while the operator-visible
        lifecycle state (``enabled`` / ``state`` / name / tags) still comes
        from the store.

        A definition that *does* declare its own conditions (an
        operator-authored or operator-edited rule) returns ``None``: the
        explicit declarative logic is authoritative and wins.
        """
        if definition.conditions is not None:
            return None
        existing = self._registry.get(definition.rule_id, definition.version)
        if existing is None or isinstance(existing, GenericDeclarativeRule):
            return None
        if not callable(getattr(existing, "with_metadata", None)):
            return None
        return existing

    def _register_in_registry(
        self,
        definition: RuleDefinition,
        *,
        implementation: Optional[Any] = None,
    ) -> None:
        """Register a single :class:`RuleDefinition` in the registry.

        ``implementation`` (optional) is a shipped rule instance whose logic
        must be preserved; it is rebound to ``definition``'s metadata via
        :meth:`with_metadata`. Any rebind failure falls back to the
        declarative wrapper (logged, never blocking the registry update).
        """
        if definition.state == STATE_RETIRED:
            return
        rule: Optional[Any] = None
        if implementation is not None:
            try:
                rule = implementation.with_metadata(definition.to_metadata())
            except Exception as exc:  # noqa: BLE001 - fall back, never block
                _log.warning(
                    "rule_management.implementation_rebind_failed",
                    extra={
                        "rule_id": definition.rule_id,
                        "version": definition.version,
                        "error_type": type(exc).__name__,
                    },
                )
                rule = None
        if rule is None:
            rule = GenericDeclarativeRule(definition)
        try:
            self._registry.register(rule)
        except DuplicateRuleError as exc:
            raise RuleManagementError(
                safe_message=exc.safe_message,
                internal_detail=exc.internal_detail,
            ) from exc
        except RuleValidationError as exc:
            raise RuleManagementError(
                safe_message=exc.safe_message,
                internal_detail=exc.internal_detail,
            ) from exc
        self._known_persisted_ids.add(
            (definition.rule_id, definition.version)
        )

    def _reregister_in_registry(
        self, definition: RuleDefinition
    ) -> None:
        """Replace the registry entry for ``(rule_id, version)``.

        A capability-owned library rule keeps its shipped implementation
        (see :meth:`_implementation_for`) while its persisted lifecycle state
        (enable / disable / retire) is honoured.
        """
        implementation = self._implementation_for(definition)
        self._safe_unregister(definition.rule_id, definition.version)
        if definition.state != STATE_RETIRED:
            self._register_in_registry(
                definition, implementation=implementation
            )

    def _unregister_from_registry(
        self, rule_id: str, version: int
    ) -> None:
        self._safe_unregister(rule_id, version)
        self._known_persisted_ids.discard((rule_id, version))

    def _safe_unregister(self, rule_id: str, version: int) -> None:
        """Best-effort unregister. Silently ignores unknown ids."""
        rule = self._registry.get(rule_id, version)
        if rule is None:
            return
        try:
            self._registry_remove(rule_id, version)
        except Exception:  # noqa: BLE001
            _log.warning(
                "rule_management.unregister_failed",
                extra={
                    "rule_id": rule_id,
                    "version": version,
                },
            )

    def _registry_remove(self, rule_id: str, version: int) -> None:
        """Drop a single ``(rule_id, version)`` entry from the registry.

        Uses the registry's documented ``_by_version`` /
        ``_latest_version`` internals. The framework does
        NOT yet expose a public ``unregister`` API, so we
        drive the documented primitives directly.
        """
        registry = self._registry
        with registry._lock:  # type: ignore[attr-defined]
            key = (rule_id, version)
            existed = registry._by_version.pop(key, None)  # type: ignore[attr-defined]
            if existed is not None:
                if registry._latest_version.get(rule_id) == version:  # type: ignore[attr-defined]
                    versions = [
                        v
                        for (rid, v) in registry._by_version.keys()  # type: ignore[attr-defined]
                        if rid == rule_id
                    ]
                    if versions:
                        registry._latest_version[rule_id] = max(versions)  # type: ignore[attr-defined]
                    else:
                        registry._latest_version.pop(rule_id, None)  # type: ignore[attr-defined]


__all__ = [
    "RuleManagementService",
    "STATE_RETIRED",
]

