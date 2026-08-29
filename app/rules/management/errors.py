"""Domain errors for the Phase 4.7 rule management layer.

All errors are subclasses of :class:`app.domain.errors.DomainError`
so a future HTTP API layer can translate them into the
documented safe-error envelope (Phase 3, Section 30).

The error hierarchy is intentionally narrow:

* :class:`RuleManagementError` - base class for every rule
  management domain error.
* :class:`RuleDefinitionValidationError` - the supplied
  rule definition failed the documented server-side
  validation gates.
* :class:`DuplicateManagedRuleError` - a rule with the
  same ``(rule_id, version)`` already exists in the
  repository.
* :class:`UnknownManagedRuleError` - a lookup / update
  targeted a rule_id that does not exist.
* :class:`RuleVersionConflictError` - an attempt to register
  a new version that is not strictly greater than the
  latest known version of the same ``rule_id``.
* :class:`RuleNotInExpectedStateError` - a state-transition
  precondition was not met (e.g. trying to enable a
  CANDIDATE rule).
* :class:`ManagedRuleRetiredError` - an attempt to operate
  on a RETIRED rule. Retire is a one-way operation; the
  rule's id+version remain in the catalogue for audit
  traceability.
* :class:`RulePersistenceError` - persistence layer failure
  (subclass of the framework's :class:`PersistenceError`).

The error module never raises bare :class:`Exception` for
normal input flow; all unexpected exceptions in the
service layer are quarantined to the service's ``errors``
list (mirroring the detection / correlation / timeline
/ severity engines' behaviour, Section 91).
"""
from __future__ import annotations

from ...domain.errors import DomainError, PersistenceError


class RuleManagementError(DomainError):
    """Base class for all rule-management domain errors."""


class RuleDefinitionValidationError(RuleManagementError):
    """A rule definition failed the documented server-side validation gates.

    ``field`` carries the dotted path of the offending field
    when known, so a future HTTP API can surface a structured
    400 response.
    """

    code = "rule_definition_validation_error"
    http_status = 400


class DuplicateManagedRuleError(RuleManagementError):
    """A rule with the same ``(rule_id, version)`` already exists."""

    code = "duplicate_managed_rule"
    http_status = 409


class UnknownManagedRuleError(RuleManagementError):
    """A lookup / update targeted a rule_id that is not registered."""

    code = "unknown_managed_rule"
    http_status = 404


class RuleVersionConflictError(RuleManagementError):
    """An attempt to register a new version that is not strictly greater.

    Versioning is a "monotonically increasing integer per
    rule_id" model (Phase 4.2, Section 33). Registering a
    version that is less than or equal to the latest known
    version is rejected.
    """

    code = "rule_version_conflict"
    http_status = 409


class RuleNotInExpectedStateError(RuleManagementError):
    """A state-transition precondition was not met.

    Example: trying to enable a CANDIDATE rule, or trying
    to retire a rule that is already RETIRED. The
    "candidate -> approved -> enabled" funnel
    (Section 59, Section 89) is enforced here.
    """

    code = "rule_not_in_expected_state"
    http_status = 409


class ManagedRuleRetiredError(RuleManagementError):
    """An attempt to operate on a RETIRED rule.

    Retire is a one-way operation. The rule's id+version
    remain in the catalogue for audit traceability, but
    the rule is invisible to the runtime evaluator and
    cannot be re-enabled, re-approved, or updated.
    """

    code = "managed_rule_retired"
    http_status = 409


class RulePersistenceError(PersistenceError):
    """Persistence layer failure scoped to the rule catalogue.

    The safe message MUST NOT include the underlying driver
    error string; the internal detail MAY include it for
    server-side logs only. This is a thin specialization of
    the framework's :class:`PersistenceError` so callers
    can catch a single persistence exception type while
    still getting a precise code.
    """

    code = "rule_persistence_error"
    http_status = 503


__all__ = [
    "DuplicateManagedRuleError",
    "ManagedRuleRetiredError",
    "RuleDefinitionValidationError",
    "RuleManagementError",
    "RuleNotInExpectedStateError",
    "RulePersistenceError",
    "RuleVersionConflictError",
    "UnknownManagedRuleError",
]
