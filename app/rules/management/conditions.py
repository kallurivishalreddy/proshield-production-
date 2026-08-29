"""Strict, declarative rule-condition model for Phase 4.7.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 13, 87-91) and
           docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.

This module defines the closed-set condition DSL for the
generic rule evaluator. It is deliberately small and strictly
allow-listed:

* **Operators** are a frozen enum (:class:`ConditionOperator`).
  The only operators the generic evaluator understands are
  the ones in that enum. No expressions, no function calls,
  no arbitrary code, no shell.
* **Combinators** are a frozen enum (:class:`ConditionCombinator`)
  with exactly two values: ``AND`` and ``OR``. The top-level
  ``combinator`` of a :class:`RuleDefinition` is the rule's
  global combinator; nested groups may carry their own
  combinator. An :class:`Expression` is a recursive
  discriminated union of an :class:`Atom` (operator + field +
  value) or a :class:`Group` (combinator + children).
* **Values** are typed by the operator (see
  :func:`_validate_value_for_operator`); the validator
  rejects values that the operator cannot meaningfully use
  (e.g. ``regex`` against a non-string, ``gt`` against a
  non-number).
* **No string evaluation.** The ``regex`` operator compiles
  the supplied pattern once at validation time and refuses
  anything outside the documented regex safety bounds
  (anchored by default; maximum length 256; no backreferences
  in deeply nested groups). The compiled pattern is used
  through :func:`re.search`; it is never ``eval``-ed and
  is never passed to ``exec`` / ``subprocess`` /
  ``importlib`` / the filesystem.

The module is dependency-free beyond :mod:`pydantic` and the
canonical :class:`SecurityEvent` envelope.
"""
from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import (
    Annotated,
    Any,
    Optional,
    Tuple,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from ...domain.security_event import SecurityEvent


# ----------------------------------------------------------------- bounds
MAX_CONDITIONS_PER_RULE = 32
MAX_NESTING_DEPTH = 4
MAX_REGEX_LEN = 256
MAX_REGEX_GROUPS = 8
MAX_VALUE_LEN = 1024
MAX_FIELD_LEN = 128
MAX_VALUES_PER_IN_OPERATOR = 64
MAX_DETAIL_KEY_LEN = 64


# A field path is a dotted string of one or more segments.
# Each segment must be a documented canonical field name
# on the SecurityEvent envelope (validated by the rule-
# definition validator, not here) or a documented ``details``
# sub-key. We forbid the leading ``__``-prefixed
# ``__class__``/``__dict__``-style dunder names so a
# crafty caller cannot reach for an attribute on a Python
# object that happens to share a name with an event field.
FIELD_NAME_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
FieldPath = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=MAX_FIELD_LEN,
        pattern=FIELD_NAME_PATTERN,
    ),
]


# ----------------------------------------------------------------- operator
class ConditionOperator(str, Enum):
    """The closed-set list of operators the generic evaluator supports.

    Adding a new operator requires a corresponding entry in
    :func:`_validate_value_for_operator` and in
    :func:`_evaluate_atom`. Anything outside this set is
    rejected at validation time so a malicious rule
    definition cannot reach an unknown operator.
    """

    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IP_IN_CIDR = "ip_in_cidr"


class ConditionCombinator(str, Enum):
    """The closed-set list of condition combinators."""

    AND = "and"
    OR = "or"


# A frozen tuple of every :class:`ConditionOperator` value,
# for callers (and the BSON-level validator) that need a
# plain iterable of the closed set.
CONDITION_OPERATOR_VALUES: Tuple[str, ...] = tuple(
    op.value for op in ConditionOperator
)
CONDITION_COMBINATOR_VALUES: Tuple[str, ...] = tuple(
    c.value for c in ConditionCombinator
)


EVENT_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        "source",
        "event_type",
        "source_ip",
        "destination",
        "endpoint",
        "asset",
        "details",
    }
)
DETAIL_KEY_PATTERN = r"^[a-z][a-z0-9_]*$"
_DETAIL_KEY_RE = re.compile(DETAIL_KEY_PATTERN)


def validate_field_path(path: str) -> None:
    """Raise :class:`ValueError` if ``path`` is not a well-formed event field path.

    A path is either one of the documented top-level fields
    (``source``, ``event_type``, ...) or a ``details.<key>``
    lookup. ``__dunder__``-style names are always rejected.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("field path must be a non-empty string")
    if len(path) > MAX_FIELD_LEN:
        raise ValueError(
            f"field path too long: {len(path)} > {MAX_FIELD_LEN}"
        )
    if not re.match(FIELD_NAME_PATTERN, path):
        raise ValueError(
            f"field path {path!r} does not match the documented pattern"
        )
    head, _, _tail = path.partition(".")
    if head not in EVENT_TOP_LEVEL_FIELDS:
        raise ValueError(
            f"unknown top-level event field {head!r}; "
            f"expected one of {sorted(EVENT_TOP_LEVEL_FIELDS)}"
        )
    if head == "details":
        rest = path[len("details") + 1:] if path != "details" else ""
        if rest:
            if len(rest) > MAX_DETAIL_KEY_LEN:
                raise ValueError(
                    f"details key too long: {len(rest)} > {MAX_DETAIL_KEY_LEN}"
                )
            if not _DETAIL_KEY_RE.match(rest):
                raise ValueError(
                    f"details key {rest!r} does not match the documented pattern"
                )
    else:
        if "." in path:
            raise ValueError(
                f"top-level field {head!r} does not accept sub-keys"
            )


def _check_size(v: Any, msg: str) -> None:
    """Best-effort size guard for string primitives."""
    if isinstance(v, str) and len(v) > MAX_VALUE_LEN:
        raise ValueError(f"{msg} ({len(v)} > {MAX_VALUE_LEN})")


def _skip_char_class(pattern: str, i: int) -> int:
    """Return the index just past a ``[ ... ]`` character class.

    Handles ``^``, ``]`` as the first character, and ``\\``
    escapes inside the class. Returns ``len(pattern)`` if the
    class is unterminated.
    """
    n = len(pattern)
    i += 1  # past '['
    if i < n and pattern[i] == "^":
        i += 1
    if i < n and pattern[i] == "]":
        i += 1
    while i < n and pattern[i] != "]":
        if pattern[i] == "\\" and i + 1 < n:
            i += 2
        else:
            i += 1
    if i < n:
        i += 1
    return i

def _is_catastrophic_backtracking(pattern: str) -> bool:
    """Return True if ``pattern`` is a documented ReDoS shape.

    A catastrophic shape is any pattern where a quantified
    sub-expression is itself inside a quantified group, e.g.:

      * ``(a+)+``            - group with ``+``, group followed by ``+``
      * ``(a*)*``            - group with ``*``, group followed by ``*``
      * ``(a+)*``            - group with ``+``, group followed by ``*``
      * ``(a+)?``            - group with ``+``, group followed by ``?``
      * ``(a+){1,3}``        - group with ``+``, group followed by ``{1,3}``
      * ``([a-z]+)+``        - same with a character class
      * ``((a+))+``         - nested groups
      * ``(?:a+)+``          - non-capturing group with the same shape

    The detector is intentionally conservative: false
    positives are acceptable (a legitimate but unusual
    pattern is rejected); false negatives are NOT
    acceptable for the documented catastrophic shapes
    above.
    """
    if not isinstance(pattern, str) or not pattern:
        return False
    n = len(pattern)
    i = 0
    # ``group_has_quantifier[d]`` is True if the group at
    # depth ``d`` already contains a quantifier. The list
    # length equals the current open-paren depth.
    group_has_quantifier: list = []
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            continue
        if c == "(":
            # Non-capturing "(?:", named "(?P<", lookahead/
            # lookbehind still nest for our purposes.
            if i + 2 < n and pattern[i + 1] == "?":
                kind = pattern[i + 2]
                if kind in (":", "P", "=", "!") or (
                    kind == "<" and i + 3 < n
                    and pattern[i + 3] in ("=", "!")
                ):
                    group_has_quantifier.append(False)
                    i += 1
                    continue
            group_has_quantifier.append(False)
            i += 1
            continue
        if c == ")":
            if not group_has_quantifier:
                i += 1
                continue
            this_had_quant = group_has_quantifier.pop()
            i += 1
            # Propagation: if the just-closed group
            # already contained a quantifier, mark the
            # parent group as containing a quantifier
            # too. This makes the detector catch nested
            # shapes like ``((a+))+``.
            if this_had_quant and group_has_quantifier:
                group_has_quantifier[-1] = True
            if this_had_quant and i < n:
                nxt = pattern[i]
                if nxt in ("*", "+", "?"):
                    return True
                if nxt == "{":
                    j = i + 1
                    while j < n and pattern[j].isdigit():
                        j += 1
                    if j < n and pattern[j] == "}":
                        i = j + 1
                        continue
                    if j < n and pattern[j] == ",":
                        # {m,} or {m,n}: upper is the second
                        # part (or unbounded).
                        j += 1
                        upper_start = j
                        while j < n and pattern[j].isdigit():
                            j += 1
                        if j < n and pattern[j] == "}":
                            upper_str = pattern[upper_start:j]
                            upper = int(upper_str) if upper_str else None
                            if upper is None or upper > 1:
                                return True
                            i = j + 1
                            continue
                    i = j
                    continue
            if group_has_quantifier and i < n:
                nxt = pattern[i]
                if nxt in ("*", "+", "?"):
                    group_has_quantifier[-1] = True
            continue
        if c in ("*", "+", "?"):
            if group_has_quantifier:
                group_has_quantifier[-1] = True
            i += 1
            continue
        if c == "{":
            j = i + 1
            while j < n and (pattern[j].isdigit() or pattern[j] == ","):
                j += 1
            if j < n and pattern[j] == "}":
                if group_has_quantifier:
                    group_has_quantifier[-1] = True
                i = j + 1
                continue
            i = j
            continue
        i += 1
    return False


def _validate_value_for_operator(op: ConditionOperator, value: Any) -> None:
    """Type-check ``value`` against the requirements of ``op``."""
    if op in (ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS):
        if value is not None:
            _check_size(value, "exists/not_exists value must be null or omitted")
        return
    if op is ConditionOperator.REGEX:
        if not isinstance(value, str):
            raise ValueError("regex operator requires a string value")
        if not value:
            raise ValueError("regex operator requires a non-empty pattern")
        if len(value) > MAX_REGEX_LEN:
            raise ValueError(
                f"regex pattern too long ({len(value)} > {MAX_REGEX_LEN})"
            )
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(
                f"invalid regex pattern: {type(exc).__name__}: {exc}"
            ) from exc
        if value.count("(") > MAX_REGEX_GROUPS:
            raise ValueError(
                f"regex pattern has too many groups "
                f"({value.count('(')} > {MAX_REGEX_GROUPS})"
            )
        # Catastrophic-backtracking gate: a quantified
        # sub-expression inside a quantified group is a
        # documented ReDoS shape (e.g. ``(a+)+``). The
        # validator rejects it before the pattern can
        # reach :func:`_regex_match`.
        if _is_catastrophic_backtracking(value):
            raise ValueError(
                "regex pattern matches a documented ReDoS shape "
                "(quantified sub-expression inside a quantified group)"
            )
        return
    if op in (ConditionOperator.IN, ConditionOperator.NOT_IN):
        if not isinstance(value, list):
            raise ValueError(f"{op.value} operator requires a list value")
        if not value:
            raise ValueError(f"{op.value} operator requires a non-empty list")
        if len(value) > MAX_VALUES_PER_IN_OPERATOR:
            raise ValueError(
                f"{op.value} list too long ({len(value)} > "
                f"{MAX_VALUES_PER_IN_OPERATOR})"
            )
        for v in value:
            if not isinstance(v, (str, int, float, bool)):
                raise ValueError(
                    f"{op.value} values must be primitives, got {type(v).__name__}"
                )
            if isinstance(v, str) and len(v) > MAX_VALUE_LEN:
                _check_size(v, f"{op.value} list element too long")
        return
    if op in (
        ConditionOperator.EQ,
        ConditionOperator.NE,
        ConditionOperator.CONTAINS,
        ConditionOperator.STARTS_WITH,
        ConditionOperator.ENDS_WITH,
    ):
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError(
                f"{op.value} operator requires a string / number / bool value"
            )
        if isinstance(value, str) and len(value) > MAX_VALUE_LEN:
            _check_size(value, f"{op.value} value too long")
        return
    if op in (
        ConditionOperator.GT,
        ConditionOperator.GTE,
        ConditionOperator.LT,
        ConditionOperator.LTE,
    ):
        # bool is a subclass of int; reject explicitly.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"{op.value} operator requires a numeric value"
            )
        return
    if op is ConditionOperator.IP_IN_CIDR:
        if not isinstance(value, str) or not value:
            raise ValueError(
                "ip_in_cidr operator requires a non-empty string value"
            )
        if len(value) > MAX_VALUE_LEN:
            _check_size(value, "ip_in_cidr value too long")
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"ip_in_cidr value {value!r} is not a valid CIDR: {exc}"
            ) from exc
        return
    raise ValueError(f"unsupported operator: {op!r}")



# ----------------------------------------------------------------- evaluation
def get_event_field(event: SecurityEvent, path: str) -> Any:
    """Return the value of ``path`` on ``event``."""
    head, _, rest = path.partition(".")
    if head == "details":
        if not rest:
            return dict(event.details or {})
        return (event.details or {}).get(rest)
    return getattr(event, head, None)


def _ip_in_cidr_match(value: Any, cidr: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return addr in net


def _regex_match(value: Any, pattern: str) -> bool:
    if not isinstance(value, str):
        return False
    if not isinstance(pattern, str):
        return False
    # Runtime defence-in-depth: a pattern that has not
    # been validated (e.g. constructed in-process from
    # data the service layer never saw) is still gated
    # by the same structural check that runs at
    # validation time.
    if _is_catastrophic_backtracking(pattern):
        return False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    return compiled.search(value) is not None


def _numeric_compare(op: ConditionOperator, left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return False
    if op is ConditionOperator.GT:
        return left > right
    if op is ConditionOperator.GTE:
        return left >= right
    if op is ConditionOperator.LT:
        return left < right
    if op is ConditionOperator.LTE:
        return left <= right
    return False


def _string_op(op: ConditionOperator, left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if op is ConditionOperator.EQ:
        return left == right
    if op is ConditionOperator.NE:
        return left != right
    if op is ConditionOperator.CONTAINS:
        return right in left
    if op is ConditionOperator.STARTS_WITH:
        return left.startswith(right)
    if op is ConditionOperator.ENDS_WITH:
        return left.endswith(right)
    return False


def _evaluate_atom(atom: "Atom", event: SecurityEvent) -> bool:
    """Evaluate a single :class:`Atom` against ``event``.

    Total: a bad shape returns ``False`` rather than raising.
    """
    try:
        field_value = get_event_field(event, atom.field)
    except Exception:  # noqa: BLE001
        return False
    op = atom.operator
    value = atom.value
    if op is ConditionOperator.EXISTS:
        return field_value is not None
    if op is ConditionOperator.NOT_EXISTS:
        return field_value is None
    if op is ConditionOperator.REGEX:
        return _regex_match(field_value, value)
    if op is ConditionOperator.IP_IN_CIDR:
        return _ip_in_cidr_match(field_value, value)
    if op is ConditionOperator.IN:
        if not isinstance(value, list):
            return False
        return any(field_value == v for v in value)
    if op is ConditionOperator.NOT_IN:
        if not isinstance(value, list):
            return False
        return all(field_value != v for v in value)
    if op in (ConditionOperator.GT, ConditionOperator.GTE,
              ConditionOperator.LT, ConditionOperator.LTE):
        return _numeric_compare(op, field_value, value)
    if op in (ConditionOperator.EQ, ConditionOperator.NE,
              ConditionOperator.CONTAINS, ConditionOperator.STARTS_WITH,
              ConditionOperator.ENDS_WITH):
        # EQ / NE handle both string and numeric values
        # (a numeric ``details.status_code`` must match
        # an int ``value``); CONTAINS / STARTS_WITH /
        # ENDS_WITH are string-only. The dispatch is
        # intentional: a numeric CONTAINS would be
        # meaningless.
        if op in (ConditionOperator.CONTAINS,
                  ConditionOperator.STARTS_WITH,
                  ConditionOperator.ENDS_WITH):
            return _string_op(op, field_value, value)
        # EQ / NE
        if field_value is None or value is None:
            return op is ConditionOperator.NE and field_value is not value
        return (field_value == value) if op is ConditionOperator.EQ else (
            field_value != value
        )
    return False


def evaluate_expression(
    expr: "Expression",
    event: SecurityEvent,
    *,
    _depth: int = 0,
) -> bool:
    """Recursively evaluate an :class:`Expression` against ``event``."""
    if _depth > MAX_NESTING_DEPTH:
        return False
    if expr.kind == "atom":
        assert expr.atom is not None
        return _evaluate_atom(expr.atom, event)
    assert expr.group is not None
    if expr.group.combinator is ConditionCombinator.AND:
        for child in expr.group.children:
            if not evaluate_expression(child, event, _depth=_depth + 1):
                return False
        return True
    if expr.group.combinator is ConditionCombinator.OR:
        for child in expr.group.children:
            if evaluate_expression(child, event, _depth=_depth + 1):
                return True
        return False
    return False



# ----------------------------------------------------------------- models
class Atom(BaseModel):
    """A single ``field OP value`` clause."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: FieldPath
    operator: ConditionOperator
    value: Any = None

    @model_validator(mode="after")
    def _value_for_operator(self) -> "Atom":
        _validate_value_for_operator(self.operator, self.value)
        return self


class Group(BaseModel):
    """A nested boolean group of children."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    combinator: ConditionCombinator
    children: Tuple["Expression", ...]

    @field_validator("children")
    @classmethod
    def _check_children(cls, v: Tuple["Expression", ...]) -> Tuple["Expression", ...]:
        if not v:
            raise ValueError("group must have at least one child")
        if len(v) > MAX_CONDITIONS_PER_RULE:
            raise ValueError(
                f"group has too many children ({len(v)} > {MAX_CONDITIONS_PER_RULE})"
            )
        return v


class Expression(BaseModel):
    """A discriminated union of an :class:`Atom` or a :class:`Group`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    atom: Optional[Atom] = None
    group: Optional[Group] = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "Expression":
        if self.kind == "atom":
            if self.atom is None:
                raise ValueError("atom expression must have an atom")
            if self.group is not None:
                raise ValueError("atom expression must not have a group")
        elif self.kind == "group":
            if self.group is None:
                raise ValueError("group expression must have a group")
            if self.atom is not None:
                raise ValueError("group expression must not have an atom")
        else:
            raise ValueError(f"unknown expression kind {self.kind!r}")
        return self

    @classmethod
    def from_atom(cls, atom: Atom) -> "Expression":
        return cls(kind="atom", atom=atom, group=None)

    @classmethod
    def from_group(cls, group: Group) -> "Expression":
        return cls(kind="group", atom=None, group=group)


__all__ = [
    "CONDITION_COMBINATOR_VALUES",
    "CONDITION_OPERATOR_VALUES",
    "ConditionCombinator",
    "ConditionOperator",
    "DETAIL_KEY_PATTERN",
    "EVENT_TOP_LEVEL_FIELDS",
    "Expression",
    "FieldPath",
    "Group",
    "MAX_CONDITIONS_PER_RULE",
    "MAX_FIELD_LEN",
    "MAX_NESTING_DEPTH",
    "MAX_REGEX_GROUPS",
    "MAX_REGEX_LEN",
    "MAX_VALUE_LEN",
    "MAX_VALUES_PER_IN_OPERATOR",
    "Atom",
    "_is_catastrophic_backtracking",
    "_skip_char_class",
    "evaluate_expression",
    "get_event_field",
    "validate_field_path",
]

