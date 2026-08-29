"""Deterministic rule loading and discovery.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md (Sections
9, 87-91) and docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5).

This module bridges "the rule files exist" and "the registry has them".
The pattern mirrors the connector loader documented in Phase 4.1
(``app/connectors/``): a list of ``module.path`` strings, each of
which must expose either a ``RULES`` iterable of rule *instances* or
``RULE_FACTORIES`` iterable of zero-arg callables.
"""
from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any, Iterable, List, Sequence, Tuple

from .registry import (
    RuleRegistry,
    RuleValidationError,
)
from .rule import Rule


# A spec is a module path string. We do NOT support the
# ``name:module:Class`` triple syntax here because rule loading is
# simpler than connector loading: a module may expose a list of
# already-instantiated rules OR a list of zero-arg factories. We do
# not need per-class lookup.
RuleModuleSpec = str


def _iter_namespace(value: Any, *, name: str) -> Iterable[Any]:
    """Return an iterable view of a module attribute.

    Accepts tuples, lists, and frozensets. Raises a
    :class:`RuleValidationError` for any other type so a typo is
    surfaced at load time rather than at evaluation time.
    """
    if isinstance(value, (list, tuple, frozenset)):
        return value
    raise RuleValidationError(
        safe_message=(
            f"module export {name!r} must be a list, tuple, "
            "or frozenset"
        ),
        internal_detail=f"got {type(value).__name__}",
    )


def discover_rules_in_module(module: ModuleType) -> List[Rule]:
    """Find every :class:`Rule` exposed by ``module``.

    The function is intentionally pure: it inspects the module
    namespace, instantiates factories if present, and returns a
    deterministic list of rule *instances*. It does NOT register
    them.

    Supported exports
    ----------------

    * ``RULES``: iterable of :class:`Rule` instances.
    * ``RULE_FACTORIES``: iterable of zero-arg callables, each
      returning a :class:`Rule` instance.

    The two are merged (factories first, then instances) and the
    final list is sorted by ``(rule_id, version)`` for determinism.
    """
    if not isinstance(module, ModuleType):
        raise RuleValidationError(
            safe_message="discover_rules_in_module requires a module",
            internal_detail=f"got {type(module).__name__}",
        )
    out: List[Rule] = []

    factories = getattr(module, "RULE_FACTORIES", None)
    if factories is not None:
        for f in _iter_namespace(factories, name="RULE_FACTORIES"):
            if not callable(f):
                raise RuleValidationError(
                    safe_message=(
                        "RULE_FACTORIES entries must be zero-arg callables"
                    ),
                    internal_detail=(
                        f"got non-callable: {f!r} of type "
                        f"{type(f).__name__}"
                    ),
                )
            rule = f()
            if not isinstance(rule, Rule):
                raise RuleValidationError(
                    safe_message=(
                        "RULE_FACTORIES entries must return a Rule instance"
                    ),
                    internal_detail=(
                        f"factory {getattr(f, '__qualname__', f)!r} "
                        f"returned {type(rule).__name__}"
                    ),
                )
            out.append(rule)

    rules = getattr(module, "RULES", None)
    if rules is not None:
        for r in _iter_namespace(rules, name="RULES"):
            if not isinstance(r, Rule):
                raise RuleValidationError(
                    safe_message="RULES entries must be Rule instances",
                    internal_detail=f"got {type(r).__name__}",
                )
            out.append(r)

    out.sort(key=lambda r: (r.metadata.rule_id, r.metadata.version))
    return out


def load_rules_from_specs(
    registry: RuleRegistry,
    specs: Sequence[RuleModuleSpec],
) -> Tuple[int, List[Rule]]:
    """Import each module in ``specs``, discover its rules, and
    register them in ``registry``.

    The function is deterministic: modules are processed in the
    given order, and rules within a module in
    ``(rule_id, version)`` order. It returns ``(count, rules)`` where
    ``count`` is the number of rules newly registered, and ``rules``
    is the combined list.

    A failing module aborts the entire load: partial loading is
    rejected because the registry should never be left in a
    half-populated state.
    """
    if not isinstance(registry, RuleRegistry):
        raise RuleValidationError(
            safe_message="load_rules_from_specs requires a RuleRegistry",
            internal_detail=f"got {type(registry).__name__}",
        )
    discovered: List[Rule] = []
    for spec in specs:
        if not isinstance(spec, str) or not spec:
            raise RuleValidationError(
                safe_message="rule spec must be a non-empty module path",
                internal_detail=f"got {spec!r}",
            )
        try:
            module = importlib.import_module(spec)
        except ImportError as exc:
            raise RuleValidationError(
                safe_message=f"could not import rule module {spec!r}",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        discovered.extend(discover_rules_in_module(module))

    registered: List[Rule] = []
    for rule in discovered:
        registry.register(rule)
        registered.append(rule)
    return len(registered), registered