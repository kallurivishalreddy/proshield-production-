"""V2-01 fix: keep the live detection engine governed by managed rules.

Root cause (V2 report, V2-01 / V2-P1): the ingress-plane
``LivePipeline`` built its own ``RuleRegistry`` from
``app.rules._library.nginx`` at startup and never reloaded managed rule
state. ``rule.create / enable / disable / retire`` (analyst plane)
mutated the analyst registry + the ``managed_rules`` collection, but
the live detector kept a *static* registry: a rule the operator
disabled in the UI **kept firing**, and operator-created declarative
rules **never fired**.

Fix (owning layer: live pipeline composition)
---------------------------------------------
:class:`ManagedRuleLifecycleSync` owns the reconciliation between the
persisted ``managed_rules`` state and the in-memory registry the
``DetectionEngine`` evaluates:

1. ``seed_builtins()`` — idempotently persist the built-in library
   rules into ``managed_rules`` (mirroring the analyst plane's
   seeding) so the UI and the detector always agree on the catalogue.
2. ``sync()`` — reconcile the registry with the persisted state via
   the documented :meth:`RuleManagementService.reload_registry`:
   enabled rules are (re)registered as
   :class:`GenericDeclarativeRule` (``enabled=False`` definitions stay
   registered but never evaluable), retired rules are unregistered,
   and rules deleted from the store are dropped.

``LivePipeline.process`` calls ``sync()`` before every detection pass,
so a disable/enable/retire made in the UI is honoured by the *very
next* event — no restart, no redeploy. The cost is one bounded
``managed_rules`` read per event (a handful of documents), which the
MVP accepts in exchange for the operator guarantee the V2 audit
demanded; the sync is fail-open only for *read* errors (an operator
can never accidentally disable all detection because the store is
momentarily unreadable — the previously synced registry keeps
serving).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

_log = logging.getLogger(__name__)

_NGINX_SPECS = ("app.rules._library.nginx",)


class ManagedRuleLifecycleSync:
    """Reconciles ``managed_rules`` into a live ``RuleRegistry``."""

    def __init__(
        self,
        *,
        repository: Any,
        registry: Any,
        config: Optional[Any] = None,
        library_specs: tuple = _NGINX_SPECS,
    ) -> None:
        """``repository`` is a :class:`RuleRepository`; ``registry``
        the :class:`RuleRegistry` the ``DetectionEngine`` evaluates
        (pre-loaded with the built-in library)."""
        if repository is None:
            raise ValueError("repository is required")
        if registry is None:
            raise ValueError("registry is required")
        self._repository = repository
        self._registry = registry
        self._config = config
        self._library_specs = tuple(library_specs) if library_specs else ()
        self._service: Optional[Any] = None
        self._seeded = False

    # ------------------------------------------------------------- public
    def seed_builtins(self) -> int:
        """Idempotently persist built-in library rules into managed state.

        Returns the number of rules now governed by ``managed_rules``.
        Mirrors the analyst plane's ``_seed_managed_rules`` so both
        planes agree on the catalogue without sharing a private
        deployment helper.
        """
        from ..rules.management.definition import RuleDefinition
        from ..rules.management.service import RuleManagementService
        from ..rules.types import RuleState
        from ..severity.models import SeverityBand

        if not self._registry.list_all() and self._library_specs:
            try:
                from ..rules.loader import load_rules_from_specs

                load_rules_from_specs(self._registry, list(self._library_specs))
            except Exception as exc:  # pragma: no cover - best effort
                _log.warning("managed_rule_sync.library_load_failed %s", exc)

        existing = {
            (d.rule_id, d.version)
            for d in self._repository.find_all()
        }
        created = 0
        for rule in self._registry.list_all():
            metadata = rule.metadata
            rule_id = metadata.rule_id
            version = metadata.version
            if (rule_id, version) in existing:
                # 2026-09-18 audit: a row created before the shipped rule
                # declared its capability owner keeps ``capability_id: null``
                # forever (seeding is insert-only), so the persisted catalogue
                # contradicts the live registry and the Rules page truthfully
                # reports "no capability owner" for a rule the detector knows
                # is ``cap-nginx``. Fill a MISSING owner from the shipped
                # definition; never overwrite an owner that is already set.
                owner = getattr(metadata, "capability_id", None)
                if owner:
                    self._backfill_owner(rule_id, version, owner)
                continue
            raw_severity = getattr(metadata, "severity", "medium")
            try:
                severity = SeverityBand(str(raw_severity).lower())
            except (ValueError, AttributeError):
                severity = SeverityBand.MEDIUM
            state_value = (
                metadata.state.value
                if hasattr(metadata.state, "value")
                else str(metadata.state)
            )
            if state_value not in (
                RuleState.APPROVED.value,
                RuleState.CANDIDATE.value,
            ):
                state_value = RuleState.APPROVED.value
            try:
                definition = RuleDefinition(
                    rule_id=rule_id,
                    version=version,
                    name=metadata.name,
                    description=getattr(metadata, "description", ""),
                    category=metadata.category,
                    sources=tuple(metadata.sources),
                    event_types=tuple(metadata.event_types),
                    tags=tuple(metadata.tags),
                    references=tuple(getattr(metadata, "references", ())),
                    state=state_value,
                    enabled=bool(getattr(metadata, "enabled", True)),
                    severity=severity,
                    # Phase 5.2: the seeded record carries the rule's
                    # capability ownership so the persisted catalogue and the
                    # live evaluator agree on which capability owns the rule
                    # (and so ``capability.list_rules`` is truthful by
                    # ownership rather than by a source-string heuristic).
                    capability_id=getattr(metadata, "capability_id", None),
                )
            except Exception as exc:  # noqa: BLE001 - validation gate
                _log.warning(
                    "managed_rule_sync.seed_definition_failed "
                    "rule_id=%s error=%s",
                    rule_id,
                    type(exc).__name__,
                )
                continue
            try:
                self._repository.create(definition)
                created += 1
            except Exception as exc:  # noqa: BLE001 - best effort
                _log.warning(
                    "managed_rule_sync.seed_persist_failed "
                    "rule_id=%s error=%s",
                    rule_id,
                    type(exc).__name__,
                )
        self._seeded = True
        governed = len(existing) + created
        _log.info(
            "managed_rule_sync.seeded_builtins created=%d governed=%d",
            created,
            governed,
        )
        return governed

    def sync(self) -> None:
        """Reconcile the live registry with the persisted rule state.

        Called before every detection pass. Failure-tolerant: a read
        error leaves the previously synced registry in place and is
        logged (fail-open on *management reads*, never on detection
        semantics).
        """
        try:
            service = self._management_service()
            count = service.reload_registry()
            _log.debug(
                "managed_rule_sync.synced rules=%d", count,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "managed_rule_sync.sync_failed error=%s",
                type(exc).__name__,
            )

    # --------------------------------------------------------- internals
    def _backfill_owner(self, rule_id: str, version: int, owner: str) -> int:
        """Fill a missing capability owner on a persisted rule row.

        Best-effort: a repository without the backfill capability (the
        in-memory dev doubles) or a write error is logged and skipped — the
        seeding pass must never fail because the catalogue could not be
        reconciled. Returns 1 when a row was updated, else 0.
        """
        backfill = getattr(
            self._repository, "set_capability_id_if_missing", None
        )
        if not callable(backfill):
            return 0
        try:
            updated = backfill(rule_id, version, owner)
        except Exception as exc:  # noqa: BLE001 - best effort
            _log.warning(
                "managed_rule_sync.owner_backfill_failed rule_id=%s error=%s",
                rule_id,
                type(exc).__name__,
            )
            return 0
        if updated:
            _log.info(
                "managed_rule_sync.owner_backfilled rule_id=%s capability_id=%s",
                rule_id,
                owner,
            )
        return 1 if updated else 0

    def _management_service(self) -> Any:
        if self._service is None:
            from ..rules.management.service import RuleManagementService

            self._service = RuleManagementService(
                repository=self._repository,
                registry=self._registry,
                config=self._config,
            )
        return self._service


__all__ = ["ManagedRuleLifecycleSync"]
