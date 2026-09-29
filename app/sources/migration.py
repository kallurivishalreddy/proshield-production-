"""Legacy Source -> Capability migration (Phase 5.2).

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md §19,
docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md §29/§38.

Contract (all six properties are load-bearing and individually tested):

``deterministic``
    The plan is a pure function of persisted state. Rows are processed in
    sorted ``source_instance_id`` order and every decision comes from
    :mod:`app.sources.capability_binding`; no wall-clock, no randomness,
    no dict-iteration order.

``idempotent``
    A second run over the same data produces **zero** changes and writes
    **zero** audit records. "Already bound and committed" is a distinct,
    explicitly-counted outcome — re-running is a no-op, not a re-write.

``restart-safe``
    All state is read from MongoDB at call time; nothing is memoised in
    process memory, so a process restart cannot change the outcome.

``dry-run capable``
    ``run(dry_run=True)`` (the default) returns the identical report it
    would produce for a real run while writing nothing at all.

``audited``
    Every applied change appends a ``source_audit`` record carrying
    before/after snapshots and the changed field list. A migration is
    never a silent security-sensitive state change.

``non-fabricating``
    When the mapping is not available — an unknown source type, or a
    seeded capability that is genuinely absent from the registry — the row
    is left with ``capability_id = None`` and marked
    ``requires_verification``. It is **never** given an invented owner and
    its historical fields are never rewritten (freeze §38: "Never turn
    missing historical truth into invented historical truth").
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .audit import (
    AUDIT_TRACKED_FIELDS,
    build_audit_record,
    append_audit_record,
    snapshot_source,
)
from .capability_binding import (
    deterministic_mapping_profile,
    resolve_capability_id_for_type,
    resolve_capability_id_for_sources,
)
from .models import CapabilityBindingStatus

_log = logging.getLogger(__name__)

#: Bumped whenever the deterministic mapping changes. Recorded in the
#: report and in every audit record so a future phase can tell two
#: migration generations apart without guessing.
CAPABILITY_MIGRATION_VERSION = 1

ACTION_SOURCE_BIND = "source_capability_bind"
ACTION_SOURCE_QUARANTINE = "source_capability_quarantine"
ACTION_RULE_BACKFILL = "rule_capability_backfill"

OUTCOME_BOUND = "bound"
OUTCOME_ALREADY_BOUND = "already_bound"
OUTCOME_QUARANTINED = "quarantined"
OUTCOME_UNCHANGED = "unchanged"
OUTCOME_AMBIGUOUS = "ambiguous"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SourceMigrationChange:
    """The planned (or applied) capability decision for one source row."""

    source_instance_id: str
    human_id: str
    source_type: str
    outcome: str
    capability_id: Optional[str] = None
    capability_version: Optional[int] = None
    mapping_profile_id: Optional[str] = None
    reason: str = ""

    @property
    def applied(self) -> bool:
        return self.outcome in (OUTCOME_BOUND, OUTCOME_QUARANTINED)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_instance_id": self.source_instance_id,
            "human_id": self.human_id or None,
            "source_type": self.source_type,
            "outcome": self.outcome,
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "mapping_profile_id": self.mapping_profile_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RuleMigrationChange:
    """The planned (or applied) capability decision for one legacy rule."""

    rule_id: str
    rule_version: int
    sources: Tuple[str, ...]
    outcome: str
    capability_id: Optional[str] = None
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "sources": list(self.sources),
            "outcome": self.outcome,
            "capability_id": self.capability_id,
            "reason": self.reason,
        }


@dataclass
class MigrationReport:
    """Evidence for one migration run (dry-run or applied)."""

    dry_run: bool
    version: int = CAPABILITY_MIGRATION_VERSION
    sources_scanned: int = 0
    sources_already_bound: int = 0
    sources_bound: int = 0
    sources_quarantined: int = 0
    sources_unchanged: int = 0
    rules_scanned: int = 0
    rules_already_bound: int = 0
    rules_bound: int = 0
    rules_ambiguous: int = 0
    documents_modified: int = 0
    audit_records_written: int = 0
    registry_reloaded: int = 0
    source_changes: List[SourceMigrationChange] = field(
        default_factory=list
    )
    rule_changes: List[RuleMigrationChange] = field(default_factory=list)

    @property
    def changed(self) -> int:
        return self.sources_bound + self.sources_quarantined

    @property
    def is_noop(self) -> bool:
        return self.changed == 0 and self.rules_bound == 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dry_run": bool(self.dry_run),
            "migration_version": int(self.version),
            "sources": {
                "scanned": int(self.sources_scanned),
                "already_bound": int(self.sources_already_bound),
                "bound": int(self.sources_bound),
                "quarantined": int(self.sources_quarantined),
                "unchanged": int(self.sources_unchanged),
            },
            "rules": {
                "scanned": int(self.rules_scanned),
                "already_bound": int(self.rules_already_bound),
                "bound": int(self.rules_bound),
                "ambiguous": int(self.rules_ambiguous),
            },
            "documents_modified": int(self.documents_modified),
            "audit_records_written": int(self.audit_records_written),
            "registry_reloaded": int(self.registry_reloaded),
            "source_changes": [c.as_dict() for c in self.source_changes],
            "rule_changes": [c.as_dict() for c in self.rule_changes],
        }


class SourceCapabilityMigration:
    """Deterministic, audited, idempotent legacy binding backfill."""

    def __init__(
        self,
        *,
        source_repository: Any,
        capability_lookup: Any,
        registry: Any = None,
        rule_repository: Any = None,
        capability_audit_collection: Any = None,
    ) -> None:
        if source_repository is None:
            raise ValueError("source_repository is required")
        if capability_lookup is None:
            raise ValueError("capability_lookup is required")
        self._sources = source_repository
        self._capability_lookup = capability_lookup
        self._registry = registry
        self._rules = rule_repository
        self._capability_audit = capability_audit_collection

    # ------------------------------------------------------------------ plan
    def plan_sources(
        self,
    ) -> Tuple[List[SourceMigrationChange], Dict[str, int]]:
        """Compute the deterministic source-side plan (no writes)."""
        rows = sorted(
            (
                r
                for r in self._sources.iter_raw_documents()
                if isinstance(r, dict)
            ),
            key=lambda r: str(r.get("source_instance_id") or ""),
        )
        changes: List[SourceMigrationChange] = []
        counters = {
            "scanned": 0,
            "already_bound": 0,
            "bound": 0,
            "quarantined": 0,
            "unchanged": 0,
        }
        for row in rows:
            counters["scanned"] += 1
            sid = str(row.get("source_instance_id") or "")
            human_id = str(row.get("human_id") or "")
            source_type = str(row.get("source_type") or "")
            existing_id = row.get("capability_id")
            status = row.get("capability_binding_status")
            if existing_id and status == CapabilityBindingStatus.BOUND.value:
                # Idempotency: already migrated and committed. Counted
                # distinctly so a second run visibly reports a no-op.
                counters["already_bound"] += 1
                changes.append(
                    SourceMigrationChange(
                        source_instance_id=sid,
                        human_id=human_id,
                        source_type=source_type,
                        outcome=OUTCOME_ALREADY_BOUND,
                        capability_id=str(existing_id),
                        capability_version=row.get("capability_version"),
                        mapping_profile_id=row.get("mapping_profile_id"),
                        reason="already bound by an earlier run",
                    )
                )
                continue
            if (
                existing_id is None
                and status
                == CapabilityBindingStatus.REQUIRES_VERIFICATION.value
            ):
                # Idempotency: already quarantined by an earlier run, with
                # nothing about the input changed. The *decision* is
                # unchanged, so this is not a change: the row is not
                # rewritten and no duplicate audit record is appended.
                # If the registry later gains the capability, the row falls
                # through to the ``bound`` branch below — which IS a real
                # change and is audited as one.
                counters["unchanged"] += 1
                changes.append(
                    SourceMigrationChange(
                        source_instance_id=sid,
                        human_id=human_id,
                        source_type=source_type,
                        outcome=OUTCOME_UNCHANGED,
                        reason=(
                            "already quarantined (requires verification) "
                            "by an earlier run"
                        ),
                    )
                )
                continue
            if existing_id:
                # A half-migrated row (capability claimed but not marked
                # bound) is not trusted: the invariant is re-derived from
                # the deterministic map rather than assumed.
                _log.warning(
                    "source_migration.inconsistent_binding row=%s "
                    "status=%r capability_id=%r",
                    sid,
                    status,
                    existing_id,
                )
            resolved_id = resolve_capability_id_for_type(source_type)
            if resolved_id is None:
                counters["quarantined"] += 1
                changes.append(
                    SourceMigrationChange(
                        source_instance_id=sid,
                        human_id=human_id,
                        source_type=source_type,
                        outcome=OUTCOME_QUARANTINED,
                        reason=(
                            "no deterministic capability mapping for "
                            f"source_type={source_type!r}"
                        ),
                    )
                )
                continue
            capability, version_int, refusal = self._load_capability(
                resolved_id
            )
            if capability is None or version_int is None:
                counters["quarantined"] += 1
                changes.append(
                    SourceMigrationChange(
                        source_instance_id=sid,
                        human_id=human_id,
                        source_type=source_type,
                        outcome=OUTCOME_QUARANTINED,
                        reason=refusal,
                    )
                )
                continue
            counters["bound"] += 1
            changes.append(
                SourceMigrationChange(
                    source_instance_id=sid,
                    human_id=human_id,
                    source_type=source_type,
                    outcome=OUTCOME_BOUND,
                    capability_id=resolved_id,
                    capability_version=version_int,
                    # The mapping profile is resolved through the same
                    # deterministic helper the new-source path uses, so a
                    # migrated row behaves like an equivalent natively
                    # registered one instead of silently dropping to None
                    # (5.2-R-05). A capability that declares exactly one
                    # profile for this source type has that profile selected;
                    # one that declares none, or several, yields None — the
                    # honest "no deterministic answer" state, never a guess.
                    mapping_profile_id=deterministic_mapping_profile(
                        capability, source_type=source_type
                    ),
                    reason=(
                        "deterministic source_type -> capability mapping"
                    ),
                )
            )
        return changes, counters

    def _load_capability(
        self, capability_id: str
    ) -> Tuple[Any, Optional[int], str]:
        """Resolve a capability record + version, or explain the refusal."""
        try:
            capability = self._capability_lookup(capability_id)
        except Exception as exc:  # noqa: BLE001 - lookup is pluggable
            _log.warning(
                "source_migration.capability_lookup_failed "
                "capability_id=%s error=%s",
                capability_id,
                type(exc).__name__,
            )
            return None, None, (
                f"capability lookup failed for {capability_id!r}"
            )
        if capability is None:
            # The map names a capability that the registry does not hold.
            # Refuse to invent one: quarantine instead.
            return None, None, (
                f"mapped capability {capability_id!r} is not present in "
                "the registry"
            )
        version = (
            capability.get("version")
            if isinstance(capability, dict)
            else getattr(capability, "version", None)
        )
        try:
            return capability, int(version), ""
        except (TypeError, ValueError):
            return None, None, (
                f"mapped capability {capability_id!r} has no usable version"
            )

    # ------------------------------------------------------------------ rules
    def plan_rules(
        self,
    ) -> Tuple[List[RuleMigrationChange], Dict[str, int]]:
        """Compute the deterministic rule-side plan (no writes).

        A legacy rule's ``sources[]`` may be ambiguous (a cross-source rule
        belongs to no single capability). Such a rule is reported as
        ``ambiguous`` and left with ``capability_id = None`` — the honest
        "not owned by one capability" state — rather than being assigned an
        arbitrary owner.
        """
        changes: List[RuleMigrationChange] = []
        counters = {"scanned": 0, "already_bound": 0, "bound": 0,
                    "ambiguous": 0}
        if self._rules is None:
            return changes, counters
        try:
            definitions = list(self._rules.find_all())
        except Exception as exc:  # noqa: BLE001 - repository is pluggable
            _log.warning(
                "rule_migration.find_all_failed error=%s",
                type(exc).__name__,
            )
            return changes, counters
        for definition in sorted(
            definitions,
            key=lambda d: (str(getattr(d, "rule_id", "")),
                           int(getattr(d, "version", 0) or 0)),
        ):
            counters["scanned"] += 1
            rule_id = str(getattr(definition, "rule_id", "") or "")
            version = int(getattr(definition, "version", 0) or 0)
            sources = tuple(getattr(definition, "sources", ()) or ())
            existing = getattr(definition, "capability_id", None)
            if existing:
                counters["already_bound"] += 1
                changes.append(
                    RuleMigrationChange(
                        rule_id=rule_id,
                        rule_version=version,
                        sources=sources,
                        outcome=OUTCOME_ALREADY_BOUND,
                        capability_id=str(existing),
                        reason="already bound by an earlier run",
                    )
                )
                continue
            resolved = resolve_capability_id_for_sources(sources)
            if resolved is None:
                counters["ambiguous"] += 1
                changes.append(
                    RuleMigrationChange(
                        rule_id=rule_id,
                        rule_version=version,
                        sources=sources,
                        outcome=OUTCOME_AMBIGUOUS,
                        reason=(
                            "sources[] does not resolve to exactly one "
                            "capability"
                        ),
                    )
                )
                continue
            counters["bound"] += 1
            changes.append(
                RuleMigrationChange(
                    rule_id=rule_id,
                    rule_version=version,
                    sources=sources,
                    outcome=OUTCOME_BOUND,
                    capability_id=resolved,
                    reason=(
                        "unambiguous sources[] -> capability mapping"
                    ),
                )
            )
        return changes, counters

    # ------------------------------------------------------------------- run
    def run(
        self,
        *,
        dry_run: bool = True,
        actor: str = "system",
        include_rules: bool = True,
    ) -> MigrationReport:
        """Plan (and optionally apply) the legacy capability backfill.

        ``dry_run=True`` (the default) is a pure read: the returned report is
        identical in shape and counts to what an apply would produce, and
        nothing is written and no audit record is appended.
        """
        report = MigrationReport(dry_run=bool(dry_run))
        source_changes, counters = self.plan_sources()
        report.sources_scanned = int(counters["scanned"])
        report.sources_already_bound = int(counters["already_bound"])
        report.sources_unchanged = int(counters["unchanged"])
        report.source_changes = list(source_changes)
        rule_changes: List[RuleMigrationChange] = []
        rule_counters = {"scanned": 0, "already_bound": 0, "bound": 0,
                         "ambiguous": 0}
        if include_rules:
            rule_changes, rule_counters = self.plan_rules()
            report.rules_scanned = int(rule_counters["scanned"])
            report.rules_already_bound = int(
                rule_counters["already_bound"]
            )
            report.rule_changes = list(rule_changes)
        if dry_run:
            report.sources_bound = int(counters["bound"])
            report.sources_quarantined = int(counters["quarantined"])
            report.rules_bound = int(rule_counters["bound"])
            report.rules_ambiguous = int(rule_counters["ambiguous"])
            return report
        self._apply_sources(
            source_changes, actor=actor, report=report
        )
        if include_rules:
            self._apply_rules(
                rule_changes, actor=actor, report=report
            )
        return report

    # ------------------------------------------------------------- appliers
    def _apply_sources(
        self,
        source_changes: List[SourceMigrationChange],
        *,
        actor: str,
        report: MigrationReport,
    ) -> None:
        """Persist the source-side decisions and audit each one."""
        raw_by_id: Dict[str, Dict[str, Any]] = {}
        for raw in self._sources.iter_raw_documents():
            if isinstance(raw, dict):
                raw_by_id[str(raw.get("source_instance_id") or "")] = raw
        audit_collection = None
        try:
            audit_collection = self._sources.audit_collection()
        except Exception as exc:  # noqa: BLE001 - in-memory fakes
            _log.warning(
                "source_migration.audit_collection_unavailable error=%s",
                type(exc).__name__,
            )
        now = _utcnow()
        for change in source_changes:
            if not change.applied:
                continue
            is_bind = change.outcome == OUTCOME_BOUND
            before_row = raw_by_id.get(change.source_instance_id) or {}
            before = {
                field: before_row.get(field)
                for field in AUDIT_TRACKED_FIELDS
            }
            modified = self._sources.set_capability_binding(
                change.source_instance_id,
                capability_id=change.capability_id,
                capability_version=change.capability_version,
                mapping_profile_id=change.mapping_profile_id,
                binding_status=(
                    CapabilityBindingStatus.BOUND.value
                    if is_bind
                    else CapabilityBindingStatus.REQUIRES_VERIFICATION.value
                ),
                bound_at=now if is_bind else None,
            )
            report.documents_modified += int(modified)
            if is_bind:
                report.sources_bound += 1
            else:
                report.sources_quarantined += 1
            if audit_collection is None:
                continue
            after = dict(before)
            after["capability_id"] = change.capability_id
            after["capability_version"] = change.capability_version
            after["mapping_profile_id"] = change.mapping_profile_id
            after["capability_binding_status"] = (
                CapabilityBindingStatus.BOUND.value
                if is_bind
                else CapabilityBindingStatus.REQUIRES_VERIFICATION.value
            )
            record = build_audit_record(
                action=(
                    ACTION_SOURCE_BIND
                    if is_bind
                    else ACTION_SOURCE_QUARANTINE
                ),
                actor=actor,
                source_instance_id=change.source_instance_id,
                human_id=change.human_id or None,
                capability_id=change.capability_id,
                reason=change.reason,
                before=before,
                after=after,
                at=now,
            )
            if append_audit_record(audit_collection, record):
                report.audit_records_written += 1
        if self._registry is not None:
            try:
                report.registry_reloaded = self.reload_registry()
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "source_migration.registry_reload_failed error=%s",
                    type(exc).__name__,
                )

    def _apply_rules(
        self,
        rule_changes: List[RuleMigrationChange],
        *,
        actor: str,
        report: MigrationReport,
    ) -> None:
        """Persist the unambiguous rule bindings and audit each change."""
        if self._rules is None:
            return
        now = _utcnow()
        for change in rule_changes:
            if change.outcome == OUTCOME_AMBIGUOUS:
                report.rules_ambiguous += 1
                continue
            if change.outcome != OUTCOME_BOUND:
                continue
            try:
                current = self._rules.get(
                    change.rule_id, change.rule_version
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "rule_migration.get_failed rule_id=%s error=%s",
                    change.rule_id,
                    type(exc).__name__,
                )
                continue
            if current is None:
                continue
            updated = current.model_copy(
                update={"capability_id": change.capability_id}
            )
            try:
                self._rules.update(updated)
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "rule_migration.update_failed rule_id=%s error=%s",
                    change.rule_id,
                    f"{type(exc).__name__}: {exc}"[:256],
                )
                continue
            report.rules_bound += 1
            if self._capability_audit is None:
                continue
            # The rule backfill is a capability-relationship change, so it is
            # recorded in the capability audit trail (the audited entity is
            # the capability that gained a real rule owner).
            try:
                from ..capabilities.audit import (
                    append_audit_record as cap_append,
                    build_audit_record as cap_build,
                )

                wrote = cap_append(
                    self._capability_audit,
                    cap_build(
                        action=ACTION_RULE_BACKFILL,
                        actor=actor,
                        capability_id=change.capability_id,
                        before={
                            "rule_id": change.rule_id,
                            "rule_version": change.rule_version,
                            "capability_id": None,
                        },
                        after={
                            "rule_id": change.rule_id,
                            "rule_version": change.rule_version,
                            "capability_id": change.capability_id,
                        },
                        at=now,
                    ),
                )
                if wrote:
                    report.audit_records_written += 1
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "rule_migration.audit_failed rule_id=%s error=%s",
                    change.rule_id,
                    type(exc).__name__,
                )

    def reload_registry(self) -> int:
        """Reload every persisted source instance into the live registry."""
        reload_fn = getattr(
            self._registry, "reload_from_repository", None
        )
        if callable(reload_fn):
            return int(reload_fn())
        return 0