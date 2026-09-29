"""Capability Registry service (Phase 5.1).

The :class:`CapabilityService` is the only orchestrator for the
capability layer. Responsibilities:

* Validation via :class:`Capability` (Pydantic is the source of truth).
* Persistence via :class:`CapabilityRepository` (only MongoDB boundary).
* In-memory :class:`CapabilityRegistry` for live lookups.
* Lifecycle: create / get / list / update / enable / disable /
  deprecate / retire / archive + derived relationship views
  (sources / rules / patterns) required by Phase 5.1.
* Security: admin-only writes; ``implementation_ref`` allowlist; no
  ``eval``/``exec``/``subprocess``/``importlib`` on user bytes.

Phase boundary: 5.1 does NOT rewire sources/rules/patterns. The
relationship views are read-only derivations from the existing live
registries so the registry is immediately useful without migrating
legacy data.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError

from ..auth.identity import Identity
from ..auth.permissions import ADMIN_ROLE, Permission, has_permission
from .audit import (
    append_audit_record,
    build_audit_record,
    read_audit_records,
    snapshot_capability,
)
from .errors import (
    CapabilityAlreadyExistsError,
    CapabilityAuthorizationError,
    CapabilityConfigurationError,
    CapabilityNotFoundError,
    CapabilityStateError,
)
from .models import Capability, CapabilityStatus, ImplementationRef, MappingProfile
from .registry import CapabilityRegistry, can_transition
from .repository import CapabilityRepository
from .seeds import build_builtin_capabilities

_log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_admin(identity: Identity) -> None:
    if not isinstance(identity, Identity):
        raise CapabilityAuthorizationError(
            safe_message="capability write denied",
            internal_detail="identity is required",
        )
    if identity.role != ADMIN_ROLE:
        raise CapabilityAuthorizationError(
            safe_message="capability write denied",
            internal_detail=f"role={identity.role!r} is not authorised for capability writes",
        )
    if identity.permissions:
        if not has_permission(
            role=identity.role,
            identity_permissions=identity.permissions,
            permission=Permission.CAPABILITY_WRITE,
        ):
            raise CapabilityAuthorizationError(
                safe_message="capability write denied",
                internal_detail="missing capability:write permission",
            )


def _parse_status(value: Any) -> CapabilityStatus:
    if isinstance(value, CapabilityStatus):
        return value
    if isinstance(value, str):
        try:
            return CapabilityStatus(value.strip().lower())
        except ValueError:
            pass
    raise CapabilityConfigurationError(
        safe_message=f"unknown capability status {value!r}",
        internal_detail="status must be active/disabled/deprecated/retired/planned/archived",
    )


def _parse_impl(value: Any) -> ImplementationRef:
    if isinstance(value, ImplementationRef):
        return value
    if isinstance(value, str):
        try:
            return ImplementationRef(value.strip().lower())
        except ValueError:
            pass
    raise CapabilityConfigurationError(
        safe_message=f"unknown implementation_ref {value!r}",
        internal_detail="implementation_ref must be nginx/simulator/planned",
    )


class CapabilityService:
    """Phase 5.1 capability orchestrator."""

    def __init__(
        self,
        repository: CapabilityRepository,
        registry: CapabilityRegistry,
        *,
        source_service: Optional[Any] = None,
        rule_service: Optional[Any] = None,
    ) -> None:
        if repository is None:
            raise ValueError("repository is required")
        if registry is None:
            raise ValueError("registry is required")
        self._repository = repository
        self._registry = registry
        self._source_service = source_service
        self._rule_service = rule_service

    # ------------------------------------------------------------------ audit
    def _audit(
        self,
        *,
        action: str,
        actor: str,
        capability: Capability,
        before: Optional[Capability] = None,
        at: Optional[datetime] = None,
    ) -> None:
        """Append one §18.27 audit record (best-effort, see audit.py)."""
        try:
            record = build_audit_record(
                action=action,
                actor=actor,
                capability_id=capability.capability_id,
                human_id=capability.human_id or None,
                before=snapshot_capability(before) if before is not None else {},
                after=snapshot_capability(capability),
                at=at,
            )
            append_audit_record(self._repository.audit_collection, record)
        except Exception:  # noqa: BLE001 - audit must never mask the op result
            _log.exception(
                "capability_audit_unexpected_error capability_id=%s action=%s",
                capability.capability_id,
                action,
            )

    def list_audit(self, capability_id: str, *, limit: int = 50) -> Dict[str, Any]:
        """Bounded, newest-first §18.27 audit read for one capability."""
        # Truthful-error rule (freeze §28.7): unknown capabilities are a
        # 404, never a fake-success empty trail — consistent with the
        # list_sources/list_rules/list_patterns views.
        current = self._registry.get(capability_id)
        if current is None:
            self._repository.get_required(capability_id)
        records = read_audit_records(self._repository.audit_collection, capability_id, limit=limit)
        return {
            "capability_id": capability_id,
            "records": records,
            "count": len(records),
        }

    @property
    def repository(self) -> CapabilityRepository:
        return self._repository

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    def attach_source_service(self, service: Optional[Any]) -> None:
        self._source_service = service

    def attach_rule_service(self, service: Optional[Any]) -> None:
        self._rule_service = service

    # ------------------------------------------------------------------ seeds
    def seed_builtins(self, *, actor: str = "system") -> Dict[str, int]:
        """Idempotently seed the 6 built-in capabilities.

        Returns ``{"created": n, "existing": m}``. Safe to call on every
        startup; existing ids are left untouched (no overwrite).
        """
        created = 0
        existing = 0
        for payload in build_builtin_capabilities(created_by=actor):
            cid = str(payload["capability_id"])
            current = self._repository.get(cid)
            if current is not None:
                if self._registry.get(cid) is None:
                    try:
                        self._registry.register(current)
                    except CapabilityAlreadyExistsError:
                        pass
                existing += 1
                continue
            try:
                capability = Capability.model_validate(payload)
            except (PydanticValidationError, ValueError, TypeError) as exc:
                _log.warning("capability.seed_invalid id=%s error=%s", cid, type(exc).__name__)
                continue
            try:
                stored = self._repository.create(capability)
            except CapabilityAlreadyExistsError:
                existing += 1
                stored = self._repository.get(cid)
                if stored is None:
                    continue
            if self._registry.get(cid) is None and stored is not None:
                try:
                    self._registry.register(stored)
                except CapabilityAlreadyExistsError:
                    pass
            if stored is not None:
                self._audit(action="seed", actor=actor, capability=stored)
            created += 1
        return {"created": created, "existing": existing}

    def reload_from_repository(self) -> int:
        instances = self._repository.find_all(limit=200)
        for inst in instances:
            if self._registry.get(inst.capability_id) is None:
                try:
                    self._registry.register(inst)
                except CapabilityAlreadyExistsError:
                    pass
            else:
                try:
                    self._registry.replace(inst)
                except CapabilityNotFoundError:
                    pass
        return len(instances)

    # ------------------------------------------------------------------ reads
    def get(self, capability_id: str) -> Dict[str, Any]:
        inst = self._registry.get(capability_id)
        if inst is None:
            inst = self._repository.get(capability_id)
            if inst is None:
                raise CapabilityNotFoundError(
                    safe_message=f"capability {capability_id!r} is not registered",
                    internal_detail="service.get() failed",
                )
            try:
                self._registry.register(inst)
            except CapabilityAlreadyExistsError:
                pass
        return self._enrich(inst)

    def list(self, *, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        bounded = max(1, min(int(limit or 50), 200))
        parsed_status = None
        if status not in (None, ""):
            parsed_status = _parse_status(status)
        items = self._registry.list_all()
        if not items:
            items = self._repository.find_all(limit=200)
            for inst in items:
                if self._registry.get(inst.capability_id) is None:
                    try:
                        self._registry.register(inst)
                    except CapabilityAlreadyExistsError:
                        pass
        if parsed_status is not None:
            items = [c for c in items if c.status is parsed_status]
        items = sorted(items, key=lambda c: c.capability_id)[:bounded]
        return [self._enrich(c) for c in items]

    # ------------------------------------------------------------- writes
    def create(
        self,
        *,
        identity: Identity,
        capability_id: str,
        name: str,
        description: str = "",
        responsibility: str = "",
        implementation_ref: Any = "planned",
        version: int = 1,
        status: Any = None,
        configuration_schema: Optional[Dict[str, Any]] = None,
        mapping_profiles: Optional[List[Dict[str, Any]]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        _require_admin(identity)
        if not isinstance(capability_id, str) or not capability_id.strip():
            raise CapabilityConfigurationError(safe_message="capability_id required", internal_detail="missing capability_id")
        cid = capability_id.strip().lower()
        impl = _parse_impl(implementation_ref)
        st = _parse_status(status) if status not in (None, "") else (
            CapabilityStatus.PLANNED if impl is ImplementationRef.PLANNED else CapabilityStatus.ACTIVE
        )
        if self._registry.get(cid) is not None or self._repository.get(cid) is not None:
            raise CapabilityAlreadyExistsError(
                safe_message=f"capability {cid!r} already exists",
                internal_detail="service.create() duplicate",
            )
        ts = now or _utcnow()
        profiles: List[MappingProfile] = []
        for raw in mapping_profiles or []:
            try:
                profiles.append(MappingProfile.model_validate(raw))
            except (PydanticValidationError, ValueError, TypeError) as exc:
                raise CapabilityConfigurationError(
                    safe_message="invalid mapping_profiles entry",
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc
        try:
            capability = Capability(
                capability_id=cid,  # type: ignore[arg-type]
                name=name,
                description=description or "",
                responsibility=responsibility or "",
                implementation_ref=impl,
                version=int(version or 1),
                status=st,
                configuration_schema=dict(configuration_schema or {}),
                mapping_profiles=tuple(profiles),
                created_by=identity.subject_id,
                created_at=ts,
                updated_by=identity.subject_id,
                updated_at=ts,
            )
        except (PydanticValidationError, ValueError, TypeError) as exc:
            raise CapabilityConfigurationError(
                safe_message="invalid capability payload",
                internal_detail=f"{type(exc).__name__}: {str(exc)[:512]}",
            ) from exc
        stored = self._repository.create(capability)
        try:
            self._registry.register(stored)
        except CapabilityAlreadyExistsError:
            pass
        self._audit(action="create", actor=identity.subject_id, capability=stored, at=ts)
        _log.info("capability.created id=%s actor=%s", cid, identity.subject_id)
        return self._enrich(stored, include_relations=False)

    def update(
        self,
        *,
        identity: Identity,
        capability_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        responsibility: Optional[str] = None,
        configuration_schema: Optional[Dict[str, Any]] = None,
        mapping_profiles: Optional[List[Dict[str, Any]]] = None,
        version: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        _require_admin(identity)
        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        if current.status in (CapabilityStatus.RETIRED, CapabilityStatus.ARCHIVED):
            raise CapabilityStateError(
                safe_message=f"capability {capability_id!r} is {current.status.value}; updates are closed",
                internal_detail=f"status={current.status.value}",
            )
        ts = now or _utcnow()
        patch: Dict[str, Any] = {"updated_by": identity.subject_id, "updated_at": ts}
        if name is not None:
            patch["name"] = name
        if description is not None:
            patch["description"] = description
        if responsibility is not None:
            patch["responsibility"] = responsibility
        if configuration_schema is not None:
            patch["configuration_schema"] = dict(configuration_schema)
        if mapping_profiles is not None:
            profiles: List[MappingProfile] = []
            for raw in mapping_profiles:
                try:
                    profiles.append(MappingProfile.model_validate(raw))
                except (PydanticValidationError, ValueError, TypeError) as exc:
                    raise CapabilityConfigurationError(
                        safe_message="invalid mapping_profiles entry",
                        internal_detail=f"{type(exc).__name__}: {exc}",
                    ) from exc
            patch["mapping_profiles"] = tuple(profiles)
        if version is not None:
            coerced = version
            if isinstance(coerced, str) and coerced.strip().lstrip("+-").isdigit():
                coerced = int(coerced.strip())
            if not isinstance(coerced, int) or isinstance(coerced, bool):
                raise CapabilityConfigurationError(safe_message="version must be an integer", internal_detail=f"got {type(version).__name__}")
            if coerced <= int(current.version):
                raise CapabilityConfigurationError(
                    safe_message=f"version must increase (current={int(current.version)})",
                    internal_detail=f"got version={version}",
                )
            patch["version"] = coerced
        try:
            updated = current.model_copy(update=patch)
            Capability.model_validate(updated.model_dump())
        except (PydanticValidationError, ValueError, TypeError) as exc:
            raise CapabilityConfigurationError(
                safe_message="invalid capability payload",
                internal_detail=f"{type(exc).__name__}: {str(exc)[:512]}",
            ) from exc
        stored = self._repository.save(updated)
        try:
            self._registry.replace(stored)
        except CapabilityNotFoundError:
            try:
                self._registry.register(stored)
            except CapabilityAlreadyExistsError:
                pass
        self._audit(action="update", actor=identity.subject_id, capability=stored, before=current, at=ts)
        _log.info("capability.updated id=%s actor=%s", capability_id, identity.subject_id)
        return self._enrich(stored, include_relations=False)

    # ------------------------------------------------------------- lifecycle
    def _lifecycle(self, *, identity: Identity, capability_id: str, target: CapabilityStatus) -> Dict[str, Any]:
        _require_admin(identity)
        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        if not can_transition(current.status, target):
            raise CapabilityStateError(
                safe_message=f"transition {current.status.value}->{target.value} is not allowed",
                internal_detail=f"current={current.status.value}",
            )
        if target is CapabilityStatus.ACTIVE and current.implementation_ref is ImplementationRef.PLANNED:
            raise CapabilityStateError(
                safe_message="planned capabilities cannot be activated without a trusted implementation",
                internal_detail="implementation_ref=planned",
            )
        ts = _utcnow()
        patch: Dict[str, Any] = {"status": target, "updated_by": identity.subject_id, "updated_at": ts}
        if target is CapabilityStatus.RETIRED:
            patch["retired_at"] = ts
        if target is CapabilityStatus.ARCHIVED:
            patch["archived_at"] = ts
            if current.retired_at is None:
                patch["retired_at"] = ts
        updated = current.model_copy(update=patch)
        # 5.1-01 root-cause guard: ``model_copy`` bypasses Pydantic
        # validation, so re-validate the transition result BEFORE any
        # write. A transition that would persist a model-invalid state
        # (e.g. implementation_ref=planned + status=disabled) is
        # rejected here with a 409 — the document can never become a
        # quarantined/unreadable phantom after restart.
        try:
            Capability.model_validate(updated.model_dump())
        except (PydanticValidationError, ValueError, TypeError) as exc:
            raise CapabilityStateError(
                safe_message=(
                    f"transition {current.status.value}->{target.value} produces an "
                    "invalid capability state and was refused"
                ),
                internal_detail=f"{type(exc).__name__}: {str(exc)[:512]}",
            ) from exc
        stored = self._repository.save(updated)
        try:
            self._registry.replace(stored)
        except CapabilityNotFoundError:
            try:
                self._registry.register(stored)
            except CapabilityAlreadyExistsError:
                pass
        action_names = {
            CapabilityStatus.ACTIVE: "enable",
            CapabilityStatus.DISABLED: "disable",
            CapabilityStatus.DEPRECATED: "deprecate",
            CapabilityStatus.RETIRED: "retire",
            CapabilityStatus.ARCHIVED: "archive",
            CapabilityStatus.PLANNED: "restore_planned",
        }
        self._audit(action=action_names[target], actor=identity.subject_id, capability=stored, before=current, at=ts)
        _log.info("capability.lifecycle id=%s %s->%s actor=%s", capability_id, current.status.value, target.value, identity.subject_id)
        return self._enrich(stored, include_relations=False)

    def enable(self, *, identity: Identity, capability_id: str) -> Dict[str, Any]:
        # enable() reactivates a disabled live capability AND returns a
        # disabled planned draft to planned (it never activates planned
        # to live; the _lifecycle guard enforces that).
        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        if current.status is CapabilityStatus.DISABLED and current.implementation_ref is ImplementationRef.PLANNED:
            _require_admin(identity)
            if not can_transition(current.status, CapabilityStatus.PLANNED):
                raise CapabilityStateError(
                    safe_message=f"transition {current.status.value}->planned is not allowed",
                    internal_detail=f"current={current.status.value}",
                )
            from datetime import datetime as _dt, timezone as _tz
            ts = _dt.now(_tz.utc)
            updated = current.model_copy(update={"status": CapabilityStatus.PLANNED, "updated_by": identity.subject_id, "updated_at": ts})
            try:
                Capability.model_validate(updated.model_dump())
            except (PydanticValidationError, ValueError, TypeError) as exc:
                raise CapabilityStateError(
                    safe_message="transition disabled->planned produces an invalid capability state and was refused",
                    internal_detail=f"{type(exc).__name__}: {str(exc)[:512]}",
                ) from exc
            stored = self._repository.save(updated)
            try:
                self._registry.replace(stored)
            except CapabilityNotFoundError:
                try:
                    self._registry.register(stored)
                except CapabilityAlreadyExistsError:
                    pass
            self._audit(action="enable", actor=identity.subject_id, capability=stored, before=current, at=ts)
            return self._enrich(stored, include_relations=False)
        return self._lifecycle(identity=identity, capability_id=capability_id, target=CapabilityStatus.ACTIVE)

    def disable(self, *, identity: Identity, capability_id: str) -> Dict[str, Any]:
        return self._lifecycle(identity=identity, capability_id=capability_id, target=CapabilityStatus.DISABLED)

    def deprecate(self, *, identity: Identity, capability_id: str) -> Dict[str, Any]:
        return self._lifecycle(identity=identity, capability_id=capability_id, target=CapabilityStatus.DEPRECATED)

    def retire(self, *, identity: Identity, capability_id: str) -> Dict[str, Any]:
        return self._lifecycle(identity=identity, capability_id=capability_id, target=CapabilityStatus.RETIRED)

    def archive(self, *, identity: Identity, capability_id: str) -> Dict[str, Any]:
        return self._lifecycle(identity=identity, capability_id=capability_id, target=CapabilityStatus.ARCHIVED)

    # ------------------------------------------------------------- views
    def list_sources(self, capability_id: str, *, limit: int = 50) -> Dict[str, Any]:  # noqa: C901

        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        bounded = max(1, min(int(limit or 50), 200))
        matched: List[Dict[str, Any]] = []
        svc = self._source_service
        if svc is not None:
            try:
                views = svc.list_all()
            except Exception:  # noqa: BLE001 - truthful empty on wiring failure
                views = []
            for view in views:
                dumped = view.model_dump(mode="json") if hasattr(view, "model_dump") else dict(view)
                stype = str(dumped.get("source_type") or dumped.get("source") or "").lower()
                impl = current.implementation_ref.value
                # Phase 5.1 compatibility mapping: a source belongs to the
                # capability whose live implementation family matches its
                # source_type. No legacy rewrite; purely derived.
                if (impl == "nginx" and stype == "nginx") or (impl == "simulator" and stype == "simulator"):
                    matched.append(dumped)
                    if len(matched) >= bounded:
                        break
        return {"capability_id": capability_id, "sources": matched, "count": len(matched)}

    def list_rules(self, capability_id: str, *, limit: int = 50) -> Dict[str, Any]:
        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        bounded = max(1, min(int(limit or 50), 200))
        matched: List[Dict[str, Any]] = []
        svc = self._rule_service
        if svc is not None:
            rules: List[Any] = []
            try:
                # Prefer the persisted managed-rule view (what rule.list
                # serves), then the live evaluator registry as fallback so
                # the relationship view is truthful in both planes.
                repo = getattr(svc, "repository", None) or getattr(svc, "_repository", None)
                if repo is not None and hasattr(repo, "find_all"):
                    try:
                        for row in repo.find_all():
                            rules.append(row.to_canonical_dict() if hasattr(row, "to_canonical_dict") else row)
                    except Exception:  # noqa: BLE001
                        rules = []
                if not rules:
                    registry = getattr(svc, "registry", None) or getattr(svc, "_registry", None)
                    if registry is not None and hasattr(registry, "list_all"):
                        for rule in registry.list_all():
                            meta = getattr(rule, "metadata", None)
                            if meta is not None and hasattr(meta, "model_dump"):
                                dumped_meta = meta.model_dump(mode="json")
                                dumped_meta.setdefault("rule_id", getattr(meta, "rule_id", ""))
                                dumped_meta.setdefault("sources", list(getattr(meta, "sources", []) or []))
                                dumped_meta.setdefault("type", "detection")
                                rules.append(dumped_meta)
                            elif hasattr(rule, "to_canonical_dict"):
                                rules.append(rule.to_canonical_dict())
            except Exception:  # noqa: BLE001
                rules = []
            for raw in rules:
                dumped = raw.model_dump(mode="json") if hasattr(raw, "model_dump") else dict(raw or {})
                sources = [str(s).lower() for s in (dumped.get("sources") or [])]
                impl = current.implementation_ref.value
                rtype = str(dumped.get("type") or "").lower()
                owner = str(dumped.get("capability_id") or "")
                if owner:
                    # Phase 5.2: an explicit capability owner is authoritative.
                    # A rule that names a ``cap-*`` owner belongs to exactly
                    # that capability. The string/type heuristics below exist
                    # only for legacy (ownerless) rules and must never
                    # reassign a rule to a capability it does not own.
                    if owner == capability_id:
                        matched.append(dumped)
                elif impl in sources or (impl == "simulator" and "simulator" in sources):
                    matched.append(dumped)
                elif impl == "nginx" and rtype in ("detection", "threshold", "rate_limit", "correlation") and not sources:
                    matched.append(dumped)
                if len(matched) >= bounded:
                    break
        return {"capability_id": capability_id, "rules": matched, "count": len(matched)}

    def list_patterns(self, capability_id: str) -> Dict[str, Any]:
        current = self._registry.get(capability_id)
        if current is None:
            current = self._repository.get_required(capability_id)
        try:
            from ..correlation.patterns import describe_registered_patterns

            patterns = describe_registered_patterns()
        except Exception:  # noqa: BLE001
            patterns = []
        impl = current.implementation_ref.value
        if impl == "nginx":
            matched = patterns
        elif impl == "simulator":
            matched = [p for p in patterns if "simulat" in str(p.get("pattern_id", "")).lower()]
        else:
            matched = []
        return {"capability_id": capability_id, "patterns": matched, "count": len(matched)}

    # ------------------------------------------------------------- enrichment
    def _enrich(self, capability: Capability, *, include_relations: bool = True) -> Dict[str, Any]:
        # include_relations=False keeps lifecycle/create/update O(1) instead
        # of O(rules+patterns+sources); list/get keep the full derivation.
        rule_ids: List[str] = []
        pattern_ids: List[str] = []
        source_count: Optional[int] = None
        if include_relations:
            try:
                rules_view = self.list_rules(capability.capability_id, limit=200)
                for raw in rules_view.get("rules", []):
                    rid = raw.get("rule_id")
                    if isinstance(rid, str) and rid:
                        rule_ids.append(rid)
            except Exception:  # noqa: BLE001
                rule_ids = []
            try:
                patterns_view = self.list_patterns(capability.capability_id)
                for raw in patterns_view.get("patterns", []):
                    pid = raw.get("pattern_id")
                    if isinstance(pid, str) and pid:
                        pattern_ids.append(pid)
            except Exception:  # noqa: BLE001
                pattern_ids = []
            try:
                if self._source_service is not None:
                    sources_view = self.list_sources(capability.capability_id, limit=200)
                    source_count = int(sources_view.get("count", 0))
            except Exception:  # noqa: BLE001
                source_count = None
        return capability.to_view_dict(rule_ids=sorted(set(rule_ids)), pattern_ids=sorted(set(pattern_ids)), source_count=source_count)


__all__ = ["CapabilityService"]
