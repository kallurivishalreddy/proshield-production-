"""Source Management service (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

The :class:`SourceManagementService` is the **only**
orchestrator for the source-management layer. It is
responsible for:

* **Validation.** Every source-instance operation passes
  through the :class:`SourceInstance` model validator before
  anything else happens. Pydantic is the source of truth for
  what a valid source instance looks like.
* **Persistence.** The service uses
  :class:`app.sources.repository.SourceRepository` as its
  only MongoDB boundary.
* **In-memory registry.** The service keeps the
  :class:`SourceRegistry` populated with the persisted
  records; the live pipeline (detection / correlation /
  centralized analysis / ingress proxy) reads source
  configuration from the registry.
* **Lifecycle.** The service implements the documented
  state machine: ``register``, ``configure``, ``validate``,
  ``enable``, ``disable``, ``retire``, ``update``.
* **Security.** The service NEVER invokes ``eval``,
  ``exec``, ``subprocess``, ``os.system``, or ``importlib``
  on user-controlled bytes.
* **Authorization.** Every write operation requires a
  verified :class:`Identity` with the documented permission
  (admin-only writes; analysts may read).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError as PydanticValidationError

from ..auth.identity import Identity
from ..auth.permissions import (
    ADMIN_ROLE,
    Permission,
    has_permission,
)
from .errors import (
    DuplicateSourceCapabilityBindingError,
    SourceAuthorizationError,
    SourceCapabilityBindingError,
    SourceCapabilityUnverifiedError,
    SourceConfigurationError,
    SourceInstanceNotFoundError,
    SourceInstanceStateError,
)
from .audit import snapshot_source
from .models import (
    MAX_SOURCE_INSTANCE_NAME_LEN,
    CapabilityBindingStatus,
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceInstanceId,
    SourceInstanceView,
    SourceState,
    SourceType,
    source_string_for_type,
)
from .registry import (
    SUPPORTED_CONNECTOR_TYPES,
    SourceRegistry,
    can_transition,
    supported_connector_types,
)
from .repository import SourceRepository
from .trust import SourceIdentityTokenIssuer


_log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_source_instance_id(handle: str) -> SourceInstanceId:
    """Build a deterministic ``src-<uuidv7>-<handle>`` id."""
    safe = "".join(
        ch.lower() if ch.isalnum() else "-"
        for ch in (handle or "")
    ).strip("-")
    safe = safe[:32] or "source"
    ts_ms = int(_utcnow().timestamp() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 56) & 0x0FFF
    rand_b_hi = (rand >> 40) & 0x3FFF | 0x8000
    rand_b_lo = rand & ((1 << 48) - 1)
    uuid_int = (
        (ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (rand_b_hi << 48)
        | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    raw = (
        "src-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )
    candidate = f"{raw}-{safe}"
    return candidate  # type: ignore[return-value]


class SourceManagementService:
    """The Phase 4.9 source-management orchestrator."""

    def __init__(
        self,
        repository: SourceRepository,
        registry: SourceRegistry,
        *,
        token_issuer: Optional[SourceIdentityTokenIssuer] = None,
        capability_lookup: Optional[Any] = None,
        audit_collection: Optional[Any] = None,
    ) -> None:
        if repository is None:
            raise ValueError("repository is required")
        if registry is None:
            raise ValueError("registry is required")
        self._repository = repository
        self._registry = registry
        self._token_issuer = token_issuer
        # Phase 5.2: server-authoritative capability resolution.
        #
        # ``capability_lookup`` is the only way this service learns what a
        # capability *is*. It is injected (rather than imported) so the
        # source layer keeps its existing one-way dependency and so the
        # tests can exercise the binding rules without a Mongo-backed
        # capability registry.
        self._capability_lookup = capability_lookup
        # Append-only Phase 5.2 audit sink for security-sensitive source
        # writes (binding, lifecycle, token issuance/rotation, migration).
        # ``None`` degrades to log-only, never to a silent success.
        self._audit_collection = audit_collection

    # ------------------------------------------------------- late wiring
    def set_capability_lookup(self, lookup: Optional[Any]) -> None:
        """Late-bind the capability registry lookup.

        The runtime composition builds the capability registry *after* the
        source service (the registry itself takes the source service as a
        relationship source), so this setter exists to avoid a circular
        construction order. Passing ``None`` restores the shipped-seed
        fallback authority.
        """
        self._capability_lookup = lookup

    def set_audit_collection(self, collection: Optional[Any]) -> None:
        """Late-bind the append-only source audit collection."""
        self._audit_collection = collection

    # ----------------------------------------------------------------- audit
    def _audit(
        self,
        *,
        action: str,
        source: Any,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> None:
        """Append one source audit record (never raises)."""
        from .audit import (
            append_audit_record,
            build_audit_record,
            snapshot_source,
        )

        if self._audit_collection is None:
            return
        source_instance_id = getattr(
            source, "source_instance_id", None
        ) or (source or {}).get("source_instance_id")
        if not source_instance_id:
            return
        try:
            record = build_audit_record(
                action=action,
                actor=actor or getattr(source, "updated_by", "") or "system",
                source_instance_id=str(source_instance_id),
                human_id=getattr(source, "human_id", None),
                capability_id=getattr(source, "capability_id", None),
                reason=reason,
                before=before if before is not None else snapshot_source(
                    source
                ),
                after=after if after is not None else snapshot_source(source),
            )
            append_audit_record(self._audit_collection, record)
        except Exception as exc:  # noqa: BLE001 - audit must never break
            _log.error(
                "source_audit_build_failed source_instance_id=%s action=%s "
                "error=%s",
                source_instance_id,
                action,
                type(exc).__name__,
            )

    # ------------------------------------------------------------- binding
    def _resolve_binding(
        self,
        *,
        source_type: SourceType,
        capability_id: Optional[str],
        mapping_profile_id: Optional[str],
        allow_non_active: bool = False,
    ) -> Any:
        """Resolve + validate the capability binding for a source type.

        Returns a :class:`ResolvedBinding`, or ``None`` when neither a
        capability nor a profile was requested **and** no capability can be
        resolved deterministically. It never returns a fabricated binding:
        every failure path raises.
        """
        from .capability_binding import (
            builtin_capability_index,
            resolve_capability_id_for_type,
            validate_capability_binding,
        )

        requested = capability_id
        if requested is None:
            requested = resolve_capability_id_for_type(source_type)
        if requested is None:
            if mapping_profile_id is not None:
                raise SourceConfigurationError(
                    safe_message=(
                        "mapping_profile_id requires a capability binding"
                    ),
                    internal_detail=(
                        "no capability provided and none could be resolved "
                        f"for source_type={source_type.value!r}"
                    ),
                )
            return None
        if not isinstance(requested, str) or not requested:
            raise SourceConfigurationError(
                safe_message="capability_id must be a non-empty string",
                internal_detail=f"got {type(requested).__name__}",
            )
        # The live capability registry is the primary authority. When the
        # source layer is composed without one (legacy Phase 4.9 harnesses),
        # the shipped seed catalogue is used so binding is still *enforced*
        # rather than silently skipped — the enforcement gate must not
        # depend on optional wiring.
        capability = None
        if self._capability_lookup is not None:
            capability = self._capability_lookup(requested)
        else:
            _log.warning(
                "source_binding_registry_absent capability_id=%s "
                "fallback=builtin_seed_catalogue",
                requested,
            )
            capability = builtin_capability_index().get(requested)
        return validate_capability_binding(
            capability,
            source_type=source_type.value,
            mapping_profile_id=mapping_profile_id,
            allow_non_active=allow_non_active,
        )

    # ------------------------------------------------------------- binding
    def _require_bound(self, current: Any, action: str) -> None:
        """Refuse a lifecycle action on a source with no verified capability.

        Phase 5.2 invariant: a source resolves to a capability before it can
        be validated, enabled or used to ingest. A quarantined
        (``requires_verification``) or unbound row is refused with an
        explicit 409 rather than being silently promoted.
        """
        status = current.capability_binding_status
        status_val = getattr(status, "value", status)
        if status_val == CapabilityBindingStatus.BOUND.value and (
            current.capability_id
        ):
            return
        raise SourceCapabilityUnverifiedError(
            safe_message=(
                f"source instance {action} requires a verified capability "
                "binding"
            ),
            internal_detail=(
                f"capability_binding_status={status_val!r} "
                f"capability_id={current.capability_id!r}"
            ),
        )

    def bind_capability(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
        capability_id: str,
        mapping_profile_id: Optional[str] = None,
    ) -> SourceInstanceView:
        """Authoritatively (re)bind a source instance to a capability.

        Admin-only. This is the supported remediation path for a source the
        legacy migration had to quarantine, and the supported way to move a
        source to a different capability after a capability migration.

        Refusals (all explicit, none silent):
        * unknown / non-live capability -> 400;
        * a mapping profile the capability does not declare -> 400;
        * the source is RETIRED (immutable history) -> 409;
        * the source already holds this exact binding -> 409, so no audit
          record claims a change that did not happen.
        """
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        if current.state is SourceState.RETIRED:
            raise SourceInstanceStateError(
                safe_message="retired source instances are immutable",
                internal_detail=(
                    f"source_instance_id={source_instance_id!r} "
                    f"state={current.state.value}"
                ),
            )
        if not isinstance(capability_id, str) or not capability_id:
            raise SourceCapabilityBindingError(
                safe_message="capability_id must be a non-empty string",
                internal_detail=f"got {type(capability_id).__name__}",
            )
        binding = self._resolve_binding(
            source_type=current.source_type,
            capability_id=capability_id,
            mapping_profile_id=mapping_profile_id,
        )
        if binding is None:
            raise SourceCapabilityBindingError(
                safe_message="unknown capability",
                internal_detail=f"capability_id={capability_id!r}",
            )
        already = (
            current.capability_id == binding.capability_id
            and current.capability_version == binding.capability_version
            and current.mapping_profile_id == binding.mapping_profile_id
        )
        if already:
            raise DuplicateSourceCapabilityBindingError(
                safe_message=(
                    "source instance is already bound to that capability"
                ),
                internal_detail=(
                    f"capability_id={binding.capability_id!r} "
                    f"capability_version={binding.capability_version}"
                ),
            )
        before = snapshot_source(current)
        now = _utcnow()
        updated = current.model_copy(update={
            **binding.as_update(),
            "capability_binding_status": CapabilityBindingStatus.BOUND,
            "capability_bound_at": now,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        self._audit(
            action="source_bind_capability",
            source=persisted,
            before=before,
            reason=(
                f"capability binding {binding.capability_id!r} "
                f"v{binding.capability_version}"
            ),
            actor=identity.subject_id,
        )
        return persisted.to_view()

    # ----------------------------------------------------------------- reads
    def get(self, source_instance_id: SourceInstanceId) -> SourceInstanceView:
        """Return the safe view for a single source instance."""
        inst = self._registry.get(source_instance_id)
        if inst is None:
            inst = self._repository.get(source_instance_id)
            if inst is None:
                raise SourceInstanceNotFoundError(
                    safe_message=(
                        f"source instance "
                        f"{source_instance_id!r} is not registered"
                    ),
                    internal_detail="service.get() failed",
                )
            self._registry.register(inst)
        return inst.to_view()

    def list_all(self) -> List[SourceInstanceView]:
        """Return every configured source instance view."""
        return [i.to_view() for i in self._registry.list_all()]

    def list_by_type(
        self, source_type: SourceType
    ) -> List[SourceInstanceView]:
        return [
            i.to_view()
            for i in self._registry.list_by_type(source_type)
        ]

    def list_enabled(self) -> List[SourceInstanceView]:
        return [
            i.to_view()
            for i in self._registry.list_by_state(SourceState.ENABLED)
        ]

    def list_supported_connector_types(self) -> List[SourceType]:
        """Return the closed-set of supported connector types."""
        return supported_connector_types()

    # ----------------------------------------------------------------- writes
    def register(
        self,
        *,
        identity: Identity,
        source_type: SourceType,
        display_name: str,
        description: str = "",
        tags: Tuple[str, ...] = (),
        asset_tags: Tuple[str, ...] = (),
        capability_id: Optional[str] = None,
        mapping_profile_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> SourceInstanceView:
        """Register a new source instance (state=REGISTERED).

        Phase 5.2: a new source always carries a validated capability
        binding. When the caller does not name one, the deterministic
        ``SourceType -> capability`` map resolves it — so "new sources must
        have a valid capability binding" holds without trusting the client
        to choose. An unknown capability or an undeclared mapping profile is
        a 400, never a silently unbound source.
        """
        _require_role(identity, ADMIN_ROLE)
        if not isinstance(source_type, SourceType):
            raise SourceConfigurationError(
                safe_message="source_type must be a SourceType enum value",
                internal_detail=f"got {type(source_type).__name__}",
            )
        if source_type not in SUPPORTED_CONNECTOR_TYPES:
            raise SourceConfigurationError(
                safe_message="unsupported source_type",
                internal_detail=f"got {source_type.value!r}",
            )
        if not isinstance(display_name, str) or not display_name:
            raise SourceConfigurationError(
                safe_message="display_name must be a non-empty string",
                internal_detail=f"got {type(display_name).__name__}",
            )
        if len(display_name) > MAX_SOURCE_INSTANCE_NAME_LEN:
            raise SourceConfigurationError(
                safe_message="display_name exceeds the documented bound",
                internal_detail=f"len={len(display_name)}",
            )
        if now is None:
            now = _utcnow()
        sid_id = _make_source_instance_id(display_name)
        # Phase 5.2: resolve + validate the capability binding *before*
        # touching persistence. A source is never persisted half-bound.
        binding = self._resolve_binding(
            source_type=source_type,
            capability_id=capability_id,
            mapping_profile_id=mapping_profile_id,
        )
        if binding is None:
            raise SourceConfigurationError(
                safe_message=(
                    "no capability could be resolved for this source type"
                ),
                internal_detail=(
                    f"source_type={source_type.value!r} has no entry in the "
                    "deterministic SourceType -> capability map"
                ),
            )
        # STRIX F-5 / N-3: normalize tag ordering/duplicates at the
        # owning layer and convert any Pydantic ValidationError to a
        # deterministic 400 ``source_configuration_error`` instead of
        # letting it escape to the proxy's generic (mis-)fallback.
        try:
            norm_asset_tags = _normalize_tag_tuple(asset_tags)
            norm_tags = _normalize_tag_tuple(tags)
            cfg = SourceInstanceConfiguration(
                connection_type=SourceConnectionType.PUSH,
                endpoint="https://pending.invalid",
                proxy_path="",
                destination="",
                asset_tags=norm_asset_tags,
                tags=norm_tags,
                references=(),
                secret_ref="",
            )
            inst = SourceInstance(
                source_instance_id=sid_id,
                source_type=source_type,
                source=source_string_for_type(source_type),
                display_name=display_name,
                description=description,
                configuration=cfg,
                state=SourceState.REGISTERED,
                created_by=identity.subject_id,
                created_at=now,
                updated_by=identity.subject_id,
                updated_at=now,
                last_validation_at=None,
                tags=norm_tags,
                asset_tags=norm_asset_tags,
                retired_at=None,
                capability_id=binding.capability_id,
                capability_version=binding.capability_version,
                mapping_profile_id=binding.mapping_profile_id,
                capability_binding_status=CapabilityBindingStatus.BOUND,
                capability_bound_at=now,
            )
        except PydanticValidationError as exc:
            raise SourceConfigurationError(
                safe_message="source validation failed",
                internal_detail=(
                    f"pydantic raised {type(exc).__name__} with "
                    f"{len(exc.errors())} error(s)"
                ),
            ) from exc
        persisted = self._repository.create(inst)
        self._registry.register(persisted)
        self._audit(
            action="source_register",
            source=persisted,
            before={},
            reason=(
                f"capability binding {binding.capability_id!r} "
                f"v{binding.capability_version}"
            ),
            actor=identity.subject_id,
        )
        return persisted.to_view()

    def configure(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
        configuration: SourceInstanceConfiguration,
    ) -> SourceInstanceView:
        """Attach a configuration to a REGISTERED source instance."""
        _require_role(identity, ADMIN_ROLE)
        if not isinstance(configuration, SourceInstanceConfiguration):
            raise SourceConfigurationError(
                safe_message=(
                    "configuration must be a "
                    "SourceInstanceConfiguration"
                ),
                internal_detail=f"got {type(configuration).__name__}",
            )
        current = self._registry.get_required(source_instance_id)
        if not can_transition(current.state, SourceState.CONFIGURED):
            raise SourceInstanceStateError(
                safe_message=(
                    f"cannot configure source instance "
                    f"{source_instance_id!r} from state "
                    f"{current.state.value}"
                ),
                internal_detail=(
                    f"current_state={current.state.value} "
                    f"target_state={SourceState.CONFIGURED.value}"
                ),
            )
        now = _utcnow()
        updated = current.model_copy(update={
            "configuration": configuration,
            "state": SourceState.CONFIGURED,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        return persisted.to_view()

    def validate_connection(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
        validator: Optional[Any] = None,
        now: Optional[datetime] = None,
    ) -> SourceInstanceView:
        """Validate the configured connection."""
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        self._require_bound(current, "validation")
        if not can_transition(current.state, SourceState.VALIDATED):
            raise SourceInstanceStateError(
                safe_message=(
                    f"cannot validate source instance "
                    f"{source_instance_id!r} from state "
                    f"{current.state.value}"
                ),
                internal_detail=(
                    f"current_state={current.state.value} "
                    f"target_state={SourceState.VALIDATED.value}"
                ),
            )
        cfg = current.configuration
        if not cfg.endpoint or cfg.endpoint.startswith("http://"):
            raise SourceConfigurationError(
                safe_message=(
                    "endpoint must be a non-empty https:// URL"
                ),
                internal_detail=f"got {cfg.endpoint!r}",
            )
        if validator is not None:
            try:
                ok = bool(validator(current))
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "source.validate.failed",
                    extra={
                        "source_instance_id": source_instance_id,
                        "error_type": type(exc).__name__,
                    },
                )
                ok = False
            if not ok:
                raise SourceConfigurationError(
                    safe_message="source validation failed",
                    internal_detail=(
                        f"validator returned False for "
                        f"{source_instance_id!r}"
                    ),
                )
        if now is None:
            now = _utcnow()
        updated = current.model_copy(update={
            "state": SourceState.VALIDATED,
            "last_validation_at": now,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        return persisted.to_view()

    def enable(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
    ) -> SourceInstanceView:
        """Enable a source instance."""
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        self._require_bound(current, "enablement")
        if not can_transition(current.state, SourceState.ENABLED):
            raise SourceInstanceStateError(
                safe_message=(
                    f"cannot enable source instance "
                    f"{source_instance_id!r} from state "
                    f"{current.state.value}"
                ),
                internal_detail=(
                    f"current_state={current.state.value} "
                    f"target_state={SourceState.ENABLED.value}"
                ),
            )
        before = snapshot_source(current)
        now = _utcnow()
        updated = current.model_copy(update={
            "state": SourceState.ENABLED,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        self._audit(
            action="source_enable",
            source=persisted,
            before=before,
            reason=(
                f"lifecycle transition {current.state.value} -> "
                f"{SourceState.ENABLED.value}"
            ),
            actor=identity.subject_id,
        )
        return persisted.to_view()

    def disable(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
    ) -> SourceInstanceView:
        """Disable an enabled source instance."""
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        if not can_transition(current.state, SourceState.DISABLED):
            raise SourceInstanceStateError(
                safe_message=(
                    f"cannot disable source instance "
                    f"{source_instance_id!r} from state "
                    f"{current.state.value}"
                ),
                internal_detail=(
                    f"current_state={current.state.value} "
                    f"target_state={SourceState.DISABLED.value}"
                ),
            )
        before = snapshot_source(current)
        now = _utcnow()
        updated = current.model_copy(update={
            "state": SourceState.DISABLED,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        self._audit(
            action="source_disable",
            source=persisted,
            before=before,
            reason=(
                f"lifecycle transition {current.state.value} -> "
                f"{SourceState.DISABLED.value}"
            ),
            actor=identity.subject_id,
        )
        return persisted.to_view()

    def retire(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
    ) -> SourceInstanceView:
        """Retire a source instance (terminal)."""
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        if current.state is SourceState.RETIRED:
            return current.to_view()
        if not can_transition(current.state, SourceState.RETIRED):
            raise SourceInstanceStateError(
                safe_message=(
                    f"cannot retire source instance "
                    f"{source_instance_id!r} from state "
                    f"{current.state.value}"
                ),
                internal_detail=(
                    f"current_state={current.state.value} "
                    f"target_state={SourceState.RETIRED.value}"
                ),
            )
        before = snapshot_source(current)
        now = _utcnow()
        updated = current.model_copy(update={
            "state": SourceState.RETIRED,
            "retired_at": now,
            "updated_by": identity.subject_id,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        self._audit(
            action="source_retire",
            source=persisted,
            before=before,
            reason=(
                f"lifecycle transition {current.state.value} -> "
                f"{SourceState.RETIRED.value}"
            ),
            actor=identity.subject_id,
        )
        return persisted.to_view()

    def update_metadata(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Tuple[str, ...]] = None,
        asset_tags: Optional[Tuple[str, ...]] = None,
    ) -> SourceInstanceView:
        """Update non-lifecycle metadata on an existing source instance."""
        _require_role(identity, ADMIN_ROLE)
        current = self._registry.get_required(source_instance_id)
        if current.state is SourceState.RETIRED:
            raise SourceInstanceStateError(
                safe_message="retired source instances are immutable",
                internal_detail=(
                    f"source_instance_id={source_instance_id!r} "
                    f"state={current.state.value}"
                ),
            )
        updates: Dict[str, Any] = {
            "updated_by": identity.subject_id,
            "updated_at": _utcnow(),
        }
        if display_name is not None:
            if (
                not isinstance(display_name, str)
                or not display_name
                or len(display_name) > MAX_SOURCE_INSTANCE_NAME_LEN
            ):
                raise SourceConfigurationError(
                    safe_message="display_name invalid",
                    internal_detail=f"got {type(display_name).__name__}",
                )
            updates["display_name"] = display_name
        if description is not None:
            updates["description"] = str(description)
        if tags is not None:
            updates["tags"] = tuple(tags)
        if asset_tags is not None:
            updates["asset_tags"] = tuple(asset_tags)
        updated = current.model_copy(update=updates)
        persisted = self._repository.upsert(updated)
        self._registry.replace(persisted)
        return persisted.to_view()

    # ----------------------------------------------------------------- tokens
    def issue_ingress_token(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
    ) -> str:
        """Issue a fresh :class:`SourceIdentityToken` for a source."""
        _require_role(identity, ADMIN_ROLE)
        if self._token_issuer is None:
            raise SourceConfigurationError(
                safe_message="source token issuer is not configured",
                internal_detail=(
                    "set PROSHIELD_SOURCE_SIGNING_KEY to enable "
                    "token issuance"
                ),
            )
        current = self._registry.get_required(source_instance_id)
        # Phase 5.2: the capability-binding gate is evaluated BEFORE the
        # lifecycle-state gate so a quarantined source always reports the
        # specific, actionable reason (a missing capability binding) rather
        # than the incidental state symptom. Both are 409 refusals.
        self._require_bound(current, "token issuance")
        if current.state not in (
            SourceState.VALIDATED,
            SourceState.ENABLED,
        ):
            raise SourceInstanceStateError(
                safe_message=(
                    f"source instance {source_instance_id!r} is "
                    f"not in VALIDATED or ENABLED state "
                    f"(state={current.state.value})"
                ),
                internal_detail=f"current_state={current.state.value}",
            )
        token = self._token_issuer.issue(
            source_instance_id=source_instance_id,
            source_type=current.source_type,
            capability_id=current.capability_id,
        )
        packed = self._token_issuer.pack(token)
        self._audit(
            action="source_token_issue",
            source=current,
            reason=(
                f"capability {current.capability_id!r} "
                f"v{current.capability_version}"
            ),
            actor=identity.subject_id,
        )
        return packed

    def rotate_ingress_token(
        self,
        *,
        identity: Identity,
        source_instance_id: SourceInstanceId,
    ) -> str:
        """Rotate a source's credential by issuing a fresh token.

        Phase 5.2 rotation semantics (master plan §15/§19, as approved):
        issuing a new token *is* the rotation. Source-identity tokens are
        single-use and short-lived, so the previous token is either already
        spent (replay-rejected) or expires within the documented window; no
        separate revocation list is maintained in this phase. Retirement,
        which must revoke *future* issuance, is enforced by the RETIRED
        state gate in :meth:`issue_ingress_token` and by the ingress
        boundary's retired-source check — so a token that was issued before
        retirement still cannot ingest anything.

        This method exists so the rotation intent is explicit and audited,
        rather than being an undocumented side effect of "issue another
        token".
        """
        current = self._registry.get_required(source_instance_id)
        self._require_bound(current, "token rotation")
        packed = self.issue_ingress_token(
            identity=identity,
            source_instance_id=source_instance_id,
        )
        self._audit(
            action="source_token_rotate",
            source=current,
            reason="credential rotation issued a fresh single-use token",
            actor=identity.subject_id,
        )
        return packed

    # ----------------------------------------------------------------- reload
    def reload_from_repository(self) -> int:
        """Reload every persisted source instance into the registry."""
        instances = self._repository.find_all()
        for inst in instances:
            existing = self._registry.get(inst.source_instance_id)
            if existing is None:
                self._registry.register(inst)
            else:
                self._registry.replace(inst)
        return len(instances)


# ----------------------------------------------------------------- helpers
def _require_role(identity: Identity, role: str) -> None:
    """Authorise a write operation against the source-management layer.

    Defence-in-depth: this is the **service-layer** gate
    invoked after the proxy-level ``SOURCE_WRITE`` permission
    check. We no longer reuse ``RULE_WRITE`` (an odd coupling
    the wiring-verification audit flagged); source management
    now uses its own ``source:write`` permission.
    """
    if not isinstance(identity, Identity):
        raise SourceAuthorizationError(
            safe_message="source write denied",
            internal_detail="identity is required",
        )
    if identity.role != ADMIN_ROLE:
        raise SourceAuthorizationError(
            safe_message="source write denied",
            internal_detail=(
                f"role={identity.role!r} is not authorised for "
                "source-management writes"
            ),
        )
    if identity.permissions:
        if not has_permission(
            role=identity.role,
            identity_permissions=identity.permissions,
            permission=Permission.SOURCE_WRITE,
        ):
            raise SourceAuthorizationError(
                safe_message="source write denied",
                internal_detail="missing source:write permission",
            )


def _normalize_tag_tuple(tags) -> Tuple[str, ...]:
    """Return a sorted, de-duplicated, string-only tag tuple.

    STRIX F-5 / N-3: the source model requires unique, sorted tags.
    Normalizing at the owning layer means unsorted/duplicate input can
    no longer escape as a pydantic error into the proxy's fail-safe
    boundary. Non-string, empty members are dropped; persistence bounds
    are enforced by the model itself.
    """
    if not isinstance(tags, (tuple, list)):
        return ()
    seen = set()
    out = []
    for t in tags:
        if not isinstance(t, str):
            continue
        t = t.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return tuple(sorted(out))


__all__ = [
    "SourceManagementService",
]