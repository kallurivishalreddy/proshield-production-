"""Source Management in-memory registry (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

The :class:`SourceRegistry` is the **in-process authoritative
catalogue** of "what external security systems are configured
to talk to ProShield". It mirrors the design rules of the
Phase 4.2 :class:`app.rules.registry.RuleRegistry`:

* **In-memory only.** Persistence is the
  :class:`app.sources.repository.SourceRepository`'s job; the
  registry is what the live pipeline looks up.
* **No mutation outside the documented methods.**
* **Idempotent lookups.** Lookup methods never raise for "not
  found"; they return ``None`` or an empty list.
* **Deterministic iteration.**
* **Strict on the lifecycle state machine.** Only the
  documented transitions are allowed.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .errors import (
    DuplicateSourceInstanceError,
    SourceInstanceNotFoundError,
    SourceInstanceStateError,
)
from .models import (
    SourceInstance,
    SourceInstanceId,
    SourceState,
    SourceType,
)


ALLOWED_TRANSITIONS: Dict[SourceState, frozenset[SourceState]] = {
    SourceState.REGISTERED: frozenset({SourceState.CONFIGURED, SourceState.RETIRED}),
    SourceState.CONFIGURED: frozenset({
        SourceState.VALIDATED,
        SourceState.REGISTERED,
        SourceState.RETIRED,
    }),
    SourceState.VALIDATED: frozenset({
        SourceState.ENABLED,
        SourceState.DISABLED,
        SourceState.CONFIGURED,
        SourceState.RETIRED,
    }),
    SourceState.ENABLED: frozenset({
        SourceState.DISABLED,
        SourceState.RETIRED,
    }),
    SourceState.DISABLED: frozenset({
        SourceState.ENABLED,
        SourceState.CONFIGURED,
        SourceState.RETIRED,
    }),
    SourceState.RETIRED: frozenset(),
}


def can_transition(
    current: SourceState, target: SourceState
) -> bool:
    """Pure helper: is ``current -> target`` a legal transition?"""
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


class SourceRegistry:
    """The authoritative in-memory source-instance catalogue."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: Dict[SourceInstanceId, SourceInstance] = {}
        self._by_state: Dict[SourceState, List[SourceInstanceId]] = {
            s: [] for s in SourceState
        }
        self._by_type: Dict[SourceType, List[SourceInstanceId]] = {
            t: [] for t in SourceType
        }

    # ----------------------------------------------------------------- mutators
    def register(self, instance: SourceInstance) -> SourceInstance:
        """Add a new :class:`SourceInstance` to the registry."""
        if not isinstance(instance, SourceInstance):
            raise TypeError(
                f"instance must be a SourceInstance, "
                f"got {type(instance).__name__}"
            )
        with self._lock:
            if instance.source_instance_id in self._by_id:
                raise DuplicateSourceInstanceError(
                    safe_message=(
                        f"source instance "
                        f"{instance.source_instance_id!r} is "
                        "already registered"
                    ),
                    internal_detail=(
                        f"duplicate id; existing state="
                        f"{self._by_id[instance.source_instance_id].state.value}"
                    ),
                )
            self._by_id[instance.source_instance_id] = instance
            self._index(instance)
            return instance

    def replace(self, instance: SourceInstance) -> SourceInstance:
        """Replace an existing :class:`SourceInstance` in place."""
        if not isinstance(instance, SourceInstance):
            raise TypeError(
                f"instance must be a SourceInstance, "
                f"got {type(instance).__name__}"
            )
        with self._lock:
            if instance.source_instance_id not in self._by_id:
                raise SourceInstanceNotFoundError(
                    safe_message=(
                        f"source instance "
                        f"{instance.source_instance_id!r} "
                        "is not registered"
                    ),
                    internal_detail="replace() called for unknown id",
                )
            self._deindex(self._by_id[instance.source_instance_id])
            self._by_id[instance.source_instance_id] = instance
            self._index(instance)
            return instance

    def transition(
        self,
        *,
        source_instance_id: SourceInstanceId,
        target: SourceState,
    ) -> SourceInstance:
        """Transition an instance to ``target`` if the state machine permits."""
        with self._lock:
            current = self._by_id.get(source_instance_id)
            if current is None:
                raise SourceInstanceNotFoundError(
                    safe_message=(
                        f"source instance "
                        f"{source_instance_id!r} "
                        "is not registered"
                    ),
                    internal_detail="transition() called for unknown id",
                )
            if not can_transition(current.state, target):
                raise SourceInstanceStateError(
                    safe_message=(
                        f"cannot transition source instance "
                        f"{source_instance_id!r} from "
                        f"{current.state.value} to {target.value}"
                    ),
                    internal_detail=(
                        f"current_state={current.state.value} "
                        f"target_state={target.value}"
                    ),
                )
            new = current.model_copy(
                update={
                    "state": target,
                    "updated_at": current.updated_at,
                },
            )
            if target is SourceState.RETIRED and new.retired_at is None:
                from datetime import datetime, timezone
                new = new.model_copy(update={
                    "retired_at": datetime.now(timezone.utc),
                })
            self._deindex(current)
            self._by_id[source_instance_id] = new
            self._index(new)
            return new

    def remove(self, source_instance_id: SourceInstanceId) -> None:
        """Remove an instance from the registry."""
        with self._lock:
            current = self._by_id.get(source_instance_id)
            if current is None:
                raise SourceInstanceNotFoundError(
                    safe_message=(
                        f"source instance "
                        f"{source_instance_id!r} "
                        "is not registered"
                    ),
                    internal_detail="remove() called for unknown id",
                )
            self._deindex(current)
            del self._by_id[source_instance_id]

    # ----------------------------------------------------------------- lookups
    def get(
        self,
        source_instance_id: SourceInstanceId,
    ) -> Optional[SourceInstance]:
        with self._lock:
            return self._by_id.get(source_instance_id)

    def get_required(
        self,
        source_instance_id: SourceInstanceId,
    ) -> SourceInstance:
        inst = self.get(source_instance_id)
        if inst is None:
            raise SourceInstanceNotFoundError(
                safe_message=(
                    f"source instance "
                    f"{source_instance_id!r} is not registered"
                ),
                internal_detail="get_required() failed",
            )
        return inst

    def list_by_state(self, state: SourceState) -> List[SourceInstance]:
        with self._lock:
            ids = list(self._by_state.get(state, ()))
        return [self._by_id[i] for i in ids if i in self._by_id]

    def list_by_type(self, source_type: SourceType) -> List[SourceInstance]:
        with self._lock:
            ids = list(self._by_type.get(source_type, ()))
        return [self._by_id[i] for i in ids if i in self._by_id]

    def list_all(self) -> List[SourceInstance]:
        with self._lock:
            ids = sorted(self._by_id.keys())
        return [self._by_id[i] for i in ids]

    def count(self) -> int:
        with self._lock:
            return len(self._by_id)

    def known_ids(self) -> Tuple[SourceInstanceId, ...]:
        with self._lock:
            return tuple(sorted(self._by_id.keys()))

    def is_enabled(self, source_instance_id: SourceInstanceId) -> bool:
        inst = self.get(source_instance_id)
        return inst is not None and inst.state is SourceState.ENABLED

    # ----------------------------------------------------------------- internals
    def _index(self, instance: SourceInstance) -> None:
        self._by_state[instance.state].append(instance.source_instance_id)
        self._by_type[instance.source_type].append(instance.source_instance_id)

    def _deindex(self, instance: SourceInstance) -> None:
        if instance.source_instance_id in self._by_state[instance.state]:
            self._by_state[instance.state].remove(
                instance.source_instance_id
            )
        if instance.source_instance_id in self._by_type[instance.source_type]:
            self._by_type[instance.source_type].remove(
                instance.source_instance_id
            )


# F-6: only connector types that have a real connector
# implementation + rule library are advertised as "supported".
# The SourceType enum still declares the full closed-set of possible
# kinds (so a future connector can reuse the model), but
# ``supported_connector_types()`` -- which drives the wire
# ``source.list_types`` response and thereby the UI combobox -- must
# reflect which kinds are actually implemented today. Only ``nginx``
# (full rule library) and ``simulator`` have runnable connectors;
# ``waf``, ``iam``, ``rate_limit`` and ``network`` have NO
# connector/rules implementation, so advertising them as "supported"
# would (and did) create phantom sources the system cannot ingest or
# evaluate.
SUPPORTED_CONNECTOR_TYPES: frozenset[SourceType] = frozenset({
    SourceType.NGINX,
    SourceType.SIMULATOR,
})


def supported_connector_types() -> List[SourceType]:
    """Return the closed-set list of supported connector types.

    Only types with a real connector implementation and a rule
    library are included (F-6). Declared-but-unimplemented kinds
    are intentionally excluded so the UI never advertises phantom
    capabilities and registration never panics on an unknown type.
    """
    return sorted(SUPPORTED_CONNECTOR_TYPES, key=lambda t: t.value)


__all__ = [
    "ALLOWED_TRANSITIONS",
    "SUPPORTED_CONNECTOR_TYPES",
    "SourceRegistry",
    "can_transition",
    "supported_connector_types",
]