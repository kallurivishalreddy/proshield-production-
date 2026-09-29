"""In-memory Capability registry (Phase 5.1).

Mirrors the Phase 4.9 :class:`SourceRegistry` design rules:
in-memory only, deterministic iteration, idempotent lookups, strict
lifecycle transitions.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from .errors import (
    CapabilityAlreadyExistsError,
    CapabilityNotFoundError,
    CapabilityStateError,
)
from .models import Capability, CapabilityId, CapabilityStatus


ALLOWED_TRANSITIONS: Dict[CapabilityStatus, frozenset] = {
    # Planned custom capabilities are creatable/editable drafts. A planned
    # draft may retire / archive only — it can NEVER go to ``disabled``:
    # the model invariant (``implementation_ref=planned`` requires status
    # planned/retired/archived) forbids impl=planned+status=disabled, and
    # persisting that combination used to quarantine the document after a
    # restart (finding 5.1-01). It can never *activate* to live either
    # (service-layer guard keeps planned implementation_ref from going
    # live).
    CapabilityStatus.PLANNED: frozenset({CapabilityStatus.RETIRED, CapabilityStatus.ARCHIVED}),
    CapabilityStatus.ACTIVE: frozenset({
        CapabilityStatus.DISABLED,
        CapabilityStatus.DEPRECATED,
        CapabilityStatus.RETIRED,
    }),
    CapabilityStatus.DISABLED: frozenset({
        CapabilityStatus.ACTIVE,
        CapabilityStatus.PLANNED,
        CapabilityStatus.DEPRECATED,
        CapabilityStatus.RETIRED,
    }),
    CapabilityStatus.DEPRECATED: frozenset({
        CapabilityStatus.ACTIVE,
        CapabilityStatus.DISABLED,
        CapabilityStatus.RETIRED,
    }),
    CapabilityStatus.RETIRED: frozenset({CapabilityStatus.ARCHIVED}),
    CapabilityStatus.ARCHIVED: frozenset(),
}


def can_transition(current: CapabilityStatus, target: CapabilityStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


class CapabilityRegistry:
    """Authoritative in-memory capability catalogue."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: Dict[str, Capability] = {}

    def register(self, capability: Capability) -> Capability:
        if not isinstance(capability, Capability):
            raise TypeError(f"capability must be a Capability, got {type(capability).__name__}")
        with self._lock:
            if capability.capability_id in self._by_id:
                raise CapabilityAlreadyExistsError(
                    safe_message=f"capability {capability.capability_id!r} already exists",
                    internal_detail="registry duplicate",
                )
            self._by_id[capability.capability_id] = capability
            return capability

    def replace(self, capability: Capability) -> Capability:
        if not isinstance(capability, Capability):
            raise TypeError(f"capability must be a Capability, got {type(capability).__name__}")
        with self._lock:
            if capability.capability_id not in self._by_id:
                raise CapabilityNotFoundError(
                    safe_message=f"capability {capability.capability_id!r} is not registered",
                    internal_detail="registry.replace() missing",
                )
            self._by_id[capability.capability_id] = capability
            return capability

    def transition(self, capability_id: str, target: CapabilityStatus) -> Capability:
        with self._lock:
            current = self._by_id.get(capability_id)
            if current is None:
                raise CapabilityNotFoundError(
                    safe_message=f"capability {capability_id!r} is not registered",
                    internal_detail="registry.transition() missing",
                )
            if not can_transition(current.status, target):
                raise CapabilityStateError(
                    safe_message=f"transition {current.status.value}->{target.value} is not allowed",
                    internal_detail=f"current={current.status.value}",
                )
            updated = current.model_copy(update={"status": target})
            self._by_id[capability_id] = updated
            return updated

    def get(self, capability_id: str) -> Optional[Capability]:
        with self._lock:
            return self._by_id.get(capability_id)

    def get_required(self, capability_id: str) -> Capability:
        inst = self.get(capability_id)
        if inst is None:
            raise CapabilityNotFoundError(
                safe_message=f"capability {capability_id!r} is not registered",
                internal_detail="get_required() failed",
            )
        return inst

    def list_all(self) -> List[Capability]:
        with self._lock:
            ids = sorted(self._by_id.keys())
        return [self._by_id[i] for i in ids]

    def list_by_status(self, status: CapabilityStatus) -> List[Capability]:
        with self._lock:
            return [c for cid in sorted(self._by_id.keys()) for c in (self._by_id[cid],) if c.status is status]

    def count(self) -> int:
        with self._lock:
            return len(self._by_id)

    def known_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._by_id.keys()))


__all__ = ["ALLOWED_TRANSITIONS", "CapabilityRegistry", "can_transition"]
