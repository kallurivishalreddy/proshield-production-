"""Authoritative, persisted, human-readable entity identifiers.

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md (gap 2).

The analyst UI presents human-readable ids (``CASE-000001``). Before
this module the ids were derived client-side from ``created_at``
ordering — deterministic only while the underlying row set is stable,
and shared by every client only by accident.

This module is the **single owning allocator** for human ids. It is
persistence-backed and concurrency-safe:

* MongoDB backend: a dedicated ``counters`` collection with an
  atomic ``find_one_and_update`` ``$inc`` (the documented
  allocation pattern for monotonic sequences). A unique index on
  the counter ``_id`` guarantees at most one counter doc per
  entity kind.
* In-memory backend (tests / ``--backend memory``): a process-local
  counter with the same allocation contract.

Guarantees
----------
* Stable across restarts (persisted counter).
* Stable across clients (server-assigned, returned on the wire).
* Unique (monotonic sequence, atomic increment).
* Concurrency-safe (atomic server-side increment, never
  read-then-write).
* Mapped 1:1 to the technical id: the human id is assigned at
  creation time and stored **on the entity document itself** next
  to the technical id.

What this module does NOT do
----------------------------
* It does NOT derive ids from wall-clock ordering of rows.
* It does NOT mutate existing documents (entities created before
  this module keep ``human_id=""``; the wire renders ``null`` and
  the UI falls back to the technical id — no fabrication).
"""
from __future__ import annotations

import itertools
import threading
from typing import Any, Dict, Optional

from pymongo import ReturnDocument
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

from ..domain.errors import PersistenceError


# Entity kind -> (counter doc _id, human-id prefix, zero padding)
ENTITY_KINDS: Dict[str, Dict[str, str]] = {
    "incident": {"counter": "incident", "prefix": "CASE", "pad": "6"},
    "detection": {"counter": "detection", "prefix": "DET", "pad": "6"},
    "correlation": {"counter": "correlation", "prefix": "CORR", "pad": "6"},
    "source": {"counter": "source", "prefix": "SRC", "pad": "6"},
    "capability": {"counter": "capability", "prefix": "CAP", "pad": "6"},
}

COUNTERS_COLLECTION = "counters"


class HumanIdAllocator:
    """Allocate monotonic human ids for one entity kind."""

    def __init__(
        self,
        collection: Optional[Collection],
        entity_kind: str,
    ) -> None:
        spec = ENTITY_KINDS.get(entity_kind)
        if spec is None:
            raise ValueError(f"unknown entity kind: {entity_kind!r}")
        self._spec = spec
        self._collection = collection
        self._lock = threading.Lock()
        self._memory_seq = itertools.count(1)

    def allocate(self) -> str:
        """Return the next human id for this entity kind."""
        if self._collection is None:
            with self._lock:
                seq = next(self._memory_seq)
            return self._format(seq)
        try:
            doc = self._collection.find_one_and_update(
                {"_id": self._spec["counter"]},
                {"$inc": {"seq": 1}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            seq = int(doc["seq"])
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not allocate identifier",
                internal_detail=(
                    f"counter={self._spec['counter']!r} "
                    f"failed: {type(exc).__name__}"
                ),
            ) from exc
        return self._format(seq)

    def _format(self, seq: int) -> str:
        return (
            f"{self._spec['prefix']}-"
            f"{seq:0{int(self._spec['pad'])}d}"
        )


__all__ = [
    "ENTITY_KINDS",
    "COUNTERS_COLLECTION",
    "HumanIdAllocator",
]
