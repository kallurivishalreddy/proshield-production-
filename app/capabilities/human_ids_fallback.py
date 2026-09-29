"""Fallback CAP- allocator for pre-5.1 HumanIdAllocator catalogues.

Phase 5.1 adds the ``capability`` entity kind to
``app.persistence.human_ids.ENTITY_KINDS``. This fallback keeps the
capability repository importable in processes that still carry an older
allocator module (tests pinning behaviour, tooling). It implements the
same monotonic contract: Mongo-backed atomic ``$inc`` when a real
collection is available, process-local counter otherwise.
"""
from __future__ import annotations

import itertools
import threading
from typing import Any, Optional

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from ..domain.errors import PersistenceError


class FallbackCapabilityAllocator:
    def __init__(self, collection: Optional[Any] = None) -> None:
        self._collection = collection
        self._lock = threading.Lock()
        self._memory_seq = itertools.count(1)

    def allocate(self) -> str:
        if self._collection is None:
            with self._lock:
                seq = next(self._memory_seq)
            return f"CAP-{seq:06d}"
        try:
            doc = self._collection.find_one_and_update(
                {"_id": "capability"},
                {"$inc": {"seq": 1}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            seq = int(doc["seq"])
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not allocate identifier",
                internal_detail=f"counter='capability' failed: {type(exc).__name__}",
            ) from exc
        return f"CAP-{seq:06d}"


__all__ = ["FallbackCapabilityAllocator"]
