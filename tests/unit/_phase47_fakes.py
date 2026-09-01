"""Shared in-memory fakes for the Phase 4.7 unit tests.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md.

The Phase 4.7 service / repository tests use these
fakes to drive the production code paths without
spinning up a MongoDB. The integration tests in
``tests/integration/test_phase47_pipeline.py`` exercise
the same code path against the real local MongoDB.

The fakes are intentionally tiny: enough to drive
``RuleRepository``'s public methods end-to-end without
pulling in the full pymongo stack.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class FakeCollection:
    """A minimal in-memory replacement for pymongo's Collection."""

    def __init__(self) -> None:
        self.docs: List[Dict[str, Any]] = []

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        for d in self.docs:
            if (
                d.get("rule_id") == doc.get("rule_id")
                and d.get("version") == doc.get("version")
            ):
                from pymongo.errors import DuplicateKeyError
                raise DuplicateKeyError("duplicate (rule_id, version)")
        self.docs.append(dict(doc))
        return type("R", (), {"inserted_id": "fake"})()

    def find_one(
        self,
        query: Dict[str, Any],
        sort: Optional[List[tuple]] = None,
    ) -> Optional[Dict[str, Any]]:
        results = [d for d in self.docs if _match(d, query)]
        if not results:
            return None
        if sort:
            for k, direction in reversed(sort):
                results.sort(key=lambda d, k=k: d.get(k), reverse=(direction == -1))
        return dict(results[0])

    def find(self, query: Dict[str, Any]) -> "FakeCursor":
        return FakeCursor([d for d in self.docs if _match(d, query)])

    def aggregate(self, pipeline: List[Dict[str, Any]]) -> "FakeCursor":
        docs = list(self.docs)
        for stage in pipeline:
            if "$match" in stage:
                docs = [d for d in docs if _match(d, stage["$match"])]
            elif "$sort" in stage:
                k, direction = list(stage["$sort"].items())[0]
                docs = sorted(docs, key=lambda d, k=k: d.get(k), reverse=(direction == -1))
            elif "$group" in stage:
                grouped: Dict[str, Any] = {}
                for d in docs:
                    grouped[d["rule_id"]] = d
                docs = [{"_id": k, "doc": v} for k, v in grouped.items()]
            elif "$replaceRoot" in stage:
                docs = [d["doc"] for d in docs]
        return FakeCursor(docs)

    def replace_one(
        self,
        query: Dict[str, Any],
        doc: Dict[str, Any],
        upsert: bool = False,
    ) -> Any:
        for d in self.docs:
            if _match(d, query):
                d.clear()
                d.update(doc)
                return type("R", (), {"matched_count": 1, "modified_count": 1})()
        if upsert:
            self.docs.append(dict(doc))
            return type("R", (), {"matched_count": 0, "upserted_id": "fake"})()
        return type("R", (), {"matched_count": 0, "modified_count": 0})()

    def update_one(
        self, query: Dict[str, Any], update: Dict[str, Any]
    ) -> Any:
        for d in self.docs:
            if _match(d, query):
                if "$set" in update:
                    d.update(update["$set"])
                return type("R", (), {"matched_count": 1, "modified_count": 1})()
        return type("R", (), {"matched_count": 0, "modified_count": 0})()

    def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for d in self.docs if _match(d, query))

    def create_index(self, key: List[tuple], *, name: str, unique: bool = False) -> Any:
        return name


class FakeCursor:
    def __init__(self, docs: List[Dict[str, Any]]) -> None:
        self.docs = docs

    def sort(self, key, direction: Optional[int] = None) -> "FakeCursor":
        """Support both ``sort("field", ASCENDING)`` and ``sort([("field", 1)])``."""
        if direction is not None:
            k = key
            d = direction
            self.docs = sorted(
                self.docs, key=lambda x, k=k: x.get(k), reverse=(d == -1)
            )
            return self
        for k, d in reversed(list(key)):
            self.docs = sorted(
                self.docs, key=lambda x, k=k: x.get(k), reverse=(d == -1)
            )
        return self

    def __iter__(self):
        return iter(self.docs)


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for k, v in query.items():
        if doc.get(k) != v:
            return False
    return True


class FakeDatabase:
    def __init__(self) -> None:
        self.collections: Dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self.collections:
            self.collections[name] = FakeCollection()
        return self.collections[name]

    def command(self, *args: Any, **kwargs: Any) -> Any:
        return {"cursor": {"firstBatch": []}}


__all__ = [
    "FakeCollection",
    "FakeCursor",
    "FakeDatabase",
    "_match",
]
