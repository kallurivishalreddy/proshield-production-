"""Shared in-memory fakes for Phase 4.9 source-management tests."""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple


class FakeSourceCollection:
    """A minimal in-memory replacement for pymongo's Collection."""

    def __init__(self, name: str = "fake_collection") -> None:
        self.name = name
        self.docs: List[Dict[str, Any]] = []

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        from pymongo.errors import DuplicateKeyError
        # D-7: Production uniqueness uses the (source_instance_id)
        # unique index. The fake must consider two docs equal only
        # when both have an explicit, non-None value.
        new_sid = doc.get("source_instance_id")
        for d in self.docs:
            existing_sid = d.get("source_instance_id")
            if (
                existing_sid is not None
                and new_sid is not None
                and existing_sid == new_sid
            ):
                raise DuplicateKeyError("duplicate source_instance_id")
        cleaned = copy.deepcopy(dict(doc))
        self.docs.append(cleaned)
        return type("R", (), {"inserted_id": "fake"})()

    def find_one(
        self,
        query: Dict[str, Any],
        sort: Optional[List[Tuple[str, int]]] = None,
    ) -> Optional[Dict[str, Any]]:
        results = [d for d in self.docs if _match(d, query)]
        if not results:
            return None
        if sort:
            for k, direction in reversed(sort):
                results.sort(
                    key=lambda d, k=k: d.get(k),
                    reverse=(direction == -1),
                )
        return copy.deepcopy(results[0])

    def find(self, query: Dict[str, Any]) -> "FakeSourceCursor":
        return FakeSourceCursor(
            [d for d in self.docs if _match(d, query)]
        )

    def replace_one(
        self,
        query: Dict[str, Any],
        doc: Dict[str, Any],
        upsert: bool = False,
    ) -> Any:
        cleaned = copy.deepcopy(dict(doc))
        for d in self.docs:
            if _match(d, query):
                d.clear()
                d.update(cleaned)
                return type(
                    "R",
                    (),
                    {"matched_count": 1, "modified_count": 1},
                )()
        if upsert:
            self.docs.append(cleaned)
            return type(
                "R",
                (),
                {
                    "matched_count": 0,
                    "modified_count": 0,
                    "upserted_id": "fake",
                },
            )()
        return type(
            "R",
            (),
            {"matched_count": 0, "modified_count": 0},
        )()

    def update_one(
        self,
        query: Dict[str, Any],
        update: Dict[str, Any],
    ) -> Any:
        for d in self.docs:
            if _match(d, query):
                if "$set" in update:
                    d.update(copy.deepcopy(update["$set"]))
                return type(
                    "R",
                    (),
                    {"matched_count": 1, "modified_count": 1},
                )()
        return type(
            "R",
            (),
            {"matched_count": 0, "modified_count": 0},
        )()

    def count_documents(
        self, query: Optional[Dict[str, Any]] = None,
    ) -> int:
        if query is None:
            return len(self.docs)
        return sum(1 for d in self.docs if _match(d, query))

    def create_index(
        self,
        keys: Any,
        name: Optional[str] = None,
        unique: bool = False,
    ) -> Any:
        return name

    def find_one_and_update(
        self,
        query: Dict[str, Any],
        update: Dict[str, Any],
        *,
        upsert: bool = False,
        return_document: Any = None,
    ) -> Optional[Dict[str, Any]]:
        # V3-5.1 fix: mutate the STORED doc, not a find_one() copy.
        target = None
        for stored in self.docs:
            if _match(stored, query):
                target = stored
                break
        if target is None:
            if not upsert:
                return None
            target = dict(query)
            self.docs.append(target)
        if "$set" in update:
            target.update(copy.deepcopy(update["$set"]))
        if "$inc" in update:
            for k, v in update["$inc"].items():
                target[k] = int(target.get(k) or 0) + int(v)
        return copy.deepcopy(target)

    def list_indexes(self) -> list:
        return []


class FakeSourceCursor:
    def __init__(self, docs: List[Dict[str, Any]]) -> None:
        self._docs = [copy.deepcopy(d) for d in docs]

    def sort(
        self, key: str, direction: int = 1,
    ) -> "FakeSourceCursor":
        self._docs.sort(
            key=lambda d: d.get(key),
            reverse=(direction == -1),
        )
        return self

    def limit(self, n: int) -> "FakeSourceCursor":
        self._docs = self._docs[:max(0, n)]
        return self

    def __iter__(self):
        return iter(self._docs)


class FakeDatabase:
    """Minimal in-memory database replacement."""

    def __init__(self) -> None:
        self._collections: Dict[str, FakeSourceCollection] = {}

    def __getitem__(self, name: str) -> FakeSourceCollection:
        if name not in self._collections:
            self._collections[name] = FakeSourceCollection(name=name)
        return self._collections[name]

    def command(
        self,
        command_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if command_name == "listCollections":
            name = kwargs.get("filter", {}).get("name")
            if name is None:
                first_batch = [
                    {"name": n} for n in self._collections
                ]
            elif name in self._collections:
                first_batch = [{"name": name}]
            else:
                first_batch = []
            return {"cursor": {"firstBatch": first_batch}}
        return {"ok": 1.0}

    def create_collection(
        self,
        name: str,
        *,
        validator: Any = None,
        validationLevel: str = "strict",
        validationAction: str = "error",
    ) -> FakeSourceCollection:
        if name in self._collections:
            from pymongo.errors import CollectionInvalid
            raise CollectionInvalid(f"{name} already exists")
        col = FakeSourceCollection(name=name)
        self._collections[name] = col
        return col

    def list_collection_names(self) -> List[str]:
        return list(self._collections.keys())


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for k, v in query.items():
        if "." in k:
            parts = k.split(".")
            cur: Any = doc
            for p in parts:
                if not isinstance(cur, dict):
                    cur = None
                    break
                cur = cur.get(p)
            if cur != v:
                return False
        else:
            if doc.get(k) != v:
                return False
    return True


__all__ = [
    "FakeDatabase",
    "FakeSourceCollection",
    "FakeSourceCursor",
]