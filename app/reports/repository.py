"""Report repository.

Reference: docs/PHASE 4/PHASE 4-08.

The :class:`ReportRepository` is the only place that
talks to pymongo about report documents.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError as PydanticValidationError
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    DuplicateKeyError,
    PyMongoError,
)

from ..config import ProShieldConfig
from ..domain.errors import (
    PersistenceError,
    ValidationError,
)
from .errors import ReportNotFoundError
from .models import Report


_log = logging.getLogger(__name__)


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "rpt_report_id_unique",
        "key": [("report_id", ASCENDING)],
        "unique": True,
    },
    {
        "name": "rpt_incident_id",
        "key": [("incident_id", ASCENDING), ("version", DESCENDING)],
    },
    {
        "name": "rpt_mode",
        "key": [("mode", ASCENDING), ("generated_at", DESCENDING)],
    },
    {
        "name": "rpt_generated_by",
        "key": [("generated_by", ASCENDING), ("generated_at", DESCENDING)],
    },
]


def report_collection_name(config: ProShieldConfig) -> str:
    """The collection name for the ``reports`` collection."""
    return getattr(config, "mongo_collection_reports", "reports")


# ----------------------------------------------------------------- repository
class ReportRepository:
    """Repository for the ``reports`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[report_collection_name(config)]

    @property
    def collection(self) -> Collection:
        return self._collection

    def ensure_schema(self) -> None:
        """Apply collection-level setup. Idempotent."""
        try:
            existing = self._db.command(
                "listCollections",
                filter={"name": self._collection.name},
            )
            docs = list(existing.get("cursor", {}).get("firstBatch", []))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not inspect reports collection",
                internal_detail=(
                    f"listCollections failed: {type(exc).__name__}"
                ),
            ) from exc
        try:
            if not docs:
                self._db.create_collection(self._collection.name)
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not apply reports schema",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def ensure_indexes(self) -> List[str]:
        try:
            existing = {
                ix["name"] for ix in self._collection.list_indexes()
            }
            created: List[str] = []
            for spec in INDEX_SPECS:
                if spec["name"] not in existing:
                    self._collection.create_index(
                        spec["key"],
                        name=spec["name"],
                        **{k: v for k, v in spec.items()
                           if k not in ("name", "key")},
                    )
                    created.append(spec["name"])
            return created
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create report indexes",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    # ----- CRUD
    def create(self, report: Report) -> Report:
        if not isinstance(report, Report):
            raise ValidationError(
                safe_message="report required",
                internal_detail=f"got {type(report).__name__}",
                field="report",
            )
        doc = report.to_dict()
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError:
            existing = self.get_by_id(report.report_id)
            if existing is not None:
                return existing
            raise PersistenceError(
                safe_message="could not create report",
                internal_detail="duplicate id but missing document",
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not create report",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return report

    def get_by_id(self, report_id: str) -> Optional[Report]:
        if not isinstance(report_id, str) or not report_id:
            raise ValidationError(
                safe_message="invalid report_id",
                internal_detail=f"got {type(report_id).__name__}",
                field="report_id",
            )
        try:
            doc = self._collection.find_one({"report_id": report_id})
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not read report",
                internal_detail=f"find_one failed: {type(exc).__name__}",
            ) from exc
        if doc is None:
            return None
        return _document_to_report(doc)

    def get_by_id_or_raise(self, report_id: str) -> Report:
        r = self.get_by_id(report_id)
        if r is None:
            raise ReportNotFoundError(
                safe_message="report not found",
                internal_detail=f"report_id={report_id}",
            )
        return r

    def find_for_incident(
        self, incident_id: str, *, limit: int = 20
    ) -> List[Report]:
        if not isinstance(incident_id, str) or not incident_id:
            raise ValidationError(
                safe_message="invalid incident_id",
                internal_detail=f"got {type(incident_id).__name__}",
                field="incident_id",
            )
        safe_limit = max(1, min(int(limit), 100))
        try:
            docs = list(
                self._collection.find({"incident_id": incident_id})
                .sort("version", DESCENDING)
                .limit(safe_limit)
            )
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not list reports",
                internal_detail=f"find failed: {type(exc).__name__}",
            ) from exc
        out: List[Report] = []
        for d in docs:
            try:
                out.append(_document_to_report(d))
            except (PydanticValidationError, ValueError, TypeError) as exc:
                _log.warning(
                    "report.document_quarantined",
                    extra={
                        "report_id": d.get("report_id"),
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:512],
                    },
                )
        return out

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise PersistenceError(
                safe_message="could not count reports",
                internal_detail=f"{type(exc).__name__}",
            ) from exc


# ----------------------------------------------------------------- helpers
def _document_to_report(doc: Dict[str, Any]) -> Report:
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    for ts_field in ("generated_at",):
        v = cleaned.get(ts_field)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                cleaned[ts_field] = v.replace(tzinfo=timezone.utc)
        elif isinstance(v, str):
            try:
                cleaned[ts_field] = datetime.fromisoformat(
                    v.replace("Z", "+00:00")
                )
            except ValueError:
                pass
    # ``to_dict`` serializes rule_references as a list of
    # ``{rule_id, rule_version}`` dicts for JSON-friendliness;
    # convert them back to the (rule_id, version) tuple
    # shape the model expects.
    refs = cleaned.get("rule_references")
    if isinstance(refs, list):
        cleaned["rule_references"] = tuple(
            (r["rule_id"], int(r["rule_version"]))
            if isinstance(r, dict)
            else tuple(r)
            for r in refs
        )
    return Report.model_validate(cleaned)


__all__ = [
    "INDEX_SPECS",
    "ReportRepository",
    "report_collection_name",
]