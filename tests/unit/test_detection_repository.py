"""Unit tests for the detection repository (no MongoDB).

The repository is a thin pymongo wrapper; the unit tests focus
on input validation, payload construction, and the
idempotency/duplicate-key path. Integration tests exercise
the real MongoDB round-trip.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.config import ProShieldConfig
from app.detection.models import Detection
from app.domain.errors import (
    DuplicateEventError,
    PersistenceError,
    ValidationError,
)
from app.persistence.detection_repository import (
    DETECTIONS_VALIDATOR,
    INDEX_SPECS,
    DetectionRepository,
    _document_to_detection,
    detection_collection_name,
)


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _det(**overrides) -> Detection:
    defaults = dict(
        detection_id="det-01923456-7890-7abc-9def-0123456789ab",
        rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1,
        category="source_specific",
        event_id="01923456-7890-7abc-9def-0123456789ab",
        evidence_refs=("01923456-7890-7abc-9def-0123456789ab",),
        reasoning="nginx HTTP 401 authentication_failure on '/api/login' from '198.51.100.7'",
        detected_at=FIXED_NOW,
    )
    defaults.update(overrides)
    return Detection(**defaults)


@pytest.fixture
def config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        mongo_uri="mongodb://localhost:27017",
        mongo_db="proshield_test",
    )


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.list_collection_names.return_value = []
    return db


class TestCollectionName:
    def test_default_name(self, config: ProShieldConfig) -> None:
        assert detection_collection_name(config) == "detections"


class TestIndexSpecs:
    def test_index_set_is_documented(self) -> None:
        names = sorted(spec["name"] for spec in INDEX_SPECS)
        assert "det_detection_id_unique" in names
        assert "det_rule_id" in names
        assert "det_event_id" in names
        assert "det_detected_at_desc" in names

    def test_detection_id_is_unique(self) -> None:
        unique_spec = next(
            s for s in INDEX_SPECS
            if s["name"] == "det_detection_id_unique"
        )
        assert unique_spec.get("unique") is True


class TestValidator:
    def test_validator_requires_documented_fields(self) -> None:
        required = DETECTIONS_VALIDATOR["$jsonSchema"]["required"]
        for field in (
            "detection_id",
            "rule_id",
            "rule_version",
            "category",
            "event_id",
            "evidence_refs",
            "reasoning",
            "detected_at",
        ):
            assert field in required

    def test_validator_rejects_extra_fields(self) -> None:
        """D-3 regression: top-level ``additionalProperties: false``.

        The MongoDB ``$jsonSchema`` validator must reject any
        top-level field not in the documented ``properties``
        dictionary, blocking direct DB writes that bypass the
        Pydantic ``extra='forbid'`` model contract.
        """
        schema = DETECTIONS_VALIDATOR["$jsonSchema"]
        assert schema.get("additionalProperties") is False


class TestConstruction:
    def test_collection_name_uses_helper(self, config, mock_db) -> None:
        repo = DetectionRepository(mock_db, config)
        assert repo._collection_name == "detections"


class TestCreateInputValidation:
    def test_non_detection_rejected(self, config, mock_db) -> None:
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.create("not a detection")  # type: ignore[arg-type]


class TestCreateMock:
    def test_inserts_detection(self, config, mock_db) -> None:
        """Capability patch gap 2: create() returns an enriched copy
        carrying the persisted human id (DET-<seq>); the input
        (frozen) model is never mutated."""
        repo = DetectionRepository(mock_db, config)
        d = _det()
        result = repo.create(d)
        assert result is not d
        assert result.detection_id == d.detection_id
        assert result.human_id == "DET-000001"
        assert d.human_id == ""  # input untouched
        args, _ = mock_db.__getitem__("detections").insert_one.call_args
        assert args[0]["correlated"] is False
        assert isinstance(args[0]["detected_at"], datetime)
        assert args[0]["human_id"] == "DET-000001"

    def test_duplicate_create_does_not_burn_human_id(
        self, config, mock_db,
    ) -> None:
        repo = DetectionRepository(mock_db, config)
        mock_db.__getitem__("detections").insert_one.side_effect = (
            DuplicateKeyError("dup")
        )
        with pytest.raises(DuplicateEventError):
            repo.create(_det())

    def test_duplicate_key_raises_duplicate_event(self, config, mock_db) -> None:
        repo = DetectionRepository(mock_db, config)
        mock_db.__getitem__("detections").insert_one.side_effect = (
            DuplicateKeyError("dup")
        )
        with pytest.raises(DuplicateEventError):
            repo.create(_det())

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        repo = DetectionRepository(mock_db, config)
        mock_db.__getitem__("detections").insert_one.side_effect = (
            PyMongoError("conn lost")
        )
        with pytest.raises(PersistenceError):
            repo.create(_det())


class TestEnsureSchema:
    def test_creates_collection_when_missing(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = []
        repo = DetectionRepository(mock_db, config)
        repo.ensure_schema()
        mock_db.create_collection.assert_called_once()

    def test_skips_when_collection_exists(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = ["detections"]
        repo = DetectionRepository(mock_db, config)
        repo.ensure_schema()
        mock_db.create_collection.assert_not_called()

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = []
        mock_db.create_collection.side_effect = PyMongoError("boom")
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.ensure_schema()


class TestEnsureIndexes:
    def test_creates_all_indexes(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.list_indexes.return_value = []
        repo = DetectionRepository(mock_db, config)
        repo.ensure_indexes()
        assert coll.create_index.call_count == len(INDEX_SPECS)

    def test_idempotent_on_existing(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.list_indexes.return_value = [
            {"name": spec["name"]} for spec in INDEX_SPECS
        ]
        repo = DetectionRepository(mock_db, config)
        repo.ensure_indexes()
        coll.create_index.assert_not_called()

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.list_indexes.side_effect = PyMongoError("boom")
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.ensure_indexes()


class TestFindByEventId:
    def test_returns_detections_sorted_by_detected_at(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.find.return_value.sort.return_value = [
            {
                "detection_id": "det-01923456-7890-7abc-9def-0123456789ab",
                "rule_id": "NGINX-AUTH-FAILURE-001",
                "rule_version": 1,
                "category": "source_specific",
                "event_id": "ev-1",
                "evidence_refs": ["ev-1"],
                "reasoning": "r",
                "detected_at": FIXED_NOW,
                "extra": (),
            }
        ]
        repo = DetectionRepository(mock_db, config)
        out = repo.find_by_event_id("ev-1")
        assert len(out) == 1
        assert out[0].detection_id.startswith("det-")

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.find.return_value.sort.side_effect = PyMongoError("boom")
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.find_by_event_id("ev-1")

    def test_dict_event_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: dict input rejected to prevent NoSQL injection."""
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_event_id({"$ne": "x"})  # type: ignore[arg-type]
        mock_db.__getitem__("detections").find.assert_not_called()

    def test_int_event_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: non-str input rejected to prevent NoSQL injection."""
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_event_id(12345)  # type: ignore[arg-type]
        mock_db.__getitem__("detections").find.assert_not_called()


class TestFindByRule:
    def test_with_rule_version(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.find.return_value.sort.return_value = []
        repo = DetectionRepository(mock_db, config)
        out = repo.find_by_rule("NGINX-AUTH-FAILURE-001", rule_version=1)
        assert out == []
        query = coll.find.call_args[0][0]
        assert query["rule_id"] == "NGINX-AUTH-FAILURE-001"
        assert query["rule_version"] == 1

    def test_without_rule_version(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.find.return_value.sort.return_value = []
        repo = DetectionRepository(mock_db, config)
        out = repo.find_by_rule("NGINX-AUTH-FAILURE-001")
        assert out == []
        query = coll.find.call_args[0][0]
        assert "rule_version" not in query

    def test_dict_rule_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: dict input rejected to prevent NoSQL injection."""
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_rule({"$ne": "x"})  # type: ignore[arg-type]
        # The query must not have been executed.
        mock_db.__getitem__("detections").find.assert_not_called()

    def test_int_rule_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: non-str input rejected to prevent NoSQL injection."""
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_rule(12345)  # type: ignore[arg-type]
        mock_db.__getitem__("detections").find.assert_not_called()


class TestCount:
    def test_count(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.count_documents.return_value = 7
        repo = DetectionRepository(mock_db, config)
        assert repo.count() == 7

    def test_pymongo_error(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("detections")
        coll.count_documents.side_effect = PyMongoError("boom")
        repo = DetectionRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.count()


class TestDocumentToDetection:
    def test_strips_id_and_correlated(self) -> None:
        doc = {
            "_id": "fake-object-id",
            "correlated": True,
            "detection_id": "det-01923456-7890-7abc-9def-0123456789ab",
            "rule_id": "NGINX-AUTH-FAILURE-001",
            "rule_version": 1,
            "category": "source_specific",
            "event_id": "ev-1",
            "evidence_refs": ["ev-1"],
            "reasoning": "r",
            "detected_at": FIXED_NOW,
            "extra": (),
        }
        d = _document_to_detection(doc)
        assert d.detection_id == doc["detection_id"]