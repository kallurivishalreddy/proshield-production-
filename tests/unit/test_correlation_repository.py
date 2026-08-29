"""Unit tests for the correlation repository (no MongoDB)."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.config import ProShieldConfig
from app.correlation.models import (
    Correlation,
    CorrelationKey,
)
from app.domain.errors import (
    DuplicateEventError,
    PersistenceError,
    ValidationError,
)
from app.persistence.correlation_repository import (
    CORRELATIONS_VALIDATOR,
    INDEX_SPECS,
    CorrelationRepository,
    _document_to_correlation,
    correlation_collection_name,
)


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
FIXED_EARLIER = datetime(2026, 8, 28, 11, 55, 0, tzinfo=timezone.utc)
FIXED_LATER = datetime(2026, 8, 28, 12, 5, 0, tzinfo=timezone.utc)


def _corr(**overrides) -> Correlation:
    defaults = dict(
        correlation_id="corr-01923456-7890-7abc-9def-0123456789ab",
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=(
            "det-01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "det-01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        event_ids=(
            "01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        window_start=FIXED_EARLIER,
        window_end=FIXED_LATER,
        count=2,
        reasoning="brute-force clustering: 2 ...",
        correlated_at=FIXED_NOW,
    )
    defaults.update(overrides)
    return Correlation(**defaults)


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
        assert correlation_collection_name(config) == "correlations"


class TestIndexSpecs:
    def test_index_set_is_documented(self) -> None:
        names = sorted(spec["name"] for spec in INDEX_SPECS)
        assert "corr_correlation_id_unique" in names
        assert "corr_pattern_id" in names
        assert "corr_window" in names
        assert "corr_key" in names

    def test_correlation_id_is_unique(self) -> None:
        spec = next(
            s for s in INDEX_SPECS
            if s["name"] == "corr_correlation_id_unique"
        )
        assert spec.get("unique") is True


class TestValidator:
    def test_validator_requires_documented_fields(self) -> None:
        required = CORRELATIONS_VALIDATOR["$jsonSchema"]["required"]
        for f in (
            "correlation_id",
            "pattern_id",
            "pattern_version",
            "trigger",
            "key",
            "detection_ids",
            "event_ids",
            "window_start",
            "window_end",
            "count",
            "reasoning",
            "correlated_at",
        ):
            assert f in required

    def test_validator_rejects_extra_fields(self) -> None:
        """D-3 regression: top-level ``additionalProperties: false``.

        The MongoDB ``$jsonSchema`` validator must reject any
        top-level field not in the documented ``properties``
        dictionary, blocking direct DB writes that bypass the
        Pydantic ``extra='forbid'`` model contract.
        """
        schema = CORRELATIONS_VALIDATOR["$jsonSchema"]
        assert schema.get("additionalProperties") is False


class TestConstruction:
    def test_collection_name(self, config, mock_db) -> None:
        repo = CorrelationRepository(mock_db, config)
        assert repo._collection_name == "correlations"


class TestCreateInputValidation:
    def test_non_correlation_rejected(self, config, mock_db) -> None:
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.create("not a correlation")  # type: ignore[arg-type]


class TestCreateMock:
    def test_inserts_correlation(self, config, mock_db) -> None:
        repo = CorrelationRepository(mock_db, config)
        c = _corr()
        result = repo.create(c)
        assert result is c
        args, _ = mock_db.__getitem__("correlations").insert_one.call_args
        assert isinstance(args[0]["correlated_at"], datetime)
        assert isinstance(args[0]["window_start"], datetime)
        assert isinstance(args[0]["window_end"], datetime)

    def test_duplicate_key_raises_duplicate_event(self, config, mock_db) -> None:
        repo = CorrelationRepository(mock_db, config)
        mock_db.__getitem__("correlations").insert_one.side_effect = (
            DuplicateKeyError("dup")
        )
        with pytest.raises(DuplicateEventError):
            repo.create(_corr())

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        repo = CorrelationRepository(mock_db, config)
        mock_db.__getitem__("correlations").insert_one.side_effect = (
            PyMongoError("conn lost")
        )
        with pytest.raises(PersistenceError):
            repo.create(_corr())


class TestEnsureSchema:
    def test_creates_collection_when_missing(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = []
        repo = CorrelationRepository(mock_db, config)
        repo.ensure_schema()
        mock_db.create_collection.assert_called_once()

    def test_skips_when_collection_exists(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = ["correlations"]
        repo = CorrelationRepository(mock_db, config)
        repo.ensure_schema()
        mock_db.create_collection.assert_not_called()

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        mock_db.list_collection_names.return_value = []
        mock_db.create_collection.side_effect = PyMongoError("boom")
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.ensure_schema()


class TestEnsureIndexes:
    def test_creates_all_indexes(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.list_indexes.return_value = []
        repo = CorrelationRepository(mock_db, config)
        repo.ensure_indexes()
        assert coll.create_index.call_count == len(INDEX_SPECS)

    def test_idempotent_on_existing(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.list_indexes.return_value = [
            {"name": spec["name"]} for spec in INDEX_SPECS
        ]
        repo = CorrelationRepository(mock_db, config)
        repo.ensure_indexes()
        coll.create_index.assert_not_called()

    def test_pymongo_error_raises_persistence(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.list_indexes.side_effect = PyMongoError("boom")
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.ensure_indexes()


class TestFindByPattern:
    def test_with_version(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.find.return_value.sort.return_value = []
        repo = CorrelationRepository(mock_db, config)
        out = repo.find_by_pattern(
            "NGINX-CORR-BRUTEFORCE-001", pattern_version=1
        )
        assert out == []
        query = coll.find.call_args[0][0]
        assert query["pattern_id"] == "NGINX-CORR-BRUTEFORCE-001"
        assert query["pattern_version"] == 1

    def test_without_version(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.find.return_value.sort.return_value = []
        repo = CorrelationRepository(mock_db, config)
        out = repo.find_by_pattern("NGINX-CORR-BRUTEFORCE-001")
        assert out == []
        query = coll.find.call_args[0][0]
        assert "pattern_version" not in query

    def test_dict_pattern_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: dict input rejected to prevent NoSQL injection."""
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_pattern({"$ne": "x"})  # type: ignore[arg-type]
        mock_db.__getitem__("correlations").find.assert_not_called()

    def test_int_pattern_id_rejected(self, config, mock_db) -> None:
        """D-2 regression: non-str input rejected to prevent NoSQL injection."""
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(ValidationError):
            repo.find_by_pattern(12345)  # type: ignore[arg-type]
        mock_db.__getitem__("correlations").find.assert_not_called()


class TestCount:
    def test_count(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.count_documents.return_value = 3
        repo = CorrelationRepository(mock_db, config)
        assert repo.count() == 3

    def test_pymongo_error(self, config, mock_db) -> None:
        coll = mock_db.__getitem__("correlations")
        coll.count_documents.side_effect = PyMongoError("boom")
        repo = CorrelationRepository(mock_db, config)
        with pytest.raises(PersistenceError):
            repo.count()


class TestDocumentToCorrelation:
    def test_strips_id(self) -> None:
        doc = {
            "_id": "fake",
            "correlation_id": "corr-01923456-7890-7abc-9def-0123456789ab",
            "pattern_id": "NGINX-CORR-BRUTEFORCE-001",
            "pattern_version": 1,
            "trigger": "brute_force_count_threshold",
            "key": CorrelationKey(parts=("198.51.100.7", "/api/login")),
            "detection_ids": (
                "det-01923456-7890-7abc-9def-aaaaaaaaaaaa",
            ),
            "event_ids": ("01923456-7890-7abc-9def-aaaaaaaaaaaa",),
            "window_start": FIXED_EARLIER,
            "window_end": FIXED_LATER,
            "count": 1,
            "reasoning": "x",
            "correlated_at": FIXED_NOW,
            "extra": (),
        }
        c = _document_to_correlation(doc)
        assert c.correlation_id == doc["correlation_id"]