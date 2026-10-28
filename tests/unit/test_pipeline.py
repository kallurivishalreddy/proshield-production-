"""Unit tests for the Phase 4.5 detection pipeline.

The pipeline wires the ingestion service, the detection engine,
and the detection repository. Unit tests use mocks for the
repository; the integration tests exercise the real MongoDB
end-to-end.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from app.config import ProShieldConfig
from app.detection import DetectionEngine, DetectionPipeline, PipelineResult
from app.detection.models import Detection, DetectionResult
from app.domain.errors import DuplicateEventError, PersistenceError
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.detection_repository import DetectionRepository
from app.rules import RuleRegistry


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _make_event(**overrides) -> SecurityEvent:
    et = FIXED_NOW
    defaults = dict(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="nginx",
        event_type="authentication_failure",
        source_ip="198.51.100.7",
        endpoint="/api/login",
        provenance=SecurityEventProvenance(
            collector="test", source_event_id="src-1"
        ),
        details={"status_code": 401},
    )
    defaults.update(overrides)
    return SecurityEvent(**defaults)


@pytest.fixture
def config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        mongo_uri="mongodb://localhost:27017",
        mongo_db="proshield_test",
    )


@pytest.fixture
def ingestion_service() -> MagicMock:
    return MagicMock(spec=SecurityEventIngestionService)


@pytest.fixture
def detection_engine() -> DetectionEngine:
    r = RuleRegistry()
    return DetectionEngine(r)


@pytest.fixture
def detection_repository() -> MagicMock:
    repo = MagicMock(spec=DetectionRepository)
    repo.find_by_event_id.return_value = []
    return repo


@pytest.fixture
def pipeline(
    ingestion_service, detection_engine, detection_repository
) -> DetectionPipeline:
    return DetectionPipeline(
        ingestion_service=ingestion_service,
        detection_engine=detection_engine,
        detection_repository=detection_repository,
    )


class TestConstruction:
    def test_rejects_none_ingestion(self, detection_engine, detection_repository) -> None:
        with pytest.raises(ValueError):
            DetectionPipeline(
                ingestion_service=None,  # type: ignore[arg-type]
                detection_engine=detection_engine,
                detection_repository=detection_repository,
            )

    def test_rejects_none_engine(self, ingestion_service, detection_repository) -> None:
        with pytest.raises(ValueError):
            DetectionPipeline(
                ingestion_service=ingestion_service,
                detection_engine=None,  # type: ignore[arg-type]
                detection_repository=detection_repository,
            )

    def test_rejects_none_repo(self, ingestion_service, detection_engine) -> None:
        with pytest.raises(ValueError):
            DetectionPipeline(
                ingestion_service=ingestion_service,
                detection_engine=detection_engine,
                detection_repository=None,  # type: ignore[arg-type]
            )

    def test_exposes_components(
        self, pipeline, ingestion_service, detection_engine, detection_repository
    ) -> None:
        assert pipeline.ingestion_service is ingestion_service
        assert pipeline.detection_engine is detection_engine
        assert pipeline.detection_repository is detection_repository


class TestRun:
    def test_runs_full_pipeline_with_no_detections(
        self, pipeline, ingestion_service, detection_engine
    ) -> None:
        ev = _make_event()
        ingestion_service.ingest.return_value = ev
        result = pipeline.run(ev, now=FIXED_NOW)
        assert isinstance(result, PipelineResult)
        assert result.event is ev
        assert result.detection_result.detection_count == 0
        assert result.persisted_detections == []
        ingestion_service.ingest.assert_called_once()

    def _real_detection(self, event_id: str) -> Detection:
        return Detection(
            detection_id="det-01923456-7890-7abc-9def-0123456789ab",
            rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=1,
            category="source_specific",
            event_id=event_id,
            evidence_refs=(event_id,),
            reasoning="r",
            detected_at=FIXED_NOW,
        )

    def test_persists_detections(
        self, pipeline, ingestion_service, detection_repository
    ) -> None:
        ev = _make_event()
        ingestion_service.ingest.return_value = ev
        det = self._real_detection(ev.event_id)
        pipeline.detection_engine.run = MagicMock(
            return_value=DetectionResult(
                event_id=ev.event_id,
                detections=(det,),
                rules_considered=1,
                rules_evaluated=1,
                errors=(),
                produced_at=FIXED_NOW,
            )
        )
        result = pipeline.run(ev, now=FIXED_NOW)
        assert len(result.persisted_detections) == 1
        # Capability patch gap 5: the pipeline composes the documented
        # severity band (SeverityEngine) and the source provenance
        # pointer before persistence, so the persisted detection is an
        # ENRICHED copy of the engine output.
        persisted = result.persisted_detections[0]
        assert persisted.detection_id == det.detection_id
        from app.severity.models import SeverityBand

        assert persisted.severity in {b.value for b in SeverityBand}
        assert detection_repository.create.call_count == 1
        assert (
            detection_repository.create.call_args[0][0].detection_id
            == det.detection_id
        )

    def test_idempotent_detection_persistence(
        self, pipeline, ingestion_service, detection_repository
    ) -> None:
        ev = _make_event()
        ingestion_service.ingest.return_value = ev
        detection_repository.create.side_effect = DuplicateEventError(
            safe_message="dup", internal_detail="dup"
        )
        det = self._real_detection(ev.event_id)
        pipeline.detection_engine.run = MagicMock(
            return_value=DetectionResult(
                event_id=ev.event_id,
                detections=(det,),
                rules_considered=1,
                rules_evaluated=1,
                errors=(),
                produced_at=FIXED_NOW,
            )
        )
        result = pipeline.run(ev, now=FIXED_NOW)
        assert len(result.persisted_detections) == 1

    def test_other_persistence_failure_is_logged_not_raised(
        self, pipeline, ingestion_service, detection_repository
    ) -> None:
        ev = _make_event()
        ingestion_service.ingest.return_value = ev
        detection_repository.create.side_effect = PersistenceError(
            safe_message="boom", internal_detail="boom"
        )
        det = self._real_detection(ev.event_id)
        pipeline.detection_engine.run = MagicMock(
            return_value=DetectionResult(
                event_id=ev.event_id,
                detections=(det,),
                rules_considered=1,
                rules_evaluated=1,
                errors=(),
                produced_at=FIXED_NOW,
            )
        )
        result = pipeline.run(ev, now=FIXED_NOW)
        assert result.persisted_detections == []


class TestRunFromConnector:
    def test_runs_per_event(self, pipeline) -> None:
        connector = MagicMock()
        connector.collect.return_value = [
            _make_event(),
            _make_event(),
        ]
        pipeline.ingestion_service.ingest.side_effect = lambda e: e
        results = pipeline.run_from_connector(connector, now=FIXED_NOW)
        assert len(results) == 2
        assert pipeline.ingestion_service.ingest.call_count == 2

    def test_rejects_none_connector(self, pipeline) -> None:
        with pytest.raises(ValueError):
            pipeline.run_from_connector(None)  # type: ignore[arg-type]