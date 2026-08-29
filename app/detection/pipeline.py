"""The detection pipeline: ingestion -> detection engine -> persistence.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 12, 13, 66, 87-91) and the
           Phase 4.1-4.4 core review (Phase 4.5 handoff
           section).

The pipeline is the documented wiring of the per-event
detection engine with the ingestion service and the detection
persistence layer. It is the **only** place in the codebase
that orchestrates these three components together.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from ..detection.engine import DetectionEngine
from ..detection.models import Detection, DetectionResult
from ..domain.errors import DomainError
from ..domain.security_event import SecurityEvent
from ..ingestion.service import SecurityEventIngestionService
from ..persistence.detection_repository import DetectionRepository


_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineResult:
    """The output of one :meth:`DetectionPipeline.run` call.

    Attributes
    ----------
    event:
        The persisted canonical :class:`SecurityEvent`.
    detection_result:
        The per-event :class:`DetectionResult` produced by
        the engine.
    persisted_detections:
        The list of detections successfully persisted. A
        detection that failed to persist is **not** in this
        list (the pipeline logged the failure).
    """

    event: SecurityEvent
    detection_result: DetectionResult
    persisted_detections: List[Detection]


class DetectionPipeline:
    """The documented wiring of ingestion -> detection -> persistence.

    Construction
    ------------

    * ``ingestion_service`` — the
      :class:`SecurityEventIngestionService` to call for
      validation + persistence of the event.
    * ``detection_engine`` — the
      :class:`app.detection.engine.DetectionEngine` to run
      on the persisted event.
    * ``detection_repository`` — the
      :class:`DetectionRepository` to call for persistence
      of detections.
    """

    def __init__(
        self,
        ingestion_service: SecurityEventIngestionService,
        detection_engine: DetectionEngine,
        detection_repository: DetectionRepository,
    ) -> None:
        if ingestion_service is None:
            raise ValueError("ingestion_service is required")
        if detection_engine is None:
            raise ValueError("detection_engine is required")
        if detection_repository is None:
            raise ValueError("detection_repository is required")
        self._ingestion = ingestion_service
        self._engine = detection_engine
        self._repo = detection_repository

    @property
    def ingestion_service(self) -> SecurityEventIngestionService:
        return self._ingestion

    @property
    def detection_engine(self) -> DetectionEngine:
        return self._engine

    @property
    def detection_repository(self) -> DetectionRepository:
        return self._repo

    def run(
        self,
        event: SecurityEvent,
        *,
        now: Optional[datetime] = None,
    ) -> PipelineResult:
        """Run the full per-event pipeline on one canonical event.

        The pipeline:

        1. Calls
           :meth:`SecurityEventIngestionService.ingest` to
           validate + persist + return the canonical event
           (idempotent re-delivery is the caller's concern;
           the ingestion service returns the existing event
           on duplicate).
        2. Calls :meth:`DetectionEngine.run` on the persisted
           event to produce the per-event
           :class:`DetectionResult`.
        3. Persists each detection via the
           :class:`DetectionRepository`. Persistence
           failures are logged; the pipeline is total.

        Parameters
        ----------
        event:
            The canonical :class:`SecurityEvent` to process.
        now:
            Optional timezone-aware UTC datetime to inject
            into the detection engine. The same value is
            forwarded to the engine; the ingestion service
            always stamps ``ingested_at`` from
            ``datetime.now(timezone.utc)``.

        Returns
        -------
        :class:`PipelineResult`
            Contains the persisted event, the engine result,
            and the list of persisted detections.
        """
        persisted_event = self._ingestion.ingest(event)
        # Default ``now`` to the event's observed
        # ``event_time`` (the source's timestamp) so
        # the detection's ``detected_at`` and
        # therefore the ``detection_id`` are content-
        # derived and stable across replays. The
        # caller may still override by passing
        # ``now=`` explicitly. This is the DEDUP-01
        # cascading fix: a stable event_id alone is
        # not enough; the detection_id must also be
        # stable on replay for the persistence layer
        # to dedup correctly.
        if now is None:
            now = persisted_event.event_time
        detection_result = self._engine.run(persisted_event, now=now)
        persisted: List[Detection] = []
        for detection in detection_result.detections:
            try:
                self._repo.create(detection)
                persisted.append(detection)
            except DomainError as exc:
                if exc.code == "duplicate_event":
                    persisted.append(detection)
                    continue
                _log.warning(
                    "detection.persistence_failed",
                    extra={
                        "detection_id": detection.detection_id,
                        "safe_message": exc.safe_message,
                    },
                )
                continue
        return PipelineResult(
            event=persisted_event,
            detection_result=detection_result,
            persisted_detections=persisted,
        )

    def run_from_connector(
        self,
        connector,
        *,
        now: Optional[datetime] = None,
    ) -> List[PipelineResult]:
        """Pull events from a connector and run the full pipeline on each.

        The connector boundary is honoured: the pipeline
        iterates the connector's ``collect()`` and runs the
        per-event pipeline on each event.
        """
        if connector is None:
            raise ValueError("connector is required")
        results: List[PipelineResult] = []
        for event in connector.collect():
            results.append(self.run(event, now=now))
        return results