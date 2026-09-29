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
class DetectionPersistFailure:
    """V2-10: an observable record of a detection that matched but
    could not be persisted. Never silently dropped: the pipeline
    includes it in :attr:`PipelineResult.persist_failures` and the
    live pipeline surfaces it on :attr:`PipelineRunOutcome.errors`."""

    detection_id: str
    safe_message: str
    error_code: str


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
    persist_failures:
        V2-10: the detections that matched but could not be
        persisted, as :class:`DetectionPersistFailure`
        records. Empty in the normal path.
    """

    event: SecurityEvent
    detection_result: DetectionResult
    persisted_detections: List[Detection]
    persist_failures: tuple = ()


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
        event_persisted: bool = False,
    ) -> PipelineResult:
        """Run the full per-event pipeline on one canonical event.

        ``event_persisted`` (V2-23): when ``True`` the caller asserts
        this exact event is already persisted (the live ingress path
        loads it from the event store); the ingestion step is then
        skipped. Re-running ingestion on a persisted event is what
        produced the double ``security_events`` rows the V2 audit
        observed when the unique index was absent.

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
        if event_persisted:
            persisted_event = event
        else:
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
        failures: List[DetectionPersistFailure] = []
        for detection in detection_result.detections:
            # Capability patch gap 5: compose the documented per-detection
            # severity band (SeverityEngine) and carry the ingesting
            # source's provenance pointer onto the detection BEFORE
            # persistence, so the wire views serve real composed values.
            try:
                from ..severity.enrichment import enrich_detection

                detection = enrich_detection(
                    detection, persisted_event, now=now,
                )
            except Exception as exc:  # noqa: BLE001 - pipeline is total
                _log.warning(
                    "detection.enrichment_failed",
                    extra={
                        "detection_id": detection.detection_id,
                        "error_type": type(exc).__name__,
                    },
                )
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
                # V2-10: observable, not silent.
                failures.append(
                    DetectionPersistFailure(
                        detection_id=detection.detection_id,
                        safe_message=str(exc.safe_message),
                        error_code=str(getattr(exc, "code", "")),
                    )
                )
                continue
        return PipelineResult(
            event=persisted_event,
            detection_result=detection_result,
            persisted_detections=persisted,
            persist_failures=tuple(failures),
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