"""Production live pipeline composition (STRIX F-1 / F-2 fix).

This module wires the already-tested individual engines into the
documented end-to-end chain that the shipped deployment was missing:

    SecurityEvent
      -> DetectionPipeline (ingestion -> detection engine ->
         DetectionRepository)
      -> CorrelationEngine (window/threshold ->
         CorrelationRepository)
      -> IncidentService.create_case_for_correlation (auto case,
         idempotent on the correlation cluster key)

It is **product code**, not test infrastructure. It reuses the
existing engines / repositories and adds only the orchestration wrapper.

Idempotency / duplicate safety
------------------------------
Repeated delivery of the same event is idempotent:

* ``DetectionPipeline.run`` no-ops on duplicate detections.
* ``CorrelationRepository`` raises ``DuplicateEventError`` on a
  duplicate ``correlation_id``, which the pipeline treats as an
  idempotent no-op (the correlation is returned so the caller can
  see it, but it is never inserted twice).
* ``IncidentService.create_case_for_correlation`` derives the case
  id deterministically from the correlation id, so re-runs never
  open a duplicate case.

No silent event loss between ingestion and detection: every accepted
event is passed synchronously to the detection stage, and any failure
is surfaced through the ``errors`` collection of
:class:`PipelineRunOutcome`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..auth.identity import Identity, INTERNAL_SERVICE_ROLE
from ..auth.permissions import Permission
from ..correlation.engine import CorrelationEngine
from ..correlation.models import Correlation
from ..detection.models import Detection
from ..detection.pipeline import DetectionPipeline, PipelineResult
from ..domain.errors import DomainError
from ..domain.security_event import SecurityEvent
from ..incidents.service import IncidentService
from ..persistence.correlation_repository import CorrelationRepository
from ..persistence.security_event_repository import SecurityEventRepository

_log = logging.getLogger(__name__)

DEFAULT_CORRELATION_WINDOW = timedelta(minutes=5)


@dataclass(frozen=True)
class PipelineRunOutcome:
    """The result of one :meth:`LivePipeline.process` call.

    Attributes
    ----------
    event_id:
        The persisted event's id.
    detections:
        The detections produced + persisted for the event.
    correlations:
        The correlations produced for the event (may be empty).
    case:
        The auto-opened case, or ``None``.
    errors:
        Non-fatal processing errors (so nothing silently disappears).
    """

    event_id: Optional[str]
    detections: Tuple[Detection, ...]
    correlations: Tuple[Correlation, ...]
    case: Any  # Incident | None
    errors: Tuple[str, ...]


class LivePipeline:
    """Orchestrates detection -> correlation -> case over persisted events.

    ``process(event)`` runs the full chain for a single canonical
    event. Events are always persisted first (source identity,
    event_id, original evidence untouched); detection then runs on the
    persisted event; correlations run over a recent persisted detection
    window; one auto case is opened per correlation.
    """

    def __init__(
        self,
        *,
        config: Any,
        detection_pipeline: DetectionPipeline,
        correlation_engine: CorrelationEngine,
        correlation_repository: CorrelationRepository,
        security_event_repository: SecurityEventRepository,
        incident_service: IncidentService,
        case_identity: Optional[Identity] = None,
        correlation_window: Optional[timedelta] = None,
        rule_lifecycle_sync: Optional[Any] = None,
        unknown_event_sink: Optional[Any] = None,
    ) -> None:
        self._config = config
        self._pipeline = detection_pipeline
        self._corr_engine = correlation_engine
        self._corr_repo = correlation_repository
        self._event_repo = security_event_repository
        self._incident_service = incident_service
        # V2-01: optional managed-rule lifecycle sync. When wired, the
        # registry the detection engine evaluates is reconciled with
        # the persisted ``managed_rules`` state before every pass, so
        # rule.disable / rule.enable / rule.retire made on the analyst
        # plane take effect on the next event without a restart.
        self._rule_lifecycle_sync = rule_lifecycle_sync
        # ADR-037: persist an unknown-event classification alert when a
        # valid event matches no active rule. This is an injected sink so
        # the pipeline stays independent of the notification persistence
        # layer; production wires NotificationService.emit_unknown_event.
        self._unknown_event_sink = unknown_event_sink
        self._correlation_window = (
            correlation_window
            if correlation_window is not None
            else DEFAULT_CORRELATION_WINDOW
        )
        if case_identity is None:
            # The live pipeline is a SYSTEM actor, not a wire principal:
            # it owns every auto-case it opens (``created_by="pipeline"``).
            # The explicit permission tuple is deliberate and is NOT
            # reachable from the wire — the seeded ``internal`` subject
            # resolves from the identity store with an EMPTY permission
            # tuple, so role defaults apply there and ``case:read:any`` is
            # never granted to a session identity. The grant is required
            # because ``IncidentService.create_case_for_correlation`` now
            # enforces the case ownership model before it merges evidence
            # into an *existing* case (OWNER-52-01): without cross-owner
            # read authority the pipeline could not accumulate evidence
            # into a cluster that a human operator had already cased.
            case_identity = Identity(
                subject_id="pipeline",
                role=INTERNAL_SERVICE_ROLE,
                permissions=(Permission.CASE_READ, Permission.CASE_READ_ANY),
            )
        self._case_identity = case_identity

    # ------------------------------------------------------------ properties
    @property
    def correlation_window(self) -> timedelta:
        return self._correlation_window

    @property
    def case_identity(self) -> Identity:
        return self._case_identity

    @property
    def event_repository(self) -> SecurityEventRepository:
        return self._event_repo

    # ------------------------------------------------------------ main api
    def process(
        self,
        event: SecurityEvent,
        *,
        now: Optional[datetime] = None,
        event_persisted: bool = False,
    ) -> PipelineRunOutcome:
        """Run detection -> correlation -> auto-case on one event.

        ``event_persisted``: pass ``True`` when the caller loaded the
        event from the event store (the ingress listener path). The
        detection pipeline then skips re-ingestion — re-running the
        ingestion step on an already-persisted event is what produced
        the double ``security_events`` rows the V2 audit observed
        (V2-23) when the unique index was absent.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        errors: List[str] = []

        # 0. Managed-rule lifecycle sync (V2-01): honour
        #    enable/disable/retire made on the analyst plane.
        if self._rule_lifecycle_sync is not None:
            try:
                self._rule_lifecycle_sync.sync()
            except Exception as exc:  # noqa: BLE001 - never block ingest
                _log.warning(
                    "pipeline.rule_lifecycle_sync_failed error=%s",
                    type(exc).__name__,
                )

        # 1. Detection (ingestion + engine + detection persistence).
        try:
            pipeline_result: PipelineResult = self._pipeline.run(
                event, now=now, event_persisted=event_persisted,
            )
        except DomainError as exc:
            _log.warning(
                "pipeline.detection_failed",
                extra={
                    "event_id": getattr(event, "event_id", None),
                    "safe_message": exc.safe_message,
                },
            )
            return PipelineRunOutcome(
                event_id=getattr(event, "event_id", None),
                detections=(),
                correlations=(),
                case=None,
                errors=(exc.safe_message,),
            )

        persisted_event = pipeline_result.event
        new_detections = tuple(pipeline_result.persisted_detections)

        # V2-10: a detection that matched but failed to persist must
        # never disappear silently. Surface it on the outcome (the
        # ingress listener logs ``outcome.errors``) and in the log.
        for failure in getattr(pipeline_result, "persist_failures", ()):
            _log.warning(
                "pipeline.detection_persist_unavailable",
                extra={
                    "event_id": persisted_event.event_id,
                    "detection_id": getattr(
                        failure, "detection_id", None
                    ),
                    "safe_message": getattr(failure, "safe_message", None),
                },
            )
            errors.append(
                f"detection persistence failed: "
                f"{getattr(failure, 'safe_message', 'unknown error')}"
            )

        no_rule_match = (
            not pipeline_result.detection_result.detections
            and not pipeline_result.detection_result.errors
            and not getattr(pipeline_result, "persist_failures", ())
        )
        if no_rule_match:
            if self._unknown_event_sink is None:
                _log.warning(
                    "pipeline.unknown_event_sink_absent event_id=%s",
                    persisted_event.event_id,
                )
            else:
                try:
                    self._unknown_event_sink(event=persisted_event)
                    _log.info(
                        "pipeline.unknown_event_classified event_id=%s",
                        persisted_event.event_id,
                    )
                except Exception as exc:  # noqa: BLE001 - never block ingest
                    _log.warning(
                        "pipeline.unknown_event_classification_failed "
                        "event_id=%s error=%s",
                        persisted_event.event_id,
                        type(exc).__name__,
                    )
                    errors.append(
                        "unknown classification failed: "
                        f"{type(exc).__name__}"
                    )

        if not new_detections:
            # No detection -> nothing to correlate; the event is
            # still persisted (visible in the event store).
            return PipelineRunOutcome(
                event_id=persisted_event.event_id,
                detections=(),
                correlations=(),
                case=None,
                errors=tuple(errors),
            )

        # 2. Correlation over the recent persisted detection window.
        correlations = self._run_correlation(
            persisted_event.event_id,
            new_detections,
            now=now,
        )
        if not correlations:
            return PipelineRunOutcome(
                event_id=persisted_event.event_id,
                detections=new_detections,
                correlations=(),
                case=None,
                errors=tuple(errors),
            )

        # 3. Auto case per correlation (idempotent on cluster key).
        cases: List[Any] = []
        for corr in correlations:
            case = self._open_case_for_correlation(
                persisted_event,
                corr,
                new_detections,
            )
            if case is not None:
                cases.append(case)

        return PipelineRunOutcome(
            event_id=persisted_event.event_id,
            detections=new_detections,
            correlations=tuple(correlations),
            case=cases[0] if cases else None,
            errors=tuple(errors),
        )

    # ------------------------------------------------------------ internals
    def _run_correlation(
        self,
        event_id: Optional[str],
        new_detections: Sequence[Detection],
        *,
        now: datetime,
    ) -> List[Correlation]:
        """Run correlation over the recent persisted detection window.

        The window is bounded by ``correlation_window``. Correlations
        are persisted idempotently (a duplicate correlation_id no-ops),
        so re-running over a window cannot create duplicates over time.
        """
        cutoff = now - self._correlation_window
        try:
            window_detections = (
                self._pipeline.detection_repository.find_recent(cutoff)
            )
        except DomainError as exc:
            _log.warning(
                "pipeline.correlation_read_failed",
                extra={"safe_message": exc.safe_message},
            )
            window_detections = list(new_detections)

        events_by_id: Dict[str, SecurityEvent] = {}
        for d in window_detections:
            eid = d.event_id
            if eid and eid not in events_by_id:
                ev = self._load_event(eid)
                if ev is not None:
                    events_by_id[eid] = ev

        result = self._corr_engine.run(
            window_detections,
            events_by_id,
            now=now,
        )
        persisted: List[Correlation] = []
        for corr in result.correlations:
            try:
                self._corr_repo.create(corr)
                persisted.append(corr)
            except DomainError as exc:
                if exc.code == "duplicate_event":
                    # V2-08: the correlation_id now identifies the
                    # logical cluster (stable while the cluster grows).
                    # A duplicate therefore means "this cluster row
                    # already exists" — grow its evidence in place so
                    # the single row reflects the newest window /
                    # detection set, and hand the merged view to the
                    # case layer.
                    try:
                        merged = self._corr_repo.upsert_growth(corr)
                        _log.info(
                            "pipeline.correlation_cluster_grown",
                            extra={
                                "correlation_id": corr.correlation_id,
                                "detections": len(merged.detection_ids),
                            },
                        )
                        persisted.append(merged)
                    except DomainError as merge_exc:
                        _log.warning(
                            "pipeline.correlation_growth_failed",
                            extra={
                                "correlation_id": corr.correlation_id,
                                "safe_message": merge_exc.safe_message,
                            },
                        )
                        persisted.append(corr)
                    continue
                _log.warning(
                    "pipeline.correlation_persist_failed",
                    extra={
                        "correlation_id": corr.correlation_id,
                        "safe_message": exc.safe_message,
                    },
                )
                continue
        return persisted

    def _load_event(self, event_id: str) -> Optional[SecurityEvent]:
        try:
            return self._event_repo.get_by_event_id(event_id)
        except DomainError as exc:
            _log.warning(
                "pipeline.event_read_failed",
                extra={"event_id": event_id, "safe_message": exc.safe_message},
            )
            return None

    def _open_case_for_correlation(
        self,
        event: SecurityEvent,
        correlation: Correlation,
        detections: Sequence[Detection],
    ) -> Any:
        """Open an idempotent case for a correlation.

        Batch 1/2 T28 (evidence integrity): the engine result contains
        **every** cluster active in the correlation window, while ``event``
        and ``detections`` belong to the single event being processed. The
        trigger event/detection were previously handed to *every* cluster's
        case, so an unrelated cluster's case absorbed foreign evidence
        (reproduced live: the T22 cluster's case held the T28 cluster's
        detection ids and vice versa).

        The event's own evidence is therefore only passed when the event is a
        member of this correlation. Every correlation still opens its case
        (create-if-missing) and the case composes its evidence from the
        correlation catalogue, so nothing is lost for the cluster the event
        actually belongs to.
        """
        try:
            member_event_ids = tuple(
                getattr(correlation, "event_ids", ()) or ()
            )
            belongs = event.event_id in member_event_ids
            return self._incident_service.create_case_for_correlation(
                identity=self._case_identity,
                correlation=correlation,
                events=[event] if belongs else [],
                detections=list(detections) if belongs else [],
            )
        except DomainError as exc:
            _log.warning(
                "pipeline.case_open_failed",
                extra={
                    "correlation_id": correlation.correlation_id,
                    "safe_message": exc.safe_message,
                },
            )
            return None


def build_live_pipeline(
    *,
    config: Any,
    db: Any,
    rule_registry: Any,
    incident_service: IncidentService,
    case_identity: Optional[Identity] = None,
    correlation_window: Optional[timedelta] = None,
    detection_pipeline: Optional[DetectionPipeline] = None,
    rule_repository: Optional[Any] = None,
    unknown_event_sink: Optional[Any] = None,
) -> LivePipeline:
    """Build a :class:`LivePipeline` from an app ``db`` handle.

    ``db`` may be a real ``pymongo.database.Database`` (``--backend
    mongo``) or one of the ``FakeDatabase`` implementations used by
    ``scripts/*_server.py`` (``--backend memory``). The repositories
    constructed here are the same classes the rest of the app uses;
    this is the orchestration layer they lacked.

    When ``rule_repository`` is provided (the Mongo deployment path),
    the pipeline additionally wires a :class:`ManagedRuleLifecycleSync`
    so rule enable/disable/retire made on the analyst plane governs
    the live detector (V2-01).

    ``unknown_event_sink`` receives the persisted event when no active
    rule matched (ADR-037). The deployment wires
    ``NotificationService.emit_unknown_event`` so the unknown
    classification is persisted in the existing analyst feed.
    """
    from ..correlation.engine import CorrelationEngine as _CE
    from ..correlation.patterns import BruteForceClusteringPattern
    from ..detection.engine import DetectionEngine
    from ..detection.pipeline import DetectionPipeline as _DP
    from ..ingestion.service import SecurityEventIngestionService
    from ..persistence.correlation_repository import CorrelationRepository
    from ..persistence.detection_repository import DetectionRepository
    from ..persistence.security_event_repository import SecurityEventRepository

    event_repo = SecurityEventRepository(db=db, config=config)
    detection_repo = DetectionRepository(db=db, config=config)
    correlation_repo = CorrelationRepository(db=db, config=config)

    rule_lifecycle_sync = None
    if rule_repository is not None:
        from .managed_rule_sync import ManagedRuleLifecycleSync

        rule_lifecycle_sync = ManagedRuleLifecycleSync(
            repository=rule_repository,
            registry=rule_registry,
            config=config,
        )

    if detection_pipeline is None:
        detection_pipeline = _DP(
            ingestion_service=SecurityEventIngestionService(
                repository=event_repo,
                config=config,
            ),
            detection_engine=DetectionEngine(rule_registry),
            detection_repository=detection_repo,
        )

    correlation_engine = _CE(patterns=[BruteForceClusteringPattern()])

    return LivePipeline(
        config=config,
        detection_pipeline=detection_pipeline,
        correlation_engine=correlation_engine,
        correlation_repository=correlation_repo,
        security_event_repository=event_repo,
        incident_service=incident_service,
        case_identity=case_identity,
        correlation_window=correlation_window,
        rule_lifecycle_sync=rule_lifecycle_sync,
        unknown_event_sink=unknown_event_sink,
    )