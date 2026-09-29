"""Incident / case service (Phase 4.8)."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import ValidationError as PydanticValidationError

from ..auth.identity import Identity
from ..auth.permissions import Permission, has_permission
from ..correlation.engine import CorrelationEngine
from ..correlation.models import Correlation
from ..detection.models import Detection
from ..domain.errors import ValidationError as DomainValidationError
from ..domain.security_event import SecurityEvent
from .errors import (
    CaseAccessDeniedError,
    CaseEvidenceError,
    CaseNotFoundError,
    CaseStateConflictError,
    InvalidIncidentInputError,
)
from .models import (
    CASE_STATE_ACKNOWLEDGED,
    CASE_STATE_CENTRALIZED_FAILED,
    CASE_STATE_CENTRALIZED_PENDING,
    CASE_STATE_CLOSED,
    CASE_STATE_INVESTIGATING,
    CASE_STATE_OPEN,
    CaseAttribution,
    CaseNote,
    Incident,
    IncidentEvidence,
    IncidentLifecycleState,
    LifecycleTransition,
    MAX_CASE_LIFECYCLE_HISTORY,
    MAX_CASE_NOTE_LEN,
    MAX_CASE_NOTES,
    MAX_CASE_TITLE_LEN,
)
from .repository import IncidentRepository

_log = logging.getLogger(__name__)

MAX_CENTRALIZED_CORRELATION_IDS = 64


@dataclass(frozen=True)
class CentralizedOutcome:
    """Structured outcome of a centralized-analysis request."""
    case: Incident
    new_correlation_ids: Tuple[str, ...]
    combined_correlation_ids: Tuple[str, ...]
    failed: bool
    failure_reason: str


class IncidentService:
    """The documented orchestrator."""

    def __init__(
        self,
        repository: IncidentRepository,
        *,
        correlation_engine: Optional[CorrelationEngine] = None,
        correlation_persister: Optional[Any] = None,
        notification_sink: Optional[Any] = None,
    ) -> None:
        if not isinstance(repository, IncidentRepository):
            raise ValueError("repository must be an IncidentRepository")
        self._repository = repository
        self._correlation_engine = correlation_engine
        self._correlation_persister = correlation_persister
        # Capability patch gap 12: an optional sink the service calls
        # after real state changes. The sink is injected by the
        # deployment wiring (notifications package); the service stays
        # decoupled from the notification persistence and NEVER fails
        # the business operation because a notification could not be
        # recorded (observable via a logged warning instead).
        self._notification_sink = notification_sink

    def _emit_notification(
        self,
        *,
        kind: str,
        case: Incident,
        actor_subject_id: str,
        detail: str,
    ) -> None:
        if self._notification_sink is None:
            return
        try:
            self._notification_sink(
                kind=str(kind),
                incident_id=case.incident_id,
                human_id=case.human_id or "",
                title=case.title,
                actor_subject_id=str(actor_subject_id),
                detail=str(detail or ""),
            )
        except Exception as exc:  # noqa: BLE001 - never fail the op
            _log.warning(
                "incident.notification_sink_failed",
                extra={
                    "incident_id": case.incident_id,
                    "kind": str(kind),
                    "error_type": type(exc).__name__,
                },
            )

    @property
    def repository(self) -> IncidentRepository:
        return self._repository

    @property
    def correlation_engine(self) -> CorrelationEngine:
        if self._correlation_engine is None:
            from ..correlation.engine import CorrelationEngine as _CE
            from ..correlation.patterns import BruteForceClusteringPattern

            self._correlation_engine = _CE(
                patterns=[BruteForceClusteringPattern()],
            )
        return self._correlation_engine

    @property
    def correlation_persister(self) -> Optional[Any]:
        return self._correlation_persister

    def _authorize_case_access(
        self, identity: Identity, case: Incident,
    ) -> None:
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        perms = tuple(identity.permissions)
        if has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.CASE_READ_ANY,
        ):
            return
        if not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.CASE_READ,
        ):
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="missing case:read",
            )
        if case.created_by != identity.subject_id:
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="wrong owner",
            )

    def get_case(
        self, identity: Identity, incident_id: str,
    ) -> Incident:
        if not isinstance(incident_id, str) or not incident_id:
            raise InvalidIncidentInputError(
                safe_message="incident_id required",
                internal_detail=f"got {type(incident_id).__name__}",
                field="incident_id",
            )
        case = self._repository.get_by_id_or_raise(incident_id)
        self._authorize_case_access(identity, case)
        return case

    def list_cases(
        self,
        identity: Identity,
        *,
        state: Optional[str] = None,
        limit: int = 50,
    ) -> List[Incident]:
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        perms = tuple(identity.permissions)
        see_any = has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.CASE_READ_ANY,
        )
        has_read = has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.CASE_READ,
        )
        if not (see_any or has_read):
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="missing case:read",
            )
        all_cases = (
            self._repository.find_by_state(
                state=state, limit=limit,
            )
            if state
            else self._repository.find_recent(limit=limit)
        )
        if see_any:
            return all_cases
        return [
            c for c in all_cases
            if c.created_by == identity.subject_id
        ]

    def create_case(
        self,
        *,
        identity: Identity,
        title: str,
        summary: str,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
        correlations: Sequence[Correlation] = (),
        timeline=None,
        severity=None,
        incident_id: Optional[str] = None,
        extra_event_ids: Sequence[str] = (),
        extra_detection_ids: Sequence[str] = (),
    ) -> Incident:
        """Create a case from resolved evidence.

        ``extra_event_ids`` / ``extra_detection_ids`` are *id-only* evidence
        references (Batch 1/2 T28): the correlation row is a cluster's
        authoritative evidence catalogue and may reference events/detections
        whose full model objects the caller does not hold (they were processed
        by an earlier request / process). They are merged, de-duplicated and
        order-preserving, so the newly opened case carries the complete
        cluster evidence instead of only the triggering member.
        """
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        if not has_permission(
            role=identity.role,
            identity_permissions=identity.permissions,
            permission=Permission.CASE_READ,
        ):
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="missing case:read",
            )
        events_list = list(events) if events is not None else []
        detections_list = list(detections) if detections is not None else []
        correlations_list = (
            list(correlations) if correlations is not None else []
        )
        for e in events_list:
            if not isinstance(e, SecurityEvent):
                raise InvalidIncidentInputError(
                    safe_message="invalid event",
                    internal_detail=f"got {type(e).__name__}",
                    field="events",
                )
        for d in detections_list:
            if not isinstance(d, Detection):
                raise InvalidIncidentInputError(
                    safe_message="invalid detection",
                    internal_detail=f"got {type(d).__name__}",
                    field="detections",
                )
        for c in correlations_list:
            if not isinstance(c, Correlation):
                raise InvalidIncidentInputError(
                    safe_message="invalid correlation",
                    internal_detail=f"got {type(c).__name__}",
                    field="correlations",
                )
        event_ids = _dedup_preserving_order(
            [e.event_id for e in events_list] + list(extra_event_ids or ())
        )
        detection_ids = _dedup_preserving_order(
            [d.detection_id for d in detections_list]
            + list(extra_detection_ids or ())
        )
        correlation_ids = tuple(c.correlation_id for c in correlations_list)
        rule_refs = _dedup_rule_refs(detections_list)
        evidence = IncidentEvidence(
            event_ids=event_ids,
            detection_ids=detection_ids,
            correlation_ids=correlation_ids,
            rule_references=rule_refs,
        )
        now = datetime.now(timezone.utc)
        if not incident_id:
            incident_id = _make_case_id(
                event_ids=event_ids,
                detection_ids=detection_ids,
                correlation_ids=correlation_ids,
                created_at=now,
                seed=identity.subject_id,
            )
        initial_transition = LifecycleTransition(
            from_state=None,
            to_state=CASE_STATE_OPEN,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason="case created",
            transitioned_at=now,
        )
        # V2-09: compose the documented severity/confidence bands from
        # the case's evidence at creation (SeverityEngine bundle pair).
        composed_severity, composed_confidence = _compose_case_severity(
            detections_list, correlations_list, {}
        )
        # Capability patch gap 3: derive the analyst-facing attribution
        # from the case's own evidence (correlation key parts + event
        # provenance). Never invented; None when underivable.
        attribution = _compose_case_attribution(
            events_list, detections_list, correlations_list,
        )
        case = Incident(
            incident_id=incident_id,
            title=str(title or "")[:MAX_CASE_TITLE_LEN],
            summary=str(summary or "")[:1024],
            state=IncidentLifecycleState.OPEN,
            evidence=evidence,
            rule_references=rule_refs,
            severity=composed_severity or "",
            confidence=composed_confidence or "",
            attribution=attribution,
            report_references=(),
            centralized_correlation_ids=(),
            centralized_reasoning="",
            centralized_failed=False,
            centralized_failure_reason="",
            created_by=identity.subject_id,
            created_at=now,
            updated_at=now,
        )
        created = self._repository.create(case)
        self._emit_notification(
            kind="case.created",
            case=created,
            actor_subject_id=identity.subject_id,
            detail=f"case created ({len(event_ids)} event(s), "
                   f"{len(detection_ids)} detection(s))",
        )
        return created

    def create_case_for_correlation(
        self,
        *,
        identity: Identity,
        correlation: Correlation,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
        title: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> Incident:
        """Open (or reuse) a case for a newly produced correlation.

        This is the **automatic correlation->case** trigger the
        STRIX F-2 finding required. It is idempotent on the
        correlation's cluster key: the ``incident_id`` is derived
        deterministically from the ``correlation_id`` (via
        :func:`_case_id_for_correlation`), and
        :meth:`IncidentRepository.create` no-ops on a duplicate, so
        re-delivered events / re-run correlations can never open a
        duplicate case.
        """
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        if not isinstance(correlation, Correlation):
            raise InvalidIncidentInputError(
                safe_message="invalid correlation",
                internal_detail=(
                    f"got {type(correlation).__name__}, expected Correlation"
                ),
                field="correlations",
            )
        case_id = _case_id_for_correlation(correlation)
        existing = self._repository.get_by_id(case_id)
        if existing is not None:
            # Phase 5.2 owner patch OWNER-52-01 — ownership gate.
            # The deterministic case id means this call is a *reuse* of
            # an already-cased cluster (every normal cluster is
            # auto-cased by the live pipeline), not a creation. The
            # caller therefore has to be authorized to read what it
            # receives, exactly as :meth:`get_case` demands. Without this
            # gate the wire operation returned the complete body of a
            # case the caller cannot read (title/summary/evidence ids,
            # an alternate-route bypass of the case ownership model) and
            # merged evidence into it. The gate runs BEFORE any
            # mutation, so an unauthorized caller can neither read nor
            # change the case.
            # The live pipeline is the only internal caller and carries
            # an explicit ``case:read:any`` system grant (see
            # :class:`app.pipeline.service.LivePipeline`), so the V2-02
            # evidence-accumulation behaviour is unchanged.
            self._authorize_case_access(identity, existing)
            # V2-02 fix: the case is idempotent on the cluster key, but
            # its *evidence* must accumulate as the cluster grows. The
            # previous implementation returned the existing case
            # unchanged, so a growing brute-force cluster left the case
            # frozen at its first triggering event (the frozen-evidence
            # finding). Merge the new evidence idempotently: same
            # incident_id, union of evidence refs, recomposed severity,
            # no duplicate rows, no duplicate case.
            merged = _merge_case_evidence(
                existing,
                events=list(events or ()),
                detections=list(detections or ()),
                correlations=[correlation],
                # V2-02 completeness: the correlation row is the
                # cluster's authoritative evidence catalogue (it may
                # hold detection/event ids from events processed before
                # the case existed). Absorb them so the case reflects
                # the full cluster, not just the triggering event.
                extra_event_ids=tuple(getattr(correlation, "event_ids", ())),
                extra_detection_ids=tuple(
                    getattr(correlation, "detection_ids", ())
                ),
            )
            if merged is not None:
                now = datetime.now(timezone.utc)
                merged = merged.model_copy(
                    update={"updated_at": now},
                )
                return self._repository.upsert(merged)
            return existing
        resolved_title = (
            str(title).strip()
            if title else _correlation_case_title(correlation)
        )
        resolved_summary = (
            str(summary).strip()
            if summary else _correlation_case_summary(correlation)
        )
        return self.create_case(
            identity=identity,
            title=resolved_title,
            summary=resolved_summary,
            events=events,
            detections=detections,
            correlations=[correlation],
            incident_id=case_id,
            # Batch 1/2 T28 fix: the correlation row is the cluster's
            # authoritative evidence catalogue. The CREATE path previously
            # captured only the triggering event/detection, so a
            # threshold-exact cluster (4 events → 1 correlation row on the
            # 4th event) opened a case holding 1 event + 1 detection while
            # the correlation held the full set. Both paths now compose the
            # identical evidence set (the reuse path already absorbed the
            # catalogue via ``_merge_case_evidence``).
            extra_event_ids=tuple(getattr(correlation, "event_ids", ())),
            extra_detection_ids=tuple(
                getattr(correlation, "detection_ids", ())
            ),
        )

    def request_centralized_analysis(
        self,
        *,
        identity: Identity,
        incident_id: str,
        detections: Sequence[Detection],
        events: Sequence[SecurityEvent],
        reason: str = "",
    ) -> CentralizedOutcome:
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        if not has_permission(
            role=identity.role,
            identity_permissions=identity.permissions,
            permission=Permission.CASE_CENTRALIZED_REQUEST,
        ):
            raise CaseAccessDeniedError(
                safe_message="centralized request denied",
                internal_detail="missing case:centralized:request",
            )
        case = self._repository.get_by_id_or_raise(incident_id)
        self._authorize_case_access(identity, case)
        detections_list = list(detections) if detections is not None else []
        events_list = list(events) if events is not None else []
        for d in detections_list:
            if not isinstance(d, Detection):
                raise CaseEvidenceError(
                    safe_message="invalid detection",
                    internal_detail=f"got {type(d).__name__}",
                )
        for e in events_list:
            if not isinstance(e, SecurityEvent):
                raise CaseEvidenceError(
                    safe_message="invalid event",
                    internal_detail=f"got {type(e).__name__}",
                )
        if len(detections_list) > 10_000:
            raise CaseEvidenceError(
                safe_message="too many detections",
                internal_detail=(
                    f"got {len(detections_list)}; cap 10000"
                ),
            )
        events_by_id = {e.event_id: e for e in events_list}
        now = datetime.now(timezone.utc)
        return self._run_centralized(
            case=case,
            identity=identity,
            detections_list=detections_list,
            events_by_id=events_by_id,
            now=now,
            reason=reason,
        )

    def _run_centralized(
        self, *, case, identity, detections_list, events_by_id, now, reason,
    ) -> CentralizedOutcome:
        """Internal: persist pending, run engine, persist outcome."""
        pending_transition = LifecycleTransition(
            from_state=case.state.value,
            to_state=CASE_STATE_CENTRALIZED_PENDING,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason=str(reason or "")[:2048],
            transitioned_at=now,
        )
        history_with_pending = _append_transition(
            case.lifecycle_history, pending_transition,
        )
        intermediate = case.model_copy(update={
            "state": IncidentLifecycleState.CENTRALIZED_PENDING,
            "lifecycle_history": history_with_pending,
            "updated_at": now,
        })
        self._repository.upsert(intermediate)
        try:
            correlation_result = self.correlation_engine.run(
                detections=detections_list,
                events=events_by_id,
                now=now,
            )
        except (PydanticValidationError, DomainValidationError) as exc:
            return self._mark_centralized_failed(
                case=intermediate, identity=identity, now=now,
                reason=f"centralized input invalid: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - fail-safe boundary
            return self._mark_centralized_failed(
                case=intermediate, identity=identity, now=now,
                reason=f"centralized engine raised {type(exc).__name__}",
            )
        new_correlations = list(correlation_result.correlations)
        if self._correlation_persister is not None and new_correlations:
            try:
                self._correlation_persister(new_correlations)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "incident.centralized_persistence_failed",
                    extra={
                        "incident_id": case.incident_id,
                        "err_type": type(exc).__name__,
                    },
                )
        existing_corr_ids = set(case.evidence.correlation_ids)
        new_ids = tuple(
            c.correlation_id for c in new_correlations
            if c.correlation_id not in existing_corr_ids
        )
        combined_ids = tuple(_dedup_preserving_order(
            list(case.evidence.correlation_ids) + list(new_ids)
        ))[:MAX_CENTRALIZED_CORRELATION_IDS]
        success_transition = LifecycleTransition(
            from_state=intermediate.state.value,
            to_state=CASE_STATE_OPEN,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason=(
                f"centralized produced {len(new_correlations)} new "
                f"correlations; {len(new_ids)} not already in case"
            )[:2048],
            transitioned_at=now,
        )
        history_done = _append_transition(
            intermediate.lifecycle_history, success_transition,
        )
        merged_centralized = _dedup_preserving_order(
            list(case.centralized_correlation_ids) + list(new_ids)
        )[:MAX_CENTRALIZED_CORRELATION_IDS]
        updated = intermediate.model_copy(update={
            "state": IncidentLifecycleState.OPEN,
            "centralized_correlation_ids": tuple(merged_centralized),
            "centralized_reasoning": (
                f"centralized produced {len(new_correlations)} "
                f"correlations; case+centralized now "
                f"{len(combined_ids)} unique ids"
            )[:2048],
            "centralized_failed": False,
            "centralized_failure_reason": "",
            "lifecycle_history": history_done,
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        return CentralizedOutcome(
            case=persisted,
            new_correlation_ids=tuple(new_ids),
            combined_correlation_ids=tuple(combined_ids),
            failed=False,
            failure_reason="",
        )

    def _mark_centralized_failed(
        self, *, case, identity, now, reason,
    ) -> CentralizedOutcome:
        safe_reason = str(reason or "centralized analysis failed")[:2048]
        failed_transition = LifecycleTransition(
            from_state=case.state.value,
            to_state=CASE_STATE_CENTRALIZED_FAILED,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason=safe_reason,
            transitioned_at=now,
        )
        history_done = _append_transition(
            case.lifecycle_history, failed_transition,
        )
        failed = case.model_copy(update={
            "state": IncidentLifecycleState.CENTRALIZED_FAILED,
            "centralized_failed": True,
            "centralized_failure_reason": safe_reason,
            "lifecycle_history": history_done,
            "updated_at": now,
        })
        persisted = self._repository.upsert(failed)
        return CentralizedOutcome(
            case=persisted,
            new_correlation_ids=(),
            combined_correlation_ids=tuple(
                persisted.centralized_correlation_ids,
            ),
            failed=True,
            failure_reason=safe_reason,
        )

    def close_case(
        self, identity, incident_id, reason="",
    ) -> Incident:
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        case = self._repository.get_by_id_or_raise(incident_id)
        self._authorize_case_access(identity, case)
        now = datetime.now(timezone.utc)
        transition = LifecycleTransition(
            from_state=case.state.value,
            to_state=CASE_STATE_CLOSED,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason=str(reason or "case closed")[:2048],
            transitioned_at=now,
        )
        closed = case.model_copy(update={
            "state": IncidentLifecycleState.CLOSED,
            "lifecycle_history": _append_transition(
                case.lifecycle_history, transition,
            ),
            "updated_at": now,
        })
        persisted = self._repository.upsert(closed)
        self._emit_notification(
            kind="case.closed",
            case=persisted,
            actor_subject_id=identity.subject_id,
            detail=str(reason or "case closed")[:256],
        )
        return persisted

    # ------------------------------------------------------------------
    # Capability patch gap 1: analyst triage transitions.
    #
    # Documented transition matrix (closed set):
    #
    #   open ----------> acknowledged    (case.acknowledge)
    #   open ----------> investigating   (case.investigate)
    #   acknowledged --> investigating   (case.investigate)
    #   {open, acknowledged, investigating} --> closed (case.close)
    #
    # Everything else is rejected with a 409 CaseStateConflictError;
    # the case is left untouched and the rejection is observable.
    # A repeated same-state request is a conflict, NOT a silent
    # success, so a duplicated click can never be mistaken for a
    # state change that did not happen.
    # ------------------------------------------------------------------

    _TRIAGE_TRANSITIONS: Dict[str, set] = {
        CASE_STATE_ACKNOWLEDGED: {CASE_STATE_OPEN},
        CASE_STATE_INVESTIGATING: {CASE_STATE_OPEN, CASE_STATE_ACKNOWLEDGED},
    }

    def acknowledge_case(
        self, identity, incident_id, reason="",
    ) -> Incident:
        """``open -> acknowledged`` (gap 1)."""
        return self._transition_triage(
            identity=identity,
            incident_id=incident_id,
            to_state_value=CASE_STATE_ACKNOWLEDGED,
            verb="acknowledge",
            reason=str(reason or "case acknowledged"),
        )

    def investigate_case(
        self, identity, incident_id, reason="",
    ) -> Incident:
        """``open|acknowledged -> investigating`` (gap 1)."""
        return self._transition_triage(
            identity=identity,
            incident_id=incident_id,
            to_state_value=CASE_STATE_INVESTIGATING,
            verb="investigate",
            reason=str(reason or "investigation started"),
        )

    def _transition_triage(
        self,
        *,
        identity,
        incident_id,
        to_state_value: str,
        verb: str,
        reason: str,
    ) -> Incident:
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        case = self._repository.get_by_id_or_raise(incident_id)
        self._authorize_case_access(identity, case)
        current = case.state.value
        allowed_from = self._TRIAGE_TRANSITIONS.get(to_state_value, set())
        if case.state is IncidentLifecycleState.CLOSED:
            raise CaseStateConflictError(
                safe_message=(
                    f"cannot {verb} a closed case"
                ),
                internal_detail=(
                    f"incident_id={incident_id} state={current!r}"
                ),
            )
        if current == to_state_value:
            raise CaseStateConflictError(
                safe_message=(
                    f"case is already in state {to_state_value!r}"
                ),
                internal_detail=(
                    f"incident_id={incident_id} repeated {verb}"
                ),
            )
        if current not in allowed_from:
            raise CaseStateConflictError(
                safe_message=(
                    f"cannot {verb} a case in state {current!r}"
                ),
                internal_detail=(
                    f"incident_id={incident_id} "
                    f"{current!r} -> {to_state_value!r} not allowed"
                ),
            )
        now = datetime.now(timezone.utc)
        transition = LifecycleTransition(
            from_state=current,
            to_state=to_state_value,
            actor_subject_id=identity.subject_id,
            actor_role=identity.role,
            reason=str(reason)[:2048],
            transitioned_at=now,
        )
        updated = case.model_copy(update={
            "state": IncidentLifecycleState(to_state_value),
            "lifecycle_history": _append_transition(
                case.lifecycle_history, transition,
            ),
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._emit_notification(
            kind=f"case.{verb}d" if verb == "acknowledge" else "case.investigating",
            case=persisted,
            actor_subject_id=identity.subject_id,
            detail=str(reason)[:256],
        )
        return persisted

    # ------------------------------------------------------------------
    # Capability patch gap 4: append-only analyst notes.
    # ------------------------------------------------------------------

    def add_note(
        self, identity, incident_id, body,
    ) -> Incident:
        """Append an immutable analyst note; returns the updated case."""
        if not isinstance(identity, Identity):
            raise InvalidIncidentInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        if not isinstance(body, str) or not body.strip():
            raise InvalidIncidentInputError(
                safe_message="note body required",
                internal_detail="empty note body",
                field="body",
            )
        case = self._repository.get_by_id_or_raise(incident_id)
        self._authorize_case_access(identity, case)
        if len(case.notes) >= MAX_CASE_NOTES:
            raise CaseStateConflictError(
                safe_message="case note limit reached",
                internal_detail=(
                    f"incident_id={incident_id} "
                    f"notes={len(case.notes)}"
                ),
            )
        now = datetime.now(timezone.utc)
        note = CaseNote(
            note_id=_make_note_id(now, identity.subject_id),
            author_subject_id=identity.subject_id,
            author_role=str(identity.role),
            body=body.strip()[:MAX_CASE_NOTE_LEN],
            created_at=now,
        )
        updated = case.model_copy(update={
            "notes": tuple(case.notes) + (note,),
            "updated_at": now,
        })
        persisted = self._repository.upsert(updated)
        self._emit_notification(
            kind="case.note_added",
            case=persisted,
            actor_subject_id=identity.subject_id,
            detail="analyst note appended",
        )
        return persisted



def _compose_case_severity(detections, correlations, events_by_id):
    """V2-09: compose the case-level severity + confidence bands.

    Delegates to the documented :class:`app.severity.engine.SeverityEngine`
    over the case's evidence and returns the bundle's documented bands
    ``(severity, confidence)`` — the exact ``SeverityBand`` /
    ``ConfidenceBand`` strings the Phase 4.6 engine emits. Returns
    ``(None, None)`` when the engine produces no bundle assessment so
    the caller leaves the case fields unset (truthful absence — the
    severity model explicitly forbids fabricated values). Fail-open: a
    composition problem never blocks case creation.
    """
    try:
        from ..severity.engine import SeverityEngine
        from ..severity.models import ConfidenceBand, SeverityBand

        result = SeverityEngine().run(
            detections=tuple(detections),
            correlations=tuple(correlations),
            events=dict(events_by_id or {}),
        )
    except Exception as exc:  # noqa: BLE001 - composition is best-effort
        _log.warning(
            "incident.severity_composition_failed error=%s",
            type(exc).__name__,
        )
        return None, None
    severity = None
    confidence = None
    # The bundle pair is the LAST assessment pair the engine produced
    # (subject_id == 'bundle:overall').
    sev_list = list(getattr(result, "severity_assessments", ()) or ())
    conf_list = list(getattr(result, "confidence_assessments", ()) or ())
    for a in reversed(sev_list):
        if str(getattr(a, "subject_id", "")) == "bundle:overall":
            band = getattr(a, "band", None)
            if isinstance(band, SeverityBand):
                severity = band.value
            break
    for a in reversed(conf_list):
        if str(getattr(a, "subject_id", "")) == "bundle:overall":
            band = getattr(a, "band", None)
            if isinstance(band, ConfidenceBand):
                confidence = band.value
            break
    return severity, confidence


def _merge_case_evidence(
    existing,
    *,
    events,
    detections,
    correlations,
    extra_event_ids: Sequence[str] = (),
    extra_detection_ids: Sequence[str] = (),
):
    """V2-02: idempotently merge new evidence into an existing case.

    Returns the merged case (unsaved) or ``None`` when the new
    evidence adds nothing new (a pure re-delivery keeps the stored
    document untouched, preserving ``updated_at`` stability). Severity
    / confidence are re-composed monotonically: a growing cluster may
    escalate a band, never silently downgrade it.

    ``extra_event_ids`` / ``extra_detection_ids``: id-only evidence
    references (e.g. the correlation row's own catalogue) merged
    alongside the full model objects.
    """
    old_ev = existing.evidence
    ev_event_ids = _dedup_preserving_order(
        list(old_ev.event_ids)
        + [e.event_id for e in events]
        + list(extra_event_ids or ())
    )
    ev_detection_ids = _dedup_preserving_order(
        list(old_ev.detection_ids)
        + [d.detection_id for d in detections]
        + list(extra_detection_ids or ())
    )
    ev_correlation_ids = _dedup_preserving_order(
        list(old_ev.correlation_ids)
        + [c.correlation_id for c in correlations]
    )
    grew = (
        len(ev_event_ids) != len(old_ev.event_ids)
        or len(ev_detection_ids) != len(old_ev.detection_ids)
        or len(ev_correlation_ids) != len(old_ev.correlation_ids)
    )
    if not grew:
        return None
    new_rule_refs = _dedup_rule_refs(list(detections))
    rule_refs = _dedup_preserving_order(
        [tuple(r) for r in old_ev.rule_references]
        + [tuple(r) for r in new_rule_refs]
    )
    new_evidence = IncidentEvidence(
        event_ids=tuple(ev_event_ids),
        detection_ids=tuple(ev_detection_ids),
        correlation_ids=tuple(ev_correlation_ids),
        rule_references=tuple(rule_refs),
    )
    updates: dict = {"evidence": new_evidence}
    severity, confidence = _compose_case_severity(
        list(detections), list(correlations), {}
    )
    try:
        from ..severity.models import (
            _CONFIDENCE_RANK,
            _SEVERITY_RANK,
            ConfidenceBand,
            SeverityBand,
        )

        old_sev = getattr(existing, "severity", "") or None
        if severity:
            new_band = SeverityBand(severity)
            if not old_sev or (
                _SEVERITY_RANK[new_band]
                >= _SEVERITY_RANK.get(SeverityBand(old_sev), 0)
            ):
                updates["severity"] = severity
        old_conf = getattr(existing, "confidence", "") or None
        if confidence:
            new_band = ConfidenceBand(confidence)
            if not old_conf or (
                _CONFIDENCE_RANK[new_band]
                >= _CONFIDENCE_RANK.get(ConfidenceBand(old_conf), 0)
            ):
                updates["confidence"] = confidence
    except Exception:  # noqa: BLE001 - composition stays best-effort
        if severity and not getattr(existing, "severity", ""):
            updates["severity"] = severity
        if confidence and not getattr(existing, "confidence", ""):
            updates["confidence"] = confidence
    return existing.model_copy(update=updates)


def _dedup_rule_refs(detections):
    seen = set()
    out = []
    for d in detections:
        key = (d.rule_id, int(d.rule_version))
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return tuple(out)


def _dedup_preserving_order(values):
    seen = set()
    out = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _append_transition(history, transition):
    out = list(history)
    out.append(transition)
    if len(out) > MAX_CASE_LIFECYCLE_HISTORY:
        out = out[-MAX_CASE_LIFECYCLE_HISTORY:]
    return tuple(out)


def _make_case_id(
    *, event_ids, detection_ids, correlation_ids, created_at, seed,
):
    body = "|".join((
        seed,
        ",".join(sorted(event_ids)),
        ",".join(sorted(detection_ids)),
        ",".join(sorted(correlation_ids)),
        str(created_at.timestamp()),
    )).encode("utf-8")
    digest = hashlib.sha256(body).digest()
    ts_ms = int(created_at.timestamp() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(digest[6:8], "big") & 0x0FFF
    rand_b_hi = (int.from_bytes(digest[8:10], "big") & 0x3FFF) | 0x8000
    rand_b_lo = int.from_bytes(digest[10:16], "big")
    uuid_int = (
        (ts_ms << 80) | (0x7 << 76) | (rand_a << 64)
        | (rand_b_hi << 48) | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    return (
        "case-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


def _case_id_for_correlation(correlation: Correlation) -> str:
    """Deterministic case id **per correlation cluster**.

    The id is a pure function of the stable cluster signature
    (``pattern_id`` + correlation key parts) — NOT the exact
    ``correlation_id`` (which changes as a cluster grows) and NOT the
    wall clock. This is the F-2 idempotency guarantee: a growing
    brute-force cluster always resolves to the same case id, and a
    re-run / retry / restarted worker never opens a duplicate case.
    The returned id is a UUID-v7-format string (>= 36 chars) that
    satisfies the ``Incident.incident_id`` constraints.
    """
    key_parts = (
        list(correlation.key.parts)
        if getattr(getattr(correlation, "key", None), "parts", None)
        else []
    )
    sig = ":".join([correlation.pattern_id, "|".join(key_parts)])
    digest = hashlib.sha256(sig.encode("utf-8")).digest()
    # Derive every UUID field from the digest so the id is stable across
    # calls, retries, and process restarts (no DateTime.now() here).
    ts_ms = int.from_bytes(digest[0:6], "big") & ((1 << 48) - 1)
    rand_a = int.from_bytes(digest[6:8], "big") & 0x0FFF
    rand_b_hi = (int.from_bytes(digest[8:10], "big") & 0x3FFF) | 0x8000
    rand_b_lo = int.from_bytes(digest[10:16], "big")
    uuid_int = (
        (ts_ms << 80) | (0x7 << 76) | (rand_a << 64)
        | (rand_b_hi << 48) | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    return (
        "case-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


def _compose_case_attribution(
    events: Sequence[SecurityEvent],
    detections: Sequence[Detection],
    correlations: Sequence[Correlation],
) -> Optional[CaseAttribution]:
    """Derive the analyst-facing attribution from the case's evidence.

    Deterministic and evidence-only (capability patch gap 3):

    * ``attacker``  - the first correlation key part (the patterns
      group by ``source_ip`` first), with the pattern id recorded as
      provenance.
    * ``target``    - the second correlation key part (the grouped
      endpoint), same provenance rule.
    * ``source_instance_id`` - the first non-empty event provenance
      pointer, falling back to the first detection provenance pointer.
    * every field records HOW it was derived in ``provenance``.

    A field that cannot be derived stays empty (wire ``null``); when
    nothing at all can be derived the attribution itself is ``None``.
    No external intel, no heuristic enrichment, no invention.
    """
    attacker = ""
    target = ""
    provenance_parts: List[str] = []
    for c in correlations:
        parts = list(getattr(getattr(c, "key", None), "parts", ()) or ())
        if parts and not attacker:
            attacker = str(parts[0])[:256]
            provenance_parts.append(
                f"attacker=correlation key part 1 ({c.pattern_id})"
            )
        if len(parts) > 1 and not target:
            target = str(parts[1])[:256]
            provenance_parts.append(
                f"target=correlation key part 2 ({c.pattern_id})"
            )
        if attacker and target:
            break
    source_instance_id = ""
    for ev in events:
        sid = getattr(getattr(ev, "provenance", None),
                      "source_instance_id", None)
        if sid:
            source_instance_id = str(sid)[:96]
            provenance_parts.append("source=event provenance")
            break
    if not source_instance_id:
        for d in detections:
            sid = getattr(d, "source_instance_id", "")
            if sid:
                source_instance_id = str(sid)[:96]
                provenance_parts.append("source=detection provenance")
                break
    if not (attacker or target or source_instance_id):
        return None
    return CaseAttribution(
        attacker=attacker,
        target=target,
        source_instance_id=source_instance_id,
        provenance="; ".join(provenance_parts)[:512],
    )


def _make_note_id(now: datetime, author: str) -> str:
    """Deterministic ``note-<uuidv7-shape>`` id for a case note."""
    body = f"{author}|{now.timestamp():.6f}".encode("utf-8")
    digest = hashlib.sha256(body).digest()
    ts_ms = int(now.timestamp() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(digest[0:2], "big") & 0x0FFF
    rand_b_hi = (int.from_bytes(digest[2:4], "big") & 0x3FFF) | 0x8000
    rand_b_lo = int.from_bytes(digest[4:10], "big")
    uuid_int = (
        (ts_ms << 80) | (0x7 << 76) | (rand_a << 64)
        | (rand_b_hi << 48) | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    return (
        "note-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


def _correlation_case_title(correlation: Correlation) -> str:
    """A human-readable title for an auto-opened case."""
    key = correlation.key
    return (
        f"Correlated security cluster "
        f"({key.parts[0] if key.parts else '?'})"
    )


def _correlation_case_summary(correlation: Correlation) -> str:
    """A brief, evidence-faithful summary for an auto-opened case."""
    reasoning = str(correlation.reasoning or "")
    if len(reasoning) > 1024:
        reasoning = reasoning[:1021] + "..."
    return (
        f"{correlation.pattern_id} v{correlation.pattern_version}: "
        f"{reasoning}"
    )


def authorize_case_access(identity, case):
    """Module-level wrapper around the case-access check."""
    if not isinstance(identity, Identity):
        raise CaseAccessDeniedError(
            safe_message="case access denied",
            internal_detail="invalid identity",
        )
    if not isinstance(case, Incident):
        raise CaseAccessDeniedError(
            safe_message="case access denied",
            internal_detail="invalid case",
        )
    perms = tuple(identity.permissions)
    if has_permission(
        role=identity.role,
        identity_permissions=perms,
        permission=Permission.CASE_READ_ANY,
    ):
        return
    if not has_permission(
        role=identity.role,
        identity_permissions=perms,
        permission=Permission.CASE_READ,
    ):
        raise CaseAccessDeniedError(
            safe_message="case access denied",
            internal_detail="missing case:read",
        )
    if case.created_by != identity.subject_id:
        raise CaseAccessDeniedError(
            safe_message="case access denied",
            internal_detail="wrong owner",
        )


__all__ = [
    "CentralizedOutcome",
    "IncidentService",
    "MAX_CENTRALIZED_CORRELATION_IDS",
    "authorize_case_access",
]