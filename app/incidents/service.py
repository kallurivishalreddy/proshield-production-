"""Incident / case service (Phase 4.8)."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence, Tuple

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
    InvalidIncidentInputError,
)
from .models import (
    CASE_STATE_CENTRALIZED_FAILED,
    CASE_STATE_CENTRALIZED_PENDING,
    CASE_STATE_CLOSED,
    CASE_STATE_OPEN,
    Incident,
    IncidentEvidence,
    IncidentLifecycleState,
    LifecycleTransition,
    MAX_CASE_LIFECYCLE_HISTORY,
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
    ) -> None:
        if not isinstance(repository, IncidentRepository):
            raise ValueError("repository must be an IncidentRepository")
        self._repository = repository
        self._correlation_engine = correlation_engine
        self._correlation_persister = correlation_persister

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
    ) -> Incident:
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
        event_ids = tuple(e.event_id for e in events_list)
        detection_ids = tuple(d.detection_id for d in detections_list)
        correlation_ids = tuple(c.correlation_id for c in correlations_list)
        rule_refs = _dedup_rule_refs(detections_list)
        evidence = IncidentEvidence(
            event_ids=event_ids,
            detection_ids=detection_ids,
            correlation_ids=correlation_ids,
            rule_references=rule_refs,
        )
        now = datetime.now(timezone.utc)
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
        case = Incident(
            incident_id=incident_id,
            title=str(title or "")[:MAX_CASE_TITLE_LEN],
            summary=str(summary or "")[:1024],
            state=IncidentLifecycleState.OPEN,
            evidence=evidence,
            rule_references=rule_refs,
            lifecycle_history=(initial_transition,),
            report_references=(),
            centralized_correlation_ids=(),
            centralized_reasoning="",
            centralized_failed=False,
            centralized_failure_reason="",
            created_by=identity.subject_id,
            created_at=now,
            updated_at=now,
        )
        return self._repository.create(case)

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
        return self._repository.upsert(closed)



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