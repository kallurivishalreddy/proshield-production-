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
        incident_id: Optional[str] = None,
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
        case = Incident(
            incident_id=incident_id,
            title=str(title or "")[:MAX_CASE_TITLE_LEN],
            summary=str(summary or "")[:1024],
            state=IncidentLifecycleState.OPEN,
            evidence=evidence,
            rule_references=rule_refs,
            severity=composed_severity or "",
            confidence=composed_confidence or "",
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
        return self._repository.upsert(closed)



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