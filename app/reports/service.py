"""Report service.

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md.

The :class:`ReportService` is the orchestrator that turns
a case into an evidence-backed, deterministic report. It
is the only layer that constructs :class:`Report`
documents.

The slice ships two report modes:

* NORMAL - built from the case's existing
  specialized evidence only.
* CENTRALIZED - built from the case's existing
  evidence PLUS the centralized context.

What the service does NOT do
----------------------------

* It does NOT use AI / LLM.
* It does NOT mutate the case.
* It does NOT place unverified / fabricated claims.
* It does NOT expose internal collection names or
  secret-shaped strings.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)

from ..auth.identity import Identity
from ..auth.permissions import Permission, has_permission
from ..correlation.models import Correlation
from ..detection.models import Detection
from ..domain.security_event import SecurityEvent
from ..incidents.errors import CaseAccessDeniedError
from ..incidents.models import Incident
from ..severity.models import SeverityResult
from ..timeline.models import TimelineResult
from .errors import (
    InvalidReportInputError,
    ReportAccessDeniedError,
)
from .models import (
    MAX_REPORT_FIELD_LEN,
    MAX_REPORT_ITEMS,
    MAX_REPORT_TITLE_LEN,
    REPORT_MODE_CENTRALIZED,
    REPORT_MODE_NORMAL,
    Report,
    ReportItem,
    ReportMode,
    ReportSection,
)
from .repository import ReportRepository


_log = logging.getLogger(__name__)


# Documented section titles. Closed-set; future report
# schema versions may extend.
SECTION_TITLE_WHAT_DETECTED = "what_was_detected"
SECTION_TITLE_SOURCES = "sources"
SECTION_TITLE_DETECTIONS = "detections"
SECTION_TITLE_SPECIALIZED_CORRELATION = "specialized_correlation"
SECTION_TITLE_TIMELINE = "timeline"
SECTION_TITLE_SEVERITY = "severity"
SECTION_TITLE_CONFIDENCE = "confidence"
SECTION_TITLE_RULE_REFERENCES = "rule_references"
SECTION_TITLE_CENTRALIZED_PARTICIPATION = (
    "centralized_participating_sources"
)
SECTION_TITLE_CENTRALIZED_DETECTIONS = "centralized_participating_detections"
SECTION_TITLE_CENTRALIZED_CORRELATION = "centralized_correlation_evidence"
SECTION_TITLE_CENTRALIZED_TIMELINE = "centralized_combined_timeline"
SECTION_TITLE_CENTRALIZED_DERIVED = "centralized_derived_results"
SECTION_TITLE_CENTRALIZED_SEVERITY_CONTEXT = "centralized_severity_context"
SECTION_TITLE_CENTRALIZED_CONFIDENCE_CONTEXT = (
    "centralized_confidence_context"
)
SECTION_TITLE_INVESTIGATION_METADATA = "investigation_metadata"

ALLOWED_SECTION_TITLES: frozenset = frozenset({
    SECTION_TITLE_WHAT_DETECTED,
    SECTION_TITLE_SOURCES,
    SECTION_TITLE_DETECTIONS,
    SECTION_TITLE_SPECIALIZED_CORRELATION,
    SECTION_TITLE_TIMELINE,
    SECTION_TITLE_SEVERITY,
    SECTION_TITLE_CONFIDENCE,
    SECTION_TITLE_RULE_REFERENCES,
    SECTION_TITLE_CENTRALIZED_PARTICIPATION,
    SECTION_TITLE_CENTRALIZED_DETECTIONS,
    SECTION_TITLE_CENTRALIZED_CORRELATION,
    SECTION_TITLE_CENTRALIZED_TIMELINE,
    SECTION_TITLE_CENTRALIZED_DERIVED,
    SECTION_TITLE_CENTRALIZED_SEVERITY_CONTEXT,
    SECTION_TITLE_CENTRALIZED_CONFIDENCE_CONTEXT,
    SECTION_TITLE_INVESTIGATION_METADATA,
})


def _authorize_case_access_via_service(
    identity: Identity, case: Incident
) -> None:
    """Re-export the incident-service authorization helper
    under a stable name so this module does not depend on
    a private symbol.
    """
    from ..incidents.service import authorize_case_access
    authorize_case_access(identity, case)


# ----------------------------------------------------------------- service
class ReportService:
    """The report orchestrator."""

    def __init__(
        self,
        repository: ReportRepository,
        incident_service: Optional[object] = None,
    ) -> None:
        if not isinstance(repository, ReportRepository):
            raise ValueError(
                "repository must be a ReportRepository"
            )
        self._repository = repository
        # The optional ``incident_service`` is used to resolve
        # the case that owns a report so that report access
        # enforces the canonical case-level authorization
        # boundary (see :func:`authorize_case_access`). It is
        # optional for backward compatibility with tests and
        # call sites that do not need case-level lookup; when
        # not provided, ``get_report`` falls back to a
        # permissive behaviour that does NOT cross the case
        # boundary (i.e. the report's existence is still
        # checked but no ownership enforcement is performed).
        # The proxy always supplies the incident service.
        self._incident_service = incident_service

    @property
    def repository(self) -> ReportRepository:
        return self._repository

    # ----- generation
    def generate_normal_report(
        self,
        *,
        identity: Identity,
        case: Incident,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
        correlations: Sequence[Correlation],
        timeline: Optional[TimelineResult] = None,
        severity: Optional[SeverityResult] = None,
        title: str = "",
    ) -> Report:
        """Generate a NORMAL / SPECIALIZED investigation
        report.

        The report covers the case's existing
        specialized evidence. Centralized context is
        NOT included even if the case carries one.
        """
        self._check_authority(identity, case)
        self._check_generate_permission(identity)
        sections = self._build_normal_sections(
            case=case,
            events=events,
            detections=detections,
            correlations=correlations,
            timeline=timeline,
            severity=severity,
        )
        return self._persist_report(
            identity=identity,
            case=case,
            mode=REPORT_MODE_NORMAL,
            title=title or f"Investigation report - {case.title}",
            sections=sections,
            evidence_references=self._evidence_refs(
                case=case,
                detections=detections,
                correlations=correlations,
            ),
            rule_references=case.rule_references,
            is_centralized=False,
            centralized_correlation_ids=(),
        )

    def generate_centralized_report(
        self,
        *,
        identity: Identity,
        case: Incident,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
        correlations: Sequence[Correlation],
        centralized_correlations: Sequence[Correlation],
        centralized_events: Sequence[SecurityEvent],
        centralized_detections: Sequence[Detection],
        centralized_severity: Optional[SeverityResult] = None,
        centralized_timeline: Optional[TimelineResult] = None,
        title: str = "",
    ) -> Report:
        """Generate a CENTRALIZED investigation report."""
        self._check_authority(identity, case)
        self._check_generate_permission(identity)
        if not case.centralized_correlation_ids and not centralized_correlations:
            raise InvalidReportInputError(
                safe_message="case has no centralized context",
                internal_detail="incident_id=" + case.incident_id,
            )
        sections = self._build_normal_sections(
            case=case,
            events=events,
            detections=detections,
            correlations=correlations,
            timeline=None,
            severity=None,
        )
        sections = list(sections) + self._build_centralized_sections(
            case=case,
            centralized_events=centralized_events,
            centralized_detections=centralized_detections,
            centralized_correlations=centralized_correlations,
            centralized_severity=centralized_severity,
            centralized_timeline=centralized_timeline,
        )
        return self._persist_report(
            identity=identity,
            case=case,
            mode=REPORT_MODE_CENTRALIZED,
            title=title or f"Centralized investigation report - {case.title}",
            sections=tuple(sections),
            evidence_references=self._evidence_refs(
                case=case,
                detections=detections,
                correlations=correlations,
            ),
            rule_references=case.rule_references,
            is_centralized=True,
            centralized_correlation_ids=tuple(
                c.correlation_id for c in centralized_correlations
            ),
        )

    # ----- read
    def get_report(
        self, identity: Identity, report_id: str
    ) -> Report:
        if not isinstance(report_id, str) or not report_id:
            raise InvalidReportInputError(
                safe_message="report_id required",
                internal_detail=f"got {type(report_id).__name__}",
                field="report_id",
            )
        report = self._repository.get_by_id_or_raise(report_id)
        perms = tuple(identity.permissions)
        if not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.REPORT_READ,
        ) and not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.REPORT_READ_ANY,
        ):
            raise ReportAccessDeniedError(
                safe_message="report access denied",
                internal_detail="missing report:read",
            )
        # Phase 4.8 remediation: a report is bound to an
        # incident. After the report-level permission check,
        # resolve the owning case and reuse the canonical
        # ``authorize_case_access`` boundary so that an
        # analyst with the default ``report:read`` permission
        # cannot read another analyst's report by guessing
        # its ``report_id`` (CONFIRMED IDOR fixed in this
        # remediation pass). If the case cannot be resolved
        # we treat the request as hidden, exactly as the
        # rest of the slice does for cross-tenant reads
        # (404, never leaking existence).
        if self._incident_service is not None:
            incident_id = str(report.incident_id)
            try:
                case = self._incident_service.get_case(
                    identity=identity, incident_id=incident_id,
                )
            except CaseAccessDeniedError:
                # Either the case is hidden, the case has
                # been deleted, or the identity is not
                # authorized to read the owning case. All
                # three collapse to the documented
                # "existence hidden" boundary (404).
                raise
            except Exception:
                # If the lookup is not implemented in the
                # injected service, fall through to a
                # safe-by-default deny.
                raise CaseAccessDeniedError(
                    safe_message="report access denied",
                    internal_detail="case lookup failed",
                )
            # ``get_case`` has already authorized the
            # identity, but we explicitly re-assert the
            # boundary so the call site reads as the
            # documented invariant.
            _authorize_case_access_via_service(identity, case)
        return report

    def list_for_incident(
        self,
        identity: Identity,
        case: Incident,
        *,
        limit: int = 20,
    ) -> List[Report]:
        self._check_authority(identity, case)
        return self._repository.find_for_incident(
            case.incident_id, limit=limit
        )

    # ----- helpers
    def _check_authority(self, identity: Identity, case: Incident) -> None:
        if not isinstance(identity, Identity):
            raise InvalidReportInputError(
                safe_message="identity required",
                internal_detail=f"got {type(identity).__name__}",
                field="identity",
            )
        _authorize_case_access_via_service(identity, case)

    def _check_generate_permission(self, identity: Identity) -> None:
        perms = tuple(identity.permissions)
        if not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.REPORT_GENERATE,
        ) and not has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.REPORT_GENERATE_ANY,
        ):
            raise ReportAccessDeniedError(
                safe_message="report generation denied",
                internal_detail="missing report:generate",
            )

    def _build_normal_sections(
        self,
        *,
        case: Incident,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
        correlations: Sequence[Correlation],
        timeline: Optional[TimelineResult],
        severity: Optional[SeverityResult],
    ) -> Tuple[ReportSection, ...]:
        sections: List[ReportSection] = []
        sections.append(self._build_what_detected_section(events, detections))
        sections.append(self._build_sources_section(events))
        sections.append(self._build_detections_section(detections))
        sections.append(self._build_correlations_section(correlations))
        if timeline is not None:
            sections.append(self._build_timeline_section(timeline))
        if severity is not None:
            sections.append(self._build_severity_section(severity))
            sections.append(self._build_confidence_section(severity))
        sections.append(self._build_rule_refs_section(case))
        sections.append(self._build_investigation_metadata_section(case))
        return tuple(sections)

    def _build_what_detected_section(
        self,
        events: Sequence[SecurityEvent],
        detections: Sequence[Detection],
    ) -> ReportSection:
        items: List[ReportItem] = []
        for ev in events:
            items.append(ReportItem(
                kind="event",
                reference_id=ev.event_id,
                title=f"{ev.source} {ev.event_type}",
                text=(
                    f"observed event from source={ev.source!r} "
                    f"event_type={ev.event_type!r} at "
                    f"{ev.event_time.isoformat()}"
                )[:MAX_REPORT_FIELD_LEN],
            ))
        for d in detections:
            items.append(ReportItem(
                kind="detection",
                reference_id=d.detection_id,
                title=f"{d.rule_id} v{d.rule_version}",
                text=d.reasoning[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_WHAT_DETECTED,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_sources_section(
        self, events: Sequence[SecurityEvent]
    ) -> ReportSection:
        sources = sorted({ev.source for ev in events})
        items = tuple(
            ReportItem(
                kind="note",
                reference_id="",
                title=src,
                text=f"participating source {src!r}",
            )
            for src in sources
        )
        return ReportSection(
            title=SECTION_TITLE_SOURCES,
            items=items[:MAX_REPORT_ITEMS],
        )

    def _build_detections_section(
        self, detections: Sequence[Detection]
    ) -> ReportSection:
        items: List[ReportItem] = []
        for d in detections:
            items.append(ReportItem(
                kind="detection",
                reference_id=d.detection_id,
                title=f"{d.rule_id} v{d.rule_version}",
                text=d.reasoning[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_DETECTIONS,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_correlations_section(
        self, correlations: Sequence[Correlation]
    ) -> ReportSection:
        items: List[ReportItem] = []
        for c in correlations:
            items.append(ReportItem(
                kind="correlation",
                reference_id=c.correlation_id,
                title=f"{c.pattern_id} v{c.pattern_version}",
                text=c.reasoning[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_SPECIALIZED_CORRELATION,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_timeline_section(
        self, timeline: TimelineResult
    ) -> ReportSection:
        items: List[ReportItem] = []
        for it in timeline.items:
            items.append(ReportItem(
                kind="timeline_item",
                reference_id=it.timeline_item_id,
                title=f"{it.kind.value} {it.source_id}",
                text=it.description[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_TIMELINE,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_severity_section(
        self, severity: SeverityResult
    ) -> ReportSection:
        items: List[ReportItem] = []
        for s in severity.severity_assessments:
            items.append(ReportItem(
                kind="severity_assessment",
                reference_id=s.subject_id,
                title=f"severity {s.band.value} ({s.subject_kind.value})",
                text=s.rationale.summary[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_SEVERITY,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_confidence_section(
        self, severity: SeverityResult
    ) -> ReportSection:
        items: List[ReportItem] = []
        for c in severity.confidence_assessments:
            items.append(ReportItem(
                kind="confidence_assessment",
                reference_id=c.subject_id,
                title=(
                    f"confidence {c.band.value} "
                    f"({c.subject_kind.value})"
                ),
                text=c.rationale.summary[:MAX_REPORT_FIELD_LEN],
            ))
        return ReportSection(
            title=SECTION_TITLE_CONFIDENCE,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_rule_refs_section(
        self, case: Incident
    ) -> ReportSection:
        items: List[ReportItem] = []
        for rid, ver in case.rule_references:
            items.append(ReportItem(
                kind="note",
                reference_id="",
                title=f"{rid} v{ver}",
                text=f"rule reference {rid} v{ver}",
            ))
        return ReportSection(
            title=SECTION_TITLE_RULE_REFERENCES,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_investigation_metadata_section(
        self, case: Incident
    ) -> ReportSection:
        items: List[ReportItem] = [
            ReportItem(
                kind="note",
                reference_id="",
                title="incident_id",
                text=case.incident_id,
            ),
            ReportItem(
                kind="note",
                reference_id="",
                title="case_state",
                text=case.state.value,
            ),
            ReportItem(
                kind="note",
                reference_id="",
                title="created_by",
                text=case.created_by,
            ),
            ReportItem(
                kind="note",
                reference_id="",
                title="created_at",
                text=case.created_at.isoformat(),
            ),
        ]
        return ReportSection(
            title=SECTION_TITLE_INVESTIGATION_METADATA,
            items=tuple(items)[:MAX_REPORT_ITEMS],
        )

    def _build_centralized_sections(
        self,
        *,
        case: Incident,
        centralized_events: Sequence[SecurityEvent],
        centralized_detections: Sequence[Detection],
        centralized_correlations: Sequence[Correlation],
        centralized_severity: Optional[SeverityResult],
        centralized_timeline: Optional[TimelineResult],
    ) -> List[ReportSection]:
        sections: List[ReportSection] = []
        sources = sorted({ev.source for ev in centralized_events})
        sections.append(ReportSection(
            title=SECTION_TITLE_CENTRALIZED_PARTICIPATION,
            items=tuple(
                ReportItem(
                    kind="note",
                    reference_id="",
                    title=src,
                    text=f"centralized participating source {src!r}",
                )
                for src in sources
            )[:MAX_REPORT_ITEMS],
        ))
        det_items: List[ReportItem] = []
        for d in centralized_detections:
            det_items.append(ReportItem(
                kind="detection",
                reference_id=d.detection_id,
                title=f"{d.rule_id} v{d.rule_version}",
                text=d.reasoning[:MAX_REPORT_FIELD_LEN],
            ))
        sections.append(ReportSection(
            title=SECTION_TITLE_CENTRALIZED_DETECTIONS,
            items=tuple(det_items)[:MAX_REPORT_ITEMS],
        ))
        corr_items: List[ReportItem] = []
        for c in centralized_correlations:
            corr_items.append(ReportItem(
                kind="centralized_correlation",
                reference_id=c.correlation_id,
                title=f"{c.pattern_id} v{c.pattern_version}",
                text=c.reasoning[:MAX_REPORT_FIELD_LEN],
            ))
        sections.append(ReportSection(
            title=SECTION_TITLE_CENTRALIZED_CORRELATION,
            items=tuple(corr_items)[:MAX_REPORT_ITEMS],
        ))
        if centralized_timeline is not None:
            tl_items: List[ReportItem] = []
            for it in centralized_timeline.items:
                tl_items.append(ReportItem(
                    kind="timeline_item",
                    reference_id=it.timeline_item_id,
                    title=f"{it.kind.value} {it.source_id}",
                    text=it.description[:MAX_REPORT_FIELD_LEN],
                ))
            sections.append(ReportSection(
                title=SECTION_TITLE_CENTRALIZED_TIMELINE,
                items=tuple(tl_items)[:MAX_REPORT_ITEMS],
            ))
        sections.append(ReportSection(
            title=SECTION_TITLE_CENTRALIZED_DERIVED,
            items=(
                ReportItem(
                    kind="note",
                    reference_id="",
                    title="centralized correlation_count",
                    text=str(len(centralized_correlations)),
                ),
                ReportItem(
                    kind="note",
                    reference_id="",
                    title="case.centralized_correlation_ids",
                    text=",".join(case.centralized_correlation_ids),
                ),
            ),
        ))
        if centralized_severity is not None:
            sev_items: List[ReportItem] = []
            for s in centralized_severity.severity_assessments:
                sev_items.append(ReportItem(
                    kind="severity_assessment",
                    reference_id=s.subject_id,
                    title=f"severity {s.band.value}",
                    text=s.rationale.summary[:MAX_REPORT_FIELD_LEN],
                ))
            sections.append(ReportSection(
                title=SECTION_TITLE_CENTRALIZED_SEVERITY_CONTEXT,
                items=tuple(sev_items)[:MAX_REPORT_ITEMS],
            ))
            conf_items: List[ReportItem] = []
            for c in centralized_severity.confidence_assessments:
                conf_items.append(ReportItem(
                    kind="confidence_assessment",
                    reference_id=c.subject_id,
                    title=f"confidence {c.band.value}",
                    text=c.rationale.summary[:MAX_REPORT_FIELD_LEN],
                ))
            sections.append(ReportSection(
                title=SECTION_TITLE_CENTRALIZED_CONFIDENCE_CONTEXT,
                items=tuple(conf_items)[:MAX_REPORT_ITEMS],
            ))
        return sections

    def _evidence_refs(
        self,
        *,
        case: Incident,
        detections: Sequence[Detection],
        correlations: Sequence[Correlation],
    ) -> Tuple[str, ...]:
        ids = list(case.evidence.event_ids)
        ids.extend(d.detection_id for d in detections)
        ids.extend(c.correlation_id for c in correlations)
        seen: set = set()
        out: List[str] = []
        for x in ids:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return tuple(out)[:MAX_REPORT_ITEMS]

    def _persist_report(
        self,
        *,
        identity: Identity,
        case: Incident,
        mode: str,
        title: str,
        sections: Tuple[ReportSection, ...],
        evidence_references: Tuple[str, ...],
        rule_references: Tuple[Tuple[str, int], ...],
        is_centralized: bool,
        centralized_correlation_ids: Tuple[str, ...],
    ) -> Report:
        existing = self._repository.find_for_incident(
            case.incident_id, limit=50
        )
        version = max(1, len(existing) + 1)
        now = datetime.now(timezone.utc)
        report_id = _make_report_id(
            incident_id=case.incident_id,
            mode=mode,
            version=version,
            generated_at=now,
            generated_by=identity.subject_id,
        )
        report = Report(
            report_id=report_id,
            incident_id=case.incident_id,
            mode=ReportMode(mode),
            version=version,
            title=str(title or "")[:MAX_REPORT_TITLE_LEN],
            sections=sections,
            generated_by=identity.subject_id,
            generated_at=now,
            evidence_references=evidence_references,
            rule_references=rule_references,
            is_centralized=is_centralized,
            centralized_correlation_ids=centralized_correlation_ids,
        )
        return self._repository.create(report)


# ----------------------------------------------------------------- helpers
def _make_report_id(
    *,
    incident_id: str,
    mode: str,
    version: int,
    generated_at: datetime,
    generated_by: str,
) -> str:
    """Deterministic ``rpt-<uuidv7>`` id."""
    ts_ms = int(generated_at.timestamp() * 1000) & ((1 << 48) - 1)
    body = "|".join((
        incident_id,
        mode,
        str(int(version)),
        str(generated_at.timestamp()),
        generated_by,
    )).encode("utf-8")
    digest = hashlib.sha256(body).digest()
    rand_a = int.from_bytes(digest[6:8], "big") & 0x0FFF
    rand_b_hi = (int.from_bytes(digest[8:10], "big") & 0x3FFF) | 0x8000
    rand_b_lo = int.from_bytes(digest[10:16], "big")
    uuid_int = (
        (ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (rand_b_hi << 48)
        | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    return (
        "rpt-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


__all__ = [
    "ALLOWED_SECTION_TITLES",
    "ReportService",
    "SECTION_TITLE_WHAT_DETECTED",
]