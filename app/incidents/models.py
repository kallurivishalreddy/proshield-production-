"""Incident / case data models.

Reference: docs/PHASE 2/DOMAIN_DATA_MODEL.md,
docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md.

The case is the **security boundary the proxy authorizes
against**. It is intentionally small:

* :class:`IncidentEvidence` - the per-case evidence
  catalogue. References (never copies) the underlying
  SecurityEvent / Detection / Correlation / rule-id
  records. The reference-only invariant is the case
  integrity boundary: a case cannot mutate evidence.
* :class:`ReportReference` - a thin pointer to a report
  document the report-generator produces.
* :class:`LifecycleTransition` - one immutable entry of
  the case's lifecycle history.
* :class:`Incident` - the frozen, BSON-safe case record.

The lifecycle states are documented in the package
``__init__``. The closed set is:

* open - initial state.
* acknowledged - an analyst acknowledged the case
  (triage recorded; capability patch gap 1).
* investigating - an analyst is actively
  investigating the case (gap 1).
* centralized_pending - an analyst requested
  centralized analysis.
* centralized_failed - the centralized correlation
  raised; the original case is intact.
* report_pending - a report is being generated.
* closed - an analyst closed the case.

A case may never silently disappear. Every state
transition appends to ``lifecycle_history`` so the
persisted document is the single source of truth.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Optional,
    Tuple,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
)


# ----------------------------------------------------------------- bounds
MAX_CASE_TITLE_LEN = 256
MAX_CASE_REASONING_LEN = 2048
MAX_CASE_SUMMARY_LEN = 1024
MAX_CASE_LIFECYCLE_HISTORY = 64
MAX_INCIDENT_REFERENCES = 256
MAX_REPORT_REFERENCES = 16
MAX_RULE_ID_LEN = 64
MAX_CASE_ID_LEN = 64
INCIDENT_ID_PREFIX = "case"
INCIDENT_ID_PATTERN = (
    r"^case-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

ReportId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=64,
        pattern=r"^rpt-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    ),
]
IncidentId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=MAX_CASE_ID_LEN,
        pattern=INCIDENT_ID_PATTERN,
    ),
]


# ----------------------------------------------------------------- states
class IncidentLifecycleState(str, Enum):
    """Closed-set case lifecycle."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CENTRALIZED_PENDING = "centralized_pending"
    CENTRALIZED_FAILED = "centralized_failed"
    REPORT_PENDING = "report_pending"
    CLOSED = "closed"


# Module-level aliases matching the documented vocabulary.
CASE_STATE_OPEN = IncidentLifecycleState.OPEN.value
CASE_STATE_ACKNOWLEDGED = IncidentLifecycleState.ACKNOWLEDGED.value
CASE_STATE_INVESTIGATING = IncidentLifecycleState.INVESTIGATING.value
CASE_STATE_CENTRALIZED_PENDING = (
    IncidentLifecycleState.CENTRALIZED_PENDING.value
)
CASE_STATE_CENTRALIZED_FAILED = (
    IncidentLifecycleState.CENTRALIZED_FAILED.value
)
CASE_STATE_REPORT_PENDING = IncidentLifecycleState.REPORT_PENDING.value
CASE_STATE_CLOSED = IncidentLifecycleState.CLOSED.value


# ----------------------------------------------------------------- evidence
class IncidentEvidence(BaseModel):
    """The per-case evidence catalogue.

    Every field is a reference (never a copy) to evidence
    already produced by Phase 4.1-4.6. The case NEVER
    carries a copy of the underlying SecurityEvent /
    Detection / Correlation / SeverityAssessment. The
    reference-only invariant is what protects evidence
    integrity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_ids: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=64)],
        ...,
    ] = ()
    detection_ids: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=64)],
        ...,
    ] = ()
    correlation_ids: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=64)],
        ...,
    ] = ()
    rule_references: Tuple[
        Tuple[
            Annotated[str, StringConstraints(min_length=1, max_length=MAX_RULE_ID_LEN)],
            int,
        ],
        ...,
    ] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_ids": list(self.event_ids),
            "detection_ids": list(self.detection_ids),
            "correlation_ids": list(self.correlation_ids),
            "rule_references": [
                {"rule_id": rid, "rule_version": ver}
                for rid, ver in self.rule_references
            ],
        }


class ReportReference(BaseModel):
    """A thin pointer to a report document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: ReportId
    mode: Annotated[
        str,
        StringConstraints(min_length=1, max_length=32),
    ]
    generated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "mode": self.mode,
            "generated_at": self.generated_at.isoformat(),
        }


class LifecycleTransition(BaseModel):
    """One immutable entry of the case's lifecycle history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    from_state: Optional[
        Annotated[str, StringConstraints(min_length=1, max_length=32)]
    ] = None
    to_state: Annotated[
        str, StringConstraints(min_length=1, max_length=32)
    ]
    actor_subject_id: Annotated[
        str, StringConstraints(min_length=1, max_length=128)
    ]
    actor_role: Annotated[
        str, StringConstraints(min_length=1, max_length=32)
    ]
    reason: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_CASE_REASONING_LEN),
    ] = ""
    transitioned_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state,
            "to_state": self.to_state,
            "actor_subject_id": self.actor_subject_id,
            "actor_role": self.actor_role,
            "reason": self.reason,
            "transitioned_at": self.transitioned_at.isoformat(),
        }


# ----------------------------------------------------------------- notes
MAX_CASE_NOTE_LEN = 4096
MAX_CASE_NOTES = 256
CASE_NOTE_ID_PREFIX = "note"


class CaseNote(BaseModel):
    """One immutable, append-only analyst note on a case.

    A note is authored evidence of the investigation: it records
    WHO wrote it (subject + role), WHEN (UTC), and WHAT (a bounded
    body). Notes are embedded on the case document, are append-only
    (never edited or removed), and are scoped to exactly one case by
    construction (no cross-case leakage is possible).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    note_id: Annotated[
        str,
        StringConstraints(
            min_length=5,
            max_length=64,
            pattern=r"^note-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        ),
    ]
    author_subject_id: Annotated[
        str, StringConstraints(min_length=1, max_length=128)
    ]
    author_role: Annotated[
        str, StringConstraints(min_length=1, max_length=32)
    ]
    body: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_CASE_NOTE_LEN),
    ]
    created_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "author_subject_id": self.author_subject_id,
            "author_role": self.author_role,
            "body": self.body,
            "created_at": self.created_at.isoformat(),
        }


# ----------------------------------------------------------------- attribution
class CaseAttribution(BaseModel):
    """Analyst-facing case attribution (capability patch gap 3).

    Values are **derived, never invented**: they are composed once
    at case assembly from the case's own evidence (correlation key
    parts and event provenance) and each field records how it was
    derived via ``provenance``. A field that cannot be derived is
    the empty string — the wire renders ``null`` and the UI renders
    "not attributed". No heuristic enrichment, no external intel.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attacker: Annotated[
        str, StringConstraints(max_length=256)
    ] = ""
    target: Annotated[
        str, StringConstraints(max_length=256)
    ] = ""
    source_instance_id: Annotated[
        str, StringConstraints(max_length=96)
    ] = ""
    provenance: Annotated[
        str, StringConstraints(max_length=512)
    ] = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker": self.attacker or None,
            "target": self.target or None,
            "source_instance_id": self.source_instance_id or None,
            "provenance": self.provenance or None,
        }


class Incident(BaseModel):
    """The frozen, BSON-safe, evidence-referencing case.

    Every field that references evidence is a tuple of
    id strings; nothing in this record may mutate the
    underlying SecurityEvent / Detection / Correlation /
    SeverityAssessment.

    The case carries:

    * a deterministic ``incident_id`` (``case-<uuidv7>``),
    * the canonical title + summary,
    * an :class:`IncidentEvidence` reference catalogue,
    * the current :class:`IncidentLifecycleState`,
    * the full :class:`LifecycleTransition` history,
    * the report references (may be empty),
    * the centralized-analysis context (None until an
      analyst explicitly requests it; see Section 3 of the
      Phase 4.8 task),
    * the audit metadata (created_by / created_at /
      updated_at),
    * the analyst-facing ``human_id`` (``CASE-000001``, gap 2),
    * the append-only analyst :class:`CaseNote` list (gap 4),
    * the evidence-derived :class:`CaseAttribution` (gap 3).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: IncidentId
    title: Annotated[
        str, StringConstraints(min_length=1, max_length=MAX_CASE_TITLE_LEN)
    ]
    summary: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_CASE_SUMMARY_LEN),
    ] = ""
    state: IncidentLifecycleState
    evidence: IncidentEvidence
    rule_references: Tuple[
        Tuple[
            Annotated[str, StringConstraints(min_length=1, max_length=MAX_RULE_ID_LEN)],
            int,
        ],
        ...,
    ] = ()
    lifecycle_history: Tuple[LifecycleTransition, ...] = ()
    report_references: Tuple[ReportReference, ...] = ()
    centralized_correlation_ids: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=64)],
        ...,
    ] = ()
    centralized_reasoning: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_CASE_REASONING_LEN),
    ] = ""
    centralized_failed: bool = False
    centralized_failure_reason: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_CASE_REASONING_LEN),
    ] = ""
    # V2-09 fix: the composed case-level severity + confidence, using
    # the *documented bands* of :class:`app.severity.models`
    # (``SeverityBand`` / ``ConfidenceBand``). Composed by the
    # documented :class:`app.severity.engine.SeverityEngine` over the
    # case's bundle evidence at case creation, and re-composed
    # (monotonically — never lowered) whenever the case evidence
    # grows. Empty string = not composed (the UI must render "—",
    # never a fabricated number: the severity model explicitly forbids
    # inventing values).
    severity: Annotated[
        str, StringConstraints(min_length=0, max_length=32)
    ] = ""
    confidence: Annotated[
        str, StringConstraints(min_length=0, max_length=32)
    ] = ""
    # Capability patch gap 2: the persisted, allocator-assigned
    # human-readable id (``CASE-000001``). Empty for entities created
    # before the allocator existed; the wire renders null.
    human_id: Annotated[
        str,
        StringConstraints(min_length=0, max_length=32),
    ] = ""
    # Capability patch gap 3: evidence-derived attribution (None when
    # it could not be derived — never fabricated).
    attribution: Optional[CaseAttribution] = None
    # Capability patch gap 4: append-only analyst notes.
    notes: Tuple[CaseNote, ...] = ()
    created_by: Annotated[
        str, StringConstraints(min_length=1, max_length=128)
    ]
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "human_id": self.human_id or None,
            "title": self.title,
            "summary": self.summary,
            "state": self.state.value,
            "evidence": self.evidence.to_dict(),
            "severity": self.severity or None,
            "confidence": self.confidence or None,
            "attribution": (
                self.attribution.to_dict() if self.attribution else None
            ),
            "notes": [n.to_dict() for n in self.notes],
            "rule_references": [
                {"rule_id": rid, "rule_version": ver}
                for rid, ver in self.rule_references
            ],
            "lifecycle_history": [
                t.to_dict() for t in self.lifecycle_history
            ],
            "report_references": [r.to_dict() for r in self.report_references],
            "centralized_correlation_ids": list(
                self.centralized_correlation_ids
            ),
            "centralized_reasoning": self.centralized_reasoning,
            "centralized_failed": self.centralized_failed,
            "centralized_failure_reason": self.centralized_failure_reason,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


__all__ = [
    "CASE_STATE_ACKNOWLEDGED",
    "CASE_STATE_CENTRALIZED_FAILED",
    "CASE_STATE_CENTRALIZED_PENDING",
    "CASE_STATE_CLOSED",
    "CASE_STATE_INVESTIGATING",
    "CASE_STATE_OPEN",
    "CASE_STATE_REPORT_PENDING",
    "CaseAttribution",
    "CaseNote",
    "Incident",
    "IncidentEvidence",
    "IncidentId",
    "IncidentLifecycleState",
    "LifecycleTransition",
    "MAX_CASE_LIFECYCLE_HISTORY",
    "MAX_CASE_REASONING_LEN",
    "MAX_CASE_SUMMARY_LEN",
    "MAX_CASE_TITLE_LEN",
    "MAX_INCIDENT_REFERENCES",
    "MAX_REPORT_REFERENCES",
    "MAX_RULE_ID_LEN",
    "ReportId",
    "ReportReference",
]