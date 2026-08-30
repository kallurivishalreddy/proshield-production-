"""Report data models.

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md.

A :class:`Report` is the deterministic, frozen,
evidence-backed artifact the report service generates.
The report:

* carries the deterministic ``report_id``
  (``rpt-<uuidv7>``),
* is bound to an ``incident_id``,
* is bound to a ``mode`` (NORMAL or CENTRALIZED),
* is owned by the ``generated_by`` identity (the analyst
  who requested it),
* is versioned (``version = 1``; future re-generations
  produce v2, v3, ...),
* is composed of ordered, named
  :class:`ReportSection` records,
* carries a deterministic textual rendering for
  human-readable export.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Tuple,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
)

from ..incidents.models import IncidentId as _IncidentId


# ----------------------------------------------------------------- modes
class ReportMode(str, Enum):
    """The two documented report modes."""

    NORMAL = "normal"
    CENTRALIZED = "centralized"


REPORT_MODE_NORMAL = ReportMode.NORMAL.value
REPORT_MODE_CENTRALIZED = ReportMode.CENTRALIZED.value


# ----------------------------------------------------------------- bounds
MAX_REPORT_FIELD_LEN = 2048
MAX_REPORT_ITEMS = 64
MAX_REPORT_REFERENCES = 64
MAX_REPORT_ID_LEN = 64
MAX_REPORT_TITLE_LEN = 256
REPORT_ID_PATTERN = (
    r"^rpt-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
ReportId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=MAX_REPORT_ID_LEN,
        pattern=REPORT_ID_PATTERN,
    ),
]
# Re-export the incident id type for callers that want a
# single import surface.
IncidentId = _IncidentId


# ----------------------------------------------------------------- content
class ReportItem(BaseModel):
    """A single piece of evidence-backed content in a
    report section.

    ``kind`` is the closed-set content kind (one of
    ``event``, ``detection``, ``correlation``,
    ``centralized_correlation``, ``timeline_item``,
    ``severity_assessment``, ``confidence_assessment``,
    ``note``). ``reference_id`` is the canonical
    underlying record id; for ``note`` items it is
    empty (the ``text`` field carries the human-readable
    note).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=32,
            pattern=(
                r"^(event|detection|correlation|"
                r"centralized_correlation|timeline_item|"
                r"severity_assessment|confidence_assessment|note)$"
            ),
        ),
    ]
    reference_id: Annotated[
        str,
        StringConstraints(min_length=0, max_length=64),
    ] = ""
    title: Annotated[
        str,
        StringConstraints(min_length=0, max_length=256),
    ] = ""
    text: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_REPORT_FIELD_LEN),
    ] = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "reference_id": self.reference_id,
            "title": self.title,
            "text": self.text,
        }


class ReportSection(BaseModel):
    """A named, ordered section of a report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: Annotated[
        str,
        StringConstraints(min_length=1, max_length=64),
    ]
    items: Tuple[ReportItem, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "items": [i.to_dict() for i in self.items],
        }


class Report(BaseModel):
    """The frozen, BSON-safe, evidence-referenced artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: ReportId
    incident_id: IncidentId
    mode: ReportMode
    version: int
    title: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_REPORT_TITLE_LEN,
        ),
    ]
    sections: Tuple[ReportSection, ...] = ()
    generated_by: Annotated[
        str, StringConstraints(min_length=1, max_length=128)
    ]
    generated_at: datetime
    evidence_references: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=64)],
        ...,
    ] = ()
    rule_references: Tuple[
        Tuple[
            Annotated[
                str,
                StringConstraints(min_length=1, max_length=64),
            ],
            int,
        ],
        ...,
    ] = ()
    is_centralized: bool = False
    centralized_correlation_ids: Tuple[
        Annotated[str, StringConstraints(min_length=0, max_length=64)],
        ...,
    ] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "mode": self.mode.value,
            "version": self.version,
            "title": self.title,
            "sections": [s.to_dict() for s in self.sections],
            "generated_by": self.generated_by,
            "generated_at": self.generated_at.isoformat(),
            "evidence_references": list(self.evidence_references),
            "rule_references": [
                {"rule_id": rid, "rule_version": ver}
                for rid, ver in self.rule_references
            ],
            "is_centralized": self.is_centralized,
            "centralized_correlation_ids": list(
                self.centralized_correlation_ids
            ),
        }


__all__ = [
    "MAX_REPORT_FIELD_LEN",
    "MAX_REPORT_ITEMS",
    "MAX_REPORT_REFERENCES",
    "MAX_REPORT_TITLE_LEN",
    "REPORT_MODE_CENTRALIZED",
    "REPORT_MODE_NORMAL",
    "Report",
    "ReportId",
    "ReportItem",
    "ReportMode",
    "ReportSection",
]