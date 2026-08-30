"""ProShield report engine (Phase 4.8).

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md,
docs/PHASE 0/MVP_REQUIREMENTS.md (Early Investigation Report),
docs/PHASE 2/DOMAIN_DATA_MODEL.md.

The report engine produces the two documented report modes:

* **NORMAL / SPECIALIZED INVESTIGATION REPORT** — built
  from the case's existing evidence + the Phase 4.6
  timeline + severity / confidence results. The case's
  centralized context (if any) is **not** included in a
  normal report.
* **CENTRALIZED INVESTIGATION REPORT** — built from the
  case's existing evidence **plus** the centralized
  context. The report clearly identifies:
  - participating sources,
  - participating detections,
  - centralized correlation evidence,
  - combined timeline,
  - derived results,
  - severity / confidence context,
  - evidence references,
  - that a broader / centralized analysis was performed.

Both report modes are:

* **deterministic** — same case + same inputs -> same
  report,
* **evidence-backed** — every conclusion traces to an
  evidence id,
* **structured** — JSON-ready + human-readable rendering,
* **safe for export / download** — secrets, internal
  details, and internal collection names are stripped,
* **frozen** — Pydantic ``frozen=True``, ``extra="forbid"``.

What this engine does NOT do
----------------------------

* It does NOT use AI / LLM. Every report field is a
  deterministic function of the case's authoritative
  evidence.
* It does NOT mutate evidence. Reports are read-only
  artifacts generated from the case.
* It does NOT place unverified / fabricated claims in a
  report. The slice ships "no extra evidence" by default
  and any extra-curated content must come from a
  Pydantic-validated input.
* It does NOT build a document-management platform.
"""
from __future__ import annotations

from .errors import (
    InvalidReportInputError,
    ReportAccessDeniedError,
    ReportError,
    ReportNotFoundError,
)
from .models import (
    MAX_REPORT_FIELD_LEN,
    MAX_REPORT_ITEMS,
    MAX_REPORT_REFERENCES,
    REPORT_MODE_CENTRALIZED,
    REPORT_MODE_NORMAL,
    Report,
    ReportItem,
    ReportMode,
    ReportSection,
)
from .repository import ReportRepository
from .service import ReportService

__all__ = [
    "MAX_REPORT_FIELD_LEN",
    "MAX_REPORT_ITEMS",
    "MAX_REPORT_REFERENCES",
    "InvalidReportInputError",
    "REPORT_MODE_CENTRALIZED",
    "REPORT_MODE_NORMAL",
    "Report",
    "ReportAccessDeniedError",
    "ReportError",
    "ReportItem",
    "ReportMode",
    "ReportNotFoundError",
    "ReportRepository",
    "ReportSection",
    "ReportService",
]