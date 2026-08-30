"""ProShield incident / case engine (Phase 4.8).

Reference: docs/PHASE 4/PHASE 4-08/PHASE-04-08-REPORT.md,
docs/PHASE 1/ARCHITECTURE.md (Section 2 target flow),
docs/PHASE 2/DOMAIN_DATA_MODEL.md (Incident model).

The incident package is the **investigation case** the
analyst / proxy interact with. It groups the existing
phase evidence (SecurityEvent -> Detection -> Correlation
-> Timeline -> Severity / Confidence) behind a single
frozen, evidence-referencing record:

* :class:`Incident` - a case. Frozen, BSON-safe, fully
  traceable to the underlying evidence. The case is
  the security boundary the proxy authorizes against.
* :class:`IncidentEvidence` - the per-case evidence
  catalogue (event ids, detection ids, correlation ids,
  rule id/version tuples).
* :class:`IncidentLifecycleState` - the documented
  lifecycle states (open / centralized_pending /
  centralized_failed / report_pending / closed). The
  slice is intentionally tiny; a full workflow engine
  is future scope.
* :class:`IncidentRepository` - the documented MongoDB
  boundary for the ``incidents`` collection.
* :class:`IncidentService` - the orchestrator that turns
  real backend evidence into an :class:`Incident` and
  mediates centralized analysis requests (reusing the
  Phase 4.5 correlation engine, never inventing a second
  correlation engine).

The case lifecycle in this slice is intentionally minimal:

1. ``open`` - the case was created from real evidence.
2. ``centralized_pending`` - an analyst-requested
   centralized correlation is in flight (or was just
   completed).
3. ``centralized_failed`` - the centralized correlation
   failed; the original evidence remains intact.
4. ``report_pending`` - a report was requested and is
   being generated.
5. ``closed`` - an analyst closed the case. The case is
   preserved (no destructive delete).

Every transition is preserved in the case's
``lifecycle_history`` field so the audit trail is
recoverable from the persisted document alone. No
separate workflow-engine state lives outside the case.

What this package does NOT do
----------------------------

* It does NOT implement a full workflow engine,
  assignment, queueing, escalation, or SLA tracking.
* It does NOT mutate the underlying SecurityEvent /
  Detection / Correlation records.
* It does NOT expose a "create evidence" API. The case
  is built by the orchestrator from evidence already
  produced by Phase 4.1-4.6.
* It does NOT silently downgrade a case on failure. A
  centralized-correlation failure leaves the original
  case intact and records the failure in
  ``lifecycle_history``.
"""
from __future__ import annotations

from .errors import (
    CaseAccessDeniedError,
    CaseEvidenceError,
    CaseNotFoundError,
    IncidentError,
    InvalidIncidentInputError,
)
from .models import (
    CASE_STATE_CENTRALIZED_FAILED,
    CASE_STATE_CENTRALIZED_PENDING,
    CASE_STATE_CLOSED,
    CASE_STATE_OPEN,
    CASE_STATE_REPORT_PENDING,
    Incident,
    IncidentEvidence,
    IncidentLifecycleState,
    LifecycleTransition,
    MAX_CASE_LIFECYCLE_HISTORY,
    MAX_CASE_REASONING_LEN,
    MAX_CASE_TITLE_LEN,
    MAX_INCIDENT_REFERENCES,
    MAX_REPORT_REFERENCES,
    ReportReference,
)
from .repository import IncidentRepository
from .service import IncidentService, CentralizedOutcome, authorize_case_access

__all__ = [
    "CASE_STATE_CENTRALIZED_FAILED",
    "CASE_STATE_CENTRALIZED_PENDING",
    "CASE_STATE_CLOSED",
    "CASE_STATE_OPEN",
    "CASE_STATE_REPORT_PENDING",
    "CaseAccessDeniedError",
    "CaseEvidenceError",
    "CaseNotFoundError",
    "CentralizedOutcome",
    "Incident",
    "IncidentError",
    "IncidentEvidence",
    "IncidentLifecycleState",
    "IncidentRepository",
    "IncidentService",
    "InvalidIncidentInputError",
    "LifecycleTransition",
    "MAX_CASE_LIFECYCLE_HISTORY",
    "MAX_CASE_REASONING_LEN",
    "MAX_CASE_TITLE_LEN",
    "MAX_INCIDENT_REFERENCES",
    "MAX_REPORT_REFERENCES",
    "ReportReference",
    "authorize_case_access",
]