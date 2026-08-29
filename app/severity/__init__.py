"""ProShield severity / confidence engine (Phase 4.6).

The severity / confidence engine is the dedicated
preliminary-triage component sitting between the
Phase 4.5 correlation engine and the future Phase 4.7
incident engine. It is responsible for producing one
SeverityAssessment + one ConfidenceAssessment per
subject (per-event Detection, cross-event Correlation),
plus a single bundle-level assessment covering the
whole evidence set.

Reference:
    docs/PHASE 2/DOMAIN_DATA_MODEL.md, Sections 10 and 11.
    docs/PHASE 0/MVP_REQUIREMENTS.md, Section 5.
    docs/PHASE 0/PRODUCT_SCOPE.md, Section 9.
    docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
    Section 66.

What this layer DOES
--------------------

* Define the SeverityBand, ConfidenceBand, ScoringSignal,
  ScoringRationale, SeverityAssessment, ConfidenceAssessment,
  and SeverityResult contracts.
* Define the SeverityEngine - a deterministic, total,
  in-memory scoring engine that consumes a stream of
  Detection and Correlation records (plus an optional
  events lookup for evidence-completeness checks) and
  produces a SeverityResult.

What this layer DOES NOT do
---------------------------

* It does NOT call into the correlation, detection, or
  timeline engines. It only reads what the caller
  supplies.
* It does NOT assign incident category, routing, or
  report content. Those are the future incident /
  routing / report engines' jobs.
* It does NOT call out to pymongo, FastAPI, the network,
  or any connector. It is pure in-memory scoring.
* It does NOT carry hidden state across calls.
* It does NOT use AI, ML, or statistical inference.
"""
from __future__ import annotations

from .engine import (
    SeverityEngine,
    THRESHOLD_CORRELATION_REPEATED,
    THRESHOLD_DETECTION_COUNT,
    THRESHOLD_EVENT_COUNT,
    THRESHOLD_RULE_REPEATED,
    THRESHOLD_WINDOW_SPAN_SECONDS,
)
from .errors import (
    InvalidSeverityInputError,
    SeverityError,
    SeverityEvidenceError,
)
from .models import (
    MAX_SCORING_RATIONALE_LEN,
    MAX_SCORING_RATIONALS,
    MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN,
    MAX_SEVERITY_EVIDENCE_REFS,
    MAX_SEVERITY_EVIDENCE_REF_LEN,
    MAX_SEVERITY_RESULT_ASSESSMENTS,
    MAX_SEVERITY_RESULT_ERRORS,
    SCORING_SIGNAL_PATTERN,
    Confidence,
    ConfidenceAssessment,
    ConfidenceBand,
    ConfidenceLevel,
    ScoringRationale,
    ScoringSignal,
    Severity,
    SeverityAssessment,
    SeverityAssessmentSubject,
    SeverityBand,
    SeverityLevel,
    SeverityResult,
    confidence_at_least,
    severity_at_least,
)

__all__ = [
    "Confidence",
    "ConfidenceAssessment",
    "ConfidenceBand",
    "ConfidenceLevel",
    "InvalidSeverityInputError",
    "MAX_SCORING_RATIONALE_LEN",
    "MAX_SCORING_RATIONALS",
    "MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN",
    "MAX_SEVERITY_EVIDENCE_REFS",
    "MAX_SEVERITY_EVIDENCE_REF_LEN",
    "MAX_SEVERITY_RESULT_ASSESSMENTS",
    "MAX_SEVERITY_RESULT_ERRORS",
    "SCORING_SIGNAL_PATTERN",
    "ScoringRationale",
    "ScoringSignal",
    "Severity",
    "SeverityAssessment",
    "SeverityAssessmentSubject",
    "SeverityBand",
    "SeverityEngine",
    "SeverityError",
    "SeverityEvidenceError",
    "SeverityLevel",
    "SeverityResult",
    "THRESHOLD_CORRELATION_REPEATED",
    "THRESHOLD_DETECTION_COUNT",
    "THRESHOLD_EVENT_COUNT",
    "THRESHOLD_RULE_REPEATED",
    "THRESHOLD_WINDOW_SPAN_SECONDS",
    "confidence_at_least",
    "severity_at_least",
]
