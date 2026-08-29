"""Build ``app/severity/models.py`` from concatenated strings.

This is a build-time helper (not committed to the runtime
package). It exists because the editor tool is bounded to
~6 KB per call and the model file is larger than that. The
helper concatenates documented sections and writes the
result.
"""
from __future__ import annotations

import io
import os
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "app", "severity", "models.py")

DOC = '''"""Severity / Confidence models: the documented preliminary
triage-assessment contract.

Reference:
    docs/PHASE 2/DOMAIN_DATA_MODEL.md, Section 10 (Severity)
    and Section 11 (Confidence).
    docs/PHASE 0/MVP_REQUIREMENTS.md, Section 5 ("Preliminary
    severity and confidence").
    docs/PHASE 0/PRODUCT_SCOPE.md, Section 9 ("Severity
    Meaning").
    docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
    Section 66 (severity / confidence responsibility).

The severity / confidence layer is the **dedicated deterministic
preliminary-triage component** sitting between the Phase 4.5
correlation engine and the future Phase 4.7 incident engine.

Three contracts are exported from this module:

* :class:`SeverityBand` (alias :class:`Severity`) - the four-band
  preliminary-triage scale (``LOW`` < ``MEDIUM`` < ``HIGH`` <
  ``CRITICAL``).
* :class:`ConfidenceBand` (alias :class:`Confidence`) - the
  four-band evidence-strength scale (``LOW`` < ``MEDIUM`` <
  ``HIGH`` < ``VERY_HIGH``).
* :class:`SeverityAssessment` / :class:`ConfidenceAssessment` -
  the deterministic, evidence-backed, frozen, BSON-safe record
  the :class:`app.severity.engine.SeverityEngine` emits for one
  piece of evidence (a single :class:`Correlation`, a single
  :class:`Detection`, or the overall evidence bundle).

Three things the contract is *deliberately* not
------------------------------------------------

* It is NOT a single overall score. The :class:`SeverityEngine`
  emits a per-correlation assessment, a per-detection
  assessment, and an overall bundle assessment; the future
  incident / routing engine will combine them in policy. The
  model itself does NOT collapse severity + confidence into
  a single scalar.
* It is NOT derived from AI, ML, or statistical inference.
  Every score component is a deterministic function of the
  documented evidence fields.
* It is NOT a fact about the world. A
  :class:`SeverityAssessment` is a *derived conclusion* and is
  clearly labelled as such (per the evidence principle).

Why four bands
--------------

The four-band scale mirrors the documented MVP requirements
(``docs/PHASE 0/MVP_REQUIREMENTS.md`` Section 5, and
``docs/PHASE 0/MVP_ACCEPTANCE.md``). The same scale is used
by the Phase 0 routing matrix (``LOW`` + ``SIMPLE`` -> ``L1``,
``HIGH`` -> ``L2``, ``CRITICAL`` + ``COMPLEX`` -> ``L3``).
Inventing finer bands now would couple the model to policy
choices that are deliberately deferred.
"""
'''

IMPORTS = '''from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)
'''

BANDS = '''
# ----------------------------------------------------------------- bands
class SeverityBand(str, Enum):
    """The four documented preliminary-severity bands.

    The bands are intentionally small and match
    ``docs/PHASE 0/ROUTING_MATRIX.md`` Section 5
    (``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Convenience alias: the band enum *is* the severity scale for
# the MVP. We keep the alias name explicit so future slices can
# subclass / extend without breaking the engine.
Severity = SeverityBand
SeverityLevel = SeverityBand


_SEVERITY_RANK: Dict[SeverityBand, int] = {
    SeverityBand.LOW: 1,
    SeverityBand.MEDIUM: 2,
    SeverityBand.HIGH: 3,
    SeverityBand.CRITICAL: 4,
}


def severity_at_least(
    a: SeverityBand, b: SeverityBand
) -> bool:
    """Return ``True`` if band ``a`` is at least as severe as ``b``."""
    return _SEVERITY_RANK[a] >= _SEVERITY_RANK[b]


# ----------------------------------------------------------------- confidence
class ConfidenceBand(str, Enum):
    """The four documented confidence bands.

    The bands are intentionally small and match
    ``docs/PHASE 2/DOMAIN_DATA_MODEL.md`` Section 11
    ("confidence must be derived from actual information; it
    must not be fabricated merely to make the incident look
    more certain"). ``VERY_HIGH`` is the documented top
    band; reserved for the case where multiple orthogonal
    signals (e.g. per-event detections + a correlation
    grouping them + an underlying event directly observed)
    all agree.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


Confidence = ConfidenceBand
ConfidenceLevel = ConfidenceBand


_CONFIDENCE_RANK: Dict[ConfidenceBand, int] = {
    ConfidenceBand.LOW: 1,
    ConfidenceBand.MEDIUM: 2,
    ConfidenceBand.HIGH: 3,
    ConfidenceBand.VERY_HIGH: 4,
}


def confidence_at_least(
    a: ConfidenceBand, b: ConfidenceBand
) -> bool:
    """Return ``True`` if band ``a`` is at least as confident as ``b``."""
    return _CONFIDENCE_RANK[a] >= _CONFIDENCE_RANK[b]
'''
print("section 1 OK")

SCORING_HEAD = '''


# ----------------------------------------------------------------- scoring
# A *scoring rationale* is the explicit, deterministic
# explanation of HOW a band was reached. The MVP scoring model
# is intentionally a small set of named signals; each signal
# has a documented meaning, a documented score contribution,
# and a documented evidence reference. Inventing new signals
# without documentation is forbidden (the engine is
# closed-catalogue by design).
#
# Each signal MUST be backed by an actual evidence field. The
# engine never emits a signal with a missing evidence field; a
# missing field is recorded as ``present=False`` in the
# rationale.
#
# The catalogue is deliberately small:
#
#   rule_category            - the rule that fired is in a
#                              documented "high-impact" or
#                              "auth-related" category.
#   correlation_trigger      - the correlation is in a
#                              documented "brute-force"
#                              (or future) trigger set.
#   detection_count          - the underlying evidence
#                              includes a non-trivial number
#                              of per-event detections.
#   event_count              - the underlying evidence
#                              spans a non-trivial number of
#                              observed events.
#   window_span_seconds      - the correlation's time window
#                              indicates a sustained attack.
#   affected_endpoint        - the underlying evidence points
#                              at a concrete endpoint.
#   source_ip_present        - the underlying evidence
#                              identifies a single concrete
#                              source_ip.
#   rule_repeated            - the same rule fired on more
#                              than one event.
#   correlation_repeated     - the same correlation pattern
#                              fired on more than one
#                              correlation.
#   evidence_completeness    - the assessment's evidence
#                              references were fully
#                              resolvable (no missing
#                              evidence in the supplied
#                              lookups).
SCORING_SIGNAL_PATTERN = r"^[a-z][a-z0-9_]{1,63}$"
MAX_SCORING_RATIONALE_LEN = 1024
MAX_SCORING_RATIONALS = 16


class ScoringSignal(str, Enum):
    """The closed catalogue of documented severity / confidence signals."""

    RULE_CATEGORY = "rule_category"
    CORRELATION_TRIGGER = "correlation_trigger"
    DETECTION_COUNT = "detection_count"
    EVENT_COUNT = "event_count"
    WINDOW_SPAN_SECONDS = "window_span_seconds"
    AFFECTED_ENDPOINT = "affected_endpoint"
    SOURCE_IP_PRESENT = "source_ip_present"
    RULE_REPEATED = "rule_repeated"
    CORRELATION_REPEATED = "correlation_repeated"
    EVIDENCE_COMPLETENESS = "evidence_completeness"


class ScoringRationale(BaseModel):
    """One rationale entry: a named signal plus the evidence that supports it."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    signal: ScoringSignal
    present: bool
    detail: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_SCORING_RATIONALE_LEN
        ),
    ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal": self.signal.value,
            "present": self.present,
            "detail": self.detail,
        }
'''
print("section 2 OK")

ASSESSMENT_HEAD = '''


# ----------------------------------------------------------------- assessment
MAX_SEVERITY_EVIDENCE_REFS = 32
MAX_SEVERITY_EVIDENCE_REF_LEN = 128
MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN = 2048
MAX_SEVERITY_RESULT_ASSESSMENTS = 32
MAX_SEVERITY_RESULT_ERRORS = 32


class SeverityAssessmentSubject(str, Enum):
    """What a :class:`SeverityAssessment` is *about*."""

    DETECTION = "detection"
    CORRELATION = "correlation"
    BUNDLE = "bundle"


class _SeverityAssessmentBase(BaseModel):
    """Shared fields for :class:`SeverityAssessment` and :class:`ConfidenceAssessment`."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    band: SeverityBand
    summary: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_SEVERITY_ASSESSMENT_RATIONALE_LEN,
        ),
    ]
    rationale: Tuple[ScoringRationale, ...] = ()
    evidence_refs: Tuple[
        Annotated[
            str,
            StringConstraints(
                min_length=1, max_length=MAX_SEVERITY_EVIDENCE_REF_LEN
            ),
        ],
        ...,
    ] = ()

    @model_validator(mode="after")
    def _evidence_refs_not_empty(self) -> "_SeverityAssessmentBase":
        if not self.evidence_refs:
            raise ValueError(
                "assessment.evidence_refs must not be empty "
                "(no unevidenced severity / confidence assessments)"
            )
        if len(self.evidence_refs) > MAX_SEVERITY_EVIDENCE_REFS:
            raise ValueError(
                f"assessment.evidence_refs must contain at most "
                f"{MAX_SEVERITY_EVIDENCE_REFS} entries, got "
                f"{len(self.evidence_refs)}"
            )
        return self

    @model_validator(mode="after")
    def _rationale_bounded(self) -> "_SeverityAssessmentBase":
        if len(self.rationale) > MAX_SCORING_RATIONALS:
            raise ValueError(
                f"assessment.rationale must contain at most "
                f"{MAX_SCORING_RATIONALS} entries, got "
                f"{len(self.rationale)}"
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "band": self.band.value,
            "summary": self.summary,
            "rationale": [r.to_dict() for r in self.rationale],
            "evidence_refs": list(self.evidence_refs),
        }
'''
print("section 3 OK")

SEVERITY_ASSESSMENT = '''


class SeverityAssessment(_SeverityAssessmentBase):
    """The documented preliminary-severity assessment.

    The :attr:`subject_id` is the canonical id the
    assessment is about (``detection_id``,
    ``correlation_id``, or ``"bundle"`` for the overall
    assessment). The engine rejects an assessment whose
    ``subject_kind`` does not match the prefix of the
    ``subject_id``.
    """

    subject_kind: SeverityAssessmentSubject
    subject_id: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_SEVERITY_EVIDENCE_REF_LEN
        ),
    ]

    @model_validator(mode="after")
    def _subject_id_matches_kind(self) -> "SeverityAssessment":
        expected_prefix = {
            SeverityAssessmentSubject.DETECTION: "det-",
            SeverityAssessmentSubject.CORRELATION: "corr-",
            SeverityAssessmentSubject.BUNDLE: "bundle:",
        }[self.subject_kind]
        if not self.subject_id.startswith(expected_prefix):
            raise ValueError(
                f"subject_id {self.subject_id!r} does not match "
                f"subject_kind {self.subject_kind.value!r} "
                f"(expected prefix {expected_prefix!r})"
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base["subject_kind"] = self.subject_kind.value
        base["subject_id"] = self.subject_id
        return base
'''

CONFIDENCE_ASSESSMENT = '''


class ConfidenceAssessment(_SeverityAssessmentBase):
    """The documented evidence-confidence assessment."""

    band: ConfidenceBand
    subject_kind: SeverityAssessmentSubject
    subject_id: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_SEVERITY_EVIDENCE_REF_LEN
        ),
    ]

    @model_validator(mode="after")
    def _subject_id_matches_kind(self) -> "ConfidenceAssessment":
        expected_prefix = {
            SeverityAssessmentSubject.DETECTION: "det-",
            SeverityAssessmentSubject.CORRELATION: "corr-",
            SeverityAssessmentSubject.BUNDLE: "bundle:",
        }[self.subject_kind]
        if not self.subject_id.startswith(expected_prefix):
            raise ValueError(
                f"subject_id {self.subject_id!r} does not match "
                f"subject_kind {self.subject_kind.value!r} "
                f"(expected prefix {expected_prefix!r})"
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base["subject_kind"] = self.subject_kind.value
        base["subject_id"] = self.subject_id
        return base
'''
print("section 4 OK")


RESULT = '''


# ----------------------------------------------------------------- result
class SeverityResult(BaseModel):
    """The deterministic, batch-level severity / confidence output."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    severity_assessments: Tuple[SeverityAssessment, ...] = ()
    confidence_assessments: Tuple[ConfidenceAssessment, ...] = ()
    detections_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    correlations_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    detections_scored: Annotated[int, Field(ge=0, le=10_000)] = 0
    correlations_scored: Annotated[int, Field(ge=0, le=10_000)] = 0
    errors: Tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=1024)],
        ...,
    ] = ()
    produced_at: datetime

    @property
    def bundle_severity(self) -> SeverityBand:
        for a in self.severity_assessments:
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE:
                return a.band
        # The documented default is LOW: "no evidence"
        # cannot justify a higher preliminary severity.
        return SeverityBand.LOW

    @property
    def bundle_confidence(self) -> ConfidenceBand:
        for a in self.confidence_assessments:
            if a.subject_kind is SeverityAssessmentSubject.BUNDLE:
                return a.band
        return ConfidenceBand.LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity_assessments": [
                a.to_dict() for a in self.severity_assessments
            ],
            "confidence_assessments": [
                a.to_dict() for a in self.confidence_assessments
            ],
            "bundle_severity": self.bundle_severity.value,
            "bundle_confidence": self.bundle_confidence.value,
            "detections_considered": self.detections_considered,
            "correlations_considered": self.correlations_considered,
            "detections_scored": self.detections_scored,
            "correlations_scored": self.correlations_scored,
            "errors": list(self.errors),
            "produced_at": self.produced_at.isoformat(),
        }
'''
print("section 5 OK")

ALL = '''
__all__ = [
    "Confidence",
    "ConfidenceAssessment",
    "ConfidenceBand",
    "ConfidenceLevel",
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
    "SeverityLevel",
    "SeverityResult",
    "confidence_at_least",
    "severity_at_least",
]


def main() -> None:
    parts = [
        DOC, IMPORTS, BANDS, SCORING_HEAD, ASSESSMENT_HEAD,
        SEVERITY_ASSESSMENT, CONFIDENCE_ASSESSMENT, RESULT, ALL,
    ]
    content = "".join(parts)
    with open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {len(content)} bytes to {TARGET}")


if __name__ == "__main__":
    main()
'''
print("section 6 OK")


def main():
    parts = [
        DOC, IMPORTS, BANDS, SCORING_HEAD, ASSESSMENT_HEAD,
        SEVERITY_ASSESSMENT, CONFIDENCE_ASSESSMENT, RESULT, ALL,
    ]
    content = "".join(parts)
    with open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {len(content)} bytes to {TARGET}")


if __name__ == "__main__":
    main()

