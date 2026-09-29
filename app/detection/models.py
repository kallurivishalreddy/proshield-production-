"""Detection models: the documented per-event detection result.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 13, 87-91) and
           docs/PHASE 2/DOMAIN_DATA_MODEL.md.

The framework's :class:`app.rules.types.RuleEvaluation` is the
**rule contract** (a single rule's verdict on a single event). The
:class:`Detection` here is the **detection contract**: a
deterministic, immutable, persistence-ready record that a rule
fired on an event, with the rule's version, reasoning, and a
reference to the supporting evidence (the event_id).

The boundary between the two is intentional:

* The rule framework owns ``RuleEvaluation`` and exposes
  ``Rule.evaluate``.
* The detection engine owns ``Detection`` and
  ``DetectionResult``. It is the only place that translates a
  ``RuleEvaluation(matched=True)`` into a ``Detection``.

The contract is small on purpose. DET-07 requires "every Detection
references its rule/version" (we have ``rule_id`` and
``rule_version``). DET-08 requires "every Detection references
supporting evidence" (we have ``event_id`` and ``evidence_refs``).
DET-09..DET-12 are test-coverage requirements, enforced by the
test suite.

A :class:`Detection` is **frozen** (immutable Pydantic model with
``frozen=True``) so it can be safely shared across the detection
engine, the future correlation engine, the future incident engine,
and the persistence layer. A :class:`Detection` is a **fact**,
not a workflow state.

What this module does NOT do
----------------------------

* It does NOT persist detections. The detection engine produces
  them; a future slice owns persistence, indexing, and the
  ``detection_id`` -> document mapping.
* It does NOT assign severity or confidence. Those are documented
  responsibilities of the severity / confidence engine, not the
  per-event detection layer (Section 66).
* It does NOT carry a rule-evaluation's *unmatched* verdict; the
  per-event layer only persists a Detection when a rule matched.
  Unmatched evaluations are the rule's own concern and live in
  ``RuleEvaluation.matched=False``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing_extensions import Annotated

from ..rules.types import MAX_RULE_REASONING_LEN, RuleCategory


# Bounds. Generous but bounded; matches the rule metadata style.
MAX_DETECTION_ID_LEN = 64
MAX_EVIDENCE_REFS = 32
MAX_EVIDENCE_REF_LEN = 128
MAX_DETECTION_RESULT_EVENT_ID = 64


# ----------------------------------------------------------------- id pattern
# A detection_id is a deterministic UUIDv7-format string with a short
# ``det-`` prefix so it is grep-friendly in logs and audit records.
# The UUID part is canonical RFC 9562 UUIDv7 (Section 5.7): 8-4-4-4-12
# lowercase hex with version 7 (the third group's first nibble is 7)
# and variant 8/9/a/b (the fourth group's first nibble).
DETECTION_ID_PATTERN = r"^det-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
DetectionId = Annotated[
    str,
    StringConstraints(
        min_length=36,
        max_length=MAX_DETECTION_ID_LEN,
        pattern=DETECTION_ID_PATTERN,
    ),
]


# ----------------------------------------------------------------- rule id / version
RuleId = Annotated[
    str,
    StringConstraints(min_length=3, max_length=64, pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$"),
]
RuleVersion = Annotated[int, Field(ge=1, le=999_999)]


# ----------------------------------------------------------------- evidence ref
# An evidence ref is an opaque pointer to a piece of evidence that
# supports this detection. In Phase 4.4 the only available evidence
# is the canonical SecurityEvent, so ``event_id`` is the canonical
# evidence ref. A future slice may add further refs (a correlation
# cluster id, an analyst note id, etc.); the field is a list so
# additional evidence is forward-compatible.
EvidenceRef = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVIDENCE_REF_LEN),
]


# ----------------------------------------------------------------- detection
class Detection(BaseModel):
    """A single, deterministic, immutable detection record.

    A ``Detection`` is produced by the detection engine when an
    approved+enabled rule fires on a canonical ``SecurityEvent``.
    The detection engine is the ONLY producer; the rule framework
    returns ``RuleEvaluation`` and the engine translates
    ``matched=True`` evaluations into ``Detection`` instances.

    Invariants
    ----------

    * ``detection_id`` is deterministic for ``(rule_id,
      rule_version, target_event_id)`` and ``detected_at``. The
      engine is responsible for computing it; here we only
      validate the form.
    * ``rule_id`` and ``rule_version`` are pinned from the
      ``RuleEvaluation`` and from the rule's :class:`RuleMetadata`.
    * ``event_id`` equals the supporting event's ``event_id`` and
      also appears in ``evidence_refs`` (DET-08).
    * ``category`` is the rule's metadata category (not derived
      from the event_type).
    * ``detected_at`` is timezone-aware UTC.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    detection_id: DetectionId
    rule_id: RuleId
    rule_version: RuleVersion
    category: RuleCategory
    event_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=64),
    ]
    evidence_refs: Tuple[EvidenceRef, ...]
    reasoning: Annotated[
        str,
        StringConstraints(max_length=MAX_RULE_REASONING_LEN),
    ] = ""
    detected_at: datetime
    extra: Tuple[Tuple[str, Any], ...] = ()
    # Capability patch gap 5: the documented SeverityBand composed by
    # the SeverityEngine at persistence time. Empty = not composed
    # (the wire renders null; the UI renders UNRATED — never a
    # fabricated band).
    severity: Annotated[str, StringConstraints(max_length=32)] = ""
    # Capability patch gap 5: the provenance pointer of the source
    # instance that ingested the supporting event (from
    # ``event.provenance.source_instance_id``). Empty when the event
    # was ingested without source-management.
    source_instance_id: Annotated[
        str, StringConstraints(max_length=96)
    ] = ""
    # Capability patch gap 2: allocator-assigned human id
    # (``DET-000001``), assigned at persistence time. Note: this field
    # is NOT part of the ``detection_id`` derivation, so replay
    # determinism of the technical id is untouched.
    human_id: Annotated[str, StringConstraints(max_length=32)] = ""
    # Phase 5.2 (§8, §12): the capability that owned the evidence this
    # detection fired on. Stamped from the supporting SecurityEvent's
    # **server-derived** ``provenance.capability_id`` — never from a
    # caller-supplied field — so a detection can never claim a capability
    # that did not actually produce the evidence. Empty means the
    # supporting event carried no derived capability (an event ingested
    # outside the binding-aware ingress, or pre-5.2 history); the wire
    # renders ``null`` and the UI renders it truthfully rather than
    # guessing. Like ``human_id`` and ``source_instance_id``, this field
    # is NOT part of the ``detection_id`` derivation, so detection-id
    # determinism is untouched.
    capability_id: Annotated[
        str, StringConstraints(max_length=64, pattern=r"^$|^cap-[a-z][a-z0-9-]{1,47}$")
    ] = ""

    @property
    def evidence(self) -> List[str]:
        """Convenience: ``evidence_refs`` as a list (read-only)."""
        return list(self.evidence_refs)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready, BSON-safe representation."""
        return {
            "detection_id": self.detection_id,
            "human_id": self.human_id or None,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "category": self.category.value,
            "event_id": self.event_id,
            "evidence_refs": list(self.evidence_refs),
            "reasoning": self.reasoning,
            "severity": self.severity or None,
            "source_instance_id": self.source_instance_id or None,
            "capability_id": self.capability_id or None,
            "detected_at": self.detected_at.isoformat(),
            "extra": dict(self.extra),
        }


# ----------------------------------------------------------------- result
class DetectionResult(BaseModel):
    """The deterministic, per-event detection output.

    A :class:`DetectionResult` is what the
    :class:`app.detection.engine.DetectionEngine` returns. It is
    the documented "create detections" output of the selection
    pipeline (Section 12, Section 13). It contains:

    * ``event_id`` -- the supporting event the engine ran on.
    * ``detections`` -- the list of :class:`Detection` objects
      produced by the engine. Empty if no applicable rule matched.
    * ``rules_considered`` -- the number of evaluable rules the
      engine actually evaluated against the event. This is the
      "did the engine skip irrelevant rules" observability
      signal (DET-04).
    * ``rules_evaluated`` -- the number of rules the engine
      called ``.evaluate`` on. (Equal to ``rules_considered`` in
      Phase 4.4; the distinction is forward-compatible for a
      future short-circuit / partial-evaluation optimisation.)
    * ``errors`` -- rule-evaluation errors. A single rule
      misbehaving must NOT block the others; the engine catches
      :class:`app.rules.rule.RuleEvaluationError` and routes it
      into ``errors`` so the rest of the rules still produce
      their detections. The detection is **fail-closed per rule
      but not per pipeline**: the per-event pipeline is total.
    * ``produced_at`` -- the time the result was produced.
      Injected by the engine; deterministic when ``now`` is
      injected.

    A :class:`DetectionResult` is **frozen** and a **fact** about
    a single canonical event. The detection engine does not
    accumulate results across events; cross-event state is the
    correlation engine's concern (a later slice).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    event_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_DETECTION_RESULT_EVENT_ID),
    ]
    detections: Tuple[Detection, ...] = ()
    rules_considered: Annotated[int, Field(ge=0, le=10_000)] = 0
    rules_evaluated: Annotated[int, Field(ge=0, le=10_000)] = 0
    errors: Tuple[str, ...] = ()
    produced_at: datetime

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "detections": [d.to_dict() for d in self.detections],
            "rules_considered": self.rules_considered,
            "rules_evaluated": self.rules_evaluated,
            "errors": list(self.errors),
            "produced_at": self.produced_at.isoformat(),
        }

