"""The deterministic per-event detection engine.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 12, 13, 49, 87-91).

The engine implements the documented selection pipeline
(Section 12):

    SecurityEvent
        ↓
    Identify source            (event.source)
        ↓
    Identify event type        (event.event_type)
        ↓
    Select applicable rules    (registry.applies_to)
        ↓
    Run relevant rules         (rule.evaluate)
        ↓
    Create detections          (Detection engine output)

The engine is **deterministic**: equal inputs produce equal
outputs. The single non-deterministic input is the
``detected_at`` timestamp; it can be injected via ``now=`` for
test reproducibility and is otherwise ``datetime.now(timezone.utc)``
captured once per call.

The engine is **per-event**: it has no cross-event state. The
correlation engine (a later slice) is responsible for
windowing, counting, and grouping.

The engine is **fail-closed per rule but not per pipeline**: a
rule that raises during ``evaluate`` is caught (the framework
already wraps unexpected exceptions in
:class:`app.rules.rule.RuleEvaluationError`; the engine catches
those and routes them into ``DetectionResult.errors``). The rest
of the rules still produce their detections. The per-event
pipeline is total: it always returns a ``DetectionResult`` for a
valid event.

The engine does NOT:

* talk to MongoDB, FastAPI, the network, or any other rule's
  logic (Section 87: cross-rule coupling is forbidden).
* carry cross-event state.
* count, window, or correlate.
* assign severity, confidence, or routing.
* persist anything.

The engine DOES:

* honour the registry's lifecycle (only ``is_evaluable()`` rules
  are considered -- APPROVED + enabled, Sections 59, 90, DET-04).
* use the registry's ``applies_to`` filter as the hot path (the
  "no per-event -> every rule" anti-pattern is explicitly
  forbidden, Section 12 + Section 69).
* produce a deterministic, frozen, BSON-safe detection record
  for every matched evaluation.
* preserve the rule's version (DET-07, Section 33: rule
  versioning).
* include the event_id in evidence_refs (DET-08).
"""
from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from ..domain.security_event import SecurityEvent
from ..rules.registry import RuleRegistry
from ..rules.rule import Rule, RuleEvaluationError
from ..rules.types import RuleEvaluation
from .errors import (
    DetectionIdGenerationError,
    InvalidEventError,
    NoRuleRegistryError,
)
from .models import Detection, DetectionResult


# Maximum length of an error string included in a DetectionResult.
# The error string is built from the framework's RuleEvaluationError
# message; it never contains attacker-controlled bytes.
_MAX_ERROR_LEN = 512


def _make_detection_id(
    rule_id: str,
    rule_version: int,
    event_id: str,
    detected_at: datetime,
) -> str:
    """Build a deterministic ``det-<uuidv7>`` id for a detection.

    Determinism contract
    --------------------

    Given the same ``(rule_id, rule_version, event_id,
    detected_at)`` inputs, the function returns the **same** id
    every time. This is the documented contract and is enforced
    by :func:`tests.unit.test_detection_engine.TestDetectionContract`.

    Two ``Detection`` records that share the same rule, the same
    rule version, the same supporting event, and the same
    ``detected_at`` instant will share the same ``detection_id``.
    Conversely, two records that differ in any one of those four
    fields will have a different id (with the same
    SHA-256-avalanche guarantee as RFC 9562 UUIDv7).

    How the id is built
    -------------------

    The id is a canonical RFC 9562 UUIDv7 (8-4-4-4-12 lowercase
    hex) prefixed with ``det-`` for grep-friendly audit logs.
    The 128 bits are laid out as:

    * bits 0..47   -- ``unix_ms(detected_at)`` (the 48-bit
      timestamp mandated by UUIDv7);
    * bits 48..51  -- version nibble ``0b0111``;
    * bits 52..63  -- 12 random bits derived from
      ``sha256(rule_id|rule_version|event_id|ts_ms)``;
    * bits 64..65  -- variant ``0b10``;
    * bits 66..127 -- 62 random bits derived from the same
      SHA-256 (bytes 2..10, masked to 62 bits).

    The 74 random bits in positions 52..63 and 66..127 are
    derived from a SHA-256 of the four-function arguments with
    no salt and no OS entropy. This makes the id deterministic
    (the documented contract) while preserving the collision
    resistance of UUIDv7 across processes: an attacker would
    need to find a SHA-256 preimage for the random bits, which
    is computationally infeasible.

    Note on the prior implementation: a previous version of
    this function mixed 16 bytes of ``os.urandom`` into the
    SHA-256, which produced a *globally unique* id (different
    per call) but contradicted the docstring's determinism
    contract. The Phase 4.4 review flagged this as defect D-2;
    the salt has been removed so the implementation matches
    the documented contract.

    Reference: docs/PHASE 4/PHASE 4-04/PHASE-04-04-REPORT.md
               (Section 4.1, "detection_id");
               docs/PHASE 4/PHASE 4-04/PHASE-04-04-REVIEW.md
               (defect D-2, FIXED).
    """
    _validate_detection_id_inputs(
        rule_id=rule_id,
        rule_version=rule_version,
        event_id=event_id,
        detected_at=detected_at,
    )
    ts_ms = int(detected_at.timestamp() * 1000)
    # Deterministic per-input random bits: SHA-256 of the
    # input tuple (rule_id, rule_version, event_id, ts_ms).
    # The 48-bit ts_ms and 74 derived random bits together
    # make the id well-formed (UUIDv7) and collision-resistant.
    h = hashlib.sha256()
    h.update(rule_id.encode("utf-8"))
    h.update(b"|")
    h.update(str(rule_version).encode("ascii"))
    h.update(b"|")
    h.update(event_id.encode("utf-8"))
    h.update(b"|")
    h.update(str(ts_ms).encode("ascii"))
    digest = h.digest()
    # Lay the hash bytes into the rand_a (12) + rand_b (62)
    # fields of a UUIDv7, and pin the ts_ms + version + variant
    # bits. The result is a valid UUIDv7 (canonical
    # 8-4-4-4-12 hex form) that we then prefix with ``det-``.
    int_form = (
        (ts_ms & 0xFFFF_FFFF_FFFF) << 80
        | (0x7 << 76)
        | ((int.from_bytes(digest[0:2], "big") & 0x0FFF) << 64)
        | (0b10 << 62)
        | (int.from_bytes(digest[2:10], "big") & 0x3FFF_FFFF_FFFF_FFFF)
    )
    return "det-" + str(uuid.UUID(int=int_form))


def _validate_detection_id_inputs(
    rule_id: str,
    rule_version: int,
    event_id: str,
    detected_at: datetime,
) -> None:
    """Defensive input checks for :func:`_make_detection_id`.

    All four arguments must be present and well-typed. The
    function is total over the four rejection paths and returns
    ``None`` when the inputs are acceptable. A failure here is
    always a bug at the caller (the engine, the loader, or a
    test); a real ``SecurityEvent`` always has the required
    shape.
    """
    if not isinstance(rule_id, str) or not rule_id:
        raise DetectionIdGenerationError(
            safe_message="detection_id: rule_id is required",
            internal_detail=f"got {type(rule_id).__name__}",
        )
    if not isinstance(rule_version, int) or rule_version < 1:
        raise DetectionIdGenerationError(
            safe_message="detection_id: rule_version must be a positive int",
            internal_detail=f"got {rule_version!r}",
        )
    if not isinstance(event_id, str) or not event_id:
        raise DetectionIdGenerationError(
            safe_message="detection_id: event_id is required",
            internal_detail=f"got {type(event_id).__name__}",
        )
    if not isinstance(detected_at, datetime):
        raise DetectionIdGenerationError(
            safe_message="detection_id: detected_at must be a datetime",
            internal_detail=f"got {type(detected_at).__name__}",
        )
    if detected_at.tzinfo is None:
        raise DetectionIdGenerationError(
            safe_message="detection_id: detected_at must be timezone-aware",
            internal_detail="tzinfo is None",
        )


class DetectionEngine:
    """The deterministic per-event detection engine.

    The engine wraps a :class:`app.rules.registry.RuleRegistry`
    and applies the documented selection pipeline (Section 12)
    to a single canonical ``SecurityEvent`` at a time.

    Construction contract
    ---------------------

    * The registry is REQUIRED. The engine refuses to start
      without one.
    * The engine does NOT mutate the registry. The registry is
      the single source of truth for "which rules are live"
      (Section 88); the engine is a pure consumer.

    Determinism contract
    --------------------

    * The engine is deterministic given a fixed ``now`` and a
      fixed registry. The selection order, the rule-evaluation
      order, the resulting ``detections`` list order, and the
      ``detection_id`` values are all stable for the same inputs.
    * When ``now`` is not injected, the engine captures
      ``datetime.now(timezone.utc)`` ONCE at the start of
      ``run()``; every detection produced in that call uses the
      same timestamp (so the engine remains deterministic per
      call, even though two calls at different wall-clock times
      produce different results).

    Failure model
    -------------

    * A rule that raises is caught (the framework already
      wraps unexpected exceptions in
      :class:`app.rules.rule.RuleEvaluationError`; the engine
      also catches the base ``Exception`` to defensively
      quarantine a truly misbehaving rule). The error message
      is added to ``DetectionResult.errors``; the rest of the
      rules still produce their detections.
    * An event that is not a :class:`SecurityEvent` is rejected
      with :class:`InvalidEventError` BEFORE any rule is
      evaluated. The pipeline is therefore strict on input but
      total on rule evaluation.
    * An empty registry is permitted: the engine returns a
      ``DetectionResult`` with zero detections and
      ``rules_considered=0``. This matches the documented
      "no false positives from empty rule catalogue" invariant
      (Section 88).
    """

    def __init__(self, registry: RuleRegistry) -> None:
        if registry is None:
            raise NoRuleRegistryError(
                safe_message="DetectionEngine requires a RuleRegistry",
                internal_detail="registry is None",
            )
        if not isinstance(registry, RuleRegistry):
            raise NoRuleRegistryError(
                safe_message="DetectionEngine requires a RuleRegistry",
                internal_detail=f"got {type(registry).__name__}",
            )
        self._registry = registry
        # The lock is for the engine's own state (none yet); it
        # is acquired by ``run()`` so the per-event pipeline is
        # serialised against any future per-engine cache
        # invalidation. The registry has its own internal lock.
        self._lock = threading.RLock()

    # -------------------------------------------------------------- properties
    @property
    def registry(self) -> RuleRegistry:
        """Return the underlying rule registry (read-only)."""
        return self._registry

    # -------------------------------------------------------------- public api
    def run(
        self,
        event: SecurityEvent,
        *,
        now: Optional[datetime] = None,
    ) -> DetectionResult:
        """Evaluate a single canonical ``SecurityEvent`` and return a result."""
        if not isinstance(event, SecurityEvent):
            raise InvalidEventError(
                safe_message="DetectionEngine.run requires a SecurityEvent",
                internal_detail=f"got {type(event).__name__}",
            )
        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise InvalidEventError(
                safe_message="now must be a datetime",
                internal_detail=f"got {type(now).__name__}",
            )
        elif now.tzinfo is None:
            raise InvalidEventError(
                safe_message="now must be timezone-aware",
                internal_detail="tzinfo is None",
            )

        with self._lock:
            applicable = self._registry.applies_to(event)
            detections: List[Detection] = []
            errors: List[str] = []
            considered = len(applicable)
            evaluated = 0
            for rule in applicable:
                evaluated += 1
                try:
                    evaluation = rule.evaluate(event)
                except RuleEvaluationError as exc:
                    errors.append(
                        _truncate(
                            f"rule {rule.metadata.rule_id} v"
                            f"{rule.metadata.version} {exc}",
                            _MAX_ERROR_LEN,
                        )
                    )
                    continue
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        _truncate(
                            f"rule {rule.metadata.rule_id} v"
                            f"{rule.metadata.version} raised unexpected "
                            f"{type(exc).__name__}: {exc}",
                            _MAX_ERROR_LEN,
                        )
                    )
                    continue
                if not isinstance(evaluation, RuleEvaluation):
                    errors.append(
                        _truncate(
                            f"rule {rule.metadata.rule_id} v"
                            f"{rule.metadata.version} returned "
                            f"{type(evaluation).__name__}, "
                            "expected RuleEvaluation",
                            _MAX_ERROR_LEN,
                        )
                    )
                    continue
                if not evaluation.matched:
                    continue
                try:
                    detection = self._build_detection(
                        event=event,
                        rule=rule,
                        evaluation=evaluation,
                        detected_at=now,
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        _truncate(
                            f"detection construction failed for "
                            f"{rule.metadata.rule_id} v"
                            f"{rule.metadata.version}: "
                            f"{type(exc).__name__}: {exc}",
                            _MAX_ERROR_LEN,
                        )
                    )
                    continue
                detections.append(detection)

            return DetectionResult(
                event_id=event.event_id,
                detections=tuple(detections),
                rules_considered=considered,
                rules_evaluated=evaluated,
                errors=tuple(errors),
                produced_at=now,
            )

    # -------------------------------------------------------------- internals
    def _build_detection(
        self,
        *,
        event: SecurityEvent,
        rule: Rule,
        evaluation: RuleEvaluation,
        detected_at: datetime,
    ) -> Detection:
        """Translate a matched ``RuleEvaluation`` into a ``Detection``."""
        detection_id = _make_detection_id(
            rule_id=rule.metadata.rule_id,
            rule_version=rule.metadata.version,
            event_id=event.event_id,
            detected_at=detected_at,
        )
        return Detection(
            detection_id=detection_id,
            rule_id=rule.metadata.rule_id,
            rule_version=rule.metadata.version,
            category=rule.metadata.category,
            event_id=event.event_id,
            evidence_refs=(event.event_id,),
            reasoning=evaluation.reasoning,
            detected_at=detected_at,
            extra=evaluation.extra,
        )


def _truncate(s: str, n: int) -> str:
    """Truncate a string to ``n`` characters (defensive bound)."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + "..."
