"""Rule domain types: category, state, version, metadata, evaluation result.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md (Sections 8, 9,
10, 11, 59, 87-91) and docs/PHASE 2/DOMAIN_DATA_MODEL.md (Section 5).

These types are the **contract surface** between the rule framework and
every higher layer. They are intentionally small, immutable, and
dependency-free (only Pydantic + the canonical ``SecurityEvent``
envelope). The rule implementation slice does not depend on pymongo,
FastAPI, or any other runtime infra.

Design rules:

* **No side effects in constructors.** All fields are validated and
  frozen at construction time.
* **No silent extension.** ``extra="forbid"`` so future drift is
  visible.
* **No detection happens here.** A ``RuleEvaluation`` is the *contract*
  of what a rule returns; the engine that creates ``Detection`` objects
  from these evaluations is a later slice.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from typing_extensions import Annotated

from ..domain.security_event import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SOURCES,
    SecurityEvent,
)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
# These bounds follow the documented "rule metadata stays consistent with
# the canonical event envelope" principle (DETECTION_ENGINEERING Section 90)
# and are intentionally generous but bounded.
MAX_RULE_ID_LEN = 64
MAX_RULE_NAME_LEN = 128
MAX_RULE_DESCRIPTION_LEN = 1024
MAX_RULE_VERSION_DIGITS = 6  # 999_999 is plenty
MAX_RULE_CATEGORY_LEN = 32
MAX_RULE_TAGS = 16
MAX_RULE_TAG_LEN = 64
MAX_RULE_REFERENCES = 16
MAX_RULE_REFERENCE_LEN = 512
MAX_RULE_REASONING_LEN = 2048
MAX_RULE_EVAL_TARGETS = 256  # bound the size of an evaluation result

# Documented source / event-type catalogues are used as the authoritative
# vocabulary for applicability metadata (Section 88).
MAX_SOURCES_PER_RULE = 16
MAX_EVENT_TYPES_PER_RULE = 16


# ---------------------------------------------------------------------------
# Rule ID and version
# ---------------------------------------------------------------------------
# ``rule_id`` follows the documented form
# ``[CATEGORY-PREFIX-]NAME`` (DETECTION_ENGINEERING §10 / §88). The
# allowed character set is a strict subset so a rule_id can be used
# safely as a registry key, a Mongo document field, and in audit logs.
RuleId = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=MAX_RULE_ID_LEN,
        # Each segment: 1+ uppercase letters followed by optional
        # uppercase letters/digits, OR 1+ digits. This allows the
        # documented WAF-001 / AUTH-BRUTEFORCE-7 / CORR-WEB-001
        # forms and rejects lowercase, underscores, spaces, etc.
        pattern=r"^([A-Z][A-Z0-9]*|[0-9]+)(-([A-Z][A-Z0-9]*|[0-9]+))*$",
    ),
]
RuleVersion = Annotated[
    int,
    Field(ge=1, le=999_999),
]


# ---------------------------------------------------------------------------
# Rule category
# ---------------------------------------------------------------------------
class RuleCategory(str, Enum):
    """The three documented rule categories.

    Reference: DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 8.
    """

    SOURCE_SPECIFIC = "source_specific"
    COMMON_BEHAVIORAL = "common_behavioral"
    CROSS_SOURCE_CORRELATION = "cross_source_correlation"


# ---------------------------------------------------------------------------
# Rule state
# ---------------------------------------------------------------------------
class RuleState(str, Enum):
    """The subset of rule lifecycle states the framework enforces.

    Reference: DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 59.
    """

    CANDIDATE = "candidate"
    APPROVED = "approved"


# ---------------------------------------------------------------------------
# Rule evaluation result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RuleEvaluation:
    """The deterministic result of evaluating a rule against a SecurityEvent.

    This is the framework's **evaluation contract** (Section 13). It is
    NOT a Detection: it is what a rule returns when asked "did you fire
    on this event?". The detection engine (a later slice) will
    translate this into a persisted Detection with evidence references.
    """

    rule_id: str
    rule_version: int
    matched: bool
    target_event_id: str
    detected_at: datetime
    reasoning: str = ""
    extra: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.matched, bool):
            raise TypeError("RuleEvaluation.matched must be a bool")
        if not self.rule_id or len(self.rule_id) > MAX_RULE_ID_LEN:
            raise ValueError(
                f"rule_id must be 1..{MAX_RULE_ID_LEN} chars, got {len(self.rule_id)}"
            )
        if not isinstance(self.rule_version, int) or self.rule_version < 1:
            raise ValueError("rule_version must be a positive int")
        if not self.target_event_id:
            raise ValueError("target_event_id is required")
        if len(self.reasoning) > MAX_RULE_REASONING_LEN:
            raise ValueError(
                f"reasoning must be <= {MAX_RULE_REASONING_LEN} chars"
            )
        if len(self.extra) > MAX_RULE_EVAL_TARGETS:
            raise ValueError(
                f"extra must contain at most {MAX_RULE_EVAL_TARGETS} items"
            )
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware UTC")
        # ``extra`` is a tuple of (k, v) so the dataclass stays
        # hashable and frozen. Forbidding non-string keys keeps the
        # contract uniform.
        for k, _ in self.extra:
            if not isinstance(k, str):
                raise TypeError("extra keys must be strings")

    def to_dict(self) -> Dict[str, Any]:
        """Safe, JSON-ready representation. Datetimes are ISO strings
        and ``extra`` is normalised to a dict. This is the framework's
        own snapshot; the eventual Detection shape belongs to the
        detection slice and is not pinned here.
        """
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "matched": self.matched,
            "target_event_id": self.target_event_id,
            "detected_at": self.detected_at.isoformat(),
            "reasoning": self.reasoning,
            "extra": dict(self.extra),
        }


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------
class RuleMetadata(BaseModel):
    """Authoritative, immutable metadata for a rule.

    The framework is the single source of truth for *what rules exist
    and what they apply to*. The metadata must be sufficient for the
    engine to skip irrelevant rules without evaluating them
    (Section 90, DET-04).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    rule_id: RuleId = Field(
        ...,
        description="Unique uppercase id, e.g. 'WAF-001' or 'AUTH-BRUTEFORCE'.",
    )
    version: RuleVersion = Field(
        ...,
        description="Monotonically increasing positive integer per rule_id.",
    )
    name: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_RULE_NAME_LEN),
    ] = Field(..., description="Short, human-readable label.")
    category: RuleCategory = Field(..., description="Documented category.")
    sources: Tuple[str, ...] = Field(
        default_factory=tuple,
        description="Applicable source identifiers (subset of ALLOWED_SOURCES).",
    )
    event_types: Tuple[str, ...] = Field(
        default_factory=tuple,
        description="Applicable event types (subset of ALLOWED_EVENT_TYPES).",
    )
    description: Annotated[
        str,
        StringConstraints(max_length=MAX_RULE_DESCRIPTION_LEN),
    ] = ""
    tags: Tuple[str, ...] = Field(default_factory=tuple)
    references: Tuple[str, ...] = Field(default_factory=tuple)
    state: RuleState = RuleState.CANDIDATE
    enabled: bool = False

    @field_validator("sources")
    @classmethod
    def _check_sources(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_SOURCES_PER_RULE:
            raise ValueError(
                f"too many sources ({len(v)} > {MAX_SOURCES_PER_RULE})"
            )
        if list(v) != sorted(set(v)):
            raise ValueError("sources must be unique and sorted")
        for s in v:
            if s not in ALLOWED_SOURCES:
                raise ValueError(
                    f"unknown source {s!r}; not in ALLOWED_SOURCES"
                )
        return v

    @field_validator("event_types")
    @classmethod
    def _check_event_types(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_EVENT_TYPES_PER_RULE:
            raise ValueError(
                f"too many event_types ({len(v)} > {MAX_EVENT_TYPES_PER_RULE})"
            )
        if list(v) != sorted(set(v)):
            raise ValueError("event_types must be unique and sorted")
        for et in v:
            if et not in ALLOWED_EVENT_TYPES:
                raise ValueError(
                    f"unknown event_type {et!r}; not in ALLOWED_EVENT_TYPES"
                )
        return v

    @field_validator("tags")
    @classmethod
    def _check_tags(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_RULE_TAGS:
            raise ValueError(f"too many tags ({len(v)} > {MAX_RULE_TAGS})")
        if list(v) != sorted(set(v)):
            raise ValueError("tags must be unique and sorted")
        for t in v:
            if not t or len(t) > MAX_RULE_TAG_LEN:
                raise ValueError(
                    f"tag must be 1..{MAX_RULE_TAG_LEN} chars, got {t!r}"
                )
            if not re.match(r"^[A-Z][A-Z0-9_\-]*$", t):
                raise ValueError(
                    f"tag must match ^[A-Z][A-Z0-9_\\-]*$, got {t!r}"
                )
        return v

    @field_validator("references")
    @classmethod
    def _check_references(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_RULE_REFERENCES:
            raise ValueError(
                f"too many references ({len(v)} > {MAX_RULE_REFERENCES})"
            )
        for r in v:
            if not r or len(r) > MAX_RULE_REFERENCE_LEN:
                raise ValueError(
                    f"reference must be 1..{MAX_RULE_REFERENCE_LEN} chars"
                )
        return v

    @model_validator(mode="after")
    def _check_category_applicability(self) -> "RuleMetadata":
        """Category-vs-applicability sanity checks (Section 8 + 91)."""
        if self.category is RuleCategory.SOURCE_SPECIFIC:
            if not self.sources:
                raise ValueError(
                    "SOURCE_SPECIFIC rule must declare at least one source"
                )
            if not self.event_types:
                raise ValueError(
                    "SOURCE_SPECIFIC rule must declare at least one event_type"
                )
        elif self.category is RuleCategory.COMMON_BEHAVIORAL:
            if not self.event_types:
                raise ValueError(
                    "COMMON_BEHAVIORAL rule must declare at least one event_type"
                )
        elif self.category is RuleCategory.CROSS_SOURCE_CORRELATION:
            if len(self.sources) < 2:
                raise ValueError(
                    "CROSS_SOURCE_CORRELATION rule must declare at "
                    "least two sources (Section 91)"
                )
        return self

    # ------------------------------------------------------------------ helpers
    def is_evaluable(self) -> bool:
        """A rule is *evaluable* if it is APPROVED and enabled.

        This is the only condition that allows the detection engine to
        call :meth:`Rule.evaluate` against a real event
        (Section 90 + 59). CANDIDATE rules are visible to the registry
        for governance and testing but must NEVER enter production
        execution.
        """
        return self.state is RuleState.APPROVED and self.enabled is True

    def applies_to_source(self, source: str) -> bool:
        """Whether the rule's applicability covers ``source``."""
        if not self.sources:
            return False
        return source in self.sources

    def applies_to_event_type(self, event_type: str) -> bool:
        if not self.event_types:
            return False
        return event_type in self.event_types

    def applies_to(self, event: SecurityEvent) -> bool:
        """Whether the rule is *applicable* to a concrete event.

        An applicable rule is one the engine should CONSIDER calling;
        the rule itself may still return ``matched=False`` (Section 90
        "rule selection, then rule evaluation").
        """
        if not self.is_evaluable():
            return False
        return (
            self.applies_to_source(event.source)
            and self.applies_to_event_type(event.event_type)
        )

    def applicability_signature(self) -> Tuple[str, ...]:
        """Stable, hashable signature used by the registry for fast
        filtering. Returns a tuple of ``(source, event_type)`` pairs,
        prefixed by the rule's ``category`` so cross-category
        signatures can never collide.

        Order is deterministic. The category is included as the
        first element so a SOURCE_SPECIFIC rule and a
        COMMON_BEHAVIORAL rule with the same ``(sources,
        event_types)`` produce different signatures.
        """
        if not self.sources or not self.event_types:
            return (self.category.value,)
        out: List[str] = [self.category.value]
        for s in self.sources:
            for et in self.event_types:
                out.append(f"{s}::{et}")
        return tuple(sorted(out[1:]) + [out[0]])
