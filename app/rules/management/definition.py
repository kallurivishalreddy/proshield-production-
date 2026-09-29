"""The Phase 4.7 RuleDefinition model.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md
           docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 10, 13, 59, 87-91).

A :class:`RuleDefinition` is the strict, declarative
configuration of a "normal" rule. It is the wire form the
Phase 4.7 UI/API sends, the persisted form the rule
repository stores, and the form the generic rule evaluator
consumes.
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Dict, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from ...domain.security_event import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SOURCES,
)
from ...rules.types import (
    MAX_RULE_DESCRIPTION_LEN,
    MAX_RULE_NAME_LEN,
    MAX_RULE_TAGS,
    MAX_RULE_TAG_LEN,
    MAX_RULE_REFERENCES,
    MAX_RULE_REFERENCE_LEN,
    MAX_SOURCES_PER_RULE,
    MAX_EVENT_TYPES_PER_RULE,
    RuleCategory,
    RuleId,
    RuleState,
    RuleVersion,
)
from ...severity.models import SeverityBand
from .conditions import (
    ConditionCombinator,
    Expression,
    validate_field_path,
)


# ----------------------------------------------------------------- bounds
MAX_ACTIONS = 8
MAX_ACTION_LEN = 32
MAX_SCOPES = 32
MAX_SCOPE_LEN = 128
MAX_EVIDENCE_REQUIREMENTS = 16
MAX_THRESHOLDS = 16
MAX_THRESHOLD_KEY_LEN = 64
MAX_THRESHOLD_VALUE = 1_000_000_000
MIN_THRESHOLD_VALUE = -1_000_000_000
MAX_WINDOW_SECONDS = 86_400 * 30  # 30 days, generous bound
MIN_WINDOW_SECONDS = 1


# ----------------------------------------------------------------- types
class RuleType(str, Enum):
    """The four documented rule types for Phase 4.7."""

    DETECTION = "detection"
    THRESHOLD = "threshold"
    RATE_LIMIT = "rate_limit"
    CORRELATION = "correlation"


class ActionType(str, Enum):
    """The closed-set list of action identifiers.

    The slice does NOT implement enforcement. Each action
    is a structured record that downstream enforcement
    layers will consume; ``block_remediation`` is the
    documented action name from the task brief.
    """

    ALERT = "alert"
    LOG = "log"
    BLOCK_REMEDIATION = "block_remediation"


# ----------------------------------------------------------------- aliases
Action = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_ACTION_LEN),
]
Scope = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_SCOPE_LEN),
]
EvidenceRequirement = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
]
ThresholdKey = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=MAX_THRESHOLD_KEY_LEN,
        pattern=r"^[a-z][a-z0-9_]*$",
    ),
]


# ----------------------------------------------------------------- definition
class RuleDefinition(BaseModel):
    """A strict, declarative, versioned rule definition.

    The model is **frozen** (immutable) and **strict**
    (``extra="forbid"``). All field-level validation lives
    here so the service layer is free to call this model
    and trust the result.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    # --- identity
    rule_id: RuleId = Field(..., description="Unique uppercase id, e.g. 'CUSTOM-001'.")
    version: RuleVersion = Field(
        ...,
        description="Monotonically increasing positive integer per rule_id.",
    )
    name: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_RULE_NAME_LEN),
    ] = Field(..., description="Short, human-readable label.")
    description: Annotated[
        str,
        StringConstraints(max_length=MAX_RULE_DESCRIPTION_LEN),
    ] = ""
    category: RuleCategory = Field(..., description="Documented category.")
    type: RuleType = Field(
        RuleType.DETECTION,
        description="Documented rule type.",
    )
    state: str = RuleState.CANDIDATE.value
    enabled: bool = False
    severity: SeverityBand = SeverityBand.MEDIUM
    # --- applicability
    sources: Tuple[str, ...] = Field(
        default_factory=tuple,
        description="Applicable source identifiers (subset of ALLOWED_SOURCES).",
    )
    event_types: Tuple[str, ...] = Field(
        default_factory=tuple,
        description="Applicable event types (subset of ALLOWED_EVENT_TYPES).",
    )
    tags: Tuple[str, ...] = Field(default_factory=tuple)
    references: Tuple[str, ...] = Field(default_factory=tuple)
    # --- Phase 5.2 capability ownership (dual-read during migration) -----
    # When set, this rule is owned by a Capability and the detection engine
    # resolves applicability through the event's **server-derived**
    # capability id rather than the legacy ``sources[]`` string match
    # (master plan §19: "rule.capability_id authoritative; dual-read during
    # migration, capability wins"). ``None`` is the honest "legacy rule,
    # not yet bound" state and keeps the Phase 4 string-matching behaviour
    # byte-identical.
    capability_id: Optional[str] = Field(
        default=None,
        description=(
            "Phase 5.2 capability ownership (``cap-<slug>``). None = "
            "legacy rule resolved by sources[] string match."
        ),
    )
    # --- logic
    combinator: ConditionCombinator = ConditionCombinator.AND
    conditions: Optional[Expression] = None
    scope: Tuple[Scope, ...] = Field(default_factory=tuple)
    evidence_requirements: Tuple[EvidenceRequirement, ...] = Field(
        default_factory=tuple,
        description="Field paths the underlying event must carry.",
    )
    # --- thresholds / windows
    thresholds: Dict[ThresholdKey, float] = Field(default_factory=dict)
    window_seconds: Optional[int] = Field(
        default=None,
        description="Required for threshold / rate_limit / correlation rules.",
    )
    # --- actions
    actions: Tuple[ActionType, ...] = Field(
        default_factory=tuple,
        description="Closed-set action identifiers; the slice does NOT enforce.",
    )



    # ---------------------------------------------------------------- validators
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

    @field_validator("scope")
    @classmethod
    def _check_scope(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if len(v) > MAX_SCOPES:
            raise ValueError(f"too many scope entries ({len(v)} > {MAX_SCOPES})")
        if list(v) != sorted(set(v)):
            raise ValueError("scope must be unique (sorting not required)")
        return v

    @field_validator("evidence_requirements")
    @classmethod
    def _check_evidence_requirements(
        cls, v: Tuple[str, ...]
    ) -> Tuple[str, ...]:
        if len(v) > MAX_EVIDENCE_REQUIREMENTS:
            raise ValueError(
                f"too many evidence_requirements ({len(v)} > "
                f"{MAX_EVIDENCE_REQUIREMENTS})"
            )
        for p in v:
            validate_field_path(p)
        return v

    @field_validator("thresholds", mode="before")
    @classmethod
    def _check_thresholds(
        cls, v: Any
    ) -> Any:
        if not isinstance(v, dict):
            raise ValueError("thresholds must be a dict")
        if len(v) > MAX_THRESHOLDS:
            raise ValueError(
                f"too many threshold keys ({len(v)} > {MAX_THRESHOLDS})"
            )
        for k, val in v.items():
            # bool is a subclass of int; reject explicitly.
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ValueError(
                    f"threshold {k!r} must be a number, got {type(val).__name__}"
                )
            if val < MIN_THRESHOLD_VALUE or val > MAX_THRESHOLD_VALUE:
                raise ValueError(
                    f"threshold {k!r} value {val} is out of bounds "
                    f"[{MIN_THRESHOLD_VALUE}, {MAX_THRESHOLD_VALUE}]"
                )
        return v

    @field_validator("state", mode="before")
    @classmethod
    def _check_state(cls, v: Any) -> Any:
        # The model accepts ``candidate`` / ``approved``
        # in the constructor. The ``retired`` value is
        # only accepted on a *read* path (the repository
        # re-builds the document after a soft-delete,
        # which must round-trip the persisted string).
        # We accept ``retired`` here so the repository's
        # ``_document_to_definition`` succeeds; the
        # service layer's ``create`` / ``update`` paths
        # still refuse to persist a retired definition.
        if v == "retired":
            return v
        return v

    @field_validator("actions")
    @classmethod
    def _check_actions(cls, v: Tuple[ActionType, ...]) -> Tuple[ActionType, ...]:
        if len(v) > MAX_ACTIONS:
            raise ValueError(
                f"too many actions ({len(v)} > {MAX_ACTIONS})"
            )
        return v

    @field_validator("window_seconds")
    @classmethod
    def _check_window_seconds(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError("window_seconds must be an int")
        if v < MIN_WINDOW_SECONDS or v > MAX_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be in "
                f"[{MIN_WINDOW_SECONDS}, {MAX_WINDOW_SECONDS}], got {v}"
            )
        return v



    @model_validator(mode="after")
    def _check_category_applicability(self) -> "RuleDefinition":
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



    @model_validator(mode="after")
    def _check_type_specific_invariants(self) -> "RuleDefinition":
        """Type-specific invariants."""
        if self.type is RuleType.THRESHOLD or self.type is RuleType.RATE_LIMIT:
            if self.window_seconds is None:
                raise ValueError(
                    f"{self.type.value} rule must declare window_seconds"
                )
            if not self.thresholds:
                raise ValueError(
                    f"{self.type.value} rule must declare at least one threshold"
                )
        if self.type is RuleType.CORRELATION:
            if self.window_seconds is None:
                raise ValueError(
                    "correlation rule must declare window_seconds"
                )
            if not self.thresholds:
                raise ValueError(
                    "correlation rule must declare exactly one threshold key"
                )
            if len(self.thresholds) > 1:
                raise ValueError(
                    "correlation rule must declare exactly one threshold key "
                    f"(got {len(self.thresholds)})"
                )
            if self.combinator is not ConditionCombinator.AND:
                raise ValueError(
                    "correlation rule combinator must be AND"
                )
        if self.conditions is None and self.type is not RuleType.DETECTION:
            raise ValueError(
                f"{self.type.value} rule must declare conditions"
            )
        return self

    @model_validator(mode="after")
    def _check_state_enabled_invariant(self) -> "RuleDefinition":
        """An enabled rule must be APPROVED (Section 59, 90)."""
        # ``state`` is a string field; normalise to the
        # enum. ``retired`` is only valid on a read path
        # (a soft-deleted document round-trip); the
        # :class:`RuleManagementService` refuses to
        # create or update a rule into a retired state.
        if self.state == "retired":
            return self
        if self.state not in (s.value for s in RuleState):
            raise ValueError(f"unknown state {self.state!r}")
        if self.enabled and self.state != RuleState.APPROVED.value:
            raise ValueError(
                "rule cannot be enabled while it is in the CANDIDATE state; "
                "promote it to APPROVED first"
            )
        return self



    # ------------------------------------------------------------------ helpers
    def to_metadata(self) -> Any:
        """Return the :class:`RuleMetadata` this definition would produce."""
        from ...rules.types import RuleMetadata, RuleState

        # ``RuleMetadata.state`` is the :class:`RuleState`
        # enum. The persisted definition may carry
        # ``"retired"``; the framework refuses to
        # register a retired rule, so this method is
        # only ever called on a non-retired definition.
        if self.state == RuleState.APPROVED.value:
            state = RuleState.APPROVED
        else:
            state = RuleState.CANDIDATE
        return RuleMetadata(
            rule_id=self.rule_id,
            version=self.version,
            name=self.name,
            category=self.category,
            sources=self.sources,
            event_types=self.event_types,
            description=self.description,
            tags=self.tags,
            references=self.references,
            state=state,
            enabled=self.enabled,
            capability_id=self.capability_id,
        )

    def to_canonical_dict(self) -> Dict[str, Any]:
        """BSON-safe canonical dict for MongoDB persistence."""
        # ``state`` is stored as a string (candidate /
        # approved / retired). All other enum-typed
        # fields are stored via their ``.value``.
        if self.state in (s.value for s in RuleState):
            state_value = self.state
        else:
            state_value = self.state  # "retired" or a malformed value
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "type": self.type.value,
            "state": state_value,
            "enabled": bool(self.enabled),
            "severity": self.severity.value,
            "sources": list(self.sources),
            "event_types": list(self.event_types),
            # Phase 5.2: capability ownership. Persisted as an explicit
            # ``null`` for a legacy rule — the honest "not yet bound"
            # state, never a fabricated id (freeze §38).
            "capability_id": self.capability_id,
            "tags": list(self.tags),
            "references": list(self.references),
            "combinator": self.combinator.value,
            "conditions": (
                self.conditions.model_dump() if self.conditions is not None else None
            ),
            "scope": list(self.scope),
            "evidence_requirements": list(self.evidence_requirements),
            "thresholds": {k: float(v) for k, v in self.thresholds.items()},
            "window_seconds": self.window_seconds,
            "actions": [a.value for a in self.actions],
        }


__all__ = [
    "ActionType",
    "MAX_ACTIONS",
    "MAX_ACTION_LEN",
    "MAX_EVIDENCE_REQUIREMENTS",
    "MAX_SCOPE_LEN",
    "MAX_SCOPES",
    "MAX_THRESHOLDS",
    "MAX_THRESHOLD_KEY_LEN",
    "MAX_THRESHOLD_VALUE",
    "MIN_THRESHOLD_VALUE",
    "MAX_WINDOW_SECONDS",
    "MIN_WINDOW_SECONDS",
    "RuleDefinition",
    "RuleType",
]

