"""Capability Registry domain models (Phase 5.1).

Reference: docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md
(sections 7.1, 10.1, 11), docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md
(section 18).

A Capability is the reusable security-processing responsibility layer
above SourceInstance. One Capability supports many SourceInstances;
there is NO subconnector abstraction; the registry never accepts
arbitrary executable backend code.

Invariants enforced here:
* ``capability_id`` is a stable technical slug ``cap-<slug>``.
* ``human_id`` is allocator-assigned (``CAP-000001``) and stored on the
  document next to the technical id.
* ``implementation_ref`` is an allowlisted trusted reference only
  (``nginx`` / ``simulator`` / ``planned``). Anything else is rejected.
* ``configuration_schema`` and ``mapping_profiles`` are bounded so a
  hostile admin-adjacent payload cannot smuggle code or unbounded blobs.
* ``rule_ids`` / ``pattern_ids`` are DERIVED relationship views, never
  stored authority. Phase 5.1 does not rewire rules/patterns.
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator


CAPABILITIES_COLLECTION = "capabilities"

MAX_CAPABILITY_ID_LEN = 64
MAX_CAPABILITY_NAME_LEN = 128
MAX_CAPABILITY_DESCRIPTION_LEN = 1024
MAX_CAPABILITY_RESPONSIBILITY_LEN = 1024
MAX_CONFIG_SCHEMA_BYTES = 8_192
MAX_MAPPING_PROFILES = 16
MAX_MAPPING_PROFILE_ID_LEN = 64
MAX_FIELD_MAP_ENTRIES = 64
MAX_FIELD_MAP_KEY_LEN = 128
MAX_FIELD_MAP_VALUE_LEN = 256

CAPABILITY_ID_RE = re.compile(r"^cap-[a-z][a-z0-9-]{1,47}$")
HUMAN_ID_RE = re.compile(r"^CAP-\d{6}$")

CapabilityId = Annotated[
    str,
    StringConstraints(min_length=5, max_length=MAX_CAPABILITY_ID_LEN, pattern=r"^cap-[a-z][a-z0-9-]{1,47}$"),
]


class CapabilityStatus(str, Enum):
    """Administrative lifecycle states for a Capability."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    RETIRED = "retired"
    PLANNED = "planned"
    ARCHIVED = "archived"


class ImplementationRef(str, Enum):
    """Allowlisted trusted implementation references.

    Only connector families with a shipped in-repo implementation may
    claim a live reference. ``planned`` marks a declared-but-unbuilt
    family; activations of ``planned`` capabilities are refused by the
    service layer so the UI can never advertise phantom live coverage.
    """

    NGINX = "nginx"
    SIMULATOR = "simulator"
    PLANNED = "planned"


class MappingProfile(BaseModel):
    """One bounded source-type mapping profile owned by a Capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: Annotated[str, StringConstraints(min_length=1, max_length=MAX_MAPPING_PROFILE_ID_LEN, pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
    source_type: Annotated[str, StringConstraints(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]{0,31}$")]
    field_map: Dict[
        Annotated[str, StringConstraints(min_length=1, max_length=MAX_FIELD_MAP_KEY_LEN)],
        Annotated[str, StringConstraints(min_length=1, max_length=MAX_FIELD_MAP_VALUE_LEN)],
    ] = {}

    @field_validator("field_map")
    @classmethod
    def _check_field_map(cls, v: Dict[str, str]) -> Dict[str, str]:
        if len(v) > MAX_FIELD_MAP_ENTRIES:
            raise ValueError(f"field_map exceeds {MAX_FIELD_MAP_ENTRIES} entries")
        for k, val in v.items():
            kl = k.strip().lower()
            if kl in ("__proto__", "constructor", "prototype"):
                raise ValueError(f"forbidden field_map key {k!r}")
            if not isinstance(val, str) or not val.strip():
                raise ValueError("field_map values must be non-empty strings")
            if "eval" in val.lower() and ("(" in val or "$" in val):
                raise ValueError("field_map values must not carry executable expressions")
        return v


class Capability(BaseModel):
    """Authoritative persisted Capability record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: CapabilityId
    human_id: str = ""
    name: Annotated[str, StringConstraints(min_length=1, max_length=MAX_CAPABILITY_NAME_LEN)]
    description: Annotated[str, StringConstraints(max_length=MAX_CAPABILITY_DESCRIPTION_LEN)] = ""
    responsibility: Annotated[str, StringConstraints(max_length=MAX_CAPABILITY_RESPONSIBILITY_LEN)] = ""
    implementation_ref: ImplementationRef
    version: int = Field(default=1, ge=1, le=1_000_000)
    status: CapabilityStatus = CapabilityStatus.ACTIVE
    configuration_schema: Dict[str, Any] = {}
    mapping_profiles: Tuple[MappingProfile, ...] = ()
    created_by: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    created_at: datetime
    updated_by: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    updated_at: datetime
    retired_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None

    @field_validator("human_id")
    @classmethod
    def _check_human_id(cls, v: str) -> str:
        if v in ("", None):  # type: ignore[comparison-overlap]
            return ""
        if not isinstance(v, str) or not HUMAN_ID_RE.match(v):
            raise ValueError(f"human_id must match CAP-NNNNNN, got {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _check_version(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("version must be an integer")
        if v < 1 or v > 1_000_000:
            raise ValueError("version must be in [1, 1000000]")
        return v

    @field_validator("configuration_schema")
    @classmethod
    def _check_config_schema(cls, v: Any) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("configuration_schema must be an object")
        import json as _json

        try:
            raw = _json.dumps(v, sort_keys=True, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"configuration_schema is not JSON-serializable: {exc}") from exc
        if len(raw.encode("utf-8")) > MAX_CONFIG_SCHEMA_BYTES:
            raise ValueError(f"configuration_schema exceeds {MAX_CONFIG_SCHEMA_BYTES} bytes")
        lowered = raw.lower()
        for marker in ("__proto__", "$where", "eval(", "exec(", "import ", "subprocess", "os.system"):
            if marker in lowered:
                raise ValueError(f"configuration_schema contains forbidden marker {marker!r}")
        return v

    @field_validator("mapping_profiles")
    @classmethod
    def _check_profiles(cls, v: Tuple[MappingProfile, ...]) -> Tuple[MappingProfile, ...]:
        items = tuple(v or ())
        if len(items) > MAX_MAPPING_PROFILES:
            raise ValueError(f"mapping_profiles exceeds {MAX_MAPPING_PROFILES}")
        seen = set()
        for p in items:
            if p.profile_id in seen:
                raise ValueError(f"duplicate mapping profile {p.profile_id!r}")
            seen.add(p.profile_id)
        return items

    @model_validator(mode="after")
    def _check_status_impl(self) -> "Capability":
        if self.implementation_ref == ImplementationRef.PLANNED and self.status not in (
            CapabilityStatus.PLANNED,
            CapabilityStatus.RETIRED,
            CapabilityStatus.ARCHIVED,
        ):
            raise ValueError("planned implementation_ref requires status planned/retired/archived")
        if self.status == CapabilityStatus.PLANNED and self.implementation_ref != ImplementationRef.PLANNED:
            raise ValueError("status planned requires implementation_ref 'planned'")
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "human_id": self.human_id or None,
            "name": self.name,
            "description": self.description,
            "responsibility": self.responsibility,
            "implementation_ref": self.implementation_ref.value,
            "version": int(self.version),
            "status": self.status.value,
            "configuration_schema": dict(self.configuration_schema),
            "mapping_profiles": [p.model_dump(mode="json") for p in self.mapping_profiles],
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "retired_at": self.retired_at,
            "archived_at": self.archived_at,
        }

    def to_view_dict(
        self,
        *,
        rule_ids: Optional[List[str]] = None,
        pattern_ids: Optional[List[str]] = None,
        source_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        base = {
            "capability_id": self.capability_id,
            "human_id": self.human_id or None,
            "name": self.name,
            "description": self.description,
            "responsibility": self.responsibility,
            "implementation_ref": self.implementation_ref.value,
            "version": int(self.version),
            "status": self.status.value,
            "configuration_schema": dict(self.configuration_schema),
            "mapping_profiles": [p.model_dump(mode="json") for p in self.mapping_profiles],
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "retired_at": self.retired_at,
            "archived_at": self.archived_at,
        }
        base["rule_ids"] = list(rule_ids or [])
        base["pattern_ids"] = list(pattern_ids or [])
        if source_count is not None:
            base["source_count"] = int(source_count)
        return base


class CapabilityView(BaseModel):
    """Safe client-facing Capability view (derived relationship ids included)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: CapabilityId
    human_id: str = ""
    name: str
    description: str = ""
    responsibility: str = ""
    implementation_ref: str
    version: int
    status: str
    configuration_schema: Dict[str, Any] = {}
    mapping_profiles: Tuple[Dict[str, Any], ...] = ()
    rule_ids: Tuple[str, ...] = ()
    pattern_ids: Tuple[str, ...] = ()
    source_count: Optional[int] = None
    created_by: str
    created_at: datetime
    updated_by: str
    updated_at: datetime
    retired_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None


__all__ = [
    "CAPABILITIES_COLLECTION",
    "CAPABILITY_ID_RE",
    "Capability",
    "CapabilityId",
    "CapabilityStatus",
    "CapabilityView",
    "HUMAN_ID_RE",
    "ImplementationRef",
    "MAX_CAPABILITY_DESCRIPTION_LEN",
    "MAX_CAPABILITY_ID_LEN",
    "MAX_CAPABILITY_NAME_LEN",
    "MAX_CAPABILITY_RESPONSIBILITY_LEN",
    "MAX_CONFIG_SCHEMA_BYTES",
    "MAX_FIELD_MAP_ENTRIES",
    "MAX_MAPPING_PROFILES",
    "MappingProfile",
]
