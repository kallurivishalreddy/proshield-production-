"""Source Management domain models (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

The source-management model is the authoritative record of
"what external security systems are configured to talk to
ProShield". It is **deliberately distinct** from rule
management, which answers "what security behaviour should
ProShield detect".

Concepts
--------

* :class:`SourceType` - a closed-set enum of the supported
  external system kinds (nginx, waf, iam, rate_limit,
  network, simulator, ...). Each value maps to a canonical
  ``source`` string from
  :data:`app.domain.security_event.ALLOWED_SOURCES` and to the
  Phase 4 connector implementation in :mod:`app.connectors`.
* :class:`SourceState` - the lifecycle state of a configured
  source instance. The state machine is enforced by the
  service layer.
* :class:`SourceConnectionType` - how the external system
  talks to ProShield (push / proxy / pull).
* :class:`SourceInstanceConfiguration` - the **server-side,
  secret-bearing** configuration.
* :class:`SourceInstance` - the **authoritative persisted
  record** of a single configured source instance.
* :class:`SourceInstanceView` - the **safe** view returned to
  the client. Strips every secret-shaped field.
* :class:`SourceInstanceHealth` - a small status envelope.
* :class:`SourceIdentityToken` - the HMAC-signed token an
  external system presents to the ingress boundary.

Lifecycle states
----------------

::

    REGISTERED -> CONFIGURED -> VALIDATED -> ENABLED
                                          |
                                          v
                                       DISABLED
                                          |
                                          v
                                       RETIRED

The service layer enforces the transitions; ``retire`` is the
soft-delete boundary that preserves every historical record.

Design rules
------------

* All fields are validated and frozen at construction time.
* ``extra="forbid"`` so future drift is visible at the model
  boundary.
* The model never carries plaintext secrets across the wire.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Optional,
    Tuple,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
    model_validator,
)

from ..domain.security_event import (
    ALLOWED_SOURCES,
    MAX_DESTINATION,
    MAX_LABEL,
)


# ----------------------------------------------------------------- bounds
MAX_SOURCE_INSTANCE_ID_LEN = 96
MAX_SOURCE_INSTANCE_NAME_LEN = 128
MAX_SOURCE_INSTANCE_DESCRIPTION_LEN = 1024
MAX_ENDPOINT_LEN = 512
MAX_PROXY_PATH_LEN = 256
MAX_TAG_LEN = 64
MAX_TAGS_PER_SOURCE = 16
MAX_REFERENCES_PER_SOURCE = 16
MAX_REFERENCE_LEN = 512
MAX_ASSET_TAGS = 16
MAX_SECRET_REF_LEN = 128


# ----------------------------------------------------------------- enums
class SourceType(str, Enum):
    """The closed-set of supported external-system kinds."""

    NGINX = "nginx"
    WAF = "waf"
    IAM = "iam"
    RATE_LIMIT = "rate_limit"
    NETWORK = "network"
    SIMULATOR = "simulator"


SOURCE_TYPE_TO_SOURCE_STRING: Dict[SourceType, str] = {
    SourceType.NGINX: "nginx",
    SourceType.WAF: "waf",
    SourceType.IAM: "iam",
    SourceType.RATE_LIMIT: "rate_limit",
    SourceType.NETWORK: "network",
    SourceType.SIMULATOR: "simulator",
}


def source_string_for_type(source_type: SourceType) -> str:
    """Return the canonical ``SecurityEvent.source`` string for a type."""
    return SOURCE_TYPE_TO_SOURCE_STRING[source_type]


def source_type_for_string(source_string: str) -> Optional[SourceType]:
    """Inverse mapping. Returns ``None`` if the source string is unknown."""
    for st, s in SOURCE_TYPE_TO_SOURCE_STRING.items():
        if s == source_string:
            return st
    return None


class SourceState(str, Enum):
    """The closed-set source lifecycle states."""

    REGISTERED = "registered"
    CONFIGURED = "configured"
    VALIDATED = "validated"
    ENABLED = "enabled"
    DISABLED = "disabled"
    RETIRED = "retired"


class SourceConnectionType(str, Enum):
    """The documented inbound connection shapes.

    * PUSH: the external system POSTs canonical events to
      ProShield's ingress boundary.
    * PROXY: ProShield pulls events from a third-party proxy
      (e.g. a SIEM forwarder) that the external system
      publishes to.
    * PULL: ProShield polls the external system on a schedule.
    """

    PUSH = "push"
    PROXY = "proxy"
    PULL = "pull"


# ----------------------------------------------------------------- aliases
SourceInstanceId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=MAX_SOURCE_INSTANCE_ID_LEN,
        pattern=r"^src-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(-[a-z0-9][a-z0-9-]{0,32})?$",
    ),
]

AssetTag = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=MAX_TAG_LEN,
        pattern=r"^[a-z][a-z0-9_-]*$",
    ),
]

Tag = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=MAX_TAG_LEN,
        pattern=r"^[A-Z][A-Z0-9_-]*$",
    ),
]


# ----------------------------------------------------------------- configuration
class SourceInstanceConfiguration(BaseModel):
    """The **server-side** configuration of a source instance.

    This model is NEVER returned to the client as-is. It is
    persisted in MongoDB (with secret-bearing fields redacted
    by the repository) and used server-side to authenticate
    the external system.

    The configuration is intentionally small:

    * ``connection_type`` - the documented connection shape.
    * ``endpoint``        - where the external system
      publishes telemetry.
    * ``proxy_path``      - optional path prefix for routing
      through a reverse proxy.
    * ``destination``     - the human-readable destination
      label (kept short, e.g. ``web-api-01``).
    * ``asset_tags``      - a small list of ``asset`` tags
      that the source is expected to populate on every
      emitted event.
    * ``tags`` / ``references`` - governance metadata.
    * ``secret_ref``      - **server-side** opaque reference
      to the secret material. The repository keeps only an
      opaque pointer.

    The model refuses any field that looks like raw secret
    material (defence-in-depth: it is small enough to audit).
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    connection_type: SourceConnectionType
    endpoint: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_ENDPOINT_LEN),
    ]
    proxy_path: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_PROXY_PATH_LEN),
    ] = ""
    destination: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_DESTINATION),
    ] = ""
    asset_tags: Tuple[AssetTag, ...] = ()
    tags: Tuple[Tag, ...] = ()
    references: Tuple[
        Annotated[str, StringConstraints(
            min_length=1, max_length=MAX_REFERENCE_LEN
        )],
        ...,
    ] = ()
    secret_ref: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_SECRET_REF_LEN),
    ] = ""

    @field_validator("endpoint")
    @classmethod
    def _check_endpoint(cls, v: str) -> str:
        if not v:
            raise ValueError("endpoint must be non-empty")
        if any(ch.isspace() for ch in v):
            raise ValueError("endpoint must not contain whitespace")
        return v

    @field_validator("asset_tags")
    @classmethod
    def _check_asset_tags(
        cls, v: Tuple[AssetTag, ...]
    ) -> Tuple[AssetTag, ...]:
        if len(v) > MAX_ASSET_TAGS:
            raise ValueError(
                f"too many asset_tags ({len(v)} > {MAX_ASSET_TAGS})"
            )
        if list(v) != sorted(set(v)):
            raise ValueError("asset_tags must be unique and sorted")
        return v

    @field_validator("tags")
    @classmethod
    def _check_tags(cls, v: Tuple[Tag, ...]) -> Tuple[Tag, ...]:
        if len(v) > MAX_TAGS_PER_SOURCE:
            raise ValueError(
                f"too many tags ({len(v)} > {MAX_TAGS_PER_SOURCE})"
            )
        if list(v) != sorted(set(v)):
            raise ValueError("tags must be unique and sorted")
        return v

    @field_validator("references")
    @classmethod
    def _check_references(
        cls, v: Tuple[str, ...]
    ) -> Tuple[str, ...]:
        if len(v) > MAX_REFERENCES_PER_SOURCE:
            raise ValueError(
                f"too many references "
                f"({len(v)} > {MAX_REFERENCES_PER_SOURCE})"
            )
        return v

    @model_validator(mode="after")
    def _check_shape(self) -> "SourceInstanceConfiguration":
        blob = self.model_dump_json()
        lowered = blob.lower()
        forbidden_substrings = (
            "password=",
            "token=",
            "apikey=",
            "secret=",
            "private_key=",
        )
        for needle in forbidden_substrings:
            if needle in lowered:
                raise ValueError(
                    f"configuration leaks a forbidden substring "
                    f"{needle!r}; use secret_ref instead"
                )
        return self

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return the public-shaped view (no secret material).

        ``secret_ref`` is reported only as a boolean; the
        repository enforces the same rule at the persistence
        boundary (a separate defence layer).
        """
        return {
            "connection_type": self.connection_type.value,
            "endpoint": self.endpoint,
            "proxy_path": self.proxy_path,
            "destination": self.destination,
            "asset_tags": list(self.asset_tags),
            "tags": list(self.tags),
            "references": list(self.references),
            "secret_ref_set": bool(self.secret_ref),
        }


# ----------------------------------------------------------------- health
class SourceInstanceHealth(BaseModel):
    """A safe health summary for a source instance."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    state: "SourceState"
    status: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_LABEL,
            pattern=r"^(ok|degraded|unknown|disabled|retired)$",
        ),
    ]
    last_received_at: Optional[datetime] = None
    last_validation_at: Optional[datetime] = None
    last_error: Annotated[
        str,
        StringConstraints(min_length=0, max_length=MAX_LABEL),
    ] = ""
    received_count: int = 0
    rejected_count: int = 0

    @field_validator("received_count", "rejected_count")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("counter must be non-negative")
        return int(v)


_STATUS_FOR_STATE: Dict["SourceState", str] = {
    SourceState.REGISTERED: "unknown",
    SourceState.CONFIGURED: "unknown",
    SourceState.VALIDATED: "ok",
    SourceState.ENABLED: "ok",
    SourceState.DISABLED: "disabled",
    SourceState.RETIRED: "retired",
}


# ----------------------------------------------------------------- instance
class SourceInstance(BaseModel):
    """The authoritative persisted record of a configured source."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    source_instance_id: SourceInstanceId
    source_type: SourceType
    source: Annotated[
        str,
        StringConstraints(min_length=1, max_length=64),
    ]
    display_name: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_SOURCE_INSTANCE_NAME_LEN,
        ),
    ]
    description: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=MAX_SOURCE_INSTANCE_DESCRIPTION_LEN,
        ),
    ] = ""
    configuration: "SourceInstanceConfiguration"
    state: SourceState
    created_by: Annotated[
        str,
        StringConstraints(min_length=1, max_length=128),
    ]
    created_at: datetime
    updated_by: Annotated[
        str,
        StringConstraints(min_length=1, max_length=128),
    ]
    updated_at: datetime
    last_validation_at: Optional[datetime] = None
    tags: Tuple[Tag, ...] = ()
    asset_tags: Tuple[AssetTag, ...] = ()
    retired_at: Optional[datetime] = None

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        if v not in ALLOWED_SOURCES:
            raise ValueError(
                f"source {v!r} is not in ALLOWED_SOURCES"
            )
        return v

    @model_validator(mode="after")
    def _check_source_string_matches_type(
        self,
    ) -> "SourceInstance":
        expected = source_string_for_type(self.source_type)
        if self.source != expected:
            raise ValueError(
                f"source {self.source!r} does not match "
                f"source_type={self.source_type.value!r}; "
                f"expected {expected!r}"
            )
        return self

    @model_validator(mode="after")
    def _check_retired_state(self) -> "SourceInstance":
        if (
            self.state is SourceState.RETIRED
            and self.retired_at is None
        ):
            raise ValueError(
                "retired source instances must carry retired_at"
            )
        if (
            self.state is not SourceState.RETIRED
            and self.retired_at is not None
        ):
            raise ValueError(
                "non-retired source instances must not carry "
                "retired_at"
            )
        return self

    def to_view(self) -> "SourceInstanceView":
        """Return the safe view returned to clients."""
        health = SourceInstanceHealth(
            state=self.state,
            status=_STATUS_FOR_STATE[self.state],
            last_received_at=None,
            last_validation_at=self.last_validation_at,
            last_error="",
            received_count=0,
            rejected_count=0,
        )
        return SourceInstanceView(
            source_instance_id=self.source_instance_id,
            source_type=self.source_type.value,
            source=self.source,
            display_name=self.display_name,
            description=self.description,
            configuration=self.configuration.to_safe_dict(),
            state=self.state.value,
            created_by=self.created_by,
            created_at=self.created_at,
            updated_by=self.updated_by,
            updated_at=self.updated_at,
            last_validation_at=self.last_validation_at,
            tags=list(self.tags),
            asset_tags=list(self.asset_tags),
            retired_at=self.retired_at,
            health=health,
        )

    def to_canonical_dict(self) -> Dict[str, Any]:
        """BSON-safe canonical dict.

        The canonical dict contains the safe configuration
        view (which includes ``secret_ref_set`` but never the
        raw ``secret_ref``). The repository's loader is
        responsible for converting the safe view back into a
        Pydantic-compatible shape on read.
        """
        config = self.configuration.to_safe_dict()
        return {
            "source_instance_id": self.source_instance_id,
            "source_type": self.source_type.value,
            "source": self.source,
            "display_name": self.display_name,
            "description": self.description,
            "configuration": config,
            "state": self.state.value,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "last_validation_at": self.last_validation_at,
            "tags": list(self.tags),
            "asset_tags": list(self.asset_tags),
            "retired_at": self.retired_at,
        }


# ----------------------------------------------------------------- view (client-facing)
class SourceInstanceView(BaseModel):
    """The safe client-facing view of a source instance.

    Secret material is intentionally absent. ``configuration``
    is the safe shape produced by
    :meth:`SourceInstanceConfiguration.to_safe_dict`.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    source_instance_id: SourceInstanceId
    source_type: str
    source: str
    display_name: str
    description: str
    configuration: Dict[str, Any]
    state: str
    created_by: str
    created_at: datetime
    updated_by: str
    updated_at: datetime
    last_validation_at: Optional[datetime]
    tags: Tuple[str, ...]
    asset_tags: Tuple[str, ...]
    retired_at: Optional[datetime]
    health: SourceInstanceHealth

    @field_validator("state")
    @classmethod
    def _check_state(cls, v: str) -> str:
        if v not in {s.value for s in SourceState}:
            raise ValueError(f"unknown state {v!r}")
        return v

    @field_validator("source_type")
    @classmethod
    def _check_source_type(cls, v: str) -> str:
        if v not in {t.value for t in SourceType}:
            raise ValueError(f"unknown source_type {v!r}")
        return v


# ----------------------------------------------------------------- token
class SourceIdentityToken(BaseModel):
    """A signed, time-bounded token that proves source identity.

    The token is the **only** thing an external system needs
    to present to the ingress boundary. It carries:

    * ``source_instance_id``
    * ``source_type``
    * ``source``  (the canonical ``SecurityEvent.source`` string)
    * ``issued_at`` / ``not_before`` / ``expires_at``
    * ``token_id`` - a per-token identifier for replay tracking
    * ``nonce``    - opaque random bytes included by the issuer
    * ``signature`` - HMAC over the canonical JSON body
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    token_id: Annotated[
        str,
        StringConstraints(
            min_length=8, max_length=64,
            pattern=r"^sit-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        ),
    ]
    source_instance_id: SourceInstanceId
    source_type: str
    source: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    nonce: Annotated[
        str,
        StringConstraints(min_length=16, max_length=64),
    ]
    key_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=32),
    ] = "k1"
    signature: Annotated[
        str,
        StringConstraints(min_length=43, max_length=128),
    ]

    @field_validator("source_type")
    @classmethod
    def _check_source_type(cls, v: str) -> str:
        if v not in {t.value for t in SourceType}:
            raise ValueError(f"unknown source_type {v!r}")
        return v

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        if v not in ALLOWED_SOURCES:
            raise ValueError(f"unknown source {v!r}")
        return v


# Sentinel type alias used as a forward reference in
# :class:`SourceInstanceConfiguration` and :class:`SourceInstanceHealth`.
SourceInstanceConfiguration.model_rebuild()
SourceInstanceHealth.model_rebuild()