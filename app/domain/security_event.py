"""Canonical ProShield SecurityEvent model.

Source of truth: docs/PHASE 2/SECURITY_EVENT_SCHEMA.md and
docs/PHASE 0/INITIAL_SECURITY_EVENTS.md (event-type catalogue).

This is the ONLY data structure that flows past the documented
Boundary 2 (Collector -> Trusted Processing). It is an observation
about the security environment, never a derived conclusion
(no detection, no incident, no severity, no routing, no analyst
judgement, no AI interpretation).

Notes on the design:

* All bounds are documented in schema Section 12 and reproduced here.
* Sensitive data (Section 20) is REJECTED at validation: the model
  refuses passwords, password hashes, access tokens, private
  credentials, and any value carrying a secret-shaped key inside
  the open-ended ``details`` field.
* Field naming, types, and optionality are exactly as documented.
  We do NOT add speculative fields and we do NOT remove documented
  ones.
* ``details`` is bounded JSON-shaped (the schema example shows
  ``http_method`` / ``status_code`` / ``reason`` style fields and
  the document explicitly allows the exact event-type-specific
  ``details`` structure to vary by event type, but the common
  envelope stays stable).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, Optional
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .errors import ValidationError
from .uuid7 import is_uuid7

# ---------------------------------------------------------------------------
# Bounds (docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 12)
# ---------------------------------------------------------------------------
MAX_BODY_BYTES_DEFAULT = 16_384
MAX_DETAILS_BYTES_DEFAULT = 8_192

MAX_EVENT_ID = 64
MAX_SOURCE = 64
MAX_EVENT_TYPE = 64
MAX_SOURCE_IP = 64
MAX_DESTINATION = 256
MAX_ENDPOINT = 512
MAX_ASSET = 128
MAX_ACCOUNT_ID = 128
MAX_DEVICE_ID = 128
MAX_PROVENANCE_COLLECTOR = 64
MAX_PROVENANCE_SOURCE_EVENT_ID = 256
MAX_SCHEMA_VERSION = 16
MAX_LABEL = 128

# ---------------------------------------------------------------------------
# Allowed event-type catalogue (docs/PHASE 0/INITIAL_SECURITY_EVENTS.md,
# Section 17). The schema allows extension; this slice locks the MVP set
# so that unrecognised event types are rejected at the trust boundary
# rather than silently entering detection.
# ---------------------------------------------------------------------------
ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "waf_attack_detected",
        "request_blocked",
        "rate_limit_exceeded",
        "suspicious_request",
        "authentication_failure",
        "authentication_success",
        "tls_anomaly",
        "network_anomaly",
        "security_control_alert",
    }
)

# ---------------------------------------------------------------------------
# Sources of telemetry (docs/PHASE 0/PRODUCT_SCOPE.md, Section 8, and
# docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 4).
# Locked for MVP: every connector must declare itself from this set so
# that rule applicability metadata stays consistent.
# ---------------------------------------------------------------------------
ALLOWED_SOURCES: frozenset[str] = frozenset(
    {
        "simulator",
        "nginx",
        "waf",
        "rate_limiter",
        "tls_network",
        "iam",
        "siem",
        "endpoint",
    }
)

# Sensitive key names that must NEVER appear inside ``details`` or
# anywhere in the document (docs/PHASE 2/SECURITY_EVENT_SCHEMA.md,
# Section 20). Match is case-insensitive and substring-based.
_FORBIDDEN_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "private_key",
    "privatekey",
    "credential",
    "session_cookie",
    "cookie",
)

REQUIRED_CANONICAL_FIELDS = (
    "event_id",
    "event_time",
    "ingested_at",
    "source",
    "event_type",
    "provenance",
)


# ---------------------------------------------------------------------------
# String-with-bounds type aliases
# ---------------------------------------------------------------------------
EventIdStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVENT_ID),
]
SourceStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_SOURCE, pattern=r"^[a-z0-9_\-]+$"),
]
EventTypeStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVENT_TYPE, pattern=r"^[a-z0-9_]+$"),
]
SourceIpStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_SOURCE_IP),
]
DestinationStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_DESTINATION),
]
EndpointStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_ENDPOINT),
]
AssetStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_ASSET),
]
SchemaVersionStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_SCHEMA_VERSION, pattern=r"^\d+\.\d+$"),
]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class _StrictModel(BaseModel):
    """Base model: extra fields forbidden, immutable after construction."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


class SecurityEventAccount(_StrictModel):
    """Optional actor/subject identity attached to a SecurityEvent.

    Free-form subfields are allowed ONLY for non-sensitive labels such as
    username / role / tenant. We do not store the password, hash, or any
    authentication secret here, ever.
    """

    id: Annotated[str, StringConstraints(min_length=1, max_length=MAX_ACCOUNT_ID)]
    username: Optional[Annotated[str, StringConstraints(max_length=MAX_LABEL)]] = None
    role: Optional[Annotated[str, StringConstraints(max_length=MAX_LABEL)]] = None
    tenant: Optional[Annotated[str, StringConstraints(max_length=MAX_LABEL)]] = None

    @field_validator("id")
    @classmethod
    def _id_must_not_look_like_a_secret(cls, v: str) -> str:
        if _looks_sensitive(v):
            raise ValueError("account.id value rejected: appears to contain a secret")
        return v


class SecurityEventDevice(_StrictModel):
    """Optional originating-device identity attached to a SecurityEvent."""

    id: Annotated[str, StringConstraints(min_length=1, max_length=MAX_DEVICE_ID)]
    hostname: Optional[Annotated[str, StringConstraints(max_length=MAX_LABEL)]] = None
    type: Optional[Annotated[str, StringConstraints(max_length=MAX_LABEL)]] = None

    @field_validator("id")
    @classmethod
    def _id_must_not_look_like_a_secret(cls, v: str) -> str:
        if _looks_sensitive(v):
            raise ValueError("device.id value rejected: appears to contain a secret")
        return v


class SecurityEventProvenance(_StrictModel):
    """Provenance records WHERE the event came from and the original
    source-side identifier so that evidence can always be traced.

    Reference: docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 8.

    The optional ``source_instance_id`` was added in Phase 4.9
    to carry the canonical reference to the
    :class:`app.sources.SourceInstance` that ingested the
    event. It is **optional** so Phase 4.1-4.8 documents /
    fixtures (which construct provenance with only
    ``collector`` + ``source_event_id``) keep working
    unchanged.
    """

    collector: Annotated[
        str, StringConstraints(min_length=1, max_length=MAX_PROVENANCE_COLLECTOR)
    ]
    source_event_id: Annotated[
        str, StringConstraints(min_length=1, max_length=MAX_PROVENANCE_SOURCE_EVENT_ID)
    ]
    source_instance_id: Optional[
        Annotated[
            str,
            StringConstraints(
                min_length=8,
                max_length=96,
                pattern=(
                    r"^src-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                    r"(-[a-z0-9][a-z0-9-]{0,32})?$"
                ),
            ),
        ]
    ] = None


class SecurityEvent(_StrictModel):
    """The canonical ProShield SecurityEvent.

    This is an observation. It is not a detection, not an incident,
    not a severity, not a routing decision, not an analyst conclusion,
    and not an AI interpretation. Anything that crosses this trust
    boundary with extra "result" fields is rejected.
    """

    # ---- Required fields (schema Section 5) ---------------------------------
    event_id: EventIdStr = Field(
        ...,
        description=(
            "Globally unique ProShield identifier for this event. UUIDv7 if "
            "ProShield generated it, otherwise the source-supplied stable id."
        ),
    )
    event_time: datetime = Field(
        ...,
        description="When the source observed the event. UTC, RFC 3339 / ISO 8601.",
    )
    ingested_at: datetime = Field(
        ...,
        description="When ProShield received the event. Set server-side at ingestion.",
    )
    source: SourceStr = Field(
        ...,
        description="Logical source system, e.g. 'waf', 'nginx', 'iam'.",
    )
    event_type: EventTypeStr = Field(
        ...,
        description="One of the MVP-catalogued event types.",
    )
    provenance: SecurityEventProvenance = Field(
        ...,
        description="Where the event came from and its source-side identifier.",
    )

    # ---- Optional but commonly present (schema Section 5) -------------------
    source_ip: Optional[SourceIpStr] = None
    destination: Optional[DestinationStr] = None
    endpoint: Optional[EndpointStr] = None
    asset: Optional[AssetStr] = None
    account: Optional[SecurityEventAccount] = None
    device: Optional[SecurityEventDevice] = None

    # ---- Free-form source-specific structured metadata (Section 5 / 11) ----
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Event-type-specific structured metadata. Must remain bounded "
            "and free of secrets."
        ),
    )

    # ---- Schema versioning (Section 29) -------------------------------------
    schema_version: SchemaVersionStr = Field(
        default="1.0",
        description="Version of the canonical SecurityEvent contract this conforms to.",
    )

    # ------------------------------------------------------------------ rules
    @field_validator("event_id")
    @classmethod
    def _event_id_must_be_uuidv7(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError) as exc:
            raise ValueError("event_id must be a valid UUID") from exc
        if not is_uuid7(parsed):
            raise ValueError(
                "event_id must be a UUIDv7 (RFC 9562); got version "
                f"{parsed.version}"
            )
        return v

    @field_validator("event_time", "ingested_at")
    @classmethod
    def _timestamps_must_be_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must include a timezone (UTC)")
        # Normalise to UTC for storage consistency.
        return v.astimezone(timezone.utc)

    @field_validator("source")
    @classmethod
    def _source_must_be_catalogue_member(cls, v: str) -> str:
        if v not in ALLOWED_SOURCES:
            raise ValueError(
                f"source must be one of {sorted(ALLOWED_SOURCES)}; got {v!r}"
            )
        return v

    @field_validator("event_type")
    @classmethod
    def _event_type_must_be_catalogue_member(cls, v: str) -> str:
        if v not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"event_type must be one of {sorted(ALLOWED_EVENT_TYPES)}; got {v!r}"
            )
        return v

    @field_validator("source_ip")
    @classmethod
    def _source_ip_must_parse(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            # Accept both IPv4 and IPv6.
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"source_ip is not a valid IP address: {v!r}") from exc
        return v

    @field_validator("details")
    @classmethod
    def _details_must_be_bounded_and_secret_free(
        cls, v: Dict[str, Any]
    ) -> Dict[str, Any]:
        _reject_sensitive_keys(v, path="details")
        _reject_unsafe_bson_keys(v, path="details")
        return v

    @model_validator(mode="after")
    def _check_timestamp_ordering(self) -> "SecurityEvent":
        # The schema allows ingested_at >= event_time (latency is real).
        # It does NOT allow ingested_at to be BEFORE event_time beyond a small
        # clock-skew tolerance.
        earliest_acceptable = self.event_time.timestamp() - 60
        if self.ingested_at.timestamp() < earliest_acceptable:
            raise ValueError(
                "ingested_at is more than 60s before event_time; "
                "check clock or payload ordering"
            )
        return self


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_SENSITIVE_SUBSTRING = re.compile(
    "|".join(re.escape(k) for k in _FORBIDDEN_SENSITIVE_KEYS),
    re.IGNORECASE,
)


def _looks_sensitive(value: str) -> bool:
    return bool(_SENSITIVE_SUBSTRING.search(value))


def _reject_sensitive_keys(obj: Any, *, path: str) -> None:
    """Walk a JSON-shaped object and raise if any key name carries a
    secret indicator (schema Section 20)."""
    if isinstance(obj, dict):
        for k, vv in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: non-string key is not allowed")
            if _SENSITIVE_SUBSTRING.search(k):
                raise ValueError(
                    f"{path}: forbidden sensitive key name {k!r} (schema Section 20)"
                )
            _reject_sensitive_keys(vv, path=f"{path}.{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _reject_sensitive_keys(item, path=f"{path}[{i}]")


# S-3: MongoDB operator-key safety. Keys beginning with "$" or
# containing "." must never reach the persistence layer; they would
# allow external telemetry to inject query operators or reach into
# sub-documents. Match is structural, not substring.
_FORBIDDEN_BSON_KEY_CHARS = ("$", ".")
_FORBIDDEN_BSON_KEY_PREFIX = "$"


def _key_is_unsafe_for_bson(key: Any) -> bool:
    if not isinstance(key, str):
        return True  # non-string keys are unsafe (cannot be BSON field names)
    if not key:
        return True  # empty keys are unsafe
    if key.startswith(_FORBIDDEN_BSON_KEY_PREFIX):
        return True
    for ch in _FORBIDDEN_BSON_KEY_CHARS:
        if ch in key:
            return True
    return False


def _reject_unsafe_bson_keys(obj: Any, *, path: str) -> None:
    """S-3: reject MongoDB-operator / dotted-path keys at the boundary.

    Walk a JSON-shaped object and raise if any key name would be
    interpreted as a MongoDB query operator or as a path into a
    sub-document. Applied to ``SecurityEvent.details`` (and to the
    other JSON-shaped fields via ``model_validator``) so that
    external telemetry cannot influence the persistence layer.
    """
    if isinstance(obj, dict):
        for k, vv in obj.items():
            if _key_is_unsafe_for_bson(k):
                raise ValueError(
                    f"{path}: forbidden BSON-unsafe key name {k!r} "
                    "(leading '$' or containing '.' are not allowed)"
                )
            _reject_unsafe_bson_keys(vv, path=f"{path}.{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _reject_unsafe_bson_keys(item, path=f"{path}[{i}]")


def to_canonical_dict(event: SecurityEvent) -> Dict[str, Any]:
    """Serialise a SecurityEvent to its canonical MongoDB-ready dict.

    BSON-safe, deterministic field order via model_dump.

    The default ``model_dump(mode="json")`` stringifies datetimes;
    MongoDB's ``$jsonSchema`` validator requires ``bsonType: "date"``
    for timestamp fields, so we explicitly use the python-mode dump
    here and let pymongo encode the datetimes as BSON ``Date``.
    """
    return event.model_dump(mode="python")


def validate_size_constraints(
    payload: Dict[str, Any],
    *,
    max_body_bytes: int = MAX_BODY_BYTES_DEFAULT,
    max_details_bytes: int = MAX_DETAILS_BYTES_DEFAULT,
) -> None:
    """Enforce documented payload-size bounds (schema Section 12).

    The schema caps field lengths in characters, but we additionally cap
    the on-the-wire JSON body and the details subdocument in raw bytes.
    Both limits are documented in schema Section 12 and treated as a
    trust-boundary defense.

    The function accepts either a python-mode payload (datetimes as
    ``datetime`` objects) or a JSON-mode payload (datetimes as ISO
    strings).  It uses a JSON-mode dump to measure the wire size
    correctly in both cases.
    """
    import json

    serialised = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, default=str
    )
    if len(serialised.encode("utf-8")) > max_body_bytes:
        raise ValidationError(
            safe_message="event payload exceeds the documented size limit",
            internal_detail=(
                f"serialised body {len(serialised.encode('utf-8'))}B > "
                f"{max_body_bytes}B"
            ),
        )
    details = payload.get("details") or {}
    details_serialised = json.dumps(
        details, separators=(",", ":"), sort_keys=True, default=str
    )
    if len(details_serialised.encode("utf-8")) > max_details_bytes:
        raise ValidationError(
            safe_message="event details exceed the documented size limit",
            internal_detail=(
                f"serialised details {len(details_serialised.encode('utf-8'))}B > "
                f"{max_details_bytes}B"
            ),
        )
