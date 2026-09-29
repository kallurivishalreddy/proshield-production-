"""Source -> Capability binding (Phase 5.2 — Source Architecture 2.0).

Reference: docs/PHASE 5(V3)/PHASE 5.0/PHASE-05-00-V3-ARCHITECTURE-FREEZE.md
(§7.1, §10.1, §12.1, §12.3, §38),
docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md (§19).

A :class:`app.sources.SourceInstance` resolves to exactly one
:class:`app.capabilities.Capability` (freeze §7.1 #6/#7). This module owns
the two things that decision needs and nothing else:

1. **The deterministic legacy mapping** used by the one-time backfill.
   It maps a *known* ``SourceType`` to the *seeded* capability id that
   owns that source family. There is deliberately no fallback: an
   unknown/unresolvable input returns ``None`` so the caller quarantines
   the row instead of inventing an owner (freeze §38).
2. **Binding validation against the registry record.** A binding is only
   accepted when the capability exists, is live (not planned / retired /
   archived), and — when a mapping profile is requested — actually
   declares that profile for the source's own source type.

Unsafe transformation is impossible by construction: a mapping profile is
a bounded ``dict`` of ``field -> canonical target`` string pairs
(``app.capabilities.models.MappingProfile`` with ``extra="forbid"``).
Nothing here evaluates, imports or compiles anything.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from .errors import SourceCapabilityBindingError
from .models import SourceType

_log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- map
#: Deterministic ``SourceType -> seeded capability id`` map (Master Plan §19).
#:
#: Every value is a capability id that ``app.capabilities.seeds`` ships, so
#: the backfill can never point a legacy source at an id nobody owns:
#:
#: * ``nginx``      -> ``cap-nginx``      (active, live connector)
#: * ``simulator``  -> ``cap-simulator``  (active, live connector)
#: * ``waf``        -> ``cap-waf``        (seeded as ``planned``)
#: * ``iam``        -> ``cap-iam``        (seeded as ``planned``)
#: * ``rate_limit`` -> ``cap-rate-limit`` (seeded as ``planned``)
#: * ``network``    -> ``cap-network``    (seeded as ``planned``)
SOURCE_TYPE_TO_CAPABILITY_ID: Dict[SourceType, str] = {
    SourceType.NGINX: "cap-nginx",
    SourceType.SIMULATOR: "cap-simulator",
    SourceType.WAF: "cap-waf",
    SourceType.IAM: "cap-iam",
    SourceType.RATE_LIMIT: "cap-rate-limit",
    SourceType.NETWORK: "cap-network",
}

#: The inverse view of the map above: the single source family each seeded
#: capability id owns. Needed because a *planned* capability's
#: ``implementation_ref`` is literally ``"planned"`` and therefore carries no
#: connector family, yet a cross-family binding must still be refused on the
#: backfill path (Master Plan §19, "mismatched source triple"). Derived from
#: the map above — never hand-maintained, so the two can never disagree.
CAPABILITY_ID_TO_SOURCE_TYPE: Dict[str, str] = {
    capability_id: source_type.value
    for source_type, capability_id in SOURCE_TYPE_TO_CAPABILITY_ID.items()
}

#: The concrete (non-planned) capability ids a *new* source may be bound to.
#: A ``planned`` capability has no connector implementation, so activating a
#: source on it would advertise phantom coverage (Phase 5.1 §18.5 truth rule).
LIVE_CAPABILITY_IDS: frozenset = frozenset({"cap-nginx", "cap-simulator"})

#: Capability statuses that may own a *new* source binding.
BINDABLE_CAPABILITY_STATUSES: frozenset = frozenset({"active"})


@dataclass(frozen=True)
class ResolvedBinding:
    """The outcome of resolving/validating a capability binding."""

    capability_id: str
    capability_version: int
    mapping_profile_id: Optional[str]
    source_type: Optional[str] = None

    def as_update(self) -> Dict[str, Any]:
        """Return the ``SourceInstance`` field updates for this binding."""
        return {
            "capability_id": self.capability_id,
            "capability_version": int(self.capability_version),
            "mapping_profile_id": self.mapping_profile_id,
        }


def resolve_capability_id_for_type(source_type: Any) -> Optional[str]:
    """Deterministically map a ``SourceType`` to a capability id.

    Returns ``None`` — never a guess — when the input is not a known
    ``SourceType``. ``None`` is the signal the migration uses to
    quarantine the row as REQUIRES VERIFICATION.
    """
    if isinstance(source_type, SourceType):
        return SOURCE_TYPE_TO_CAPABILITY_ID.get(source_type)
    if isinstance(source_type, str):
        try:
            return SOURCE_TYPE_TO_CAPABILITY_ID.get(SourceType(source_type))
        except ValueError:
            return None
    return None


def resolve_capability_id_for_source_string(
    source_string: Any,
) -> Optional[str]:
    """Deterministically map a canonical ``SecurityEvent.source`` string.

    Used by the legacy *rule* backfill, where the only available input is
    the rule's ``sources[]`` applicability tuple.
    """
    if not isinstance(source_string, str) or not source_string:
        return None
    for st in SourceType:
        if st.value == source_string:
            return SOURCE_TYPE_TO_CAPABILITY_ID.get(st)
    return None


def resolve_capability_id_for_sources(
    sources: Iterable[str],
) -> Optional[str]:
    """Resolve a capability id from a rule's ``sources[]`` applicability.

    Returns a capability id **only when the resolution is unambiguous**:
    every declared source must resolve, and they must all resolve to the
    *same* capability. A cross-source rule (e.g. ``nginx`` + ``waf``) is
    legitimately ambiguous — it belongs to no single capability — so the
    result is ``None`` and the rule is left with no capability claim
    instead of being handed an invented one.
    """
    resolved: set = set()
    seen_any = False
    for src in sources or ():
        seen_any = True
        cid = resolve_capability_id_for_source_string(src)
        if cid is None:
            return None
        resolved.add(cid)
    if not seen_any or len(resolved) != 1:
        return None
    return next(iter(resolved))


# ------------------------------------------------------------------- validation
def _capability_field(capability: Any, name: str) -> Any:
    """Read ``name`` from a capability mapping view or model instance."""
    if isinstance(capability, Mapping):
        return capability.get(name)
    return getattr(capability, name, None)


def _profile_entries(capability: Any) -> Sequence[Any]:
    raw = _capability_field(capability, "mapping_profiles")
    if raw is None:
        return ()
    if isinstance(raw, (str, bytes)):
        return ()
    try:
        return tuple(raw)
    except TypeError:
        return ()


def declared_mapping_profiles(
    capability: Any, *, source_type: Optional[str] = None
) -> list:
    """List the profile ids a capability declares, optionally per source type."""
    out = []
    for profile in _profile_entries(capability):
        if isinstance(profile, Mapping):
            pid = profile.get("profile_id")
            ptype = profile.get("source_type")
        else:
            pid = getattr(profile, "profile_id", None)
            ptype = getattr(profile, "source_type", None)
        if not isinstance(pid, str) or not pid:
            continue
        if source_type is not None and ptype != source_type:
            continue
        out.append(pid)
    return out


def deterministic_mapping_profile(
    capability: Any, *, source_type: Optional[str] = None
) -> Optional[str]:
    """The single declared mapping profile for a source type, else ``None``.

    Selecting the *only* profile a capability declares for a source type is
    deterministic, not a guess. If it declares none, or several, there is no
    deterministic answer and the caller must resolve the profile explicitly.

    Both binding paths (a new source in ``validate_capability_binding`` and
    the legacy backfill in :mod:`app.sources.migration`) resolve through this
    one helper so a migrated row cannot land on a different profile than the
    equivalent natively-registered row (5.2-R-05).
    """
    declared = declared_mapping_profiles(capability, source_type=source_type)
    return declared[0] if len(declared) == 1 else None


def validate_capability_binding(
    capability: Any,
    *,
    source_type: Optional[str] = None,
    mapping_profile_id: Optional[str] = None,
    allow_non_active: bool = False,
) -> ResolvedBinding:
    """Validate a (capability, mapping profile) pair for a source.

    ``capability`` may be the registry model or the service's view dict.

    Raises :class:`SourceCapabilityBindingError` (HTTP 400) for every
    refusal. Never silently downgrades to "no capability": a binding
    request that cannot be satisfied is an error, not an omission.
    """
    if capability is None:
        raise SourceCapabilityBindingError(
            safe_message="unknown capability",
            internal_detail="capability lookup returned None",
        )
    capability_id = _capability_field(capability, "capability_id")
    if not isinstance(capability_id, str) or not capability_id:
        raise SourceCapabilityBindingError(
            safe_message="unknown capability",
            internal_detail="capability record carries no capability_id",
        )
    version = _capability_field(capability, "version")
    try:
        version_int = int(version)
    except (TypeError, ValueError):
        raise SourceCapabilityBindingError(
            safe_message="capability has no usable version",
            internal_detail=f"capability_version={version!r}",
        )
    if version_int < 1:
        raise SourceCapabilityBindingError(
            safe_message="capability has no usable version",
            internal_detail=f"capability_version={version_int}",
        )
    status = _capability_field(capability, "status")
    status_str = status.value if hasattr(status, "value") else status
    impl = _capability_field(capability, "implementation_ref")
    impl_str = impl.value if hasattr(impl, "value") else impl

    if not allow_non_active:
        if status_str not in BINDABLE_CAPABILITY_STATUSES:
            raise SourceCapabilityBindingError(
                safe_message=(
                    "capability is not accepting new sources "
                    f"(status={status_str!r})"
                ),
                internal_detail=(
                    f"capability_id={capability_id!r} status={status_str!r}"
                ),
            )
        if impl_str == "planned":
            raise SourceCapabilityBindingError(
                safe_message=(
                    "capability has no connector implementation "
                    "(planned); a source cannot be bound to it"
                ),
                internal_detail=(
                    f"capability_id={capability_id!r} "
                    "implementation_ref='planned'"
                ),
            )

    # Phase 5.2 (master plan §19, "mismatched source triple"): the
    # capability's shipped connector family must BE this source's source
    # type — on BOTH paths, not only the new-source path. A capability is the
    # reusable owner of one connector implementation, so binding an ``nginx``
    # source to ``cap-simulator`` would let one connector claim another's
    # telemetry. The client may request a capability, but it cannot make it
    # implement something it does not implement.
    #
    # This check is deliberately OUTSIDE the ``allow_non_active`` branch: the
    # legacy backfill binds a source to its own family's *planned* capability
    # (``implementation_ref == 'planned'``), and that must stay permitted —
    # but only for the family that capability actually owns. A planned
    # capability's ``implementation_ref`` is literally "planned" and so
    # carries no family, which is read from the deterministic map above in
    # reverse. Nothing is invented: a capability outside that map has no
    # declared family and this check abstains rather than guess (5.2-R-01).
    family = impl_str
    if impl_str == "planned":
        family = CAPABILITY_ID_TO_SOURCE_TYPE.get(capability_id)
    if (
        isinstance(source_type, str)
        and source_type
        and isinstance(family, str)
        and family
        and family != source_type
    ):
        raise SourceCapabilityBindingError(
            safe_message=(
                "capability does not implement this source type"
            ),
            internal_detail=(
                f"capability_id={capability_id!r} "
                f"family={family!r} "
                f"implementation_ref={impl_str!r} "
                f"source_type={source_type!r} "
                f"allow_non_active={allow_non_active!r}"
            ),
        )

    resolved_profile: Optional[str] = None
    declared = declared_mapping_profiles(capability, source_type=source_type)
    if mapping_profile_id is not None:
        if not isinstance(mapping_profile_id, str) or not mapping_profile_id:
            raise SourceCapabilityBindingError(
                safe_message="mapping_profile_id must be a non-empty string",
                internal_detail=f"got {type(mapping_profile_id).__name__}",
            )
        all_declared = declared_mapping_profiles(capability)
        if mapping_profile_id not in declared:
            raise SourceCapabilityBindingError(
                safe_message=(
                    "capability does not declare that mapping profile "
                    "for this source type"
                ),
                internal_detail=(
                    f"capability_id={capability_id!r} "
                    f"source_type={source_type!r} "
                    f"requested={mapping_profile_id!r} "
                    f"declared_for_type={sorted(declared)} "
                    f"declared_total={sorted(all_declared)}"
                ),
            )
        resolved_profile = mapping_profile_id
    else:
        # Exactly one declared profile for this source type: selecting it is
        # deterministic, not a guess. Resolved through the shared helper so
        # the new-source path and the legacy backfill cannot drift.
        resolved_profile = deterministic_mapping_profile(
            capability, source_type=source_type
        )

    return ResolvedBinding(
        capability_id=capability_id,
        capability_version=version_int,
        mapping_profile_id=resolved_profile,
        source_type=source_type,
    )


def builtin_capability_index() -> Dict[str, Any]:
    """Index of the **shipped** capability definitions, keyed by id.

    Used as the binding authority when a deployment wires the source layer
    without a live capability registry (legacy Phase 4.9 harnesses and the
    direct-construction unit tests). This is *not* a fabricated owner: the
    ids come from the frozen deterministic map above and the records come
    from :mod:`app.capabilities.seeds`, the same catalogue the registry
    seeds itself from on every startup. The live registry, when present,
    always takes precedence (it may carry a newer version or a status
    change).
    """
    from ..capabilities.seeds import build_builtin_capabilities

    return {
        str(record["capability_id"]): record
        for record in build_builtin_capabilities()
    }


__all__ = [
    "BINDABLE_CAPABILITY_STATUSES",
    "CAPABILITY_ID_TO_SOURCE_TYPE",
    "LIVE_CAPABILITY_IDS",
    "SOURCE_TYPE_TO_CAPABILITY_ID",
    "ResolvedBinding",
    "builtin_capability_index",
    "declared_mapping_profiles",
    "deterministic_mapping_profile",
    "resolve_capability_id_for_source_string",
    "resolve_capability_id_for_sources",
    "resolve_capability_id_for_type",
    "validate_capability_binding",
]


