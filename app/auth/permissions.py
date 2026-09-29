"""Authorization permission catalogue.

Reference: docs/PHASE 3/AUTH_RBAC.md (Identity Classes,
Resource Authorization Rules), docs/PHASE 2/API_CONTRACTS.md.

Phase 4.8 introduces a **closed-set** permission catalogue
covering the operations the proxy / core-backend actually
expose. Each permission is a stable string so it can appear
in audit records without translation. Inventing new
permissions at the call site is forbidden; future IAM may
extend the catalogue.

The catalogue covers the four documented resource types
(SecurityEvent, Detection, Incident, Report,
RoutingRecommendation, Rule) and the centralized-analysis
permission, the report-generation permission, and the
case-access permission, as documented in Phase 4.8.

Permission string convention
----------------------------

Permissions are namespaced by resource + action:

* ``case:read`` / ``case:read:any`` - case access control
* ``case:centralized:request`` - centralized analysis request
* ``report:read`` / ``report:generate`` - report generation
* ``routing:read`` / ``routing:override`` - routing access
* ``event:read`` - SecurityEvent visibility
* ``detection:read`` - detection visibility
* ``rule:read`` / ``rule:write`` - rule management

Per-role defaults are explicit and documented below.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Iterable

from .identity import (
    ADMIN_ROLE,
    ANALYST_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
)


# ----------------------------------------------------------------- catalogue
# Each permission is a stable string. The audit subsystem
# uses the same string in audit-record ``action`` fields.
class Permission:
    """Closed-set permission strings.

    Exposed as class attributes so callers can write
    ``Permission.CASE_READ`` instead of a magic string. The
    actual value is what matters for audit and the
    authorization decision.
    """

    # Case / incident
    CASE_READ = "case:read"
    CASE_READ_ANY = "case:read:any"
    CASE_CENTRALIZED_REQUEST = "case:centralized:request"
    CASE_CENTRALIZED_REQUEST_ANY = "case:centralized:request:any"

    # Reports
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    REPORT_READ_ANY = "report:read:any"
    REPORT_GENERATE_ANY = "report:generate:any"

    # Routing
    ROUTING_READ = "routing:read"
    ROUTING_READ_ANY = "routing:read:any"
    ROUTING_OVERRIDE = "routing:override"

    # Evidence visibility
    EVENT_READ = "event:read"
    DETECTION_READ = "detection:read"
    CORRELATION_READ = "correlation:read"
    TIMELINE_READ = "timeline:read"
    OVERVIEW_READ = "overview:read"

    # Rule management (admin only)
    RULE_READ = "rule:read"
    RULE_WRITE = "rule:write"

    # Source management (admin only). Distinct from
    # RULE_WRITE so a future slice can grant one without
    # the other. Previously the source-management layer
    # reused RULE_WRITE (an odd coupling) — see the
    # SourceManagementService._require_role() note.
    SOURCE_READ = "source:read"
    SOURCE_WRITE = "source:write"

    # Capability registry (Phase 5.1, admin writes; analyst/admin reads).
    CAPABILITY_READ = "capability:read"
    CAPABILITY_WRITE = "capability:write"


ALL_PERMISSIONS: FrozenSet[str] = frozenset(
    v for k, v in vars(Permission).items()
    if not k.startswith("_") and isinstance(v, str)
)


# Per-role default permission sets. An identity with an
# empty ``permissions`` tuple uses the role default; an
# identity with a non-empty tuple OVERRIDES the role default.
ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    ANALYST_ROLE: frozenset({
        Permission.CASE_READ,
        Permission.CASE_CENTRALIZED_REQUEST,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
        Permission.ROUTING_READ,
        Permission.EVENT_READ,
        Permission.DETECTION_READ,
        Permission.CORRELATION_READ,
        Permission.TIMELINE_READ,
        Permission.OVERVIEW_READ,
        Permission.RULE_READ,
        Permission.SOURCE_READ,
        Permission.CAPABILITY_READ,
    }),
    ADMIN_ROLE: frozenset({
        Permission.CASE_READ,
        Permission.CASE_READ_ANY,
        Permission.CASE_CENTRALIZED_REQUEST,
        Permission.CASE_CENTRALIZED_REQUEST_ANY,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ_ANY,
        Permission.REPORT_GENERATE_ANY,
        Permission.ROUTING_READ,
        Permission.ROUTING_READ_ANY,
        Permission.ROUTING_OVERRIDE,
        Permission.EVENT_READ,
        Permission.DETECTION_READ,
        Permission.CORRELATION_READ,
        Permission.TIMELINE_READ,
        Permission.OVERVIEW_READ,
        Permission.RULE_READ,
        Permission.RULE_WRITE,
        Permission.SOURCE_READ,
        Permission.SOURCE_WRITE,
        Permission.CAPABILITY_READ,
        Permission.CAPABILITY_WRITE,
    }),
    # Collectors submit events but cannot read cases /
    # reports / routing.
    #
    # OWNER-52-02 (Phase 5.2 baseline): the collector role carries NO
    # analyst-plane read permission. A collector is a SOURCE identity
    # (docs/PHASE 3/AUTH_RBAC.md §10-§12): it authenticates to the
    # ingestion boundary, submits SecurityEvents and reads the
    # ingestion response. There is no wire link from a collector
    # *subject* to the events it submitted (events are attributed by
    # `provenance.source_instance_id`, a source credential, not a
    # session subject), so the previous `event:read` grant could not be
    # scoped to "its own submitted events" and in practice exposed every
    # recently ingested event to a semi-trusted role. Minimum-permission
    # is the documented direction, so the grant was removed rather than
    # left unscoped.
    COLLECTOR_ROLE: frozenset(),
    # Internal services get the full read surface minus
    # override / write.
    INTERNAL_SERVICE_ROLE: frozenset({
        Permission.CASE_READ,
        Permission.REPORT_READ,
        Permission.ROUTING_READ,
        Permission.EVENT_READ,
        Permission.DETECTION_READ,
        Permission.CORRELATION_READ,
        Permission.TIMELINE_READ,
        Permission.OVERVIEW_READ,
        Permission.RULE_READ,
        Permission.SOURCE_READ,
        Permission.CAPABILITY_READ,
    }),
}


def _permissions_for_role(role: str) -> FrozenSet[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(
    *,
    role: str,
    identity_permissions: Iterable[str],
    permission: str,
) -> bool:
    """Return True iff the (role, override) tuple carries the
    requested permission.

    The rule is:

    * if ``identity_permissions`` is empty, fall back to the
      role default;
    * otherwise, the explicit ``identity_permissions``
      tuple is the source of truth (no role defaults
      mixed in).

    This is the single authoritative permission check used
    by the proxy / core services. It is intentionally tiny
    so future IAM can replace it without disturbing every
    call site.
    """
    if not isinstance(role, str) or not role:
        return False
    if not isinstance(permission, str) or not permission:
        return False
    perm_tuple = tuple(identity_permissions or ())
    if perm_tuple:
        return permission in perm_tuple
    return permission in _permissions_for_role(role)


__all__ = [
    "ALL_PERMISSIONS",
    "Permission",
    "ROLE_PERMISSIONS",
    "has_permission",
]