"""Identity (principal) model and in-memory identity store.

Reference: docs/PHASE 3/AUTH_RBAC.md (Identity Classes,
Security Analyst, Security Admin, Collector, Internal Service).

The Phase 4.8 identity layer is intentionally tiny:

* :class:`Role` - a closed enum of the four documented
  identity classes (analyst / admin / collector /
  internal_service).
* :class:`Identity` - a frozen principal carrying the
  user-id, the role, an optional display name, and a list of
  permissions.
* :class:`InMemoryIdentityStore` - the deterministic,
  in-memory implementation used by the Phase 4.8 slice.

AUTH-001 remediation: the identity store now also carries
a credential map (``{subject_id: shared_secret}``) used by
the credential-verifying ``auth.issue`` flow. Tests inject
explicit credentials; production deployments wire them
through ``PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS``. The
default empty catalogue forces every test / deployment to
inject credentials; no default password is ever hard-coded.

The identity layer does NOT store tokens or signing
material. It is read-only.
"""
from __future__ import annotations

import hmac as _hmac
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple


# Canonical role identifiers. These strings appear in
# session tokens and audit records, so they MUST be stable.
ANALYST_ROLE = "analyst"
ADMIN_ROLE = "admin"
COLLECTOR_ROLE = "collector"
INTERNAL_SERVICE_ROLE = "internal_service"


class Role(str, Enum):
    """The closed-set identity catalogue."""

    ANALYST = ANALYST_ROLE
    ADMIN = ADMIN_ROLE
    COLLECTOR = COLLECTOR_ROLE
    INTERNAL_SERVICE = INTERNAL_SERVICE_ROLE


# Defaults (so callers don't need to import the module-level
# constants). The aliases preserve the documented vocabulary.
DEFAULT_ROLES: Tuple[str, ...] = (
    ANALYST_ROLE,
    ADMIN_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
)


@dataclass(frozen=True)
class Identity:
    """A verified principal.

    An :class:`Identity` is the canonical result of a
    successful session-token verification. It carries:

    * ``subject_id`` - the stable per-identity id.
    * ``role`` - one of :class:`Role`.
    * ``display_name`` - optional human-readable label;
      never used for authorization.
    * ``permissions`` - explicit allow-list of permission
      strings. If non-empty, these OVERRIDE the role's
      default permission set. If empty, the role defaults
      apply.

    The dataclass is frozen so a verified identity cannot be
    mutated mid-request by an attacker.
    """

    subject_id: str
    role: str
    display_name: Optional[str] = None
    permissions: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, str) or not self.subject_id:
            raise ValueError("Identity.subject_id must be a non-empty str")
        if not isinstance(self.role, str) or self.role not in DEFAULT_ROLES:
            raise ValueError(
                f"Identity.role must be one of {DEFAULT_ROLES}, got {self.role!r}"
            )
        # Force the permissions tuple into a tuple of strings
        # so a caller cannot smuggle in a dict / list.
        object.__setattr__(
            self,
            "permissions",
            tuple(str(p) for p in self.permissions),
        )

    @property
    def is_human(self) -> bool:
        """True for analyst / admin; False for collector / internal service."""
        return self.role in (ANALYST_ROLE, ADMIN_ROLE)

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "role": self.role,
            "display_name": self.display_name,
            "permissions": list(self.permissions),
        }


class IdentityStore:
    """Read-only lookup interface."""

    def get(self, subject_id: str) -> Optional[Identity]:
        raise NotImplementedError

    def verify_credential(
        self, subject_id: str, credential: str,
    ) -> bool:
        """AUTH-001: verify a presented credential against the
        identity store. Returns ``True`` iff the credential
        matches the one registered for ``subject_id``. The
        base class default raises :class:`NotImplementedError`
        so every concrete store must opt-in to credential
        verification.
        """
        raise NotImplementedError


class InMemoryIdentityStore(IdentityStore):
    """Deterministic, in-memory identity catalogue.

    Constructed with an explicit ``identities`` mapping so
    tests can inject a known catalogue. AUTH-001: the
    default catalogue is intentionally **empty** so
    misconfigured deployments fail closed (no default
    credentials are ever hard-coded). Tests / demos inject
    their own catalogue plus a credentials map.
    """

    DEFAULT_IDENTITIES: Dict[str, Identity] = {}

    def __init__(
        self,
        identities: Optional[Dict[str, Identity]] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> None:
        seed = identities if identities is not None else self.DEFAULT_IDENTITIES
        if not isinstance(seed, dict):
            raise ValueError("identities must be a dict[subject_id -> Identity]")
        self._identities: Dict[str, Identity] = {
            str(k): v for k, v in seed.items()
        }
        cred_seed = credentials if credentials is not None else {}
        if not isinstance(cred_seed, dict):
            raise ValueError(
                "credentials must be a dict[subject_id -> str]"
            )
        self._credentials: Dict[str, str] = {
            str(k): str(v) for k, v in cred_seed.items()
        }

    def get(self, subject_id: str) -> Optional[Identity]:
        if not isinstance(subject_id, str) or not subject_id:
            return None
        return self._identities.get(subject_id)

    def verify_credential(
        self, subject_id: str, credential: str,
    ) -> bool:
        """AUTH-001: verify a presented credential.

        Uses :func:`hmac.compare_digest` for timing-safe
        comparison. Returns ``False`` when either input is
        missing / wrong type or when the subject has no
        registered credential.
        """
        if not isinstance(subject_id, str) or not subject_id:
            return False
        if not isinstance(credential, str) or not credential:
            return False
        expected = self._credentials.get(subject_id)
        if expected is None:
            return False
        return _hmac.compare_digest(expected, credential)

    def all_subject_ids(self) -> Tuple[str, ...]:
        return tuple(self._identities.keys())

    def __contains__(self, subject_id: object) -> bool:
        return isinstance(subject_id, str) and subject_id in self._identities


__all__ = [
    "ADMIN_ROLE",
    "ANALYST_ROLE",
    "COLLECTOR_ROLE",
    "DEFAULT_ROLES",
    "Identity",
    "IdentityStore",
    "InMemoryIdentityStore",
    "INTERNAL_SERVICE_ROLE",
    "Role",
]