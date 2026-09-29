"""Source identity tokens (Phase 4.9).

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

A :class:`SourceIdentityToken` is the HMAC-signed, time-bounded
proof that an inbound payload comes from a trusted source
instance. It is the **only** thing the ingress boundary
trusts to identify a source; the connector type and the
canonical ``SecurityEvent.source`` are then validated against
the registered source instance.

Design
------

The implementation mirrors the Phase 4.8
:class:`SessionTokenService` (HMAC over a canonical JSON
body, deterministic JSON serialisation).

Wire format
-----------

::

    sit-<uuidv7>.<base64url-body>.<base64url-hmac>

``base64url`` uses the URL-safe alphabet without padding so
the token is single-line and header-safe.

Secret material
---------------

The signing key is the ``source_signing_key`` config knob.
A missing key is rejected at token-issuance time (fail-fast
for misconfigured production startups; the test fixtures
inject a deterministic key). The service layer refuses to
issue a token when the source instance is not in
``VALIDATED`` or ``ENABLED`` state (and only ``ENABLED``
sources are accepted at the ingress boundary).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .errors import SourceIdentityTokenError
from .models import (
    SourceIdentityToken,
    SourceInstanceId,
    SourceType,
    source_string_for_type,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def new_development_signing_key() -> str:
    """Generate a deterministic dev-mode signing key.

    Tests / demos inject this so token issuance / verification
    is reproducible. Production deployments MUST supply a
    real key through the ``PROSHIELD_SOURCE_SIGNING_KEY``
    environment variable.
    """
    return os.urandom(32).hex()


def _canonical_body(
    *,
    token_id: str,
    source_instance_id: str,
    source_type: str,
    source: str,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    key_id: str = "k1",
    capability_id: Optional[str] = None,
) -> bytes:
    body = {
        "token_id": token_id,
        "source_instance_id": source_instance_id,
        "source_type": source_type,
        "source": source,
        "issued_at": int(issued_at.timestamp()),
        "expires_at": int(expires_at.timestamp()),
        "nonce": nonce,
        "key_id": key_id,
    }
    # Phase 5.2: the capability is part of the signed claim *only when the
    # source is bound*. Omitting the key entirely (rather than signing a
    # null) keeps a pre-Phase-5.2 token's canonical body byte-identical, so
    # a token issued by an older build still verifies during a rolling
    # deployment instead of failing as a signature mismatch.
    if capability_id is not None:
        body["capability_id"] = capability_id
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _compute_signature(secret: str, body: bytes) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).digest()
    return _b64url(digest)


@dataclass(frozen=True)
class SourceIdentityTokenIssuer:
    """Issue :class:`SourceIdentityToken` objects for a known source."""

    secret: str
    lifetime_seconds: int = 3600
    key_id: str = "k1"
    max_lifetime_seconds: int = 3600  # S-2 server-side cap

    def __post_init__(self) -> None:
        if not isinstance(self.secret, str) or not self.secret:
            raise ValueError(
                "secret must be a non-empty str (set "
                "PROSHIELD_SOURCE_SIGNING_KEY in production)"
            )
        if (
            not isinstance(self.lifetime_seconds, int)
            or self.lifetime_seconds < 1
        ):
            raise ValueError("lifetime_seconds must be a positive int")
        if (
            not isinstance(self.max_lifetime_seconds, int)
            or self.max_lifetime_seconds < 1
        ):
            raise ValueError("max_lifetime_seconds must be a positive int")
        if self.lifetime_seconds > self.max_lifetime_seconds:
            raise ValueError(
                "lifetime_seconds must not exceed max_lifetime_seconds"
            )

    def issue(
        self,
        *,
        source_instance_id: SourceInstanceId,
        source_type: SourceType,
        capability_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> SourceIdentityToken:
        """Issue a fresh token for a registered source instance.

        Phase 5.2: when the source instance is bound to a capability the
        binding is included in the *signed* claim, so a token can never be
        replayed against a different capability (the signature covers it)
        and the ingress boundary can prove which capability the authenticated
        source owned at issuance time.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            raise ValueError("now must be timezone-aware UTC")
        effective_lifetime = min(
            self.lifetime_seconds, self.max_lifetime_seconds
        )
        expires_at = datetime.fromtimestamp(
            now.timestamp() + effective_lifetime,
            tz=timezone.utc,
        )
        nonce = _b64url(os.urandom(16))
        token_id = _make_token_id(now)
        body = _canonical_body(
            token_id=token_id,
            source_instance_id=source_instance_id,
            source_type=source_type.value,
            source=source_string_for_type(source_type),
            issued_at=now,
            expires_at=expires_at,
            nonce=nonce,
            key_id=self.key_id,
            capability_id=capability_id,
        )
        signature = _compute_signature(self.secret, body)
        return SourceIdentityToken(
            token_id=token_id,
            source_instance_id=source_instance_id,
            source_type=source_type.value,
            source=source_string_for_type(source_type),
            capability_id=capability_id,
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
            nonce=nonce,
            key_id=self.key_id,
            signature=signature,
        )

    def pack(self, token: SourceIdentityToken) -> str:
        """Serialise a token to its wire form."""
        key_id = getattr(token, "key_id", None) or self.key_id
        body = _canonical_body(
            token_id=token.token_id,
            source_instance_id=token.source_instance_id,
            source_type=token.source_type,
            source=token.source,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            nonce=token.nonce,
            key_id=key_id,
            capability_id=getattr(token, "capability_id", None),
        )
        signature = _compute_signature(self.secret, body)
        encoded_body = _b64url(body)
        return f"{token.token_id}.{encoded_body}.{signature}"


@dataclass(frozen=True)
class SourceIdentityTokenKeyring:
    """A collection of signing keys for source-identity tokens.

    The active key is the one used for issuance; previous keys may
    continue to verify tokens during a documented rotation overlap.
    Retired keys verify nothing.
    """

    keys: Dict[str, str]
    active_key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.keys, dict) or not self.keys:
            raise ValueError("keys must be a non-empty dict")
        if self.active_key_id not in self.keys:
            raise ValueError(
                f"active_key_id {self.active_key_id!r} not in keys"
            )
        for k, v in self.keys.items():
            if not isinstance(k, str) or not k:
                raise ValueError("key ids must be non-empty strings")
            if not isinstance(v, str) or not v:
                raise ValueError(
                    f"key {k!r} has empty secret (set the env var)"
                )

    def secret_for(self, key_id: str) -> Optional[str]:
        return self.keys.get(key_id)

    def is_known(self, key_id: str) -> bool:
        return key_id in self.keys


@dataclass(frozen=True)
class SourceIdentityTokenVerifier:
    """Verify a packed :class:`SourceIdentityToken`.

    Phase 4.9 post-review security controls:

    * keyring-based verification (D-4): the token's ``key_id`` is
      matched against a server-controlled keyring. Unknown or
      retired keys are rejected.
    * max-lifetime enforcement (S-2): the verifier independently
      bounds the lifetime of a token. A re-signed token cannot
      extend its allowed lifetime beyond ``max_lifetime_seconds``.
    * replay-store callback (R-1): the verifier consults an
      authoritative single-use store keyed on ``token_id``.
    * source-binding callback (S-1): the verifier consults a
      server-controlled source-resolver to look up the
      ``SourceInstance`` and rejects if the body's claims do not
      match the registered triple.
    """

    keyring: SourceIdentityTokenKeyring
    max_lifetime_seconds: int = 3600
    replay_store: Any = None
    source_resolver: Any = None
    replay_store_required: bool = True

    @classmethod
    def from_secret(
        cls,
        secret: str,
        *,
        max_lifetime_seconds: int = 3600,
        replay_store: Any = None,
        source_resolver: Any = None,
        key_id: str = "k1",
        require_replay_store: bool = True,
    ) -> "SourceIdentityTokenVerifier":
        """Build a verifier from a single shared secret.

        ST-02 fail-closed gate: ``require_replay_store``
        (default ``True``) refuses to construct without a
        non-``None`` ``replay_store``. Legacy in-memory
        tests can opt out by passing
        ``require_replay_store=False``.
        """
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty str")
        if require_replay_store and replay_store is None:
            raise ValueError(
                "replay_store is required (ST-02 fail-closed); "
                "pass require_replay_store=False to bypass"
            )
        keyring = SourceIdentityTokenKeyring(
            keys={key_id: secret}, active_key_id=key_id,
        )
        return cls(
            keyring=keyring,
            max_lifetime_seconds=max_lifetime_seconds,
            replay_store=replay_store,
            source_resolver=source_resolver,
            replay_store_required=require_replay_store,
        )

    def verify(
        self,
        packed: str,
        *,
        now: Optional[datetime] = None,
    ) -> SourceIdentityToken:
        """Parse + verify a packed token.

        Raises :class:`SourceIdentityTokenError` on any
        failure (malformed, tampered, expired, not-yet-valid,
        key unknown, lifetime exceeded, replay, source mismatch).
        """
        if not isinstance(packed, str) or not packed:
            raise SourceIdentityTokenError(
                safe_message="source identity token missing",
                internal_detail="empty packed form",
            )
        try:
            token_id, encoded_body, signature = packed.split(".")
        except ValueError as exc:
            raise SourceIdentityTokenError(
                safe_message="source identity token malformed",
                internal_detail=f"expected 3 parts: {exc}",
            )
        if (
            not isinstance(token_id, str)
            or not isinstance(encoded_body, str)
            or not isinstance(signature, str)
        ):
            raise SourceIdentityTokenError(
                safe_message="source identity token malformed",
                internal_detail="non-string parts",
            )
        try:
            body_bytes = _b64url_decode(encoded_body)
        except Exception as exc:  # noqa: BLE001
            raise SourceIdentityTokenError(
                safe_message="source identity token malformed",
                internal_detail=f"could not decode body: {exc}",
            )
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise SourceIdentityTokenError(
                safe_message="source identity token malformed",
                internal_detail=f"could not parse body: {exc}",
            )
        # D-4: key_id must be a known key.
        key_id = str(body.get("key_id", "k1"))
        secret = self.keyring.secret_for(key_id)
        if secret is None:
            raise SourceIdentityTokenError(
                safe_message="source identity token signature mismatch",
                internal_detail=(
                    f"token_id={token_id} key_id={key_id!r} unknown"
                ),
            )
        expected_sig = _compute_signature(secret, body_bytes)
        if not hmac.compare_digest(expected_sig, signature):
            raise SourceIdentityTokenError(
                safe_message="source identity token signature mismatch",
                internal_detail=(
                    f"token_id={token_id} expected_sig={expected_sig[:8]}..."
                    f" got_sig={signature[:8]}..."
                ),
            )
        try:
            issued_at = datetime.fromtimestamp(
                int(body["issued_at"]), tz=timezone.utc
            )
            expires_at = datetime.fromtimestamp(
                int(body["expires_at"]), tz=timezone.utc
            )
            token = SourceIdentityToken(
                token_id=body["token_id"],
                source_instance_id=body["source_instance_id"],
                source_type=body["source_type"],
                source=body["source"],
                capability_id=body.get("capability_id"),
                issued_at=issued_at,
                not_before=issued_at,
                expires_at=expires_at,
                nonce=body["nonce"],
                key_id=key_id,
                signature=signature,
            )
        except Exception as exc:  # noqa: BLE001
            raise SourceIdentityTokenError(
                safe_message="source identity token malformed",
                internal_detail=f"could not rebuild token: {exc}",
            )
        if now is None:
            now = datetime.now(timezone.utc)
        if token.not_before > now:
            raise SourceIdentityTokenError(
                safe_message="source identity token not yet valid",
                internal_detail=f"not_before={token.not_before.isoformat()}",
            )
        if token.expires_at <= now:
            raise SourceIdentityTokenError(
                safe_message="source identity token expired",
                internal_detail=(
                    f"expires_at={token.expires_at.isoformat()} "
                    f"now={now.isoformat()}"
                ),
            )
        # S-2: server-side max-lifetime enforcement.
        actual_lifetime = (
            token.expires_at - token.issued_at
        ).total_seconds()
        if actual_lifetime > self.max_lifetime_seconds:
            raise SourceIdentityTokenError(
                safe_message="source identity token lifetime exceeds server cap",
                internal_detail=(
                    f"lifetime={actual_lifetime:.0f}s > "
                    f"max_lifetime_seconds={self.max_lifetime_seconds}"
                ),
            )
        # S-1: source-binding check. The token's claims must match
        # the registered source for the claimed source_instance_id.
        if self.source_resolver is not None:
            registered = self.source_resolver(token.source_instance_id)
            if registered is None:
                raise SourceIdentityTokenError(
                    safe_message=(
                        "source identity token references unknown source"
                    ),
                    internal_detail=(
                        f"source_instance_id={token.source_instance_id!r} "
                        "not registered"
                    ),
                )
            r_type = getattr(registered, "source_type", None)
            r_source = getattr(registered, "source", None)
            r_type_val = (
                r_type.value if hasattr(r_type, "value") else r_type
            )
            if (
                r_type_val != token.source_type
                or r_source != token.source
            ):
                raise SourceIdentityTokenError(
                    safe_message=(
                        "source identity token does not match "
                        "registered source"
                    ),
                    internal_detail=(
                        f"registered=(type={r_type_val!r} "
                        f"source={r_source!r}) "
                        f"token=(type={token.source_type!r} "
                        f"source={token.source!r})"
                    ),
                )
            # Phase 5.2 capability cross-check. A token that was signed
            # against capability X must not authenticate a source instance
            # whose *current* binding is capability Y: that is a stale (or
            # forged) credential and it is rejected before any telemetry is
            # accepted. A token with no capability claim (issued before the
            # source was bound) is allowed through — the ingress boundary
            # then derives the capability from the authenticated source
            # instance rather than from the token.
            r_capability = getattr(registered, "capability_id", None)
            if (
                token.capability_id is not None
                and r_capability is not None
                and token.capability_id != r_capability
            ):
                raise SourceIdentityTokenError(
                    safe_message=(
                        "source identity token does not match the "
                        "registered source capability"
                    ),
                    internal_detail=(
                        f"token_capability={token.capability_id!r} "
                        f"registered_capability={r_capability!r}"
                    ),
                )
        # R-1: replay protection. The first use is accepted; any
        # subsequent use of the same token_id is rejected.
        # ST-02 fail-closed: when ``replay_store_required`` is
        # True (the production default) the verifier rejects
        # ANY token when no replay_store is wired — the
        # documented single-use guarantee is silent-by-default
        # otherwise.
        if self.replay_store_required and self.replay_store is None:
            raise SourceIdentityTokenError(
                safe_message=(
                    "source identity token replay store missing"
                ),
                internal_detail=(
                    "replay_store_required is True but no "
                    "replay_store was wired"
                ),
            )
        if self.replay_store is not None:
            accepted = self.replay_store.claim(
                token_id=token.token_id,
                expires_at=token.expires_at,
            )
            if not accepted:
                raise SourceIdentityTokenError(
                    safe_message="source identity token replay rejected",
                    internal_detail=f"token_id={token.token_id}",
                )
        return token


def _make_token_id(now: datetime) -> str:
    """Build a deterministic ``sit-<uuidv7>`` id from ``now``."""
    ts_ms = int(now.timestamp() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 56) & 0x0FFF
    rand_b_hi = (rand >> 40) & 0x3FFF | 0x8000
    rand_b_lo = rand & ((1 << 48) - 1)
    uuid_int = (
        (ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (rand_b_hi << 48)
        | rand_b_lo
    )
    hex_str = f"{uuid_int:032x}"
    return (
        "sit-"
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


__all__ = [
    "SourceIdentityTokenIssuer",
    "SourceIdentityTokenKeyring",
    "SourceIdentityTokenVerifier",
    "new_development_signing_key",
]