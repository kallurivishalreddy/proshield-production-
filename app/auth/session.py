"""HMAC-signed session tokens.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md (Authentication
Configuration, Secret Handling), docs/PHASE 3/AUTH_RBAC.md
(Identity Claims), docs/PHASE 2/API_CONTRACTS.md
(Authorization: Bearer <access-token>).

The Phase 4.8 session layer is intentionally simple:

* A token has the wire form::

      <prefix>.<subject_id>.<issued_at_unix>.<expires_at_unix>.<hex_hmac>

  where ``<prefix>`` is ``"ps"`` (ProShield), the four
  fields are joined by ``"."``, and ``<hex_hmac>`` is an
  HMAC-SHA256 over the canonical ``"<prefix>.<subject_id>.<issued_at_unix>.<expires_at_unix>"``
  string using the configured signing key.

* The signing key comes from :class:`app.config.ProShieldConfig`
  (``auth_signing_key`` field). Tests inject a deterministic
  key. The key never appears in a token, in a log, or in an
  API response (the proxy and audit subsystem redacted the
  ``safe_summary`` style; this module never logs the key).

* :class:`SessionToken` is a frozen Pydantic-style record.
* :class:`SessionTokenService` issues tokens (the auth flow).
* :class:`SessionVerifier` verifies + parses tokens and
  re-derives the :class:`Identity` from the verified
  subject_id via the :class:`IdentityStore`.

The token is opaque to the client: clients carry the
string but cannot decode it without the signing key. A
client cannot mutate the role / permissions / expiry
because the HMAC guards every field.

What this module does NOT do
----------------------------

* It does NOT implement refresh-token flows, MFA,
  federation, SSO, OAuth, OIDC, or PKI. Those are
  future-IAM.
* It does NOT persist tokens. The slice ships an
  in-memory issuance path; persistence is the caller's
  concern (audit / observability only).
* It does NOT trust client-supplied identity. Every
  protected operation calls :meth:`SessionVerifier.verify`
  on the wire token.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from ..domain.errors import (
    AuthenticationRequiredError,
    ValidationError,
)
from .errors import (
    InvalidSessionTokenError,
    SessionExpiredError,
)
from .identity import Identity, IdentityStore


_log = logging.getLogger(__name__)


# ----------------------------------------------------------------- constants
# Wire token format: ps.<subject_id>.<iat>.<exp>.<hex_hmac>
TOKEN_PREFIX = "ps"
TOKEN_FIELD_COUNT = 5
TOKEN_MIN_LENGTH = 8
MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60  # 24 hours


@dataclass(frozen=True)
class SessionToken:
    """The decoded view of an issued / verified token.

    The fields are the verified claims the rest of the
    backend trusts:

    * token - the on-the-wire string (opaque to clients,
      safe to log via :meth:`safe_log_value`).
    * subject_id - the verified subject id.
    * issued_at / expires_at - timezone-aware
      Unix timestamps (UTC).
    """

    token: str
    subject_id: str
    issued_at: int
    expires_at: int

    def is_expired(self, *, now: Optional[int] = None) -> bool:
        ts = int(time.time()) if now is None else int(now)
        return ts >= self.expires_at

    @property
    def safe_log_value(self) -> str:
        """Redacted form for log lines / audit records.

        Returns only the prefix + last 4 chars of the HMAC;
        the subject_id and expiry are NEVER logged here.
        """
        if not isinstance(self.token, str) or "." not in self.token:
            return "<malformed>"
        parts = self.token.split(".")
        if len(parts) != TOKEN_FIELD_COUNT:
            return "<malformed>"
        sig = parts[-1]
        if len(sig) < 4:
            return f"{TOKEN_PREFIX}.<...>.<sig-truncated>"
        return f"{TOKEN_PREFIX}.<subject>.<iat>.<exp>.{sig[-4:]}"


@dataclass(frozen=True)
class VerifierResult:
    """The structured outcome of :meth:`SessionVerifier.verify`.

    The verifier never returns a partial answer: a token is
    either fully verified (and the corresponding
    :class:`Identity` returned) or the verification failed
    with one of the documented typed errors.
    """

    token: SessionToken
    identity: Identity


# ----------------------------------------------------------------- issuance
class SessionTokenService:
    """Issues new session tokens for a known :class:`Identity`.

    The service is constructed with a signing key. The key
    MUST be a non-empty ``str``; the production startup
    validation guarantees a non-placeholder key in
    production.

    Issuance is deterministic for a given
    ``(subject_id, issued_at, expires_at)`` triple. Tests can
    therefore produce stable tokens.
    """

    def __init__(self, *, signing_key: str) -> None:
        if not isinstance(signing_key, str) or not signing_key:
            raise ValueError("signing_key must be a non-empty str")
        self._signing_key = signing_key

    @property
    def signing_key(self) -> str:
        return self._signing_key

    def issue(
        self,
        *,
        subject_id: str,
        lifetime_seconds: int = 3600,
        now: Optional[int] = None,
    ) -> SessionToken:
        """Issue a fresh session token for ``subject_id``.

        Parameters
        ----------
        subject_id:
            The verified subject id to embed.
        lifetime_seconds:
            Positive seconds-to-live; bounded by
            :data:`MAX_TOKEN_LIFETIME_SECONDS`. The default
            one-hour lifetime matches the documented auth
            guidance.
        now:
            Optional Unix timestamp to use as ``iat``. The
            default is the current time.
        """
        if not isinstance(subject_id, str) or not subject_id:
            raise ValidationError(
                safe_message="subject_id required",
                internal_detail=f"got {type(subject_id).__name__}",
                field="subject_id",
            )
        if not isinstance(lifetime_seconds, int) or isinstance(
            lifetime_seconds, bool
        ):
            raise ValidationError(
                safe_message="lifetime_seconds must be int",
                internal_detail=f"got {type(lifetime_seconds).__name__}",
                field="lifetime_seconds",
            )
        if lifetime_seconds <= 0:
            raise ValidationError(
                safe_message="lifetime_seconds must be positive",
                internal_detail=f"got {lifetime_seconds}",
                field="lifetime_seconds",
            )
        if lifetime_seconds > MAX_TOKEN_LIFETIME_SECONDS:
            raise ValidationError(
                safe_message="lifetime_seconds exceeds cap",
                internal_detail=(
                    f"got {lifetime_seconds}, cap "
                    f"{MAX_TOKEN_LIFETIME_SECONDS}"
                ),
                field="lifetime_seconds",
            )
        ts = int(time.time()) if now is None else int(now)
        exp = ts + lifetime_seconds
        token_str = self._build_token(subject_id, ts, exp)
        return SessionToken(
            token=token_str,
            subject_id=subject_id,
            issued_at=ts,
            expires_at=exp,
        )

    def _build_token(self, subject_id: str, issued_at: int, expires_at: int) -> str:
        body = ".".join(
            (TOKEN_PREFIX, subject_id, str(issued_at), str(expires_at))
        )
        sig = self._sign(body)
        return f"{body}.{sig}"

    def _sign(self, body: str) -> str:
        mac = hmac.new(
            self._signing_key.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        )
        return mac.hexdigest()


# ----------------------------------------------------------------- verification
class SessionVerifier:
    """Verifies + parses a wire token and re-derives Identity.

    The verifier is the single point at which a wire token
    becomes a trusted :class:`Identity`. Every protected
    backend call MUST go through :meth:`verify`.

    On failure the verifier raises one of the typed
    auth errors so the proxy can map the failure to a
    safe HTTP envelope without leaking internals.
    """

    def __init__(
        self,
        *,
        signing_key: str,
        identity_store: IdentityStore,
    ) -> None:
        if not isinstance(signing_key, str) or not signing_key:
            raise ValueError("signing_key must be a non-empty str")
        if not isinstance(identity_store, IdentityStore):
            raise ValueError("identity_store must be an IdentityStore")
        self._signing_key = signing_key
        self._identity_store = identity_store

    @property
    def identity_store(self) -> IdentityStore:
        return self._identity_store

    def verify(
        self,
        token: str,
        *,
        now: Optional[int] = None,
    ) -> VerifierResult:
        """Verify the wire token and return the
        :class:`VerifierResult` carrying the parsed
        :class:`SessionToken` and the re-derived
        :class:`Identity`.
        """
        if not isinstance(token, str) or not token:
            raise AuthenticationRequiredError(
                safe_message="missing session token",
                internal_detail="empty or non-string token",
            )
        if len(token) < TOKEN_MIN_LENGTH:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail=(
                    f"token length {len(token)} below minimum "
                    f"{TOKEN_MIN_LENGTH}"
                ),
            )
        parts = token.split(".")
        if len(parts) != TOKEN_FIELD_COUNT:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail=(
                    f"expected {TOKEN_FIELD_COUNT} parts, got {len(parts)}"
                ),
            )
        prefix, subject_id, iat_s, exp_s, sig = parts
        if prefix != TOKEN_PREFIX:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail=f"unexpected prefix {prefix!r}",
            )
        # Defensive: each field must be a non-empty string of
        # a safe character class.
        if not all(
            isinstance(p, str) and p
            and all(c.isalnum() or c == "_" or c == "-" for c in p)
            for p in (subject_id, iat_s, exp_s)
        ):
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail="non-alphanumeric field",
            )
        if not isinstance(sig, str) or len(sig) != 64:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail="unexpected signature length",
            )
        try:
            iat = int(iat_s)
            exp = int(exp_s)
        except ValueError as exc:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail=f"non-integer timestamp: {exc}",
            ) from exc
        if iat < 0 or exp < 0 or exp <= iat:
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail=f"iat={iat}, exp={exp}",
            )
        body = ".".join((TOKEN_PREFIX, subject_id, str(iat), str(exp)))
        expected_sig = self._sign(body)
        if not hmac.compare_digest(expected_sig, sig):
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail="signature mismatch",
            )
        ts = int(time.time()) if now is None else int(now)
        if ts >= exp:
            raise SessionExpiredError(
                safe_message="session token expired",
                internal_detail=f"exp={exp}, now={ts}",
            )
        identity = self._identity_store.get(subject_id)
        if identity is None:
            # Subject id signed by a valid key but unknown to
            # the catalogue - treat as a verification failure
            # so the proxy returns 401 and never reveals
            # whether the subject_id "exists".
            raise InvalidSessionTokenError(
                safe_message="invalid session token",
                internal_detail="unknown subject",
            )
        return VerifierResult(
            token=SessionToken(
                token=token,
                subject_id=subject_id,
                issued_at=iat,
                expires_at=exp,
            ),
            identity=identity,
        )

    def _sign(self, body: str) -> str:
        mac = hmac.new(
            self._signing_key.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        )
        return mac.hexdigest()
# ----------------------------------------------------------------- key helper
def new_development_signing_key() -> str:
    """Generate a fresh development signing key.

    Production MUST source the key from a secure secret
    store; this helper exists for tests and the demo script
    so the wire format is exercised without ever embedding a
    constant in source code.
    """
    return os.urandom(32).hex()


__all__ = [
    "MAX_TOKEN_LIFETIME_SECONDS",
    "SessionToken",
    "SessionTokenService",
    "SessionVerifier",
    "TOKEN_FIELD_COUNT",
    "TOKEN_PREFIX",
    "VerifierResult",
    "new_development_signing_key",
]