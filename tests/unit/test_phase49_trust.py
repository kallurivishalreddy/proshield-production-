"""Phase 4.9 — Source-identity token (trust) tests.

Post-review security controls:

* S-1 — source binding (token source_instance_id/source_type/source
  must match a registered source).
* S-2 — server-side maximum lifetime enforcement.
* R-1 — server-controlled single-use replay protection.
* D-4 — keyring-based verification with rotation support.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest

from app.sources.errors import SourceIdentityTokenError
from app.sources.models import SourceInstanceId, SourceType
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenKeyring,
    SourceIdentityTokenVerifier,
    new_development_signing_key,
)


_SECRET = new_development_signing_key()
_OTHER_SECRET = new_development_signing_key()
_ISSUER = SourceIdentityTokenIssuer(
    secret=_SECRET, lifetime_seconds=600
)


# -----------------------------------------------------------------------
# Replay store test double (R-1) — defined before the module-level
# verifier below so the verifier can be constructed with one.
# -----------------------------------------------------------------------
class _InMemoryReplayStore:
    """Server-side single-use token store.

    Production replay stores must be cross-process (Mongo / Redis).
    This in-memory implementation is sufficient for unit tests.
    """

    def __init__(self) -> None:
        self._used: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim(
        self, *, token_id: str, expires_at: datetime
    ) -> bool:
        with self._lock:
            if token_id in self._used:
                return False
            self._used[token_id] = expires_at
            return True

    def release(self, token_id: str) -> None:
        with self._lock:
            self._used.pop(token_id, None)

    def gc(self, now: datetime) -> int:
        with self._lock:
            expired = [
                tid for tid, exp in self._used.items() if exp <= now
            ]
            for tid in expired:
                del self._used[tid]
            return len(expired)


_VERIFIER = SourceIdentityTokenVerifier.from_secret(
    _SECRET,
    max_lifetime_seconds=3600,
    # ST-02 fail-closed: tests wire a replay store so the
    # verifier can replay-claim tokens.
    replay_store=_InMemoryReplayStore(),
)

_SID = SourceInstanceId(
    "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
)


# -----------------------------------------------------------------------
# Replay store test double (R-1)
# -----------------------------------------------------------------------
# (Defined above the module-level verifier; this comment
# block is intentionally retained as a marker.)


def _verifier_with_replay(
    *, secret: str = _SECRET, resolver: Any = None
) -> SourceIdentityTokenVerifier:
    return SourceIdentityTokenVerifier.from_secret(
        secret,
        max_lifetime_seconds=3600,
        replay_store=_InMemoryReplayStore(),
        source_resolver=resolver,
    )


# -----------------------------------------------------------------------
# A registered-source resolver stub for S-1
# -----------------------------------------------------------------------
class _RegisteredSource:
    def __init__(
        self,
        *,
        source_instance_id: str,
        source_type: SourceType,
        source: str,
    ) -> None:
        self.source_instance_id = source_instance_id
        self.source_type = source_type
        self.source = source


def _registry_resolver(records: Dict[str, _RegisteredSource]):
    def _resolve(sid: str) -> Optional[_RegisteredSource]:
        return records.get(sid)
    return _resolve


class TestTokenIssueAndVerify:
    def test_round_trip(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        verified = _VERIFIER.verify(packed)
        assert verified.source_instance_id == _SID
        assert verified.source_type == "nginx"
        assert verified.source == "nginx"

    def test_token_id_format(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        assert token.token_id.startswith("sit-")
        # 8-4-4-4-12 hex = 36 chars after the prefix.
        assert len(token.token_id) == 4 + 36

    def test_signature_verified_against_body(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        # Tamper with the payload (after the token id).
        tampered = packed[:40] + "AAAA" + packed[44:]
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify(tampered)

    def test_wrong_secret_rejected(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        bad_verifier = SourceIdentityTokenVerifier.from_secret(
            _OTHER_SECRET,
            replay_store=_InMemoryReplayStore(),
        )
        with pytest.raises(SourceIdentityTokenError):
            bad_verifier.verify(packed)

    def test_expired_token_rejected(self) -> None:
        # Issue with a one-second lifetime, sleep past it.
        short_issuer = SourceIdentityTokenIssuer(
            secret=_SECRET, lifetime_seconds=1
        )
        token = short_issuer.issue(
            source_instance_id=_SID,
            source_type=SourceType.NGINX,
        )
        packed = short_issuer.pack(token)
        import time
        time.sleep(1.2)
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify(packed)

    def test_missing_packed_rejected(self) -> None:
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify("")

    def test_malformed_packed_rejected(self) -> None:
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify("not-a-token")

    def test_short_signature_rejected(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        # Drop the signature.
        head, _ = packed.rsplit(".", 1)
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify(head)

    def test_packed_contains_token_id(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        assert packed.startswith(token.token_id + ".")

    def test_nonce_is_unique_per_issuance(self) -> None:
        seen = set()
        for _ in range(5):
            token = _ISSUER.issue(
                source_instance_id=_SID,
                source_type=SourceType.NGINX,
            )
            seen.add(token.nonce)
        # Two unique nonces among five issuances (probability
        # of collision negligible with 16 random bytes).
        assert len(seen) == 5

    def test_issuer_requires_secret(self) -> None:
        with pytest.raises(ValueError):
            SourceIdentityTokenIssuer(secret="", lifetime_seconds=60)

    def test_issuer_requires_positive_lifetime(self) -> None:
        with pytest.raises(ValueError):
            SourceIdentityTokenIssuer(
                secret=_SECRET, lifetime_seconds=0,
            )

    def test_verifier_requires_secret(self) -> None:
        with pytest.raises(ValueError):
            SourceIdentityTokenVerifier.from_secret("")

    def test_now_must_be_aware(self) -> None:
        with pytest.raises(ValueError):
            _ISSUER.issue(
                source_instance_id=_SID,
                source_type=SourceType.NGINX,
                now=datetime(2026, 1, 1, 0, 0, 0),
            )

    def test_packed_format_has_three_parts(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        assert len(packed.split(".")) == 3


class TestTokenTimeWindow:
    def test_explicit_now_in_past_rejects(self) -> None:
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        # A ``now`` far in the future is past ``expires_at``.
        future = datetime.now(timezone.utc) + timedelta(days=365)
        with pytest.raises(SourceIdentityTokenError):
            _VERIFIER.verify(packed, now=future)


# -----------------------------------------------------------------------
# S-1 — source binding
# -----------------------------------------------------------------------
class TestSourceBindingS1:
    def test_token_for_a_cannot_be_accepted_as_b(self) -> None:
        """A token issued for source A must NOT authenticate as source B.

        Even if the attacker re-signs the same body with a stolen
        issuer secret, the source-binding callback prevents
        authentication to a different registered source.
        """
        sid_a = SourceInstanceId(
            "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5faa"
        )
        sid_b = SourceInstanceId(
            "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fbb"
        )
        records = {
            sid_a: _RegisteredSource(
                source_instance_id=str(sid_a),
                source_type=SourceType.NGINX,
                source="nginx",
            ),
            sid_b: _RegisteredSource(
                source_instance_id=str(sid_b),
                source_type=SourceType.NGINX,
                source="nginx",
            ),
        }
        resolver = _registry_resolver(records)
        verifier = _verifier_with_replay(resolver=resolver)

        token_a = _ISSUER.issue(
            source_instance_id=sid_a, source_type=SourceType.NGINX,
        )
        packed_a = _ISSUER.pack(token_a)
        verifier.verify(packed_a)

        from app.sources.trust import (
            _canonical_body, _compute_signature, _b64url,
        )
        now = datetime.now(timezone.utc)
        body_b = _canonical_body(
            token_id=token_a.token_id,
            source_instance_id=str(sid_b),
            source_type="nginx",
            source="nginx",
            issued_at=now,
            expires_at=token_a.expires_at,
            nonce=token_a.nonce,
            key_id=token_a.key_id,
        )
        sig_b = _compute_signature(_SECRET, body_b)
        forged = f"{token_a.token_id}.{_b64url(body_b)}.{sig_b}"
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(forged)

    def test_token_for_unknown_source_rejected(self) -> None:
        verifier = _verifier_with_replay(
            resolver=_registry_resolver({})
        )
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)


# -----------------------------------------------------------------------
# S-2 — max-lifetime enforcement
# -----------------------------------------------------------------------
class TestMaxLifetimeS2:
    def test_extended_expiry_rejected(self) -> None:
        """A re-signed token whose ``expires_at`` is far in the future
        must be rejected by the server-side lifetime cap.
        """
        verifier = SourceIdentityTokenVerifier.from_secret(
            _SECRET,
            max_lifetime_seconds=3600,
            replay_store=_InMemoryReplayStore(),
        )
        from app.sources.trust import (
            _canonical_body, _compute_signature, _b64url,
        )
        now = datetime.now(timezone.utc)
        far_future = now + timedelta(days=30)
        body = _canonical_body(
            token_id="sit-00000000-0000-7000-8000-000000000000",
            source_instance_id=str(_SID),
            source_type="nginx",
            source="nginx",
            issued_at=now,
            expires_at=far_future,
            nonce="n" * 22,
            key_id="k1",
        )
        sig = _compute_signature(_SECRET, body)
        packed = (
            "sit-00000000-0000-7000-8000-000000000000."
            f"{_b64url(body)}.{sig}"
        )
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)

    def test_just_outside_max_rejected(self) -> None:
        verifier = SourceIdentityTokenVerifier.from_secret(
            _SECRET,
            max_lifetime_seconds=60,
            replay_store=_InMemoryReplayStore(),
        )
        issuer = SourceIdentityTokenIssuer(
            secret=_SECRET,
            lifetime_seconds=120,
            max_lifetime_seconds=120,
        )
        token = issuer.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = issuer.pack(token)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)


# -----------------------------------------------------------------------
# R-1 — token replay protection
# -----------------------------------------------------------------------
class TestReplayR1:
    def test_first_use_accepted_second_use_rejected(self) -> None:
        verifier = _verifier_with_replay()
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        verifier.verify(packed)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)

    def test_concurrent_replay_exactly_one_accepted(self) -> None:
        verifier = _verifier_with_replay()
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        results: list = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                verifier.verify(packed)
                with lock:
                    results.append("ok")
            except SourceIdentityTokenError:
                with lock:
                    results.append("rejected")

        threads = [
            threading.Thread(target=worker) for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        accepted = results.count("ok")
        rejected = results.count("rejected")
        assert accepted == 1
        assert rejected == 7

    def test_replay_store_gc_is_bounded(self) -> None:
        store = _InMemoryReplayStore()
        store._used["expired"] = datetime(
            2020, 1, 1, tzinfo=timezone.utc
        )
        removed = store.gc(
            datetime(2025, 1, 1, tzinfo=timezone.utc)
        )
        assert removed == 1
        assert "expired" not in store._used


# -----------------------------------------------------------------------
# D-4 — keyring rotation
# -----------------------------------------------------------------------
class TestKeyringD4:
    def test_unknown_key_id_rejected(self) -> None:
        # Token signed with "k1" but verifier only knows "k2".
        keyring = SourceIdentityTokenKeyring(
            keys={"k2": _OTHER_SECRET}, active_key_id="k2",
        )
        verifier = SourceIdentityTokenVerifier(
            keyring=keyring,
            max_lifetime_seconds=3600,
            replay_store=_InMemoryReplayStore(),
        )
        token = _ISSUER.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = _ISSUER.pack(token)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)

    def test_old_key_overlap_accepted(self) -> None:
        """During a rotation overlap, a token signed with the
        previous key must still verify.
        """
        old_key = new_development_signing_key()
        new_key = new_development_signing_key()
        old_issuer = SourceIdentityTokenIssuer(
            secret=old_key, lifetime_seconds=600, key_id="k-old",
        )
        keyring = SourceIdentityTokenKeyring(
            keys={"k-old": old_key, "k-new": new_key},
            active_key_id="k-new",
        )
        verifier = SourceIdentityTokenVerifier(
            keyring=keyring,
            max_lifetime_seconds=3600,
            replay_store=_InMemoryReplayStore(),
        )
        token = old_issuer.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = old_issuer.pack(token)
        verified = verifier.verify(packed)
        assert verified.token_id == token.token_id

    def test_retired_key_rejected(self) -> None:
        old_key = new_development_signing_key()
        new_key = new_development_signing_key()
        old_issuer = SourceIdentityTokenIssuer(
            secret=old_key, lifetime_seconds=600, key_id="k-old",
        )
        # After rotation, the old key is removed from the keyring.
        keyring = SourceIdentityTokenKeyring(
            keys={"k-new": new_key}, active_key_id="k-new",
        )
        verifier = SourceIdentityTokenVerifier(
            keyring=keyring,
            max_lifetime_seconds=3600,
            replay_store=_InMemoryReplayStore(),
        )
        token = old_issuer.issue(
            source_instance_id=_SID, source_type=SourceType.NGINX,
        )
        packed = old_issuer.pack(token)
        with pytest.raises(SourceIdentityTokenError):
            verifier.verify(packed)