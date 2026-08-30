"""Phase 4.8 auth foundation unit tests."""
from __future__ import annotations

import pytest

from app.auth import (
    ADMIN_ROLE,
    ANALYST_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
    Identity,
    InMemoryIdentityStore,
)
from app.auth.errors import (
    AuthenticationError,
    InvalidSessionTokenError,
    PermissionDeniedError,
    SessionExpiredError,
)
from app.auth.permissions import Permission, has_permission
from app.auth.session import (
    MAX_TOKEN_LIFETIME_SECONDS,
    SessionTokenService,
    SessionVerifier,
    TOKEN_FIELD_COUNT,
)
from app.domain.errors import AuthorizationError


class TestIdentity:
    def test_role_must_be_closed_set(self) -> None:
        with pytest.raises(ValueError):
            Identity(subject_id="u1", role="hacker")

    def test_subject_id_required(self) -> None:
        with pytest.raises(ValueError):
            Identity(subject_id="", role=ANALYST_ROLE)

    def test_permissions_are_frozen_tuple(self) -> None:
        i = Identity(
            subject_id="u1",
            role=ANALYST_ROLE,
            permissions=("a:1", "b:2"),  # type: ignore[arg-type]
        )
        assert i.permissions == ("a:1", "b:2")

    def test_to_dict(self) -> None:
        i = Identity(
            subject_id="u1", role=ANALYST_ROLE, display_name="Alice",
        )
        d = i.to_dict()
        assert d["subject_id"] == "u1"
        assert d["role"] == ANALYST_ROLE
        assert d["display_name"] == "Alice"


class TestIdentityStore:
    def test_default_catalogue(self) -> None:
        store = InMemoryIdentityStore()
        assert "user-analyst-001" in store
        assert "user-admin-001" in store

    def test_get_returns_none_for_unknown(self) -> None:
        store = InMemoryIdentityStore()
        assert store.get("missing") is None
        assert store.get("") is None
        assert store.get(None) is None  # type: ignore[arg-type]


class TestPermissions:
    def test_analyst_default_permissions(self) -> None:
        perms = [
            Permission.CASE_READ,
            Permission.CASE_CENTRALIZED_REQUEST,
            Permission.REPORT_READ,
            Permission.REPORT_GENERATE,
            Permission.ROUTING_READ,
            Permission.EVENT_READ,
            Permission.DETECTION_READ,
            Permission.RULE_READ,
        ]
        for p in perms:
            assert has_permission(
                role=ANALYST_ROLE, identity_permissions=(), permission=p,
            )
        for p in (
            Permission.CASE_READ_ANY,
            Permission.RULE_WRITE,
            Permission.ROUTING_OVERRIDE,
        ):
            assert not has_permission(
                role=ANALYST_ROLE, identity_permissions=(), permission=p,
            )

    def test_admin_default_permissions(self) -> None:
        for p in (
            Permission.CASE_READ_ANY,
            Permission.RULE_WRITE,
            Permission.ROUTING_OVERRIDE,
            Permission.REPORT_GENERATE_ANY,
        ):
            assert has_permission(
                role=ADMIN_ROLE, identity_permissions=(), permission=p,
            )

    def test_collector_cannot_read_cases(self) -> None:
        assert not has_permission(
            role=COLLECTOR_ROLE,
            identity_permissions=(),
            permission=Permission.CASE_READ,
        )
assert not has_permission(
            role=ANALYST_ROLE, identity_permissions=(), permission="",
        )


class TestSessionTokenService:
    def test_issue_returns_5_part_token(self) -> None:
        svc = SessionTokenService(signing_key="k" * 32)
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=10)
        assert tok.token.count(".") == TOKEN_FIELD_COUNT - 1
        assert tok.subject_id == "u1"
        assert tok.issued_at == 10
        assert tok.expires_at == 70

    def test_issue_rejects_blank_subject_id(self) -> None:
        svc = SessionTokenService(signing_key="k" * 32)
        with pytest.raises(Exception):
            svc.issue(subject_id="", lifetime_seconds=60)

    def test_issue_rejects_zero_or_oversized_lifetime(self) -> None:
        svc = SessionTokenService(signing_key="k" * 32)
        with pytest.raises(Exception):
            svc.issue(subject_id="u1", lifetime_seconds=0)
        with pytest.raises(Exception):
            svc.issue(
                subject_id="u1",
                lifetime_seconds=MAX_TOKEN_LIFETIME_SECONDS + 1,
            )


class TestSessionVerifier:
    def _setup(self):
        store = InMemoryIdentityStore({
            "u1": Identity(subject_id="u1", role=ANALYST_ROLE),
        })
        svc = SessionTokenService(signing_key="k" * 32)
        ver = SessionVerifier(signing_key="k" * 32, identity_store=store)
        return store, svc, ver

    def test_verify_round_trip(self) -> None:
        _store, svc, ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=100)
        result = ver.verify(tok.token, now=110)
        assert result.identity.subject_id == "u1"
        assert result.token.expires_at == 160

    def test_missing_token_is_unauthorized(self) -> None:
        _store, _svc, ver = self._setup()
        with pytest.raises(Exception):
            ver.verify("")

    def test_tampered_signature_rejected(self) -> None:
        _store, svc, ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=100)
        last = tok.token[-1]
        flipped = "0" if last != "0" else "1"
        tampered = tok.token[:-1] + flipped
        with pytest.raises(InvalidSessionTokenError):
            ver.verify(tampered, now=110)

    def test_tampered_subject_rejected(self) -> None:
        _store, svc, ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=100)
        body, _, sig = tok.token.rpartition(".")
        tampered = body.replace("u1", "admin", 1) + "." + sig
        with pytest.raises(InvalidSessionTokenError):
            ver.verify(tampered, now=110)

    def test_wrong_prefix_rejected(self) -> None:
        _store, svc, ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=100)
        tampered = "xx" + tok.token[2:]
        with pytest.raises(InvalidSessionTokenError):
            ver.verify(tampered, now=110)

    def test_wrong_field_count_rejected(self) -> None:
        _store, _svc, ver = self._setup()
        with pytest.raises(InvalidSessionTokenError):
            ver.verify("a.b.c", now=110)

    def test_expired_token_rejected(self) -> None:
        _store, svc, ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=10, now=100)
        with pytest.raises(SessionExpiredError):
            ver.verify(tok.token, now=200)

    def test_unknown_subject_treated_as_invalid(self) -> None:
        _store, _svc, ver = self._setup()
        other_svc = SessionTokenService(signing_key="k" * 32)
        tok = other_svc.issue(
            subject_id="ghost", lifetime_seconds=60, now=100,
        )
        with pytest.raises(InvalidSessionTokenError):
            ver.verify(tok.token, now=110)

    def test_wrong_signing_key_rejected(self) -> None:
        _store, svc, _ver = self._setup()
        tok = svc.issue(subject_id="u1", lifetime_seconds=60, now=100)
        other_ver = SessionVerifier(
            signing_key="different-key",
            identity_store=InMemoryIdentityStore({
                "u1": Identity(subject_id="u1", role=ANALYST_ROLE),
            }),
        )
        with pytest.raises(InvalidSessionTokenError):
            other_ver.verify(tok.token, now=110)


class TestPermissionDeniedErrorAlias:
    def test_permission_denied_is_authorization_error(self) -> None:
        err = PermissionDeniedError(safe_message="nope")
        assert isinstance(err, AuthorizationError)
        assert err.http_status == 403


class TestSafeLogValue:
    def test_safe_log_value_is_redacted(self) -> None:
        from app.auth.session import SessionToken
        tok = SessionToken(
            token="ps.user-1.1700000000.1700003600." + "a" * 64,
            subject_id="user-1",
            issued_at=1700000000,
            expires_at=1700003600,
        )
        assert "user-1" not in tok.safe_log_value
        assert "1700003600" not in tok.safe_log_value
        assert tok.safe_log_value.endswith("aaaa")

    def test_safe_log_value_handles_malformed(self) -> None:
        from app.auth.session import SessionToken
        tok = SessionToken(
            token="bad", subject_id="x",
            issued_at=1, expires_at=2,
        )
        assert tok.safe_log_value == "<malformed>"

    def test_internal_service_cannot_override_routing(self) -> None:
        assert not has_permission(
            role=INTERNAL_SERVICE_ROLE,
            identity_permissions=(),
            permission=Permission.ROUTING_OVERRIDE,
        )

    def test_explicit_override_replaces_defaults(self) -> None:
        assert has_permission(
            role=ANALYST_ROLE,
            identity_permissions=(Permission.RULE_WRITE,),
            permission=Permission.RULE_WRITE,
        )
        assert not has_permission(
            role=ANALYST_ROLE,
            identity_permissions=(Permission.RULE_WRITE,),
            permission=Permission.CASE_READ,
        )

    def test_invalid_inputs(self) -> None:
        assert not has_permission(
            role="", identity_permissions=(), permission=Permission.CASE_READ,
        )
        assert not has_permission(
            role=ANALYST_ROLE, identity_permissions=(), permission="",
        )