"""Regression tests for ``app.detection.redact``.

These tests are the focused regression for the Phase 4.4 review
defect D-1: ``Detection.reasoning`` previously echoed the raw
``event.endpoint`` URL verbatim, so a request to
``/admin?token=SECRET-TOKEN-123&next=/dashboard`` produced a
``reasoning`` field that contained the secret in plain text.

The fix introduces a small, pure redaction helper,
:func:`app.detection.redact.redact_endpoint`, and uses it from
every per-event rule's ``_reasoner`` function. This file asserts
the helper's behaviour directly and asserts that the rule
factory's ``_reasoner`` does not leak query strings, fragments,
or oversized paths.

Reference: ``docs/PHASE 4/PHASE 4-04/PHASE-04-04-REVIEW.md`` (D-1,
FIXED). The tests are intentionally narrow: each test asserts
one property of the redaction contract.
"""
from __future__ import annotations

from typing import Optional

import pytest

from app.detection.redact import (
    MAX_REDACTED_ENDPOINT_LEN,
    redact_endpoint,
)
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules._library import nginx as nginx_rules


# ============================================================================
# Helper unit tests
# ============================================================================
class TestRedactEndpoint:
    """Direct unit tests for :func:`redact_endpoint`."""

    def test_none_renders_as_placeholder(self) -> None:
        # The analyst never sees the literal ``None`` in the reasoning.
        assert redact_endpoint(None) == "<none>"

    def test_empty_path_passes_through(self) -> None:
        # Some events have no path at all; an empty string is allowed.
        assert redact_endpoint("") == ""

    def test_strips_query_string(self) -> None:
        # The motivating case from D-1: a 403 on
        # /admin?token=SECRET-TOKEN-123&next=/dashboard.
        url = "/admin?token=SECRET-TOKEN-123&next=/dashboard"
        out = redact_endpoint(url)
        assert "?" not in out
        assert "token" not in out
        assert "SECRET" not in out
        assert "next" not in out
        assert out == "/admin"

    def test_strips_fragment(self) -> None:
        # Fragments must not leak either.
        url = "/admin#fragment-with-secret-1"
        out = redact_endpoint(url)
        assert "#" not in out
        assert "fragment" not in out
        assert "secret" not in out
        assert out == "/admin"

    def test_strips_both_query_and_fragment(self) -> None:
        # The order is "fragment first, then query" so an
        # embedded "#" inside a query value does not survive.
        url = "/admin?q=foo#bar&r=baz#qux"
        out = redact_endpoint(url)
        assert "?" not in out
        assert "#" not in out
        assert out == "/admin"

    def test_preserves_normal_path(self) -> None:
        # Benign paths must round-trip unchanged.
        assert redact_endpoint("/api/v1/users") == "/api/v1/users"
        assert redact_endpoint("/.env") == "/.env"
        assert redact_endpoint("/wp-admin/admin.php") == "/wp-admin/admin.php"

    def test_truncates_oversized_path(self) -> None:
        # A 300-char path is truncated to MAX_REDACTED_ENDPOINT_LEN
        # with a "..." suffix.
        long_path = "/" + "a" * 300
        out = redact_endpoint(long_path)
        assert len(out) == MAX_REDACTED_ENDPOINT_LEN
        assert out.endswith("...")

    def test_truncates_then_strips_query(self) -> None:
        # Order of operations: the query strip happens BEFORE the
        # truncation, so the truncation cap is not consumed by a
        # 1k-char query string.
        long_path = "/" + "a" * 200 + "?token=" + "x" * 1000
        out = redact_endpoint(long_path)
        assert "?" not in out
        assert "token" not in out
        assert len(out) == MAX_REDACTED_ENDPOINT_LEN

    def test_non_string_input_does_not_crash(self) -> None:
        # Defensive: the helper never raises. A non-str input
        # is rendered with ``str(...)``.
        assert isinstance(redact_endpoint(123), str)  # type: ignore[arg-type]
        assert isinstance(redact_endpoint(["/x"]), str)  # type: ignore[arg-type]

    def test_custom_max_len(self) -> None:
        # Callers can pass a smaller cap (used in tests; production
        # always uses the default).
        assert redact_endpoint("/a/very/long/path", max_len=5) == "/a..."


# ============================================================================
# Rule-reasoner integration tests
# ============================================================================
def _build_event(
    *,
    path: Optional[str] = "/api/v1/users",
    status: int = 401,
    event_type: str = "authentication_failure",
    source_ip: str = "198.51.100.7",
) -> SecurityEvent:
    """Build a minimal SecurityEvent for reasoning-string tests."""
    from datetime import datetime, timezone
    et = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="nginx",
        event_type=event_type,
        source_ip=source_ip,
        endpoint=path,
        provenance=SecurityEventProvenance(
            collector="nginx", source_event_id="src-p44-redact"
        ),
        details={
            "http_method": "GET",
            "status_code": status,
            "protocol": "HTTP/1.1",
            "body_bytes_sent": 0,
            "log_line_number": 1,
        },
    )


# Token-shaped and fragment-shaped substrings the test asserts are
# NOT present in the redacted reasoning. These are the values
# that an attacker might leak via a query string.
_SECRET_TOKENS = (
    "SECRET-TOKEN-123",
    "ABCD-SIGNED-RESET-LINK",
    "OAUTH-AUTH-CODE-9876",
    "API-KEY-LIVE-555-444-333",
)


def _all_rule_factories():
    """Return every rule factory exposed by ``app.rules._library.nginx``."""
    return [
        ("NGINX-AUTH-FAILURE-001", nginx_rules.build_nginx_auth_failure_observation_rule),
        ("NGINX-AUTH-BRUTEFORCE-001", nginx_rules.build_nginx_auth_brute_force_rule),
        ("NGINX-ACCESS-DENIED-001", nginx_rules.build_nginx_access_denied_sensitive_path_rule),
        ("NGINX-STATUS-ANOMALY-001", nginx_rules.build_nginx_server_error_observation_rule),
        ("NGINX-RATE-LIMIT-001", nginx_rules.build_nginx_rate_limit_observation_rule),
    ]


class TestReasonerDoesNotLeakQueryOrFragment:
    """The regression for review defect D-1.

    For every per-event rule, a SecurityEvent whose endpoint
    contains a token-shaped query parameter (the Phase 4.4
    attack-simulation scenario) MUST produce a ``reasoning``
    string that does NOT contain the token.
    """

    @pytest.mark.parametrize("secret", _SECRET_TOKENS)
    @pytest.mark.parametrize(
        "rule_id,factory",
        _all_rule_factories(),
        ids=[r[0] for r in _all_rule_factories()],
    )
    def test_reasoner_strips_query_token(
        self,
        rule_id: str,
        factory,
        secret: str,
    ) -> None:
        # A request to /api/v1/login?token=<secret> should never
        # surface <secret> in the rule's reasoning string.
        rule = factory()
        event = _build_event(
            path=f"/api/v1/login?token={secret}",
            status=401,
            event_type="authentication_failure",
        )
        evaluation = rule.evaluate(event)
        # Only AUTH-FAILURE-001 and BRUTEFORCE-001 fire on a
        # 401/auth-shaped path; the other three do not. We assert
        # on the REASONER (which is the property under test) only
        # when the rule fired.
        if not evaluation.matched:
            # The reasoner is not called for non-matching events;
            # invoke it directly to test the redaction contract.
            reasoning = rule._reasoner(event)  # type: ignore[attr-defined]
        else:
            reasoning = evaluation.reasoning
        assert secret not in reasoning, (
            f"{rule_id} reasoning leaks the secret token {secret!r}: "
            f"{reasoning!r}"
        )
        assert "?" not in reasoning
        assert "token=" not in reasoning

    @pytest.mark.parametrize(
        "rule_id,factory",
        _all_rule_factories(),
        ids=[r[0] for r in _all_rule_factories()],
    )
    def test_reasoner_strips_fragment(
        self,
        rule_id: str,
        factory,
    ) -> None:
        rule = factory()
        event = _build_event(
            path="/admin/users#DELETE-ALL-USERS-secret-action",
        )
        reasoning = rule._reasoner(event)  # type: ignore[attr-defined]
        assert "DELETE-ALL-USERS" not in reasoning
        assert "secret-action" not in reasoning
        assert "#" not in reasoning

    @pytest.mark.parametrize(
        "rule_id,factory",
        _all_rule_factories(),
        ids=[r[0] for r in _all_rule_factories()],
    )
    def test_reasoner_renders_none_as_placeholder(
        self,
        rule_id: str,
        factory,
    ) -> None:
        rule = factory()
        event = _build_event(path=None)
        reasoning = rule._reasoner(event)  # type: ignore[attr-defined]
        # The analyst never sees a literal Python ``None``; the
        # helper renders the empty/None case as ``<none>``.
        assert "None" not in reasoning
        assert "<none>" in reasoning


# ============================================================================
# End-to-end: Detection.reasoning must not contain token-shaped
# substrings (the persistence-slice concern).
# ============================================================================
class TestDetectionReasoningNoLeak:
    """Run the engine end-to-end and assert the Detection record
    is safe to persist to an audit / SIEM feed.
    """

    def test_403_on_sensitive_path_with_query_does_not_leak_token(
        self,
    ) -> None:
        # The exact attack scenario from the D-1 review probe:
        # a 403 on /admin?token=SECRET-TOKEN-123&next=/dashboard
        # must NOT produce a Detection whose reasoning echoes the
        # secret in the query string.
        from app.detection import DetectionEngine
        from app.rules import RuleRegistry, load_rules_from_specs
        from datetime import datetime, timezone

        r = RuleRegistry()
        load_rules_from_specs(r, ["app.rules._library.nginx"])
        engine = DetectionEngine(r)
        event = _build_event(
            path="/admin?token=SECRET-TOKEN-123&next=/dashboard",
            status=403,
            event_type="request_blocked",
        )
        result = engine.run(
            event,
            now=datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc),
        )
        # The ACCESS-DENIED-001 rule must fire.
        assert result.detection_count == 1
        d = result.detections[0]
        # The reasoning must not contain the secret substring or
        # the query-string separator.
        assert "SECRET-TOKEN-123" not in d.reasoning
        assert "?" not in d.reasoning
        assert "token=" not in d.reasoning
        assert "next=" not in d.reasoning
        # The path /admin is preserved (useful for the analyst).
        assert "/admin" in d.reasoning

    def test_401_with_query_does_not_leak_token(self) -> None:
        # Same concern, on the auth path that fires BOTH
        # NGINX-AUTH-FAILURE-001 and NGINX-AUTH-BRUTEFORCE-001
        # (D-3 overlap). Both Detections must be safe to persist.
        from app.detection import DetectionEngine
        from app.rules import RuleRegistry, load_rules_from_specs
        from datetime import datetime, timezone

        r = RuleRegistry()
        load_rules_from_specs(r, ["app.rules._library.nginx"])
        engine = DetectionEngine(r)
        event = _build_event(
            path="/api/v1/login?token=SECRET-TOKEN-123&next=/dashboard",
            status=401,
            event_type="authentication_failure",
        )
        result = engine.run(
            event,
            now=datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc),
        )
        # Two detections (D-3 overlap), but each one is safe.
        assert result.detection_count == 2
        for d in result.detections:
            assert "SECRET-TOKEN-123" not in d.reasoning
            assert "?" not in d.reasoning
            assert "token=" not in d.reasoning
