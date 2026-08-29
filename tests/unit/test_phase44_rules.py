"""Unit tests for the Phase 4.4 per-event NGINX rules."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules import (
    RuleCategory,
    RuleRegistry,
    RuleState,
    load_rules_from_specs,
)
from app.rules._library.nginx import (
    build_nginx_access_denied_sensitive_path_rule,
    build_nginx_auth_failure_observation_rule,
    build_nginx_rate_limit_observation_rule,
    build_nginx_server_error_observation_rule,
)


def _ev(
    *,
    event_type: str = "request_blocked",
    status: int = 404,
    path: Optional[str] = "/.env",
    source_ip: str = "198.51.100.7",
    method: str = "GET",
    account_id: Optional[str] = None,
) -> SecurityEvent:
    et = datetime(2026, 8, 26, 11, 0, 0, tzinfo=timezone.utc)
    kwargs: Dict[str, Any] = dict(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="nginx",
        event_type=event_type,
        source_ip=source_ip,
        endpoint=path,
        provenance=SecurityEventProvenance(
            collector="nginx", source_event_id="src-p44"
        ),
        details={
            "http_method": method,
            "status_code": status,
            "protocol": "HTTP/1.1",
            "body_bytes_sent": 0,
            "log_line_number": 1,
        },
    )
    return SecurityEvent(**kwargs)


# ============================================================================
# NGINX-AUTH-FAILURE-001: per-event single-401 observation
# ============================================================================
class TestAuthFailureObservation:
    def test_401_on_any_endpoint_matches(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        for path in ("/api/v1/login", "/api/users/1", "/index.html"):
            ev = _ev(event_type="authentication_failure", status=401, path=path)
            assert rule.evaluate(ev).matched is True, f"401 on {path} should match"

    def test_403_does_not_match(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        ev = _ev(event_type="request_blocked", status=403, path="/api/v1/login")
        assert rule.evaluate(ev).matched is False

    def test_404_does_not_match(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        ev = _ev(event_type="request_blocked", status=404, path="/api/v1/login")
        assert rule.evaluate(ev).matched is False

    def test_200_does_not_match(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        ev = _ev(event_type="authentication_success", status=200, path="/api/v1/login")
        assert rule.evaluate(ev).matched is False

    def test_non_nginx_source_does_not_match(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        ev = _ev(event_type="authentication_failure", status=401, path="/api/v1/login")
        tampered = ev.model_copy(update={"source": "waf"})
        assert rule.evaluate(tampered).matched is False

    def test_metadata(self) -> None:
        rule = build_nginx_auth_failure_observation_rule()
        m = rule.metadata
        assert m.rule_id == "NGINX-AUTH-FAILURE-001"
        assert m.version == 1
        assert m.category is RuleCategory.SOURCE_SPECIFIC
        assert m.sources == ("nginx",)
        assert m.event_types == ("authentication_failure",)
        assert m.state is RuleState.APPROVED
        assert m.enabled is True


# ============================================================================
# NGINX-ACCESS-DENIED-001: 4xx on sensitive/admin path
# ============================================================================
class TestAccessDeniedSensitivePath:
    def test_dotfile_matches(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        for path in ("/.env", "/.git/HEAD", "/.htaccess", "/.htpasswd"):
            ev = _ev(event_type="request_blocked", status=404, path=path)
            assert rule.evaluate(ev).matched is True, f"404 on {path} should match"

    def test_admin_path_matches(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        for path in (
            "/admin",
            "/admin/users",
            "/administrator",
            "/wp-admin",
            "/wp-login",
            "/wp-config",
            "/phpmyadmin",
            "/pma",
            "/server-status",
            "/server-info",
            "/actuator",
            "/cgi-bin",
            "/manager",
            "/api/internal",
            "/internal",
            "/.svn",
            "/.hg",
            "/backup",
            "/db/",
            "/database",
            "/.DS_Store",
            "/web.config",
        ):
            ev = _ev(event_type="request_blocked", status=404, path=path)
            assert rule.evaluate(ev).matched is True, f"404 on {path} should match"

    def test_403_on_sensitive_path_matches(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="request_blocked", status=403, path="/admin/users")
        assert rule.evaluate(ev).matched is True

    def test_405_on_sensitive_path_matches(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="request_blocked", status=405, path="/api/internal")
        assert rule.evaluate(ev).matched is True

    def test_404_on_public_path_does_not_match(self) -> None:
        """The FP guard: a 404 on a public path must NOT fire."""
        rule = build_nginx_access_denied_sensitive_path_rule()
        for path in (
            "/products/123",
            "/api/users/1",
            "/blog/my-typo",
            "/index.html",
            "/about",
        ):
            ev = _ev(event_type="request_blocked", status=404, path=path)
            assert rule.evaluate(ev).matched is False, f"404 on {path} should NOT match"

    def test_401_on_sensitive_path_does_not_match(self) -> None:
        """401 is owned by NGINX-AUTH-FAILURE-001, not by this rule."""
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="authentication_failure", status=401, path="/admin")
        assert rule.evaluate(ev).matched is False

    def test_429_on_sensitive_path_does_not_match(self) -> None:
        """429 is owned by NGINX-RATE-LIMIT-001, not by this rule."""
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="rate_limit_exceeded", status=429, path="/admin")
        assert rule.evaluate(ev).matched is False

    def test_5xx_on_sensitive_path_does_not_match(self) -> None:
        """5xx is owned by NGINX-STATUS-ANOMALY-001, not by this rule."""
        rule = build_nginx_access_denied_sensitive_path_rule()
        for s in (500, 502, 503, 504):
            ev = _ev(event_type="request_blocked", status=s, path="/admin")
            assert rule.evaluate(ev).matched is False, f"{s} on /admin should NOT match"

    def test_200_on_sensitive_path_does_not_match(self) -> None:
        """A 200 on /admin (admin granted access) is a success, not a candidate."""
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="authentication_success", status=200, path="/admin")
        # 200 is not in _FIRE_STATUSES anyway, but the connector would
        # not emit ``request_blocked`` for a 200. The test confirms
        # the rule's status filter is robust to a tampered event.
        assert rule.evaluate(ev).matched is False

    def test_missing_endpoint_does_not_match(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="request_blocked", status=404, path=None)
        assert rule.evaluate(ev).matched is False

    def test_case_insensitive_path_match(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        ev = _ev(event_type="request_blocked", status=404, path="/ADMIN/USERS")
        assert rule.evaluate(ev).matched is True

    def test_metadata(self) -> None:
        rule = build_nginx_access_denied_sensitive_path_rule()
        m = rule.metadata
        assert m.rule_id == "NGINX-ACCESS-DENIED-001"
        assert m.version == 1
        assert m.category is RuleCategory.SOURCE_SPECIFIC
        assert m.sources == ("nginx",)
        assert m.event_types == ("request_blocked",)
        assert m.state is RuleState.APPROVED
        assert m.enabled is True


# ============================================================================
# NGINX-STATUS-ANOMALY-001: 5xx server error observation
# ============================================================================
class TestServerErrorObservation:
    @pytest.mark.parametrize("status", [500, 501, 502, 503, 504])
    def test_each_5xx_matches(self, status: int) -> None:
        rule = build_nginx_server_error_observation_rule()
        ev = _ev(event_type="request_blocked", status=status, path="/api/orders/1")
        assert rule.evaluate(ev).matched is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 429])
    def test_4xx_does_not_match(self, status: int) -> None:
        rule = build_nginx_server_error_observation_rule()
        ev = _ev(event_type="request_blocked", status=status, path="/api/orders/1")
        assert rule.evaluate(ev).matched is False, f"4xx ({status}) must not match"

    def test_2xx_does_not_match(self) -> None:
        rule = build_nginx_server_error_observation_rule()
        ev = _ev(event_type="authentication_success", status=200, path="/api/orders/1")
        assert rule.evaluate(ev).matched is False

    def test_non_nginx_does_not_match(self) -> None:
        rule = build_nginx_server_error_observation_rule()
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        tampered = ev.model_copy(update={"source": "iam"})
        assert rule.evaluate(tampered).matched is False

    def test_metadata(self) -> None:
        rule = build_nginx_server_error_observation_rule()
        m = rule.metadata
        assert m.rule_id == "NGINX-STATUS-ANOMALY-001"
        assert m.version == 1
        assert m.category is RuleCategory.SOURCE_SPECIFIC
        assert m.sources == ("nginx",)
        assert m.event_types == ("request_blocked",)
        assert m.state is RuleState.APPROVED
        assert m.enabled is True


# ============================================================================
# NGINX-RATE-LIMIT-001: 429 observation
# ============================================================================
class TestRateLimitObservation:
    def test_429_matches(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        ev = _ev(event_type="rate_limit_exceeded", status=429, path="/api/items")
        assert rule.evaluate(ev).matched is True

    def test_200_does_not_match(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        ev = _ev(event_type="authentication_success", status=200, path="/api/items")
        assert rule.evaluate(ev).matched is False

    def test_503_does_not_match(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        ev = _ev(event_type="request_blocked", status=503, path="/api/items")
        assert rule.evaluate(ev).matched is False

    def test_status_mismatch_does_not_match(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        ev = _ev(event_type="rate_limit_exceeded", status=200, path="/api/items")
        assert rule.evaluate(ev).matched is False

    def test_non_nginx_does_not_match(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        ev = _ev(event_type="rate_limit_exceeded", status=429, path="/api/items")
        tampered = ev.model_copy(update={"source": "waf"})
        assert rule.evaluate(tampered).matched is False

    def test_metadata(self) -> None:
        rule = build_nginx_rate_limit_observation_rule()
        m = rule.metadata
        assert m.rule_id == "NGINX-RATE-LIMIT-001"
        assert m.version == 1
        assert m.category is RuleCategory.SOURCE_SPECIFIC
        assert m.sources == ("nginx",)
        assert m.event_types == ("rate_limit_exceeded",)
        assert m.state is RuleState.APPROVED
        assert m.enabled is True


# ============================================================================
# Loader-level tests for the Phase 4.4 library.
# ============================================================================
def test_phase44_loader_registers_all_nginx_rules() -> None:
    r = RuleRegistry()
    n, _ = load_rules_from_specs(r, ["app.rules._library.nginx"])
    assert n == 5
    expected = {
        "NGINX-ACCESS-DENIED-001",
        "NGINX-AUTH-BRUTEFORCE-001",
        "NGINX-AUTH-FAILURE-001",
        "NGINX-RATE-LIMIT-001",
        "NGINX-STATUS-ANOMALY-001",
    }
    actual = {rule.metadata.rule_id for rule in r.list_all()}
    assert actual == expected


def test_phase44_rules_are_all_enabled() -> None:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    enabled_ids = {rule.metadata.rule_id for rule in r.list_enabled()}
    expected = {
        "NGINX-ACCESS-DENIED-001",
        "NGINX-AUTH-BRUTEFORCE-001",
        "NGINX-AUTH-FAILURE-001",
        "NGINX-RATE-LIMIT-001",
        "NGINX-STATUS-ANOMALY-001",
    }
    assert enabled_ids == expected


def test_phase44_disabled_rule_is_excluded_from_applicability() -> None:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    r.set_enabled("NGINX-AUTH-FAILURE-001", False)
    ev = _ev(event_type="authentication_failure", status=401, path="/api/v1/login")
    applicable_ids = {
        rule.metadata.rule_id for rule in r.applies_to(ev)
    }
    assert "NGINX-AUTH-FAILURE-001" not in applicable_ids
    assert "NGINX-AUTH-BRUTEFORCE-001" in applicable_ids
