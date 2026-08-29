"""Unit tests for the first production NGINX rule."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from app.domain.security_event import (
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules import (
    RuleCategory,
    RuleRegistry,
    RuleState,
    load_rules_from_specs,
)
from app.rules._library.nginx import build_nginx_auth_brute_force_rule


def _ev(
    *,
    event_type: str = "authentication_failure",
    status: int = 401,
    path: str = "/api/login",
    source_ip: str = "192.0.2.10",
    account_id: Optional[str] = "alice",
) -> SecurityEvent:
    et = datetime(2026, 8, 26, 3, 0, 0, tzinfo=timezone.utc)
    kwargs: Dict[str, Any] = dict(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="nginx",
        event_type=event_type,
        source_ip=source_ip,
        endpoint=path,
        provenance=SecurityEventProvenance(
            collector="nginx", source_event_id="src-1"
        ),
        details={
            "http_method": "POST",
            "status_code": status,
            "protocol": "HTTP/1.1",
            "body_bytes_sent": 0,
            "log_line_number": 1,
        },
    )
    if account_id is not None:
        kwargs["account"] = SecurityEventAccount(id=account_id)
    return SecurityEvent(**kwargs)


# ------------------------------------------------------------------ positives
def test_401_on_auth_login_endpoint_matches() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    out = rule.evaluate(ev)
    assert out.matched is True
    assert out.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
    assert out.rule_version == 1
    assert out.target_event_id == ev.event_id


def test_403_on_auth_endpoint_matches() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="request_blocked", status=403, path="/api/v1/auth/login")
    out = rule.evaluate(ev)
    assert out.matched is True


def test_401_on_oauth_endpoint_matches() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/oauth/token")
    out = rule.evaluate(ev)
    assert out.matched is True


def test_401_on_sso_endpoint_matches() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/sso/login")
    out = rule.evaluate(ev)
    assert out.matched is True


def test_403_on_token_endpoint_matches() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="request_blocked", status=403, path="/api/token/refresh")
    out = rule.evaluate(ev)
    assert out.matched is True


# ------------------------------------------------------------------ negatives
def test_200_on_auth_endpoint_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_success", status=200, path="/api/login")
    out = rule.evaluate(ev)
    assert out.matched is False


def test_404_on_auth_endpoint_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="request_blocked", status=404, path="/api/login")
    out = rule.evaluate(ev)
    assert out.matched is False


def test_401_on_non_auth_endpoint_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/users/1")
    out = rule.evaluate(ev)
    assert out.matched is False


def test_401_on_static_path_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/index.html")
    out = rule.evaluate(ev)
    assert out.matched is False


def test_non_nginx_source_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    tampered = ev.model_copy(update={"source": "waf"})
    out = rule.evaluate(tampered)
    assert out.matched is False


def test_missing_endpoint_does_not_match() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    tampered = ev.model_copy(update={"endpoint": None})
    out = rule.evaluate(tampered)
    assert out.matched is False


# ------------------------------------------------------------------ metadata
def test_rule_metadata_is_correct() -> None:
    rule = build_nginx_auth_brute_force_rule()
    m = rule.metadata
    assert m.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
    assert m.version == 1
    assert m.category is RuleCategory.SOURCE_SPECIFIC
    assert m.sources == ("nginx",)
    assert m.event_types == ("authentication_failure", "request_blocked")
    assert m.state is RuleState.APPROVED
    assert m.enabled is True
    assert "AUTH" in m.tags


# ------------------------------------------------------------------ applicability
def test_rule_is_applicable_to_nginx_auth_failure() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    assert rule.metadata.applies_to(ev) is True


def test_rule_not_applicable_to_other_source() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    tampered = ev.model_copy(update={"source": "iam"})
    assert rule.metadata.applies_to(tampered) is False


def test_rule_not_applicable_when_disabled() -> None:
    """When the registry disables the rule, applies_to
    returns False (the documented enabled => APPROVED
    invariant is enforced by the registry).
    """
    rule = build_nginx_auth_brute_force_rule()
    r = RuleRegistry()
    r.register(rule)
    r.set_enabled("NGINX-AUTH-BRUTEFORCE-001", False)
    # Re-fetch the rule (registry mutates the instance).
    registered = r.get("NGINX-AUTH-BRUTEFORCE-001")
    assert registered is not None
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    assert registered.metadata.applies_to(ev) is False


# ------------------------------------------------------------------ registry
def test_rule_loads_via_loader_and_registers() -> None:
    r = RuleRegistry()
    n, _ = load_rules_from_specs(r, ["app.rules._library.nginx"])
    # Phase 4.4 adds 4 more per-event production rules to the
    # NGINX rule library (the original BRUTEFORCE rule is still
    # registered). The library is now 1 + 4 = 5 rules.
    assert n == 5
    assert r.has("NGINX-AUTH-BRUTEFORCE-001")
    assert r.latest_version("NGINX-AUTH-BRUTEFORCE-001") == 1


def test_rule_is_listed_for_nginx_auth_failure() -> None:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    applicable = r.list_for_event(ev.source, ev.event_type)
    assert any(
        rule.metadata.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
        for rule in applicable
    )


def test_rule_is_listed_for_nginx_request_blocked() -> None:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    ev = _ev(event_type="request_blocked", status=403, path="/api/v1/auth/login")
    applicable = r.list_for_event(ev.source, ev.event_type)
    assert any(
        rule.metadata.rule_id == "NGINX-AUTH-BRUTEFORCE-001"
        for rule in applicable
    )


def test_rule_not_listed_for_other_source() -> None:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    tampered = ev.model_copy(update={"source": "iam"})
    applicable = r.list_for_event(tampered.source, tampered.event_type)
    assert all(
        rule.metadata.rule_id != "NGINX-AUTH-BRUTEFORCE-001"
        for rule in applicable
    )


# ------------------------------------------------------------------ reasoning
def test_reasoning_mentions_status_and_endpoint() -> None:
    rule = build_nginx_auth_brute_force_rule()
    ev = _ev(event_type="authentication_failure", status=401, path="/api/login")
    out = rule.evaluate(ev)
    assert out.matched is True
    assert "401" in out.reasoning
    assert "/api/login" in out.reasoning

