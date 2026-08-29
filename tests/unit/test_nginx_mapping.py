"""Unit tests for the parsed-NGINX-record -> SecurityEvent mapping."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.connectors.nginx.mapping import map_parsed_record_to_event
from app.connectors.nginx.parser import ParsedNginxLine
from app.domain.security_event import SecurityEvent
from app.domain.uuid7 import is_uuid7


def _rec(
    *,
    status: int,
    method: str = "GET",
    path: str = "/index",
    remote_user=None,
    remote_addr: str = "192.0.2.10",
    user_agent: str = "ua/1",
    body_bytes_sent: int = 0,
) -> ParsedNginxLine:
    return ParsedNginxLine(
        remote_addr=remote_addr,
        remote_user=remote_user,
        event_time=datetime(2026, 8, 26, 3, 0, 0, tzinfo=timezone.utc),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        body_bytes_sent=body_bytes_sent,
        referer=None,
        user_agent=user_agent,
    )


def _map(rec: ParsedNginxLine, **kw) -> SecurityEvent:
    out = map_parsed_record_to_event(
        rec,
        line_number=42,
        source_event_id="abc-123",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
        **kw,
    )
    assert out is not None
    return out


# ------------------------------------------------------------------ positives
def test_401_maps_to_authentication_failure() -> None:
    e = _map(_rec(status=401, path="/api/login"))
    assert e.event_type == "authentication_failure"
    assert e.details["status_code"] == 401


def test_403_maps_to_request_blocked() -> None:
    e = _map(_rec(status=403, path="/api/users"))
    assert e.event_type == "request_blocked"
    assert e.details["status_code"] == 403


def test_404_maps_to_request_blocked() -> None:
    e = _map(_rec(status=404, path="/missing"))
    assert e.event_type == "request_blocked"


def test_429_maps_to_rate_limit_exceeded() -> None:
    e = _map(_rec(status=429, path="/api/v1/users"))
    assert e.event_type == "rate_limit_exceeded"


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_maps_to_request_blocked(status: int) -> None:
    e = _map(_rec(status=status, path="/api/x"))
    assert e.event_type == "request_blocked"


def test_2xx_on_auth_endpoint_with_user_maps_to_auth_success() -> None:
    e = _map(
        _rec(status=200, path="/api/v1/auth/login", remote_user="alice")
    )
    assert e.event_type == "authentication_success"
    assert e.account is not None
    assert e.account.id == "alice"


def test_2xx_on_non_auth_path_emits_no_event() -> None:
    """Normal 2xx traffic on a public page is not security signal.

    The rule layer is the right place to draw conclusions from
    2xx traffic; the connector does not pre-judge.
    """
    out = map_parsed_record_to_event(
        _rec(status=200, path="/index.html"),
        line_number=1,
        source_event_id="x",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
    )
    assert out is None


def test_2xx_on_auth_path_without_user_emits_no_event() -> None:
    out = map_parsed_record_to_event(
        _rec(status=200, path="/api/login", remote_user=None),
        line_number=1,
        source_event_id="x",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
    )
    assert out is None


def test_3xx_emits_no_event() -> None:
    out = map_parsed_record_to_event(
        _rec(status=304),
        line_number=1,
        source_event_id="x",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
    )
    assert out is None


def test_1xx_emits_no_event() -> None:
    out = map_parsed_record_to_event(
        _rec(status=100),
        line_number=1,
        source_event_id="x",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
    )
    assert out is None


# ------------------------------------------------------------------ envelope
def test_event_envelope_is_canonical() -> None:
    """The mapping must produce a canonical SecurityEvent.

    ``source`` is a documented ALLOWED_SOURCES member; the
    event_type is a documented ALLOWED_EVENT_TYPES member;
    the event_id is a UUIDv7.
    """
    e = _map(_rec(status=403, path="/api/x"))
    assert e.source == "nginx"
    assert e.event_type in (
        "waf_attack_detected",
        "request_blocked",
        "rate_limit_exceeded",
        "suspicious_request",
        "authentication_failure",
        "authentication_success",
        "tls_anomaly",
        "network_anomaly",
        "security_control_alert",
    )
    assert e.provenance.collector == "nginx"
    assert e.provenance.source_event_id == "abc-123"
    # The mapping uses the connector-supplied event_id
    # verbatim; the connector derives a deterministic
    # UUIDv7-shaped id from a hash. The mapping does not
    # mint ids of its own.
    assert e.event_id == "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12"


def test_provenance_preserved() -> None:
    """The documented provenance contract (Section 8) is
    preserved: collector + source_event_id remain traceable.
    """
    e = _map(_rec(status=403, path="/api/x"))
    assert e.provenance.collector == "nginx"
    assert e.provenance.source_event_id == "abc-123"


def test_account_id_when_remote_user_present() -> None:
    e = _map(_rec(status=401, path="/api/login", remote_user="bob"))
    assert e.account is not None
    assert e.account.id == "bob"


def test_no_account_when_remote_user_dash() -> None:
    e = _map(_rec(status=403, path="/api/x", remote_user=None))
    assert e.account is None


def test_details_contain_method_status_protocol() -> None:
    e = _map(_rec(status=403, path="/api/x", method="POST"))
    assert e.details["http_method"] == "POST"
    assert e.details["status_code"] == 403
    assert e.details["protocol"] == "HTTP/1.1"


def test_details_contain_user_agent_when_present() -> None:
    e = _map(_rec(status=403, user_agent="curl/8.5"))
    assert e.details["user_agent"] == "curl/8.5"


def test_details_omit_user_agent_when_dash() -> None:
    e = _map(_rec(status=403, user_agent=None))
    assert "user_agent" not in e.details


def test_details_contain_line_number() -> None:
    e = map_parsed_record_to_event(
        _rec(status=403, path="/api/x"),
        line_number=4242,
        source_event_id="x",
        event_id="0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
    )
    assert e.details["log_line_number"] == 4242


def test_asset_propagated_when_supplied() -> None:
    e = _map(_rec(status=403, path="/api/x"), asset="web-api-01")
    assert e.asset == "web-api-01"
    assert e.destination == "web-api-01"


def test_source_ip_propagated() -> None:
    e = _map(_rec(status=403, remote_addr="203.0.113.99"))
    assert e.source_ip == "203.0.113.99"


def test_endpoint_propagated() -> None:
    e = _map(_rec(status=403, path="/api/v1/users/42"))
    assert e.endpoint == "/api/v1/users/42"

