"""Permanent regression tests for the structured-logging scrubber.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md, Section 30, and
docs/PHASE 3/SECURITY_CONFIGURATION.md (AC-CONFIG-07: "Secrets
never appear in logs, API responses, or audit records.").

These tests cover the two HIGH-severity findings from
docs/PHASE 4/PHASE 4-01/PHASE-04-01-REVIEW.md:

  * FINDING-001: ``mongodb://user:secret@host`` previously became
    ``***user:secret@host`` because the scrubber only replaced the
    scheme.  The userinfo segment is now stripped.
  * FINDING-002: mixed-case key names (``Password=``) and the *value*
    attached to scrubbed keys (``PASSWORD=hunter2``) previously
    survived.  Detection and replacement are now case-insensitive
    and global, and a dedicated ``KEY=value`` redactor handles
    the common case.
"""
from __future__ import annotations

import io
import json
import logging

import pytest

from app.observability.logging import (
    _JsonFormatter,
    _redact_key_equals_value,
    _redact_uri_userinfo,
    _scrub,
    configure_logging,
)


# ---------------------------------------------------------------------------
# FINDING-001: MongoDB credential-bearing URI
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "uri,expected",
    [
        ("mongodb://user:secret@host:27017/db", "mongodb://***@host:27017/db"),
        ("mongodb://host:27017/db", "mongodb://host:27017/db"),
        (
            "mongodb+srv://alice:pa55word@cluster0.example.net/?retryWrites=true",
            "mongodb+srv://***@cluster0.example.net/?retryWrites=true",
        ),
        (
            "connecting from mongodb://a:b@host1 to mongodb://c:d@host2",
            "connecting from mongodb://***@host1 to mongodb://***@host2",
        ),
        (
            "ctx: see mongodb://root:pw@prod.example:27017/admin for the config",
            "ctx: see mongodb://***@prod.example:27017/admin for the config",
        ),
        (
            "mongodb://root:pw@prod.example:27017/admin?ssl=true",
            "mongodb://***@prod.example:27017/admin?ssl=true",
        ),
    ],
)
def test_uri_userinfo_is_always_stripped(uri: str, expected: str) -> None:
    assert _redact_uri_userinfo(uri) == expected


# ---------------------------------------------------------------------------
# FINDING-002: mixed-case key names and the value side
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("password=hunter2", "password=***"),
        ("Password=hunter2", "Password=***"),
        ("PASSWORD=hunter2", "PASSWORD=***"),
        ("PASSWORD=hunter2;user=alice", "PASSWORD=***;user=alice"),
        ("PASSWORD=hunter2&user=alice", "PASSWORD=***&user=alice"),
        ("PASSWORD=hunter2 user=alice", "PASSWORD=*** user=alice"),
        ("PASSWORD: hunter2", "PASSWORD: ***"),
        ("user=alice", "user=alice"),
        ("host=db.example", "host=db.example"),
    ],
)
def test_key_value_pair_redaction(raw: str, expected: str) -> None:
    assert _redact_key_equals_value(raw) == expected


@pytest.mark.parametrize(
    "raw,forbidden_substring",
    [
        ("PASSWORD=hunter2", "hunter2"),
        ("Password=hunter2", "hunter2"),
        ("password=hunter2", "hunter2"),
        ("API_KEY=sk_live_abc", "sk_live_abc"),
        ("Token=ghp_abcdef", "ghp_abcdef"),
        ("Bearer eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9"),
        ("PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA"),
        ("CREDENTIAL=user:pass@host", "user:pass@host"),
    ],
)
def test_value_after_sensitive_key_is_never_logged(
    raw: str, forbidden_substring: str
) -> None:
    scrubbed = _scrub(raw)
    assert forbidden_substring not in scrubbed, (
        f"scrubbed message {scrubbed!r} still contains {forbidden_substring!r}"
    )


@pytest.mark.parametrize(
    "raw,sensitive",
    [
        ("PASSWORD=abc", "PASSWORD"),
        ("Password=abc", "Password"),
        ("password=abc", "password"),
        ("Authorization: Bearer xyz", "Bearer"),
        ("Auth-Token: secret", "Token"),
        ("My-Secret-Field=1", "Secret"),
        ("Has-Token-Inside=1", "Token"),
    ],
)
def test_sensitive_key_name_is_always_removed(
    raw: str, sensitive: str
) -> None:
    scrubbed = _scrub(raw)
    assert sensitive not in scrubbed, (
        f"scrubbed message {scrubbed!r} still contains {sensitive!r}"
    )


def test_uri_and_key_value_in_same_message() -> None:
    raw = (
        "fail to open mongodb://root:secret@db:27017/admin; "
        "Password=ops; next"
    )
    out = _scrub(raw)
    assert "root" not in out
    assert "secret" not in out
    assert "ops" not in out
    assert "***" in out


# ---------------------------------------------------------------------------
# Sanity: benign messages are not damaged.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        "user logged in",
        "request completed in 12ms",
        "host=db.example port=27017",
        "session_id=abcd",
    ],
)
def test_benign_messages_are_not_modified(raw: str) -> None:
    assert _scrub(raw) == raw


# ---------------------------------------------------------------------------
# End-to-end via the actual JSON formatter (the only path that matters)
# ---------------------------------------------------------------------------
@pytest.fixture
def captured_log() -> io.StringIO:
    """Install a fresh JSON handler on a private logger and return the buffer."""
    configure_logging("INFO")
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_JsonFormatter())
    test_logger = logging.getLogger("review_test_scrubber")
    for h in list(test_logger.handlers):
        test_logger.removeHandler(h)
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.INFO)
    test_logger.propagate = False
    return buf


def test_json_formatter_strips_mongodb_credentials(
    captured_log: io.StringIO,
) -> None:
    log = logging.getLogger("review_test_scrubber")
    log.info("ctx: connecting to %s", "mongodb://user:secret@host:27017/db")
    line = captured_log.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert "user" not in payload["msg"]
    assert "secret" not in payload["msg"]
    assert "mongodb://***@host:27017/db" in payload["msg"]


def test_json_formatter_strips_mixed_case_key_and_value(
    captured_log: io.StringIO,
) -> None:
    log = logging.getLogger("review_test_scrubber")
    log.info("config: Password=hunter2; user=alice")
    line = captured_log.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert "hunter2" not in payload["msg"]
    assert "Password" not in payload["msg"]
    assert "user=alice" in payload["msg"]


def test_json_formatter_strips_scrubbed_substring_inside_extras(
    captured_log: io.StringIO,
) -> None:
    log = logging.getLogger("review_test_scrubber")
    log.info(
        "recording",
        extra={
            "config": "mongodb://u:p@h:27017",
        },
    )
    line = captured_log.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert "u" not in payload["config"]
    assert "p" not in payload["config"]
    assert "mongodb://***@h:27017" in payload["config"]


# ---------------------------------------------------------------------------
# The forbidden-substrings set itself: defense-in-depth.
# ---------------------------------------------------------------------------
def test_forbidden_substrings_is_a_tuple() -> None:
    assert isinstance(_JsonFormatter._FORBIDDEN_SUBSTRINGS, tuple)


def test_forbidden_substrings_contains_documented_keys() -> None:
    for key in ("PASSWORD", "SECRET", "TOKEN", "BEARER", "API_KEY"):
        assert key in _JsonFormatter._FORBIDDEN_SUBSTRINGS


def test_uri_schemes_contains_documented_schemes() -> None:
    assert "mongodb://" in _JsonFormatter._URI_SCHEMES
    assert "mongodb+srv://" in _JsonFormatter._URI_SCHEMES
