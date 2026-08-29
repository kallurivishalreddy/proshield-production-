"""Unit tests for the NGINX access-log parser.

The parser is a pure function from one log line to a
:class:`ParsedNginxLine`. The tests cover positive cases,
negative cases, malformed input, and edge cases.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.connectors.nginx.parser import (
    MAX_LINE_BYTES,
    NginxParseError,
    ParsedNginxLine,
    parse_combined_line,
)


_GOOD_LINE = (
    '192.0.2.10 - alice [26/Aug/2026:03:15:42 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"'
)


# ------------------------------------------------------------------ positive
def test_parses_well_formed_line() -> None:
    rec = parse_combined_line(_GOOD_LINE)
    assert isinstance(rec, ParsedNginxLine)
    assert rec.remote_addr == "192.0.2.10"
    assert rec.remote_user == "alice"
    assert rec.event_time == datetime(2026, 8, 26, 3, 15, 42, tzinfo=timezone.utc)
    assert rec.method == "POST"
    assert rec.path == "/api/login"
    assert rec.protocol == "HTTP/1.1"
    assert rec.status == 401
    assert rec.body_bytes_sent == 612
    assert rec.referer is None
    assert rec.user_agent == "curl/8.5.0"


def test_tolerates_trailing_newline() -> None:
    rec1 = parse_combined_line(_GOOD_LINE + "\n")
    rec2 = parse_combined_line(_GOOD_LINE)
    assert rec1 == rec2


def test_tolerates_trailing_crlf() -> None:
    rec = parse_combined_line(_GOOD_LINE + "\r\n")
    assert rec.status == 401


def test_minus_remote_user_is_none() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    )
    assert rec.remote_user is None
    assert rec.referer is None


def test_minus0000_treated_as_utc() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 -0000] '
        '"GET /x HTTP/1.1" 200 0 "-" "-"'
    )
    assert rec.event_time.tzinfo is timezone.utc


def test_nonzero_timezone_offset_preserved() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0530] '
        '"GET /x HTTP/1.1" 200 0 "-" "-"'
    )
    # 03:16:00 +0530 == 21:46:00 UTC the previous day.
    assert rec.event_time == datetime(
        2026, 8, 25, 21, 46, 0, tzinfo=timezone.utc
    )


def test_ipv6_remote_addr_accepted() -> None:
    rec = parse_combined_line(
        '2001:db8::1 - - [26/Aug/2026:03:16:00 +0000] '
        '"GET / HTTP/1.1" 200 0 "-" "-"'
    )
    assert rec.remote_addr == "2001:db8::1"


def test_user_agent_with_spaces_preserved() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        '"GET /x HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0) test"'
    )
    assert rec.user_agent == "Mozilla/5.0 (Windows NT 10.0) test"


def test_status_range_parsed() -> None:
    for status, line in [
        (200, '"GET /a HTTP/1.1" 200 0 "-" "-"'),
        (301, '"GET /b HTTP/1.1" 301 0 "-" "-"'),
        (404, '"GET /c HTTP/1.1" 404 0 "-" "-"'),
        (500, '"GET /d HTTP/1.1" 500 0 "-" "-"'),
    ]:
        full = (
            f"198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] {line}"
        )
        assert parse_combined_line(full).status == status


def test_status_599_accepted() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        '"GET /x HTTP/1.1" 599 0 "-" "-"'
    )
    assert rec.status == 599


# ------------------------------------------------------------------ negative
def test_empty_line_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line("")


def test_non_string_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(b"not a str")  # type: ignore[arg-type]


def test_garbage_line_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line("this is not a log line at all")


def test_missing_method_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '/api/x HTTP/1.1 200 0 "-" "-"'
        )


def test_status_99_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '"GET /x HTTP/1.1" 99 0 "-" "-"'
        )


def test_status_600_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '"GET /x HTTP/1.1" 600 0 "-" "-"'
        )


def test_status_not_a_number_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '"GET /x HTTP/1.1" abc 0 "-" "-"'
        )


def test_non_ip_remote_addr_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            'not-an-ip - - [26/Aug/2026:03:16:00 +0000] '
            '"GET /x HTTP/1.1" 200 0 "-" "-"'
        )


def test_lowercase_method_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '"get /x HTTP/1.1" 200 0 "-" "-"'
        )


def test_bad_time_format_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [not-a-time] '
            '"GET /x HTTP/1.1" 200 0 "-" "-"'
        )


def test_trailing_garbage_rejected() -> None:
    with pytest.raises(NginxParseError):
        parse_combined_line(_GOOD_LINE + " extra-stuff")


def test_error_message_does_not_leak_line() -> None:
    """Raw line must NEVER appear in the parser error message.

    A log line can carry attacker-controlled bytes; the
    safe-error envelope forbids echoing them.
    """
    secret = "very-secret-token-AAAAA"
    bad = f"prefix {secret} rest"
    with pytest.raises(NginxParseError) as exc:
        parse_combined_line(bad)
    assert secret not in str(exc.value)


# ------------------------------------------------------------------ edge
def test_oversized_line_rejected_before_regex() -> None:
    # Use a 1-char string that is large enough on the wire to
    # exceed MAX_LINE_BYTES. Single ASCII chars are 1 byte each.
    huge = "x" * (MAX_LINE_BYTES + 100)
    with pytest.raises(NginxParseError):
        parse_combined_line(huge)


def test_oversized_user_agent_rejected() -> None:
    big_ua = "A" * 600
    line = (
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        f'"GET /x HTTP/1.1" 200 0 "-" "{big_ua}"'
    )
    with pytest.raises(NginxParseError):
        parse_combined_line(line)


def test_oversized_referer_rejected() -> None:
    big_ref = "B" * 600
    line = (
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        f'"GET /x HTTP/1.1" 200 0 "{big_ref}" "-"'
    )
    with pytest.raises(NginxParseError):
        parse_combined_line(line)


def test_oversized_remote_user_rejected() -> None:
    big_user = "U" * 200
    line = (
        f'198.51.100.7 - {big_user} [26/Aug/2026:03:16:00 +0000] '
        '"GET /x HTTP/1.1" 200 0 "-" "-"'
    )
    with pytest.raises(NginxParseError):
        parse_combined_line(line)


def test_path_with_nul_rejected() -> None:
    # The NUL is rejected because the parser regex forbids
    # control characters in the path.
    with pytest.raises(NginxParseError):
        parse_combined_line(
            '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
            '"GET /x\x00y HTTP/1.1" 200 0 "-" "-"'
        )


def test_zero_body_bytes_accepted() -> None:
    rec = parse_combined_line(
        '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
        '"GET /x HTTP/1.1" 304 0 "-" "-"'
    )
    assert rec.body_bytes_sent == 0

