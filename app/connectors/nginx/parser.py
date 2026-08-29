"""Pure parser for NGINX access-log lines.

This module is the *only* place in the codebase that knows about the
shape of an NGINX access log line. The rest of the connector and the
rest of the system operate on the parsed structured record.

The default supported format is the standard ``combined`` NGINX log
format (the format produced by NGINX's default ``log_format combined``
directive):

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

A representative line:

    192.0.2.10 - alice [26/Aug/2026:03:15:42 +0000] "POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"

Design rules:

* **Pure.** No I/O, no globals, no time, no logging.
* **Bounded.** Every captured field is bounded to documented sizes.
* **No secrets.** The parser NEVER captures request or response
  bodies. It only captures the documented fields and bounds
  ``Referer`` and ``User-Agent`` defensively.
* **Explicit failure.** A line that cannot be parsed raises
  :class:`NginxParseError`. The raw line is never included in the
  error message (an attacker can put anything in a log line).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


# ------------------------------------------------------------------ bounds
# Field-size bounds for the parsed record. The connector maps these
# fields into SecurityEvent fields with their own bounds; this set is
# a defensive first pass so a 10 MB User-Agent cannot enter the
# pipeline. Bounds mirror the schema's documented field limits
# (docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 12).
MAX_LINE_BYTES = 16 * 1024
MAX_REMOTE_ADDR = 64
MAX_REMOTE_USER = 128
MAX_REFERER = 512
MAX_USER_AGENT = 512
MAX_METHOD = 16
MAX_PATH = 512
MAX_PROTOCOL = 16
MAX_BODY_BYTES_STR = 20  # 64-bit decimal fits in 20 chars


class NginxParseError(ValueError):
    """A line cannot be parsed as an NGINX ``combined`` log line.

    The connector catches this and either skips the line (default)
    or aborts (strict mode). The error message intentionally does
    NOT include the raw line content: a malformed log line can
    contain attacker-controlled bytes.
    """


@dataclass(frozen=True)
class ParsedNginxLine:
    """The structured result of parsing one access-log line.

    Connector-internal record, NOT a SecurityEvent. The mapping
    step in :mod:`app.connectors.nginx.mapping` converts it to a
    canonical :class:`SecurityEvent`.
    """

    remote_addr: str
    remote_user: Optional[str]
    event_time: datetime
    method: str
    path: str
    protocol: str
    status: int
    body_bytes_sent: int
    referer: Optional[str]
    user_agent: Optional[str]


# ------------------------------------------------------------------ regex
# Combined-format regex. Each named group corresponds to a field in
# :class:`ParsedNginxLine`. Compiled once at module load.
_COMBINED_RE = re.compile(
    r"^(?P<remote_addr>\S+)"
    r" - "
    r"(?P<remote_user>\S+)"
    r" \[(?P<time_local>[^\]\n\r]+)\]"
    r' "(?P<method>[A-Z]+)'
    r" (?P<path>[^\s\n\r]+)"
    r" (?P<protocol>HTTP/\d\.\d)"
    r'"'
    r" (?P<status>\d{3})"
    r" (?P<body_bytes>\d+)"
    r' "(?P<referer>[^"\n\r]*)"'
    r' "(?P<user_agent>[^"\n\r]*)"'
    r"\s*$"
)

_TIME_LOCAL_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})"
    r" (?P<tzsign>[+\-])(?P<tzhh>\d{2})(?P<tzmm>\d{2})$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# ------------------------------------------------------------------ helpers
def _coerce_remote_user(raw: str) -> Optional[str]:
    """``remote_user`` is ``-`` when NGINX did not authenticate the
    request; treat it as the absence of an identity.
    """
    if raw is None or raw == "-":
        return None
    return raw


def _coerce_optional_quoted(raw: str) -> Optional[str]:
    """A quoted field is ``-`` when the source did not supply it."""
    if raw is None or raw == "-":
        return None
    return raw


def _parse_time_local(raw: str) -> datetime:
    """Parse NGINX's ``$time_local`` into a tz-aware UTC datetime.

    NGINX emits ``26/Aug/2026:03:15:42 +0000`` (or ``-0000`` for UTC).
    Strict: any deviation raises :class:`NginxParseError`. The
    result is normalised to UTC.
    """
    m = _TIME_LOCAL_RE.match(raw)
    if not m:
        raise NginxParseError("time_local does not match the expected format")
    try:
        month = _MONTHS[m.group("mon").title()]
        year = int(m.group("year"))
        day = int(m.group("day"))
        hour = int(m.group("hour"))
        minute = int(m.group("min"))
        second = int(m.group("sec"))
        tz_sign = 1 if m.group("tzsign") == "+" else -1
        tz_off_minutes = tz_sign * (
            int(m.group("tzhh")) * 60 + int(m.group("tzmm"))
        )
        local = datetime(year, month, day, hour, minute, second)
        if tz_off_minutes == 0:
            return local.replace(tzinfo=timezone.utc)
        return local.replace(tzinfo=timezone(timedelta(minutes=tz_off_minutes)))
    except (KeyError, ValueError) as exc:
        raise NginxParseError(
            "time_local values are not in the expected ranges"
        ) from exc


def _bounded(value: str, *, max_length: int) -> str:
    """Truncate a string field to ``max_length`` characters."""
    if len(value) > max_length:
        return value[:max_length]
    return value


def _require_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise NginxParseError("remote_addr is not a valid IP address") from exc
    return value


def _require_int_in_range(value: str, *, lo: int, hi: int, field: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise NginxParseError(f"{field} is not an integer") from exc
    if n < lo or n > hi:
        raise NginxParseError(f"{field} is out of range")
    return n


# ------------------------------------------------------------------ public
def parse_combined_line(line: str) -> ParsedNginxLine:
    """Parse a single NGINX ``combined``-format access-log line.

    A line exceeding :data:`MAX_LINE_BYTES` is rejected before
    regex-matching so a 1 GB line cannot consume memory. The raw
    line is never echoed back in the error message.

    Returns
    -------
    ParsedNginxLine
        Connector-internal record. NOT a SecurityEvent.

    Raises
    ------
    NginxParseError
        If the line cannot be parsed. Safe to catch at the
        connector boundary; per-line error messages are
        attacker-controllable in principle, so the connector
        itself counts and logs them rather than re-throwing.
    """
    if not isinstance(line, str):
        raise NginxParseError("line is not a string")
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n") or line.endswith("\r"):
        line = line[:-1]
    if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
        raise NginxParseError("line exceeds the documented size limit")
    if not line:
        raise NginxParseError("line is empty")

    m = _COMBINED_RE.match(line)
    if not m:
        raise NginxParseError("line does not match the combined format")

    remote_addr = _bounded(
        m.group("remote_addr"), max_length=MAX_REMOTE_ADDR
    )
    _require_ip(remote_addr)
    remote_user_raw = m.group("remote_user")
    if remote_user_raw != "-" and len(remote_user_raw) > MAX_REMOTE_USER:
        raise NginxParseError("remote_user exceeds the documented size limit")
    remote_user = _coerce_remote_user(remote_user_raw)

    event_time = _parse_time_local(m.group("time_local"))

    method = _bounded(m.group("method"), max_length=MAX_METHOD)
    if not method.isalpha() or not method.isupper():
        raise NginxParseError("method must be uppercase ASCII letters")

    path = _bounded(m.group("path"), max_length=MAX_PATH)
    if "\x00" in path or "\n" in path or "\r" in path:
        raise NginxParseError("path contains forbidden characters")

    protocol = _bounded(m.group("protocol"), max_length=MAX_PROTOCOL)

    status = _require_int_in_range(
        m.group("status"), lo=100, hi=599, field="status"
    )

    body_bytes_raw = m.group("body_bytes")
    if len(body_bytes_raw) > MAX_BODY_BYTES_STR:
        raise NginxParseError("body_bytes_sent is not bounded")
    body_bytes = _require_int_in_range(
        body_bytes_raw, lo=0, hi=10**12, field="body_bytes_sent"
    )

    referer_raw = m.group("referer")
    if len(referer_raw) > MAX_REFERER:
        raise NginxParseError("referer exceeds the documented size limit")
    referer = _coerce_optional_quoted(referer_raw)

    user_agent_raw = m.group("user_agent")
    if len(user_agent_raw) > MAX_USER_AGENT:
        raise NginxParseError("user_agent exceeds the documented size limit")
    user_agent = _coerce_optional_quoted(user_agent_raw)

    return ParsedNginxLine(
        remote_addr=remote_addr,
        remote_user=remote_user,
        event_time=event_time,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        body_bytes_sent=body_bytes,
        referer=referer,
        user_agent=user_agent,
    )

