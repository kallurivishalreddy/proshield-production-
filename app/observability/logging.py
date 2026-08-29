"""Structured JSON logging for ProShield.

Why JSON: it composes with log aggregators without losing the safety
guarantees we need. Every log record carries a ``request_id`` so that
safe client-facing errors can be correlated with server-side
diagnostics (docs/PHASE 3/SECURE_FOUNDATION.md, Section 30).

We deliberately do NOT use ``logging.basicConfig`` in the application
code: the host process owns log configuration. We only emit through a
named logger so the host can route and filter as needed.

NEVER log:
  * raw event payloads (may contain sensitive data)
  * MongoDB connection URIs containing credentials
  * stack traces from internal driver errors to client-visible surfaces
  * full request bodies
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional

# A request_id is per-request; the default value is "-" so it is always
# a string (never None) when emitted in JSON.
_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def set_request_id(request_id: Optional[str] = None) -> str:
    rid = request_id or uuid.uuid4().hex
    _request_id_var.set(rid)
    return rid


def get_request_id() -> str:
    return _request_id_var.get()


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    # Substrings that must NEVER appear in a log message. The scrubber
    # runs case-insensitively and globally, so mixed-case key names are
    # also redacted.  This is a defense-in-depth net; the primary
    # contract is that the application must never log secrets in the
    # first place (see app/observability/logging.py docstring).
    _FORBIDDEN_SUBSTRINGS = (
        "JWT_SECRET",
        "SECRET",
        "PASSWORD",
        "PRIVATE_KEY",
        "BEARER",
        "TOKEN",
        "API_KEY",
        "CREDENTIAL",
        "SESSION_COOKIE",
        "COOKIE",
    )

    # Substrings that look like a known credential-bearing URI scheme.
    # The entire userinfo segment of any matching URI is stripped.
    _URI_SCHEMES = (
        "mongodb://",
        "mongodb+srv://",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": _scrub(record.getMessage()),
            "request_id": _request_id_var.get(),
        }
        # Extra structured fields, if any.
        for key, value in record.__dict__.items():
            if key in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "levelname", "levelno", "lineno",
                "message", "module", "msecs", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "stack_info",
                "thread", "threadName", "taskName",
            ):
                continue
            payload[key] = _scrub_value(value)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            # We deliberately do not emit the formatted traceback here.
            # The host process may attach its own handler that does.
        return json.dumps(payload, default=str, ensure_ascii=False)


def _redact_uri_userinfo(message: str) -> str:
    """Strip the userinfo segment from any credential-bearing URI in
    the message. ``mongodb://user:secret@host:27017/db`` becomes
    ``mongodb://***@host:27017/db``.  Operates on every URI in the
    string, not just the first.

    The authority section ends at the first ``/``, ``?``, ``#`` or
    *whitespace* (URIs are not legal inside free text without quoting,
    so whitespace reliably delimits them in log messages).
    """
    for scheme in _JsonFormatter._URI_SCHEMES:
        idx = 0
        while True:
            j = message.find(scheme, idx)
            if j < 0:
                break
            auth_start = j + len(scheme)
            end = len(message)
            for terminator in ("/", "?", "#", " ", "\t", "\n", "\r"):
                k = message.find(terminator, auth_start)
                if 0 <= k < end:
                    end = k
            authority = message[auth_start:end]
            at_idx = authority.rfind("@")
            if at_idx >= 0:
                new_authority = "***@" + authority[at_idx + 1:]
                message = message[:auth_start] + new_authority + message[end:]
                # Skip past the redacted authority to find the next URI.
                idx = auth_start + len(new_authority)
            else:
                idx = end
    return message


# Characters that terminate a value in a ``KEY=value`` or ``KEY value`` pair.
_VALUE_TERMINATORS = (";", "&", " ", "\t", "\n", "\r", ",", "|", "]", ")", "}")


def _redact_key_equals_value(message: str) -> str:
    """Redact the value following a sensitive key.

    Recognises both ``KEY=value`` and ``KEY value`` (e.g. ``Bearer xyz``)
    patterns, case-insensitively.  The terminator character that ends
    the value is preserved verbatim, so ``PASSWORD=hunter2; user=alice``
    becomes ``PASSWORD=***; user=alice`` and ``Bearer eyJ...`` becomes
    ``*** eyJ...``.
    """
    sensitive = _JsonFormatter._FORBIDDEN_SUBSTRINGS
    out_chars: list[str] = []
    i = 0
    n = len(message)
    lower = message.lower()
    while i < n:
        match_key = None
        match_len = 0
        # Try each sensitive key at position i.
        for key in sensitive:
            klen = len(key)
            if i + klen <= n and lower[i:i + klen] == key.lower():
                # Look at the character after the key.
                sep = message[i + klen] if i + klen < n else ""
                if sep in ("=", ":"):
                    match_key = key
                    match_len = klen
                    break
                # Whitespace-separated KEY value (e.g. ``Bearer xyz``):
                # the next non-space character must exist, and that
                # character must be the start of a value (i.e. not a
                # terminator).
                if sep == " ":
                    # Peek past any further whitespace to find the
                    # first value character.  If it exists and is not
                    # a terminator, this is a KEY value pair.
                    k = i + klen + 1
                    while k < n and message[k] == " ":
                        k += 1
                    if k < n and message[k] not in _VALUE_TERMINATORS:
                        match_key = key
                        match_len = klen
                        break
        if match_key is None:
            out_chars.append(message[i])
            i += 1
            continue
        # Preserve the key + the (single-character) separator
        # verbatim, then scan the value. For the whitespace-separated
        # case (e.g. ``PASSWORD: hunter2``), the leading whitespace
        # between the separator and the value is also preserved.
        sep_char = message[i + match_len]
        out_chars.append(message[i:i + match_len + 1])
        value_start = i + match_len + 1
        # If the value is colon/equals-prefixed, also skip any
        # whitespace between the separator and the actual value
        # (e.g. ``PASSWORD: hunter2`` -> value is ``hunter2``).
        if sep_char in (":", "="):
            while value_start < n and message[value_start] == " ":
                out_chars.append(" ")
                value_start += 1
        # Scan the value to its terminator. The terminator is
        # consumed but preserved in the output so that
        # ``PASSWORD=abc;`` becomes ``PASSWORD=***;`` and the outer
        # loop does not double-emit it.
        j = value_start
        while j < n and message[j] not in _VALUE_TERMINATORS:
            j += 1
        out_chars.append("***")
        if j < n:
            out_chars.append(message[j])
            j += 1
        i = j
    return "".join(out_chars)


def _scrub(message: str) -> str:
    """Defense-in-depth scrub applied to every JSON log line.

    Order of operations (each is independent and additive):

      1. Strip the userinfo from any URI matching a known
         credential-bearing scheme (mongodb://, mongodb+srv://).
         The ``***@host`` form is preserved so the host remains
         diagnosable.
      2. Redact the value of any ``KEY=value`` pair where KEY is
         case-insensitively equal to a known sensitive key.  This
         catches ``PASSWORD=hunter2`` AND ``password=hunter2``.
      3. Apply a global, case-insensitive substring replacement for
         the sensitive names themselves.  This is a last-resort
         scrub; a name that only *contains* a sensitive substring
         (e.g. ``my_password_field``) is also redacted.
    """
    if not isinstance(message, str) or not message:
        return message
    out = _redact_uri_userinfo(message)
    out = _redact_key_equals_value(out)
    # Global, case-insensitive substring replacement.
    for needle in _JsonFormatter._FORBIDDEN_SUBSTRINGS:
        out = re.sub(re.escape(needle), "***", out, flags=re.IGNORECASE)
    return out


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        return _scrub(value)
    if isinstance(value, dict):
        return {str(k): _scrub_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_value(v) for v in value]
    return value


_CONFIGURED = False
_LOCK = threading.Lock()


def configure_logging(level: str = "INFO") -> None:
    """Idempotently install the JSON formatter on the root logger.

    Safe to call multiple times. Honours PROSHIELD_LOG_LEVEL only if the
    caller does not pass an explicit level.
    """
    global _CONFIGURED
    with _LOCK:
        if _CONFIGURED:
            return
        level_name = (
            level
            or os.environ.get("PROSHIELD_LOG_LEVEL", "INFO")
        ).upper()
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())

        root = logging.getLogger()
        # Remove any default handlers so the JSON one is the only emitter.
        for h in list(root.handlers):
            root.removeHandler(h)
        root.addHandler(handler)
        root.setLevel(getattr(logging, level_name, logging.INFO))
        _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
