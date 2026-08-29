"""NGINX source connector.

The first documented real (non-simulated) source connector for the
ProShield MVP. NGINX is the first real source in the documented source
progression in
``docs/PHASE 2/SECURITY_EVENT_SCHEMA.md`` (Section 3):

    1. Simulator          (Phase 4.1)
    2. NGINX              (Phase 4.3  <- this slice)
    3. WAF / Cezara       (later)
    4. Rate Limiting      (later)
    5. TLS / Network      (later)
    6. Future SIEM / Endpoint / IAM (later)

The connector reads an NGINX access log (the standard ``combined``
log format by default), parses each line into a structured record,
and maps that record to a canonical :class:`SecurityEvent`.

The connector is the *only* place licensed to know about NGINX
log-line shape. It does not perform detection, correlation, or any
other rule-side work (see
``docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md``, Section 4).
It does not import the rule framework and it does not import any
other connector.

Public surface:

* :class:`NginxConnector` -- the connector (subclass of
  :class:`SecurityEventConnector`).
* :class:`NginxParseError` -- the connector-internal parse error.
  Caught inside the connector; per-line malformed input never
  crosses the connector boundary.
* :func:`parse_combined_line` -- pure parser. Exposed for tests and
  for callers that need to validate lines without opening a file.
* :func:`map_parsed_record_to_event` -- pure mapping. Exposed for
  tests.

Reference: docs/PHASE 2/SECURITY_EVENT_SCHEMA.md (Sections 3, 4, 5,
6, 7, 8, 9), docs/PHASE 1/ARCHITECTURE.md (Section 8, Boundary 2).
"""
from __future__ import annotations

from .parser import NginxParseError, parse_combined_line
from .connector import NginxConnector, NginxConnectorStats
from .mapping import map_parsed_record_to_event

__all__ = [
    "NginxConnector",
    "NginxConnectorStats",
    "NginxParseError",
    "parse_combined_line",
    "map_parsed_record_to_event",
]
