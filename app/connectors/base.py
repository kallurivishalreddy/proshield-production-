"""Connector base interface.

A connector is a per-source ADAPTER with exactly one responsibility:

    source-specific telemetry
    -> source-specific parsing
    -> validation / mapping
    -> canonical SecurityEvent

Connectors MUST NOT:

* perform detection, correlation, severity, or routing,
* call another connector or its rules (no cross-source coupling),
* pass payloads through unvalidated,
* admit oversized / unbounded enrichment blobs, secrets, or
  executable expressions,
* assert severity, confidence, or routing as authority.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 4.
"""
from __future__ import annotations

import abc
from typing import Any, Dict, Iterable, Optional

from ..domain.security_event import SecurityEvent


class SecurityEventConnector(abc.ABC):
    """Abstract base for any per-source connector."""

    #: Stable logical name of the source.  Must be one of
    #: :data:`app.domain.security_event.ALLOWED_SOURCES`.
    source: str

    @abc.abstractmethod
    def collect(self) -> Iterable[SecurityEvent]:
        """Return one or more canonical SecurityEvents from the source.

        For a simulator this is a deterministic generator; for a real
        source (NGINX, WAF, ...) it would be a stream consumer.  The
        ingestion service is responsible for stamping ``ingested_at``
        and (if absent) generating an ``event_id``.
        """

    @abc.abstractmethod
    def health(self) -> Dict[str, Any]:
        """Return a small status dict suitable for diagnostics.

        MUST NOT include secrets, file paths, raw records, or
        any other sensitive information.  The shape is intentionally
        free-form so different sources can report their own relevant
        indicators.
        """
        return {"source": getattr(self, "source", "unknown"), "status": "ok"}

    # ------------------------------------------------------------------- utils
    @staticmethod
    def safe_str(value: Optional[Any], *, max_length: int = 256) -> Optional[str]:
        """Trim and bound a string value before it is placed into
        SecurityEvent fields.  ``None`` is preserved.
        """
        if value is None:
            return None
        s = str(value)
        if len(s) > max_length:
            s = s[:max_length]
        return s
