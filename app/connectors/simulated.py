"""Simulated source connector.

The first MVP validation source is simulated canonical security events
(docs/PHASE 0/INITIAL_SECURITY_EVENTS.md, Section 2; docs/PHASE 0/
MVP_ACCEPTANCE.md, Section 6).  The simulator must not bypass the
documented processing pipeline; it only produces raw canonical
``SecurityEvent`` objects that the ingestion service then validates,
normalises (no-op for canonical events), and persists.

This module is the simplest possible realisation: a small catalog of
deterministic scenarios, ``collect()`` yielding each scenario's events
in order.  Real collectors (NGINX, WAF, ...) are not part of Phase 4.1.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List
from uuid import UUID

from ..domain.security_event import (
    SecurityEvent,
    SecurityEventAccount,
    SecurityEventProvenance,
)
from ..domain.uuid7 import uuid7
from .base import SecurityEventConnector


class SimulatedConnector(SecurityEventConnector):
    """Emit a small library of deterministic canonical events.

    Each event already has a valid ``event_id`` (UUIDv7), a source-side
    ``source_event_id``, and complete provenance.  The ingestion service
    will stamp ``ingested_at`` and re-validate the event.
    """

    source = "simulator"

    def __init__(self, *, seed: int = 0) -> None:
        # ``seed`` is accepted for future deterministic generators;
        # the current MVP uses fixed scenarios only.
        self._seed = seed
        self._counter = 0

    def health(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "status": "ok",
            "kind": "simulated",
            "scenarios": len(self._scenarios()),
        }

    def collect(self) -> Iterable[SecurityEvent]:
        anchor = datetime.now(timezone.utc)
        for scenario in self._scenarios():
            for offset_ms, partial in scenario:
                self._counter += 1
                yield self._build(anchor, offset_ms, partial)

    # ----------------------------------------------------------------- build
    def _build(
        self, anchor: datetime, offset_ms: int, partial: Dict[str, Any]
    ) -> SecurityEvent:
        event_time = anchor + timedelta(milliseconds=offset_ms)
        seq = partial.get("seq", self._counter)
        # UUIDv7 generated server-side; for a future deterministic
        # simulator we would derive it from the sequence number.
        eid = uuid7(timestamp_ms=int(event_time.timestamp() * 1000))
        eid_str = str(eid)
        provenance = SecurityEventProvenance(
            collector="simulated",
            source_event_id=partial["source_event_id"],
        )
        account = None
        if partial.get("account_id"):
            account = SecurityEventAccount(id=partial["account_id"])
        return SecurityEvent(
            event_id=eid_str,
            event_time=event_time,
            ingested_at=event_time + timedelta(milliseconds=1),
            source=self.source,
            event_type=partial["event_type"],
            source_ip=partial.get("source_ip"),
            destination=partial.get("destination"),
            endpoint=partial.get("endpoint"),
            asset=partial.get("asset"),
            account=account,
            details=partial.get("details", {}),
            provenance=provenance,
        )

    # ----------------------------------------------------------- scenarios
    def _scenarios(self) -> List[List[tuple]]:
        return _SIMULATED_SCENARIOS


_SCENARIO_A = [
    (0, {
        "seq": 1,
        "source_event_id": "sim-A-001",
        "event_type": "waf_attack_detected",
        "source_ip": "203.0.113.10",
        "destination": "app.example.internal",
        "endpoint": "/api/login",
        "asset": "web-api-01",
        "details": {"rule": "941100-xss", "severity_hint": "high"},
    }),
]

_AUTH_FAIL_BASE = {
    "event_type": "authentication_failure",
    "source_ip": "198.51.100.7",
    "destination": "auth.example.internal",
    "endpoint": "/auth/login",
    "asset": "auth-svc-01",
    "account_id": "user-123",
}

_SCENARIO_B = [
    (10,  {"seq": 1, "source_event_id": "sim-B-001", **_AUTH_FAIL_BASE}),
    (110, {"seq": 2, "source_event_id": "sim-B-002", **_AUTH_FAIL_BASE}),
    (210, {"seq": 3, "source_event_id": "sim-B-003", **_AUTH_FAIL_BASE}),
    (310, {"seq": 4, "source_event_id": "sim-B-004", **_AUTH_FAIL_BASE}),
]

_SIMULATED_SCENARIOS: List[List[tuple]] = [
    _SCENARIO_A,
    _SCENARIO_B,
]
