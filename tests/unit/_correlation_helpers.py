"""Shared helpers for Phase 4.5 correlation tests.

Helpers for building small, deterministic sequences of
detections + events that exercise the brute-force clustering
pattern's positive, negative, near-miss, threshold-boundary,
window-boundary, and isolation cases.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from app.detection.models import Detection
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7


def _ev(
    *,
    event_id: str,
    source_ip: str = "198.51.100.7",
    endpoint: str = "/api/login",
    event_time: datetime,
    source: str = "nginx",
    event_type: str = "authentication_failure",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_time=event_time,
        ingested_at=event_time,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        endpoint=endpoint,
        provenance=SecurityEventProvenance(
            collector="test", source_event_id=f"src-{event_id}"
        ),
        details={"status_code": 401},
    )


def _det(
    *,
    event_id: str,
    rule_id: str = "NGINX-AUTH-FAILURE-001",
    rule_version: int = 1,
    detected_at: datetime,
) -> Detection:
    return Detection(
        detection_id=f"det-{uuid7(timestamp_ms=int(detected_at.timestamp() * 1000))}",
        rule_id=rule_id,
        rule_version=rule_version,
        category="source_specific",
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="test",
        detected_at=detected_at,
    )


def make_burst(
    *,
    n: int,
    start: datetime,
    step: timedelta = timedelta(seconds=10),
    source_ip: str = "198.51.100.7",
    endpoint: str = "/api/login",
    rule_id: str = "NGINX-AUTH-FAILURE-001",
    event_type: str = "authentication_failure",
) -> Tuple[List[SecurityEvent], List[Detection]]:
    """Build ``n`` auth-failure events + detections from the same
    source_ip + endpoint, spaced by ``step``.

    Returns ``(events, detections)``.
    """
    events: List[SecurityEvent] = []
    detections: List[Detection] = []
    for i in range(n):
        et = start + step * i
        eid = str(uuid7(timestamp_ms=int(et.timestamp() * 1000) + i))
        ev = _ev(
            event_id=eid,
            source_ip=source_ip,
            endpoint=endpoint,
            event_time=et,
            event_type=event_type,
        )
        events.append(ev)
        detections.append(
            _det(
                event_id=eid,
                rule_id=rule_id,
                detected_at=et,
            )
        )
    return events, detections
