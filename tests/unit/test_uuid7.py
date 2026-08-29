"""Unit tests for the self-contained UUIDv7 generator.

Reference: docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-003: Internal
entity IDs are UUIDv7).  RFC 9562 Section 5.7.
"""
from __future__ import annotations

import time
import uuid

from app.domain.uuid7 import is_uuid7, uuid7


def test_uuid7_has_version_7() -> None:
    u = uuid7()
    assert u.version == 7
    assert is_uuid7(u)


def test_uuid7_has_rfc4122_variant() -> None:
    u = uuid7()
    assert u.variant == uuid.RFC_4122


def test_uuid7_is_unique_across_calls() -> None:
    seen = {str(uuid7()) for _ in range(2000)}
    assert len(seen) == 2000


def test_uuid7_embeds_unix_timestamp() -> None:
    before_ms = int(time.time() * 1000)
    u = uuid7()
    after_ms = int(time.time() * 1000)
    embedded_ms = (u.int >> 80) & 0xFFFF_FFFF_FFFF
    # Allow for millisecond rounding: embedded_ms must be in the
    # observed window.
    assert before_ms - 1 <= embedded_ms <= after_ms + 1


def test_uuid7_with_explicit_timestamp() -> None:
    ts = 1_700_000_000_000
    u = uuid7(timestamp_ms=ts)
    embedded_ms = (u.int >> 80) & 0xFFFF_FFFF_FFFF
    assert embedded_ms == ts


def test_is_uuid7_rejects_v4() -> None:
    v4 = uuid.uuid4()
    assert not is_uuid7(v4)
    assert v4.version == 4
