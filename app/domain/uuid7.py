"""Self-contained RFC 9562 UUIDv7 generator.

ProShield internal entity IDs are UUIDv7 (docs/PHASE 2/CONTRACT_DECISIONS.md,
ADR-003). Python 3.13 does not yet ship uuid.uuid7() in the standard library,
and we deliberately avoid adding a third-party dependency for ~30 lines of
spec. The implementation here follows RFC 9562 Section 5.7 exactly.

Layout (128 bits):
    48 bits  unix_ts_ms
    4 bits   version (0b0111)
    12 bits  rand_a
    2 bits   variant (0b10)
    62 bits  rand_b
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Optional


def _unix_ms(timestamp_ms: Optional[int] = None) -> int:
    if timestamp_ms is None:
        return time.time_ns() // 1_000_000
    return int(timestamp_ms)


def uuid7(timestamp_ms: Optional[int] = None) -> uuid.UUID:
    """Generate a fresh RFC 9562 UUIDv7.

    Layout (128 bits total):
        48 bits  unix_ts_ms
        4 bits   version = 0b0111            (bits 76..79 of the int)
        12 bits  rand_a (12 random bits)     (bits 64..75)
        2 bits   variant = 0b10              (bits 62..63)
        62 bits  rand_b (62 random bits)     (bits 0..61)

    The 12 + 62 = 74 random bits come from 10 random bytes (80 bits); we
    discard 6 bits to align with the spec layout.  In practice, since we
    only ever use the 80 random bits to fill two well-defined fields, we
    just mask accordingly.
    """
    ts_ms = _unix_ms(timestamp_ms)

    # 10 random bytes read as a 80-bit big-endian integer.
    raw = int.from_bytes(os.urandom(10), "big")

    # rand_a is the top 12 bits of the 80-bit random word.
    rand_a = (raw >> 68) & 0x0FFF
    # rand_b is the low 62 bits of the 80-bit random word.
    rand_b = raw & 0x3FFF_FFFF_FFFF_FFFF

    # ts_ms (48) | version(4)=0x7 | rand_a(12) | variant(2)=0b10 | rand_b(62)
    value = (
        (ts_ms & 0xFFFF_FFFF_FFFF)
        << 80
    ) | (
        0x7 << 76
    ) | (
        rand_a << 64
    ) | (
        0b10 << 62
    ) | (
        rand_b
    )
    return uuid.UUID(int=value)


def is_uuid7(value: uuid.UUID) -> bool:
    """Return True iff the UUID has version 7 and RFC 4122 variant."""
    return value.version == 7 and value.variant == uuid.RFC_4122
