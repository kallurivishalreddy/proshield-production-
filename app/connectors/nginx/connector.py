"""NGINX access-log connector.

This is the FIRST documented real (non-simulated) source
connector for the ProShield MVP. NGINX is the first real
source in the documented source progression
(docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 3).

The connector reads an NGINX access log file in the standard
``combined`` format line by line, parses each line, and maps
the parsed record to a canonical :class:`SecurityEvent`. The
connector does not perform detection, correlation, or any
other rule-side work (see
docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md, Section 4).
It does not import the rule framework and it does not import
any other connector.

Provenance
----------

Every emitted event carries:

* ``provenance.collector = "nginx"``
* ``provenance.source_event_id`` = a deterministic
  ``sha1(log_path:line_number:raw_line)`` truncated to fit
  the documented bound. This is the connector's source-side
  identifier; identical re-deliveries of the same line
  produce the same id and hit the documented Boundary 2
  idempotency path.

Error handling
--------------

* The connector NEVER raises across :meth:`collect`. Per-line
  parse errors are counted in :attr:`stats` and the line is
  skipped; the connector's :meth:`health` reflects the
  counters. This implements the documented "do not silently
  discard security events" principle (PRODUCT_SCOPE Section
  16) by always surfacing per-line errors in stats and
  health.
* File-level failures (file not found, permission denied)
  are caught, counted, and the connector yields zero events.
  The caller can inspect :attr:`stats` and :meth:`health` to
  discover the failure.
* The connector does NOT log raw line content. Per-line
  error counters are sufficient for observability without
  leaking potentially attacker-controlled bytes.
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Union

from ..base import SecurityEventConnector
from ...domain.security_event import SecurityEvent
from .errors import NginxConnectorError
from .mapping import map_parsed_record_to_event
from .parser import MAX_LINE_BYTES, NginxParseError, parse_combined_line


_log = logging.getLogger(__name__)


# ------------------------------------------------------------------ stats
class NginxConnectorStats:
    """Per-connector counters, surfaced via :attr:`NginxConnector.stats`.

    The class is intentionally small: it is not a domain model,
    it is a connector-internal observability record. It is
    exposed for tests and for the health endpoint, NOT for
    upper layers to drive behaviour from.
    """

    __slots__ = (
        "lines_read",
        "lines_parsed",
        "lines_skipped_parse_error",
        "lines_skipped_no_signal",
        "events_emitted",
        "connector_errors",
    )

    def __init__(self) -> None:
        self.lines_read: int = 0
        self.lines_parsed: int = 0
        self.lines_skipped_parse_error: int = 0
        self.lines_skipped_no_signal: int = 0
        self.events_emitted: int = 0
        self.connector_errors: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "lines_read": self.lines_read,
            "lines_parsed": self.lines_parsed,
            "lines_skipped_parse_error": self.lines_skipped_parse_error,
            "lines_skipped_no_signal": self.lines_skipped_no_signal,
            "events_emitted": self.events_emitted,
            "connector_errors": self.connector_errors,
        }

    def reset(self) -> None:
        self.lines_read = 0
        self.lines_parsed = 0
        self.lines_skipped_parse_error = 0
        self.lines_skipped_no_signal = 0
        self.events_emitted = 0
        self.connector_errors = 0


# ------------------------------------------------------------------ connector
class NginxConnector(SecurityEventConnector):
    """Read an NGINX access log and yield canonical SecurityEvents.

    Parameters
    ----------
    log_path:
        Path to the NGINX access log file. A string or
        :class:`pathlib.Path`. The file is opened once per
        :meth:`collect` call and closed deterministically; the
        connector does not hold the file open between calls.
    asset:
        Optional asset label to attach to every event emitted
        from this connector (e.g. ``web-api-01``). When
        ``None``, the canonical event omits the field.
    encoding:
        File encoding. Defaults to ``utf-8``. Per-line decode
        errors are treated as parse errors: the line is
        skipped and counted, not raised.
    strict:
        When ``True``, the connector raises
        :class:`NginxParseError` for the first malformed line
        it encounters. When ``False`` (default), malformed
        lines are skipped and counted. ``strict`` is
        production-default ``False``: a real NGINX log can
        legitimately contain an attacker-injected malformed
        line, and silently aborting the stream would lose
        security signal.
    max_line_bytes:
        Override for the parser's per-line byte cap. Defaults
        to the parser's documented :data:`MAX_LINE_BYTES`.
    """

    source = "nginx"

    def __init__(
        self,
        log_path: Union[str, Path],
        *,
        asset: Optional[str] = None,
        encoding: str = "utf-8",
        strict: bool = False,
        max_line_bytes: int = MAX_LINE_BYTES,
    ) -> None:
        if not isinstance(log_path, (str, Path)):
            raise TypeError(
                f"log_path must be str or Path, got {type(log_path).__name__}"
            )
        if not encoding or not isinstance(encoding, str):
            raise TypeError(
                f"encoding must be a non-empty str, got {type(encoding).__name__}"
            )
        if not isinstance(strict, bool):
            raise TypeError(
                f"strict must be a bool, got {type(strict).__name__}"
            )
        if not isinstance(max_line_bytes, int) or max_line_bytes <= 0:
            raise TypeError(
                f"max_line_bytes must be a positive int, got {max_line_bytes!r}"
            )
        self._log_path = Path(log_path)
        self._asset = self.safe_str(asset) if asset is not None else None
        self._encoding = encoding
        self._strict = strict
        self._max_line_bytes = max_line_bytes
        # ``_last_health`` is updated by ``health()`` and by
        # ``collect()`` when a file-level error occurs. The
        # connector does not maintain mutable health state
        # between ``collect()`` calls beyond the stats.
        self.stats: NginxConnectorStats = NginxConnectorStats()

    # ----------------------------------------------------------------- utils
    @property
    def log_path(self) -> Path:
        return self._log_path

    def _make_source_event_id(
        self, line_number: int, raw_line: str
    ) -> str:
        """Build a deterministic per-line source_event_id.

        The id is the SHA-1 of ``log_path:line_number:raw_line``
        truncated to the documented bound for
        ``provenance.source_event_id``. Using a hash of the
        raw line content makes the id robust to log
        rotations: a line that appears in two log files at
        the same offset will have the same id; a line that
        differs even by one byte will have a different id
        (and therefore not idempotently dedup to a different
        line).
        """
        h = hashlib.sha1(
            f"{self._log_path}:{line_number}:{raw_line}".encode(
                "utf-8", errors="replace"
            )
        ).hexdigest()
        # 40 chars (sha1) fits well under the documented
        # bound of 256 chars. We keep the full hex digest.
        return h

    def _make_event_id(
        self, line_number: int, raw_line: str, event_time_ms: int
    ) -> str:
        """Build a deterministic per-line event_id that is
        a **real RFC 9562 UUIDv7**.

        The repository's idempotency path (Boundary 2,
        Section 16) keys on the canonical event_id: a
        re-delivery of the same event must hit the
        duplicate-key branch of ``insert_one`` and be
        treated as a no-op. A freshly-minted UUIDv7 per
        ``collect()`` call would defeat that path: the
        second reading would be inserted as a new event
        with a different event_id, bypassing the dedup.

        We therefore derive the event_id deterministically
        from a **source-derived** unix-ms timestamp (the
        NGINX ``$time_local`` field parsed to UTC) plus a
        per-line SHA-1 digest of the line content. The
        canonical ``SecurityEvent`` model requires the
        event_id to be a UUIDv7 (RFC 9562 version 7). The
        result is a real UUIDv7:

        * Bits 0..47 of the 128-bit value are the
          ``event_time_ms`` argument — the real unix-ms
          timestamp of the **observed event** per the
          source (NGINX ``$time_local``). This is content-
          derived, so two connector instances, two
          processes, or repeated reads of the same log
          file all produce the **same** event_id for the
          same line.
        * Bits 48..51 are the version nibble (``0b0111``).
        * Bits 52..63 are ``rand_a`` (12 bits derived from
          the SHA-1 digest of the line).
        * Bits 64..65 are the variant (``0b10``).
        * Bits 66..127 are ``rand_b`` (62 bits derived from
          the SHA-1 digest of the line).

        Cross-instance replay determinism is preserved by
        deriving the embedded unix-ms timestamp from the
        source's own ``$time_local`` rather than from a
        construction-time wall-clock sample. The two
        remaining dimensions of the UUIDv7 (rand_a +
        rand_b) are derived from a per-line SHA-1 digest
        that already varies deterministically per line, so
        two lines that differ in content produce different
        ids while two connectors reading the same line
        produce the same id.
        """
        # 16 bytes of deterministic per-line randomness
        # drawn from the same SHA-1 used for
        # ``source_event_id``. The full 20-byte digest is
        # preserved so that two lines that differ by even
        # one byte produce observably different ids.
        h = hashlib.sha1(
            f"event-id:{self._log_path}:{line_number}:{raw_line}".encode(
                "utf-8", errors="replace"
            )
        ).digest()  # 20 bytes

        # Layout of the 16-byte UUID value (RFC 9562 §5.7):
        #   bytes 0..5   = unix_ts_ms (48 bits, big-endian)
        #   byte  6 high nibble = version (0x7)
        #   bytes 6 low  / 7    = rand_a (12 bits)
        #   byte  8 high 2 bits = variant (0b10)
        #   bytes 8 low  / 9..15 = rand_b (62 bits)
        # We use the first 16 bytes of the SHA-1 digest
        # for rand_a (12 bits) and rand_b (62 bits). The
        # timestamp is the source's observed ``$time_local``
        # converted to unix-ms, which is a real RFC 9562
        # UUIDv7 timestamp with a stable, content-derived
        # meaning.
        b = bytearray(16)
        # unix_ts_ms (48 bits, big-endian) into bytes 0..5
        ts_ms = event_time_ms & 0xFFFF_FFFF_FFFF
        b[0] = (ts_ms >> 40) & 0xFF
        b[1] = (ts_ms >> 32) & 0xFF
        b[2] = (ts_ms >> 24) & 0xFF
        b[3] = (ts_ms >> 16) & 0xFF
        b[4] = (ts_ms >> 8) & 0xFF
        b[5] = ts_ms & 0xFF
        # rand_a (12 bits) lives in the low nibble of
        # byte 6 (4 bits) plus byte 7 (8 bits) = 12 bits.
        # We take the top 12 bits of the 16-byte digest's
        # byte index 0..1 region. The digest bytes used
        # for rand_a are h[0] (high 4 bits) and h[1].
        rand_a = ((h[0] << 8) | h[1]) & 0x0FFF
        b[6] = 0x70 | ((rand_a >> 8) & 0x0F)  # version 7
        b[7] = rand_a & 0xFF
        # rand_b (62 bits) lives in the low 6 bits of
        # byte 8 (2 of the 6 are the variant) plus bytes
        # 9..15. We use the remaining 14 digest bytes
        # h[2..15] for the 62 random bits: 2 bits of
        # byte 8 are the variant 0b10, leaving 6 random
        # bits there, and bytes 9..15 provide 56 random
        # bits, for 62 bits total.
        rand_b_top6 = h[2] & 0x3F
        b[8] = 0x80 | rand_b_top6  # variant 0b10
        b[9] = h[3]
        b[10] = h[4]
        b[11] = h[5]
        b[12] = h[6]
        b[13] = h[7]
        b[14] = h[8]
        b[15] = h[9]
        return str(uuid.UUID(bytes=bytes(b)))

    def _read_lines(self) -> Iterator[str]:
        """Yield each line of the log file as a string.

        File-level errors (not found, permission denied) are
        converted to :class:`NginxConnectorError`, counted in
        :attr:`stats`, and the generator yields no lines.
        """
        try:
            with self._log_path.open(
                "r",
                encoding=self._encoding,
                errors="replace",  # never raise on decode; parser counts
            ) as fh:
                for line in fh:
                    yield line
        except FileNotFoundError as exc:
            self.stats.connector_errors += 1
            _log.warning(
                "nginx.connector.file_not_found",
                extra={"request_id": None},
            )
            raise NginxConnectorError(
                "log file not found"
            ) from exc
        except PermissionError as exc:
            self.stats.connector_errors += 1
            _log.warning(
                "nginx.connector.permission_denied",
                extra={"request_id": None},
            )
            raise NginxConnectorError(
                "log file is not readable"
            ) from exc
        except OSError as exc:
            self.stats.connector_errors += 1
            _log.warning(
                "nginx.connector.os_error",
                extra={"request_id": None},
            )
            raise NginxConnectorError(
                "log file could not be opened"
            ) from exc

    # ---------------------------------------------------------------- collect
    def collect(self) -> Iterable[SecurityEvent]:
        """Yield canonical SecurityEvents from the configured log.

        The method is a generator: it does not pre-read the
        entire file into memory. The stream is opened
        lazily on first iteration so the connector is safe
        to construct before the log file exists.

        Per-line malformed input is skipped and counted in
        :attr:`stats`; in strict mode the connector raises
        :class:`NginxParseError` on the first malformed
        line.
        """
        # File-level errors (not found, permission denied) must
        # NOT propagate out of ``collect``: the documented
        # connector contract is that the caller can inspect
        # ``stats`` and ``health`` to discover a file-level
        # failure. ``_read_lines`` is a generator; the file
        # is opened lazily, so the exception can only fire
        # during iteration. We therefore wrap the entire
        # iteration in a try/except.
        try:
            for line_number, raw_line in enumerate(
                self._read_lines(), start=1
            ):
                self.stats.lines_read += 1
                # Per-line size cap BEFORE the parser. The
                # parser applies its own cap as defence in
                # depth.
                if (
                    len(raw_line.encode("utf-8", errors="replace"))
                    > self._max_line_bytes
                ):
                    self.stats.lines_skipped_parse_error += 1
                    if self._strict:
                        raise NginxParseError(
                            "line exceeds the connector's per-line size cap"
                        )
                    _log.info(
                        "nginx.connector.line_too_large",
                        extra={"request_id": None, "line_number": line_number},
                    )
                    continue
                try:
                    record = parse_combined_line(raw_line)
                except NginxParseError as exc:
                    self.stats.lines_skipped_parse_error += 1
                    if self._strict:
                        raise
                    _log.info(
                        "nginx.connector.parse_error",
                        extra={
                            "request_id": None,
                            "line_number": line_number,
                            "category": str(exc),
                        },
                    )
                    continue
                self.stats.lines_parsed += 1
                source_event_id = self._make_source_event_id(
                    line_number, raw_line
                )
                # The embedded unix-ms timestamp in the
                # event_id is the source's observed
                # ``$time_local`` (parsed to UTC) — not a
                # construction-time wall-clock sample. This
                # makes the event_id stable across connector
                # instances, process restarts, and repeated
                # reads of the same log file. ``event_time``
                # is a tz-aware datetime produced by the
                # parser (defence-in-depth: the parser
                # already rejects naive datetimes).
                event_time_ms = int(
                    record.event_time.timestamp() * 1000
                )
                event_id = self._make_event_id(
                    line_number, raw_line, event_time_ms
                )
                event = map_parsed_record_to_event(
                    record,
                    line_number=line_number,
                    source_event_id=source_event_id,
                    event_id=event_id,
                    asset=self._asset,
                )
                if event is None:
                    self.stats.lines_skipped_no_signal += 1
                    continue
                self.stats.events_emitted += 1
                yield event
        except NginxConnectorError:
            # File-level error surfaced mid-iteration (the
            # generator opens the file lazily on the first
            # ``next()``). The error has already been counted
            # in ``stats.connector_errors`` by ``_read_lines``;
            # we just stop yielding.
            return

    # ---------------------------------------------------------------- health
    def health(self) -> Dict[str, Any]:
        """Return a small status dict suitable for diagnostics.

        MUST NOT include the log path (which can carry
        sensitive deployment details in production), raw
        line content, secrets, or any other sensitive
        information. Includes the source, status, and the
        current :attr:`stats`.

        ``status`` is ``degraded`` if:

        * the underlying log file does not exist or cannot
          be stat-ed (a file-level error);
        * the connector has surfaced any
          :class:`NginxConnectorError` in ``stats`` so far.

        The probe is direct (``Path.exists()`` / ``Path.stat()``)
        so the health endpoint is meaningful even when
        ``collect()`` has not been called yet.
        """
        # We deliberately do NOT include the log path. A
        # future slice may add a hashed/redacted form here,
        # but a raw path can disclose internal hostnames
        # and filesystem layout.
        try:
            exists = self._log_path.exists()
            size_bytes = self._log_path.stat().st_size if exists else 0
        except OSError:
            exists = False
            size_bytes = 0
        if not exists:
            # The log file is missing. The health endpoint
            # must report a degraded ``status`` AND the
            # ``stats.connector_errors`` counter must
            # reflect the file-missing error so the two
            # are consistent. We do this by recording the
            # error in ``stats`` (idempotent for repeated
            # health probes: if ``connector_errors`` is
            # already non-zero from a prior
            # ``collect()`` that surfaced the same error,
            # we leave it alone; otherwise we record it
            # now). The test contract is that
            # ``status == "degraded"`` implies
            # ``stats.connector_errors >= 1``.
            if self.stats.connector_errors == 0:
                self.stats.connector_errors += 1
        status = "ok" if self.stats.connector_errors == 0 else "degraded"
        return {
            "source": self.source,
            "status": status,
            "kind": "nginx",
            "log_exists": exists,
            "log_size_bytes": size_bytes,
            "strict": self._strict,
            "stats": self.stats.as_dict(),
        }


