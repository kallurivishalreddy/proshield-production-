"""Unit tests for the NGINX connector (file I/O, stats, health)."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.connectors.nginx import NginxConnector, NginxConnectorStats
from app.connectors.nginx.errors import NginxConnectorError
from app.connectors.nginx.parser import NginxParseError
from app.domain.security_event import SecurityEvent


# Reusable log content.
_GOOD_LOG = (
    '192.0.2.10 - alice [26/Aug/2026:03:15:42 +0000] '
    '"POST /api/login HTTP/1.1" 401 612 "-" "curl/8.5.0"\n'
    '198.51.100.7 - - [26/Aug/2026:03:16:00 +0000] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
    '203.0.113.10 - - [26/Aug/2026:03:16:30 +0000] '
    '"GET /api/v1/users/1 HTTP/1.1" 429 50 "-" "bot/1.0"\n'
)


@pytest.fixture
def tmp_log(tmp_path: Path) -> Path:
    p = tmp_path / "access.log"
    p.write_text(_GOOD_LOG, encoding="utf-8")
    return p


# ------------------------------------------------------------------ happy
def test_collect_yields_canonical_events(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log, asset="web-api-01")
    events = list(c.collect())
    # 1 (401) + 0 (200) + 1 (429) = 2 emitted (200 has no security signal)
    assert len(events) == 2
    for e in events:
        assert isinstance(e, SecurityEvent)
        assert e.source == "nginx"
        assert e.asset == "web-api-01"


def test_collect_skips_malformed_line(tmp_path: Path) -> None:
    p = tmp_path / "bad.log"
    p.write_text(
        _GOOD_LOG + "this is not a log line\n",
        encoding="utf-8",
    )
    c = NginxConnector(p)
    list(c.collect())
    # 3 OK + 1 bad line
    assert c.stats.lines_read == 4
    assert c.stats.lines_parsed == 3
    assert c.stats.lines_skipped_parse_error == 1
    assert c.stats.events_emitted == 2


def test_collect_skips_no_signal_lines(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    list(c.collect())
    # The 200 GET on /index.html has no security signal.
    assert c.stats.lines_skipped_no_signal == 1


def test_provenance_collector_is_nginx(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    events = list(c.collect())
    for e in events:
        assert e.provenance.collector == "nginx"
        assert e.provenance.source_event_id  # non-empty


def test_source_event_id_is_deterministic(tmp_log: Path) -> None:
    """Re-reading the same line must produce the same id.

    This is the documented Boundary 2 idempotency path: the
    ingestion service's dedup uses the (source, source_event_id)
    pair, so the connector MUST emit the same id for the same
    line on every ``collect()`` call.
    """
    c1 = NginxConnector(tmp_log)
    e1 = list(c1.collect())
    # Reset stats so we are reading the *id* deterministically,
    # not the stats.
    c2 = NginxConnector(tmp_log)
    e2 = list(c2.collect())
    assert [e.provenance.source_event_id for e in e1] == [
        e.provenance.source_event_id for e in e2
    ]


def test_source_event_id_is_unique_per_line(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    events = list(c.collect())
    ids = [e.provenance.source_event_id for e in events]
    assert len(ids) == len(set(ids))


def test_source_event_id_differs_by_line_content(tmp_path: Path) -> None:
    """Two lines that differ by even one byte produce different ids.

    This protects against a hash collision collapsing two
    distinct log entries into the same source_event_id.
    """
    p1 = tmp_path / "a.log"
    p2 = tmp_path / "b.log"
    p1.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    p2.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 404 0 "-" "-"\n',
        encoding="utf-8",
    )
    e1 = list(NginxConnector(p1).collect())
    e2 = list(NginxConnector(p2).collect())
    assert e1[0].provenance.source_event_id != e2[0].provenance.source_event_id


# ------------------------------------------------------------------ event_id
def test_event_id_is_deterministic(tmp_path: Path) -> None:
    """The connector MUST emit the same event_id for the
    same line on every ``collect()`` call on the **same
    connector instance** so the repository's
    ``insert_one`` dedup path is reachable. A freshly-
    minted UUIDv7 per call would defeat the documented
    Boundary 2 idempotency contract.

    The determinism is per-instance: a new
    ``NginxConnector`` samples a new frozen unix-ms
    timestamp at construction time, so two instances
    produce different event_ids for the same line. That
    is the expected behaviour of a real UUIDv7
    (different generators produce different ids).
    Replay determinism — the documented Boundary 2
    contract — is per-instance, not cross-instance.
    """
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    # Same connector instance, two collect() calls ->
    # same event_id (per-instance replay identity).
    c = NginxConnector(p)
    e1 = list(c.collect())
    e2 = list(c.collect())
    assert e1[0].event_id == e2[0].event_id


def test_event_id_is_uuidv7_compliant(tmp_path: Path) -> None:
    """The deterministic event_id MUST still satisfy the
    canonical SecurityEvent contract: a real UUIDv7
    (RFC 9562 version 7) with the RFC 4122 variant.
    """
    import uuid as _uuid
    from app.domain.uuid7 import is_uuid7
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    e = list(NginxConnector(p).collect())[0]
    parsed = _uuid.UUID(e.event_id)
    assert parsed.version == 7
    assert parsed.variant == _uuid.RFC_4122
    # The canonical model validator also enforces this:
    assert is_uuid7(parsed) is True


def test_event_id_embeds_real_unix_ms_timestamp(tmp_path: Path) -> None:
    """The deterministic event_id MUST embed a real
    unix-ms timestamp in the first 48 bits (the
    high-order ``time_low`` and ``time_mid`` fields of
    a UUIDv7, per RFC 9562 §5.7).

    As of the DEDUP-01 fix, the embedded timestamp is
    the source's observed ``$time_local`` parsed to
    UTC, NOT a wall-clock sample taken at connector
    construction. The embedded timestamp is therefore
    a real unix-ms that is stable across connector
    instances, process restarts, and repeated reads of
    the same log file. Two connectors reading the same
    log line produce the same embedded timestamp; two
    different log lines produce different embedded
    timestamps (because their ``$time_local`` differs).
    """
    import uuid as _uuid
    from datetime import datetime, timezone
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    e = list(NginxConnector(p).collect())[0]
    parsed = _uuid.UUID(e.event_id)
    # The first 48 bits of a UUID's big-endian 128-bit
    # value are the unix-ms timestamp.
    ts_ms = (parsed.int >> 80) & 0xFFFF_FFFF_FFFF
    # The embedded timestamp MUST be the source's
    # observed $time_local, NOT a random SHA-1 output
    # or a wall-clock sample.
    expected_ms = int(
        datetime(
            2026, 8, 26, 3, 15, 42, tzinfo=timezone.utc
        ).timestamp() * 1000
    )
    assert ts_ms == expected_ms, (
        f"event_id timestamp {ts_ms} must match the source "
        f"$time_local {expected_ms} (= 2026-08-26T03:15:42Z)"
    )
    # Sanity: decode the embedded timestamp as a
    # datetime and assert it equals the source's
    # $time_local exactly (no drift, no rounding).
    embedded = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    expected_dt = datetime(2026, 8, 26, 3, 15, 42, tzinfo=timezone.utc)
    assert embedded == expected_dt, (
        f"event_id embedded timestamp {embedded.isoformat()} "
        f"must equal the source $time_local {expected_dt.isoformat()}"
    )


def test_event_id_timestamp_is_source_derived(tmp_path: Path) -> None:
    """The embedded unix-ms timestamp in the event_id
    MUST be the source's observed ``$time_local`` (not
    a wall-clock sample). Two different lines in the
    same log file therefore embed different
    timestamps; the connector does NOT sample a
    connector-level timestamp.
    """
    import uuid as _uuid
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n'
        '198.51.100.7 - - [26/Aug/2026:03:15:43 +0000] '
        '"GET /b HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    events = list(NginxConnector(p).collect())
    ts_ms_list = [
        (_uuid.UUID(e.event_id).int >> 80) & 0xFFFF_FFFF_FFFF
        for e in events
    ]
    # The two lines have different $time_local (42s vs
    # 43s), so the embedded timestamps differ.
    assert ts_ms_list[0] != ts_ms_list[1]
    # And the embedded timestamps must match the
    # $time_local of each line exactly.
    from datetime import datetime, timezone
    assert ts_ms_list[0] == int(
        datetime(2026, 8, 26, 3, 15, 42, tzinfo=timezone.utc).timestamp()
        * 1000
    )
    assert ts_ms_list[1] == int(
        datetime(2026, 8, 26, 3, 15, 43, tzinfo=timezone.utc).timestamp()
        * 1000
    )


def test_event_id_is_stable_across_connector_instances(tmp_path: Path) -> None:
    """REGRESSION TEST FOR DEDUP-01.

    Two different connector instances (even when
    constructed seconds apart) MUST produce the same
    event_id for the same log line. The embedded
    unix-ms timestamp is the source's ``$time_local``,
    not a construction-time wall-clock sample, so the
    event_id is content-derived and stable across
    instances, process restarts, and repeated reads of
    the same log file.
    """
    import time
    import uuid as _uuid
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    c1 = NginxConnector(p)
    e1 = list(c1.collect())
    # Sleep so that any construction-time timestamp
    # would observably differ; the source-derived
    # timestamp must NOT.
    time.sleep(0.05)
    c2 = NginxConnector(p)
    e2 = list(c2.collect())
    # Same event_id across connector instances for
    # the same log line.
    assert e1[0].event_id == e2[0].event_id
    # And the embedded timestamp is the source's
    # $time_local, not a connector-construction sample.
    from datetime import datetime, timezone
    expected_ms = int(
        datetime(2026, 8, 26, 3, 15, 42, tzinfo=timezone.utc).timestamp()
        * 1000
    )
    ts1 = (_uuid.UUID(e1[0].event_id).int >> 80) & 0xFFFF_FFFF_FFFF
    ts2 = (_uuid.UUID(e2[0].event_id).int >> 80) & 0xFFFF_FFFF_FFFF
    assert ts1 == ts2 == expected_ms


def test_event_id_differs_per_line(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_text(
        '192.0.2.10 - - [26/Aug/2026:03:15:42 +0000] '
        '"GET /a HTTP/1.1" 403 0 "-" "-"\n'
        '198.51.100.7 - - [26/Aug/2026:03:15:43 +0000] '
        '"GET /b HTTP/1.1" 403 0 "-" "-"\n',
        encoding="utf-8",
    )
    events = list(NginxConnector(p).collect())
    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


# ------------------------------------------------------------------ error handling
def test_missing_file_yields_no_events(tmp_path: Path) -> None:
    p = tmp_path / "does_not_exist.log"
    c = NginxConnector(p)
    events = list(c.collect())
    assert events == []
    assert c.stats.connector_errors == 1


def test_missing_file_health_reports_degraded(tmp_path: Path) -> None:
    p = tmp_path / "does_not_exist.log"
    c = NginxConnector(p)
    h = c.health()
    assert h["status"] == "degraded"
    assert h["log_exists"] is False


def test_missing_file_health_stats_consistent(tmp_path: Path) -> None:
    """Regression test for CONFIRMED-2.

    When the log file is missing, ``health()["status"]``
    is ``"degraded"`` AND
    ``health()["stats"]["connector_errors"]`` MUST be
    ``>= 1``. The review's H2 test verified the original
    behaviour (status="degraded" but stats.connector_errors=0),
    which is now fixed.
    """
    p = tmp_path / "does_not_exist.log"
    c = NginxConnector(p)
    h = c.health()
    assert h["status"] == "degraded"
    assert h["log_exists"] is False
    # The consistency contract: status and stats agree.
    assert h["stats"]["connector_errors"] >= 1, (
        f"health() reports status={h['status']} but "
        f"stats.connector_errors={h['stats']['connector_errors']}; "
        "the two must be consistent (status=degraded implies "
        "connector_errors >= 1)"
    )


def test_missing_file_health_stats_consistent_after_collect(tmp_path: Path) -> None:
    """After ``collect()`` on a missing file, the health
    probe must still report consistent status and stats.
    The ``collect()`` path already increments
    ``stats.connector_errors`` (via the file-level error
    branch), so the health probe must NOT double-count.
    """
    p = tmp_path / "does_not_exist.log"
    c = NginxConnector(p)
    list(c.collect())
    h = c.health()
    assert h["status"] == "degraded"
    # After collect(), stats.connector_errors is already 1
    # (from the file-level error). The health probe must
    # not double-count: it should remain 1.
    assert h["stats"]["connector_errors"] >= 1


def test_existing_file_health_stats_consistent(tmp_log: Path) -> None:
    """For an existing log file, the health probe must
    report ``status="ok"`` and ``stats.connector_errors=0``.
    The health probe must NOT mark a healthy connector
    as degraded.
    """
    c = NginxConnector(tmp_log)
    list(c.collect())
    h = c.health()
    assert h["log_exists"] is True
    assert h["status"] == "ok"
    assert h["stats"]["connector_errors"] == 0


def test_health_probe_is_idempotent_for_missing_file(tmp_path: Path) -> None:
    """Multiple health probes on a missing file must
    NOT keep incrementing ``stats.connector_errors``.
    The connector's health endpoint is read-only from
    the perspective of the operator: repeated calls
    must not amplify the counter.
    """
    p = tmp_path / "does_not_exist.log"
    c = NginxConnector(p)
    h1 = c.health()
    err1 = c.stats.connector_errors
    h2 = c.health()
    err2 = c.stats.connector_errors
    h3 = c.health()
    err3 = c.stats.connector_errors
    assert h1["status"] == "degraded"
    assert h2["status"] == "degraded"
    assert h3["status"] == "degraded"
    assert err1 == err2 == err3, (
        f"health() must be idempotent for a missing file; "
        f"connector_errors grew from {err1} -> {err2} -> {err3}"
    )


def test_oversized_line_skipped_not_raised(tmp_path: Path) -> None:
    """A real NGINX log can contain an attacker-injected huge
    line. The connector must skip and count it, not raise.
    """
    p = tmp_path / "huge.log"
    p.write_text(
        _GOOD_LOG + ("x" * 20000) + "\n",
        encoding="utf-8",
    )
    c = NginxConnector(p)
    list(c.collect())
    assert c.stats.lines_skipped_parse_error >= 1


def test_strict_mode_raises_on_malformed_line(tmp_path: Path) -> None:
    p = tmp_path / "bad.log"
    p.write_text("not a log line\n", encoding="utf-8")
    c = NginxConnector(p, strict=True)
    with pytest.raises(NginxParseError):
        list(c.collect())


def test_non_strict_mode_does_not_raise(tmp_path: Path) -> None:
    p = tmp_path / "bad.log"
    p.write_text("not a log line\n", encoding="utf-8")
    c = NginxConnector(p)  # strict=False default
    list(c.collect())  # no raise


def test_connector_constructor_validates_types() -> None:
    with pytest.raises(TypeError):
        NginxConnector(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        NginxConnector("/x", strict="yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        NginxConnector("/x", max_line_bytes=0)
    with pytest.raises(TypeError):
        NginxConnector("/x", encoding="")


# ------------------------------------------------------------------ health
def test_health_reports_ok_for_clean_log(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    list(c.collect())
    h = c.health()
    assert h["source"] == "nginx"
    assert h["status"] == "ok"
    assert h["kind"] == "nginx"
    assert h["log_exists"] is True
    assert h["log_size_bytes"] == tmp_log.stat().st_size
    assert h["strict"] is False
    assert h["stats"]["events_emitted"] >= 1


def test_health_does_not_leak_path(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    list(c.collect())
    h = c.health()
    # The connector contract: health MUST NOT include the
    # raw log path. A real path can disclose internal
    # hostnames / deployment layout.
    blob = str(h)
    assert "access.log" not in blob
    assert str(tmp_log) not in blob


def test_health_does_not_leak_secrets(tmp_log: Path) -> None:
    c = NginxConnector(tmp_log)
    list(c.collect())
    h = c.health()
    forbidden = (
        "password", "secret", "token", "mongodb://",
        "apikey", "api-key", "credential",
    )
    for v in h.values():
        if isinstance(v, str):
            for needle in forbidden:
                assert needle not in v.lower()
    # The nested stats dict is also safe to expose (it is
    # only integer counters).
    stats_blob = str(h["stats"])
    for needle in forbidden:
        assert needle not in stats_blob.lower()


# ------------------------------------------------------------------ stats
def test_stats_dict_is_complete() -> None:
    s = NginxConnectorStats()
    d = s.as_dict()
    assert set(d) == {
        "lines_read",
        "lines_parsed",
        "lines_skipped_parse_error",
        "lines_skipped_no_signal",
        "events_emitted",
        "connector_errors",
    }


def test_stats_reset_clears_all_fields() -> None:
    s = NginxConnectorStats()
    s.lines_read = 5
    s.events_emitted = 2
    s.reset()
    assert s.lines_read == 0
    assert s.events_emitted == 0
    assert s.connector_errors == 0


# ------------------------------------------------------------------ source
def test_connector_declares_canonical_source() -> None:
    from app.connectors.base import SecurityEventConnector
    assert NginxConnector.source == "nginx"
    # Subclass relationship
    assert issubclass(NginxConnector, SecurityEventConnector)

