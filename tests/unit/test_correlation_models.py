"""Unit tests for the Phase 4.5 correlation models."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.correlation.models import (
    Correlation,
    CorrelationKey,
    CorrelationResult,
    MAX_CORRELATION_EXTRA,
    MAX_CORRELATION_REASONING_LEN,
    _ALLOWED_TRIGGERS,
    validate_trigger,
)


FIXED_NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
FIXED_EARLIER = datetime(2026, 8, 28, 11, 55, 0, tzinfo=timezone.utc)
FIXED_LATER = datetime(2026, 8, 28, 12, 5, 0, tzinfo=timezone.utc)


def _make_corr(cid="corr-01923456-7890-7abc-9def-0123456789ab", **overrides):
    defaults = dict(
        correlation_id=cid,
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=(
            "det-01923456-7890-7abc-9def-0123456789ab",
            "det-01923456-7890-7abc-9def-0123456789ac",
        ),
        event_ids=(
            "01923456-7890-7abc-9def-0123456789ab",
            "01923456-7890-7abc-9def-0123456789ac",
        ),
        window_start=FIXED_EARLIER,
        window_end=FIXED_LATER,
        count=2,
        reasoning="brute-force clustering: 2 ...",
        correlated_at=FIXED_NOW,
    )
    defaults.update(overrides)
    return Correlation(**defaults)


class TestCorrelationIdPattern:
    def test_well_formed_corr_uuidv7_is_accepted(self) -> None:
        c = _make_corr()
        assert c.correlation_id == "corr-01923456-7890-7abc-9def-0123456789ab"

    def test_bad_prefix_is_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(cid="det-01923456-7890-7abc-9def-0123456789ab")

    def test_non_uuidv7_version_nibble_is_rejected(self) -> None:
        bad = "corr-01923456-7890-6abc-9def-0123456789ab"
        with pytest.raises(PydanticValidationError):
            _make_corr(cid=bad)


class TestCorrelationKey:
    def test_two_part_key(self) -> None:
        k = CorrelationKey(parts=("198.51.100.7", "/api/login"))
        assert k.parts == ("198.51.100.7", "/api/login")
        assert str(k) == "198.51.100.7|/api/login"
        assert k.as_tuple == ("198.51.100.7", "/api/login")

    def test_empty_parts_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            CorrelationKey(parts=())

    def test_empty_string_part_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            CorrelationKey(parts=("",))

    def test_too_many_parts_rejected(self) -> None:
        parts = tuple(str(i) for i in range(20))
        with pytest.raises(PydanticValidationError):
            CorrelationKey(parts=parts)

    def test_frozen(self) -> None:
        k = CorrelationKey(parts=("1.2.3.4", "/x"))
        with pytest.raises(Exception):
            k.parts = ("a", "b")  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(PydanticValidationError):
            CorrelationKey(parts=("1.2.3.4",), extra_field="bad")  # type: ignore[call-arg]


class TestTrigger:
    def test_allowed_trigger(self) -> None:
        for t in _ALLOWED_TRIGGERS:
            assert validate_trigger(t) == t

    def test_disallowed_trigger_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_trigger("made_up_trigger")

    def test_correlation_rejects_unknown_trigger(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(trigger="made_up")


class TestCorrelation:
    def test_minimal_construction(self) -> None:
        c = _make_corr()
        assert c.pattern_id == "NGINX-CORR-BRUTEFORCE-001"
        assert c.count == 2

    def test_frozen(self) -> None:
        c = _make_corr()
        with pytest.raises(Exception):
            c.count = 3  # type: ignore[misc]

    def test_to_dict_is_bson_safe(self) -> None:
        c = _make_corr()
        d = c.to_dict()
        assert d["correlation_id"].startswith("corr-")
        assert d["pattern_id"] == "NGINX-CORR-BRUTEFORCE-001"
        assert d["key"] == ["198.51.100.7", "/api/login"]
        assert d["window_start"] == FIXED_EARLIER.isoformat()
        assert d["window_end"] == FIXED_LATER.isoformat()
        assert d["count"] == 2
        assert isinstance(d["detection_ids"], list)
        assert isinstance(d["event_ids"], list)

    def test_count_must_be_at_least_one(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(count=0)

    def test_count_must_be_bounded(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(count=10_000)

    def test_at_least_one_detection_required(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(detection_ids=())

    def test_window_end_after_window_start(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(
                window_start=FIXED_LATER,
                window_end=FIXED_EARLIER,
            )

    def test_detection_ids_are_deduped_in_order(self) -> None:
        d1 = "det-01923456-7890-7abc-9def-aaaaaaaaaaaa"
        d2 = "det-01923456-7890-7abc-9def-bbbbbbbbbbbb"
        d3 = "det-01923456-7890-7abc-9def-cccccccccccc"
        c = _make_corr(
            detection_ids=(
                d1,
                d2,
                d1,
                d3,
            )
        )
        assert c.detection_ids == (d1, d2, d3)

    def test_reasoning_max_length(self) -> None:
        long = "x" * (MAX_CORRELATION_REASONING_LEN + 1)
        with pytest.raises(PydanticValidationError):
            _make_corr(reasoning=long)

    def test_pattern_id_pattern_enforced(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(pattern_id="lower")

    def test_extra_is_forbidden(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_corr(made_up_field="bad")  # type: ignore[call-arg]

    def test_extra_max_length_enforced(self) -> None:
        """D-4 regression: ``extra`` is bounded by ``MAX_CORRELATION_EXTRA``.

        The constant is defined in ``app.correlation.models`` and
        must be enforced at the Pydantic layer so a future pattern
        cannot silently store an unbounded ``extra`` payload.
        """
        # At the boundary: 16 entries is allowed.
        ok_extra = tuple((f"k{i}", i) for i in range(MAX_CORRELATION_EXTRA))
        c_ok = _make_corr(extra=ok_extra)
        assert len(c_ok.extra) == MAX_CORRELATION_EXTRA

        # Over the boundary: 17 entries is rejected.
        too_big_extra = tuple(
            (f"k{i}", i) for i in range(MAX_CORRELATION_EXTRA + 1)
        )
        with pytest.raises(PydanticValidationError):
            _make_corr(extra=too_big_extra)

        # 100 entries (the original D-4 reproduction) is rejected.
        huge_extra = tuple((f"k{i}", i) for i in range(100))
        with pytest.raises(PydanticValidationError):
            _make_corr(extra=huge_extra)


class TestCorrelationResult:
    def test_empty_result(self) -> None:
        r = CorrelationResult(produced_at=FIXED_NOW)
        assert r.correlation_count == 0
        assert r.patterns_considered == 0
        assert r.errors == ()
        d = r.to_dict()
        assert d["correlations"] == []
        assert d["patterns_considered"] == 0
        assert d["errors"] == []

    def test_frozen(self) -> None:
        r = CorrelationResult(produced_at=FIXED_NOW)
        with pytest.raises(Exception):
            r.correlations = ()  # type: ignore[misc]

    def test_extra_forbid(self) -> None:
        with pytest.raises(PydanticValidationError):
            CorrelationResult(produced_at=FIXED_NOW, foo="bar")  # type: ignore[call-arg]

    def test_to_dict_includes_produced_at(self) -> None:
        r = CorrelationResult(produced_at=FIXED_NOW)
        d = r.to_dict()
        assert d["produced_at"] == FIXED_NOW.isoformat()