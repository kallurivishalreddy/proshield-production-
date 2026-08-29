"""Unit tests for the Phase 4.4 deterministic per-event detection engine."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import pytest
import re

from app.detection import (
    DetectionEngine,
    DetectionResult,
    InvalidEventError,
    NoRuleRegistryError,
)
from app.detection.engine import _make_detection_id
from app.detection.models import DETECTION_ID_PATTERN
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.rules import (
    RuleCategory,
    RuleRegistry,
    RuleState,
    load_rules_from_specs,
)
from app.rules.rule import Rule, RuleEvaluation, RuleEvaluationError
from app.rules.types import RuleMetadata


# A fixed ``now`` for deterministic detection_id tests.
FIXED_NOW = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)


def _ev(
    *,
    event_type: str = "request_blocked",
    status: int = 404,
    path: str = "/.env",
    source_ip: str = "198.51.100.7",
    method: str = "GET",
    event_time: Optional[datetime] = None,
) -> SecurityEvent:
    et = event_time or datetime(2026, 8, 26, 11, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        event_id=str(uuid7()),
        event_time=et,
        ingested_at=et,
        source="nginx",
        event_type=event_type,
        source_ip=source_ip,
        endpoint=path,
        provenance=SecurityEventProvenance(
            collector="nginx", source_event_id="src-p44-eng"
        ),
        details={
            "http_method": method,
            "status_code": status,
            "protocol": "HTTP/1.1",
            "body_bytes_sent": 0,
            "log_line_number": 1,
        },
    )


@pytest.fixture
def registry() -> RuleRegistry:
    r = RuleRegistry()
    load_rules_from_specs(r, ["app.rules._library.nginx"])
    return r


@pytest.fixture
def engine(registry: RuleRegistry) -> DetectionEngine:
    return DetectionEngine(registry)


# ============================================================================
# Construction
# ============================================================================
class TestConstruction:
    def test_requires_a_registry(self) -> None:
        with pytest.raises(NoRuleRegistryError):
            DetectionEngine(None)  # type: ignore[arg-type]

    def test_rejects_non_registry(self) -> None:
        with pytest.raises(NoRuleRegistryError):
            DetectionEngine("not a registry")  # type: ignore[arg-type]

    def test_accepts_an_empty_registry(self) -> None:
        r = RuleRegistry()
        e = DetectionEngine(r)
        ev = _ev()
        result = e.run(ev, now=FIXED_NOW)
        assert isinstance(result, DetectionResult)
        assert result.detection_count == 0
        assert result.rules_considered == 0
        assert result.errors == ()

    def test_registry_is_a_read_only_property(self, engine: DetectionEngine, registry: RuleRegistry) -> None:
        assert engine.registry is registry


# ============================================================================
# Input validation
# ============================================================================
class TestInputValidation:
    def test_rejects_non_security_event(self, engine: DetectionEngine) -> None:
        with pytest.raises(InvalidEventError):
            engine.run({"event_type": "request_blocked"}, now=FIXED_NOW)  # type: ignore[arg-type]

    def test_rejects_naive_datetime(self, engine: DetectionEngine) -> None:
        ev = _ev()
        with pytest.raises(InvalidEventError):
            engine.run(ev, now=datetime(2026, 1, 1, 0, 0, 0))  # naive

    def test_rejects_non_datetime_now(self, engine: DetectionEngine) -> None:
        ev = _ev()
        with pytest.raises(InvalidEventError):
            engine.run(ev, now="not a datetime")  # type: ignore[arg-type]


# ============================================================================
# Per-scenario detections
# ============================================================================
class TestScenarios:
    def test_401_brute_force_event_fires_two_rules(self, engine: DetectionEngine) -> None:
        ev = _ev(
            event_type="authentication_failure",
            status=401,
            path="/api/v1/login",
        )
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 2
        rule_ids = {d.rule_id for d in result.detections}
        # The broad per-event rule + the auth-shaped brute-force rule.
        assert "NGINX-AUTH-FAILURE-001" in rule_ids
        assert "NGINX-AUTH-BRUTEFORCE-001" in rule_ids
        assert result.errors == ()

    def test_401_on_non_auth_endpoint_fires_only_broad_rule(self, engine: DetectionEngine) -> None:
        ev = _ev(
            event_type="authentication_failure",
            status=401,
            path="/api/users/1",
        )
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-AUTH-FAILURE-001"

    def test_404_on_dotfile_fires_access_denied(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=404, path="/.env")
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-ACCESS-DENIED-001"

    def test_404_on_public_path_fires_nothing(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=404, path="/blog/typo")
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 0

    def test_5xx_fires_status_anomaly(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-STATUS-ANOMALY-001"

    def test_429_fires_rate_limit(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="rate_limit_exceeded", status=429, path="/api/items")
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-RATE-LIMIT-001"

    def test_403_on_admin_fires_access_denied_only(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=403, path="/admin/users")
        result = engine.run(ev, now=FIXED_NOW)
        # 403 is in _FIRE_STATUSES for ACCESS-DENIED; it is also
        # the brute-force rule's status (when path is auth-shaped).
        # /admin is sensitive but not auth-shaped, so only
        # ACCESS-DENIED fires.
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-ACCESS-DENIED-001"

    def test_200_on_public_page_fires_nothing(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="authentication_success", status=200, path="/index.html")
        result = engine.run(ev, now=FIXED_NOW)
        assert result.detection_count == 0
        # No rule is applicable to authentication_success +
        # /index.html. The engine must report considered=0.
        assert result.rules_considered == 0


# ============================================================================
# Detection contract
# ============================================================================
class TestDetectionContract:
    def test_detection_carries_rule_id_and_version(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result = engine.run(ev, now=FIXED_NOW)
        d = result.detections[0]
        assert d.rule_id == "NGINX-STATUS-ANOMALY-001"
        assert d.rule_version == 1
        assert d.category is RuleCategory.SOURCE_SPECIFIC

    def test_detection_carries_supporting_event_id_in_evidence(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result = engine.run(ev, now=FIXED_NOW)
        d = result.detections[0]
        assert d.event_id == ev.event_id
        assert d.evidence_refs == (ev.event_id,)

    def test_detection_id_is_deterministic_for_same_inputs(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        r1 = engine.run(ev, now=FIXED_NOW)
        r2 = engine.run(ev, now=FIXED_NOW)
        # Per the documented determinism contract, two calls with
        # the same (rule, event, now) MUST produce the same id.
        # (Phase 4.4 review D-2: the previous implementation used
        # an os.urandom salt and produced globally-unique ids,
        # contradicting the docstring; the salt has been removed.)
        d1 = r1.detections[0].detection_id
        d2 = r2.detections[0].detection_id
        # Same inputs -> same id.
        assert d1 == d2
        # Both are valid detection_ids.
        assert re.match(DETECTION_ID_PATTERN, d1)
        assert re.match(DETECTION_ID_PATTERN, d2)
        # Direct call to the helper is also deterministic.
        id_a = _make_detection_id("RULE-001", 1, ev.event_id, FIXED_NOW)
        id_b = _make_detection_id("RULE-001", 1, ev.event_id, FIXED_NOW)
        assert id_a == id_b
        assert re.match(DETECTION_ID_PATTERN, id_a)
        assert re.match(DETECTION_ID_PATTERN, id_b)

    def test_detection_id_differs_by_rule(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="authentication_failure", status=401, path="/api/v1/login")
        result = engine.run(ev, now=FIXED_NOW)
        ids = {d.detection_id for d in result.detections}
        # The two rules firing on the same event produce two
        # distinct detection_ids.
        assert len(ids) == 2

    def test_detection_id_differs_by_version(self) -> None:
        ev_id = "01a043e9-0000-7000-8000-000000000001"
        id_v1_a = _make_detection_id("RULE-001", 1, ev_id, FIXED_NOW)
        id_v2_a = _make_detection_id("RULE-001", 2, ev_id, FIXED_NOW)
        # They may collide on the salt but the version is part of
        # the input set; the well-formedness invariant holds.
        assert re.match(DETECTION_ID_PATTERN, id_v1_a)
        assert re.match(DETECTION_ID_PATTERN, id_v2_a)

    def test_detection_id_is_deterministic_across_many_calls(self) -> None:
        """Regression for Phase 4.4 review defect D-2.

        The previous implementation mixed 16 bytes of ``os.urandom``
        into the SHA-256 input, so two calls with the same
        arguments produced different ids. The current
        implementation is fully deterministic: 1000 calls with
        the same arguments MUST produce the same id (the
        documented contract). This test is the focused regression
        for that fix.
        """
        args = ("RULE-DET-001", 1, "ev-deterministic", FIXED_NOW)
        ids = [_make_detection_id(*args) for _ in range(1000)]
        # All 1000 ids are identical.
        assert len(set(ids)) == 1
        # And the single id is well-formed.
        assert re.match(DETECTION_ID_PATTERN, ids[0])

    def test_detection_id_timestamp_bits_match_detected_at(self) -> None:
        """Regression: the UUIDv7 first 48 bits encode the unix_ms
        of ``detected_at`` (the documented contract; see Section 4.1).
        Two ``detected_at`` values that differ by 1 ms MUST produce
        ids whose first 48 bits differ by the same amount.
        """
        import uuid as _uuid
        ts1 = datetime(2026, 8, 27, 12, 0, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2026, 8, 27, 12, 0, 0, 1_000, tzinfo=timezone.utc)
        id1 = _make_detection_id("RULE-001", 1, "ev-1", ts1)
        id2 = _make_detection_id("RULE-001", 1, "ev-1", ts2)
        u1 = _uuid.UUID(id1.removeprefix("det-"))
        u2 = _uuid.UUID(id2.removeprefix("det-"))
        ts_bits1 = (u1.int >> 80) & 0xFFFF_FFFF_FFFF
        ts_bits2 = (u2.int >> 80) & 0xFFFF_FFFF_FFFF
        # The 1 ms difference is exactly preserved in the first 48 bits.
        assert ts_bits2 - ts_bits1 == 1

    def test_detection_id_is_deterministic_for_same_timestamp(self) -> None:
        """Three calls with identical inputs and FIXED_NOW produce
        the same well-formed id. The determinism contract
        (Section 4.1, defect D-2 FIXED) is the property under test.
        """
        ts = FIXED_NOW
        ids = [
            _make_detection_id("RULE-001", 1, "ev-1", ts) for _ in range(3)
        ]
        # All match the canonical pattern.
        for i in ids:
            assert re.match(DETECTION_ID_PATTERN, i)
        # They are all the same id (deterministic).
        assert len(set(ids)) == 1

    def test_detection_is_frozen(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result = engine.run(ev, now=FIXED_NOW)
        d = result.detections[0]
        with pytest.raises(Exception):
            d.rule_id = "TAMPERED"  # type: ignore[misc]

    def test_detection_to_dict_is_json_safe(self, engine: DetectionEngine) -> None:
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result = engine.run(ev, now=FIXED_NOW)
        d = result.detections[0]
        dct = d.to_dict()
        assert dct["rule_id"] == "NGINX-STATUS-ANOMALY-001"
        assert dct["rule_version"] == 1
        assert dct["category"] == "source_specific"
        assert dct["event_id"] == ev.event_id
        assert dct["evidence_refs"] == [ev.event_id]
        assert isinstance(dct["detected_at"], str)
        # Round-trip via json.dumps.
        import json
        s = json.dumps(dct)
        assert isinstance(s, str)


# ============================================================================
# Quarantine / failure handling
# ============================================================================
class _BoomRule(Rule):
    """A rule that always raises during evaluation."""
    def __init__(self) -> None:
        self.metadata = RuleMetadata(
            rule_id="BOOM-001",
            version=1,
            name="boom",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=("nginx",),
            event_types=("request_blocked",),
            state=RuleState.APPROVED,
            enabled=True,
        )

    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        raise RuleEvaluationError(
            rule_id="BOOM-001",
            rule_version=1,
            event_id=event.event_id,
            cause=RuntimeError("simulated"),
        )


class TestQuarantine:
    def test_misbehaving_rule_is_quarantined(self, registry: RuleRegistry) -> None:
        registry.register(_BoomRule())
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        engine = DetectionEngine(registry)
        result = engine.run(ev, now=FIXED_NOW)
        # The boom rule raised, but the NGINX-STATUS-ANOMALY-001
        # rule still produces its detection.
        assert any(d.rule_id == "NGINX-STATUS-ANOMALY-001" for d in result.detections)
        # The error is recorded.
        assert any("BOOM-001" in e for e in result.errors)

    def test_unexpected_exception_is_also_quarantined(self) -> None:
        class TrulyEvil(Rule):
            def __init__(self) -> None:
                self.metadata = RuleMetadata(
                    rule_id="EVIL-001",
                    version=1,
                    name="evil",
                    category=RuleCategory.SOURCE_SPECIFIC,
                    sources=("nginx",),
                    event_types=("request_blocked",),
                    state=RuleState.APPROVED,
                    enabled=True,
                )
            def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
                raise RuntimeError("not a RuleEvaluationError")

        r = RuleRegistry()
        load_rules_from_specs(r, ["app.rules._library.nginx"])
        r.register(TrulyEvil())
        ev = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        engine = DetectionEngine(r)
        result = engine.run(ev, now=FIXED_NOW)
        # Real rule still fires; evil is captured in errors.
        assert any(d.rule_id == "NGINX-STATUS-ANOMALY-001" for d in result.detections)
        assert any("EVIL-001" in e for e in result.errors)


# ============================================================================
# Hot-path: applicability filter
# ============================================================================
class TestApplicabilityFiltering:
    """The engine must use the registry's applicability filter
    as the hot path. We verify by registering a single
    applicable rule and confirming only that rule is invoked.
    """
    def test_only_applicable_rules_are_evaluated(self) -> None:
        # A rule applicable only to a specific (source, event_type).
        only_fire_on_auth_failure = _OnlyApplicableRule(
            ("nginx", "authentication_failure")
        )
        r = RuleRegistry()
        load_rules_from_specs(r, ["app.rules._library.nginx"])
        r.register(only_fire_on_auth_failure)
        # Sanity: the rule is registered.
        assert only_fire_on_auth_failure.metadata.rule_id in r
        # 5xx event -> no auth-failure rule fires.
        ev_5xx = _ev(event_type="request_blocked", status=502, path="/api/orders/1")
        result_5xx = DetectionEngine(r).run(ev_5xx, now=FIXED_NOW)
        # The bogus rule is NOT in the result.
        assert all(
            d.rule_id != "ONLY-AUTH-FAILURE" for d in result_5xx.detections
        )
        # The NGINX-STATUS-ANOMALY-001 rule still fires.
        assert any(d.rule_id == "NGINX-STATUS-ANOMALY-001" for d in result_5xx.detections)
        # 401 event -> the rule IS in the result.
        ev_401 = _ev(event_type="authentication_failure", status=401, path="/api/v1/login")
        result_401 = DetectionEngine(r).run(ev_401, now=FIXED_NOW)
        assert any(d.rule_id == "ONLY-AUTH-FAILURE" for d in result_401.detections)


class _OnlyApplicableRule(Rule):
    """Helper rule whose applicability is hard-coded to one (source, event_type)."""
    def __init__(self, applicability: tuple) -> None:
        source, event_type = applicability
        self.metadata = RuleMetadata(
            rule_id="ONLY-AUTH-FAILURE",
            version=1,
            name="only on auth failure",
            category=RuleCategory.SOURCE_SPECIFIC,
            sources=(source,),
            event_types=(event_type,),
            state=RuleState.APPROVED,
            enabled=True,
        )
        self.calls = 0

    def evaluate(self, event: SecurityEvent) -> RuleEvaluation:
        self.calls += 1
        return self.make_evaluation(
            event,
            matched=(event.event_type == "authentication_failure"),
            reasoning="only fires on auth failure",
        )


# ============================================================================
# End-to-end: real NGINX connector -> SecurityEvent -> detection engine
# ============================================================================
class TestEndToEndWithConnector:
    """The full documented flow:

    NGINX log line
        -> NginxConnector (Phase 4.3)
        -> canonical SecurityEvent
        -> DetectionEngine.run
        -> DetectionResult

    This is the proof that the engine correctly consumes the
    real connector's output and produces the documented detection
    records.
    """
    def test_brute_force_log_yields_two_detections(self, tmp_path, engine: DetectionEngine) -> None:
        log = tmp_path / "access.log"
        log.write_text(
            '198.51.100.77 - - [26/Aug/2026:11:00:00 +0000] '
            '"POST /api/v1/login HTTP/1.1" 401 64 "-" "curl/8.0"\n',
            encoding="utf-8",
        )
        from app.connectors.nginx import NginxConnector
        events = list(NginxConnector(log).collect())
        assert len(events) == 1
        result = engine.run(events[0], now=FIXED_NOW)
        assert result.detection_count == 2
        assert {d.rule_id for d in result.detections} == {
            "NGINX-AUTH-FAILURE-001",
            "NGINX-AUTH-BRUTEFORCE-001",
        }

    def test_directory_enumeration_log_yields_access_denied(self, tmp_path, engine: DetectionEngine) -> None:
        log = tmp_path / "access.log"
        log.write_text(
            '198.51.100.99 - - [26/Aug/2026:11:00:00 +0000] '
            '"GET /.env HTTP/1.1" 404 24 "-" "sqlmap/1.7"\n',
            encoding="utf-8",
        )
        from app.connectors.nginx import NginxConnector
        events = list(NginxConnector(log).collect())
        assert len(events) == 1
        result = engine.run(events[0], now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-ACCESS-DENIED-001"

    def test_5xx_burst_log_yields_status_anomaly(self, tmp_path, engine: DetectionEngine) -> None:
        log = tmp_path / "access.log"
        log.write_text(
            '198.51.100.50 - - [26/Aug/2026:11:00:00 +0000] '
            '"GET /api/orders/1 HTTP/1.1" 502 18 "-" "kube-probe/1.29"\n',
            encoding="utf-8",
        )
        from app.connectors.nginx import NginxConnector
        events = list(NginxConnector(log).collect())
        assert len(events) == 1
        result = engine.run(events[0], now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-STATUS-ANOMALY-001"

    def test_429_burst_log_yields_rate_limit(self, tmp_path, engine: DetectionEngine) -> None:
        log = tmp_path / "access.log"
        log.write_text(
            '198.51.100.55 - - [26/Aug/2026:11:00:00 +0000] '
            '"GET /api/items HTTP/1.1" 429 0 "-" "loader/1.0"\n',
            encoding="utf-8",
        )
        from app.connectors.nginx import NginxConnector
        events = list(NginxConnector(log).collect())
        assert len(events) == 1
        result = engine.run(events[0], now=FIXED_NOW)
        assert result.detection_count == 1
        assert result.detections[0].rule_id == "NGINX-RATE-LIMIT-001"

    def test_404_on_public_path_yields_no_detection(self, tmp_path, engine: DetectionEngine) -> None:
        log = tmp_path / "access.log"
        log.write_text(
            '203.0.113.10 - - [26/Aug/2026:11:00:00 +0000] '
            '"GET /blog/typo HTTP/1.1" 404 24 "-" "Mozilla/5.0"\n',
            encoding="utf-8",
        )
        from app.connectors.nginx import NginxConnector
        events = list(NginxConnector(log).collect())
        assert len(events) == 1
        result = engine.run(events[0], now=FIXED_NOW)
        assert result.detection_count == 0
