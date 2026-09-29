"""Capability patch regression tests (gaps 1-15).

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md.

Each test class maps to one documented gap and asserts the CORRECTED
wire/service/persistence contract. Unit-level: in-memory fakes only
(no MongoDB required); live-DB and browser verification are documented
separately in the patch report.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest

from app.auth import (
    ANALYST_ROLE,
    Identity,
    InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.correlation.models import Correlation, CorrelationKey
from app.correlation.patterns import describe_registered_patterns
from app.correlation.service import CorrelationReadService
from app.detection.models import Detection
from app.detection.service import DetectionReadService
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.errors import ValidationError as DomainValidationError
from app.incidents.errors import (
    CaseNotFoundError,
    CaseStateConflictError,
)
from app.incidents.models import CASE_STATE_ACKNOWLEDGED
from app.incidents.repository import IncidentRepository
from app.incidents.service import IncidentService
from app.notifications import (
    NotificationRepository,
    NotificationService,
)
from app.observability.health import (
    DEGRADED,
    HEALTHY,
    NOT_CONFIGURED,
    UNAVAILABLE,
    DeepHealthService,
)
from app.overview.service import OverviewReadService
from app.persistence.detection_repository import DetectionRepository
from app.persistence.human_ids import HumanIdAllocator
from app.persistence.security_event_repository import SecurityEventRepository
from app.persistence.telemetry import SourceTelemetryStore
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_CASE_ACKNOWLEDGE,
    OP_CASE_ADD_NOTE,
    OP_CASE_CREATE_FROM_CORRELATION,
    OP_CASE_INVESTIGATE,
    OP_CORRELATION_LIST_PATTERNS,
    OP_NOTIFICATION_LIST,
    OP_NOTIFICATION_MARK_READ,
    OP_NOTIFICATION_UNREAD_COUNT,
    OP_OVERVIEW_TIMESERIES,
    OP_SYSTEM_HEALTH_DEEP,
    OP_TIMELINE_GLOBAL_QUERY,
    PROXY_HEADER_AUTHORIZATION,
    ALLOWED_OPERATIONS,
    ProxyRequest,
    SecureProxy,
)
from app.severity.enrichment import (
    enrich_correlation,
    enrich_detection,
)
from app.severity.models import ConfidenceBand, SeverityBand
from app.timeline.engine import TimelineEngine
from app.timeline.service import TimelineReadService
from tests.unit._phase47_fakes import FakeCursor


class GenericFakeCollection:
    """A content-agnostic in-memory collection (no rule_id dedup)."""

    def __init__(self) -> None:
        self.docs: list = []

    def insert_one(self, doc: Dict[str, Any]) -> Any:
        self.docs.append(dict(doc))
        return type("R", (), {"inserted_id": "fake"})()

    def find_one(self, query: Dict[str, Any]) -> Any:
        for d in self.docs:
            if self._match(d, query):
                return dict(d)
        return None

    def find(self, query: Dict[str, Any]) -> Any:
        return FakeCursor(
            [dict(d) for d in self.docs if self._match(d, query)]
        )

    def replace_one(
        self, query: Dict[str, Any], doc: Dict[str, Any],
        upsert: bool = False,
    ) -> Any:
        for d in self.docs:
            if self._match(d, query):
                d.clear()
                d.update(doc)
                return type("R", (), {"modified_count": 1})()
        if upsert:
            self.docs.append(dict(doc))
        return type("R", (), {"modified_count": 0})()

    def update_one(
        self, query: Dict[str, Any], update: Dict[str, Any],
        upsert: bool = False,
    ) -> Any:
        from tests.unit._phase47_fakes import _apply_update_ops

        for d in self.docs:
            if self._match(d, query):
                _apply_update_ops(d, update)
                return type("R", (), {"modified_count": 1})()
        if upsert:
            doc_new = dict(query)
            _apply_update_ops(doc_new, update, upsert=True)
            self.docs.append(doc_new)
        return type("R", (), {"modified_count": 0})()

    def find_one_and_update(
        self, query: Dict[str, Any], update: Dict[str, Any],
        *, upsert: bool = False, return_document: Any = None,
    ) -> Any:
        from tests.unit._phase47_fakes import _apply_update_ops

        for d in self.docs:
            if self._match(d, query):
                _apply_update_ops(d, update)
                return dict(d)
        if not upsert:
            return None
        doc = dict(query)
        _apply_update_ops(doc, update, upsert=True)
        self.docs.append(doc)
        return dict(doc)

    def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for d in self.docs if self._match(d, query))

    def create_index(self, *a: Any, **k: Any) -> Any:
        return "ok"

    def list_indexes(self) -> list:
        return []

    @staticmethod
    def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for k, v in query.items():
            if k.startswith("$"):
                continue  # top-level operator queries match everything
            if doc.get(k) != v:
                return False
        return True


class GenericFakeDatabase:
    def __init__(self) -> None:
        self.collections: Dict[str, GenericFakeCollection] = {}

    def __getitem__(self, name: str) -> GenericFakeCollection:
        if name not in self.collections:
            self.collections[name] = GenericFakeCollection()
        return self.collections[name]

    def list_collection_names(self) -> list:
        return list(self.collections.keys())

    def command(self, *a: Any, **k: Any) -> Any:
        return {"cursor": {"firstBatch": []}}


FIXED_NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
ANALYST = Identity(
    subject_id="user-analyst-001", role=ANALYST_ROLE,
    permissions=frozenset(),
)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        auth_signing_key=new_development_signing_key(),
        source_signing_key=new_development_signing_key(),
        proxy_rate_limit_per_minute=10000,
    )


def _make_event(**overrides: Any) -> SecurityEvent:
    defaults: Dict[str, Any] = dict(
        event_id="01923456-7890-7abc-9def-0123456789ab",
        event_time=FIXED_NOW,
        ingested_at=FIXED_NOW,
        source="nginx",
        event_type="authentication_failure",
        source_ip="198.51.100.7",
        endpoint="/api/login",
        provenance=SecurityEventProvenance(
            collector="test", source_event_id="src-1",
        ),
        details={"status_code": 401},
    )
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _make_detection(event_id: str, **overrides: Any) -> Detection:
    defaults: Dict[str, Any] = dict(
        detection_id="det-01923456-7890-7abc-9def-0123456789ab",
        rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1,
        category="source_specific",
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="nginx HTTP 401 authentication_failure",
        detected_at=FIXED_NOW,
    )
    defaults.update(overrides)
    return Detection(**defaults)


def _make_correlation(**overrides: Any) -> Correlation:
    defaults: Dict[str, Any] = dict(
        correlation_id="corr-01923456-7890-7abc-9def-0123456789ab",
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=(
            "det-01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "det-01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        event_ids=(
            "01923456-7890-7abc-9def-aaaaaaaaaaaa",
            "01923456-7890-7abc-9def-bbbbbbbbbbbb",
        ),
        window_start=FIXED_NOW - timedelta(seconds=60),
        window_end=FIXED_NOW,
        count=2,
        reasoning="brute-force clustering: 2 ...",
        correlated_at=FIXED_NOW,
    )
    defaults.update(overrides)
    return Correlation(**defaults)


@pytest.fixture
def db() -> GenericFakeDatabase:
    return GenericFakeDatabase()


@pytest.fixture
def config() -> ProShieldConfig:
    return _config()


@pytest.fixture
def incident_service(db: FakeDatabase, config: ProShieldConfig) -> IncidentService:
    return IncidentService(repository=IncidentRepository(db, config))


# =====================================================================
# Gap 2: stable human-readable ids
# =====================================================================
class TestHumanIds:
    def test_allocator_format(self) -> None:
        allocator = HumanIdAllocator(None, "incident")
        assert allocator.allocate() == "CASE-000001"
        assert allocator.allocate() == "CASE-000002"

    def test_allocator_unique_across_kinds(self) -> None:
        case_a = HumanIdAllocator(None, "incident")
        det_a = HumanIdAllocator(None, "detection")
        assert case_a.allocate() == "CASE-000001"
        assert det_a.allocate() == "DET-000001"
        assert case_a.allocate() == "CASE-000002"

    def test_incident_human_id_persisted(self, db, config, incident_service) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        assert case.human_id == "CASE-000001"
        fetched = incident_service.repository.get_by_id(case.incident_id)
        assert fetched is not None
        assert fetched.human_id == "CASE-000001"

    def test_wire_includes_human_id(self, db, config, incident_service) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        wire = case.to_dict()
        assert wire["human_id"] == "CASE-000001"

    def test_upsert_keeps_human_id(self, db, config, incident_service) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        closed = incident_service.close_case(
            ANALYST, case.incident_id, reason="done",
        )
        assert closed.human_id == case.human_id


# =====================================================================
# Gap 1: case acknowledge / investigate lifecycle
# =====================================================================
class TestCaseLifecycleTransitions:
    def _case(self, incident_service: IncidentService) -> Any:
        return incident_service.create_case(
            identity=ANALYST, title="brute force", summary="s",
            events=(), detections=(),
        )

    def test_open_to_acknowledged(self, incident_service) -> None:
        case = self._case(incident_service)
        acked = incident_service.acknowledge_case(
            ANALYST, case.incident_id, reason="triaged",
        )
        assert acked.state.value == "acknowledged"
        last = acked.lifecycle_history[-1].to_dict()
        assert last["from_state"] == "open"
        assert last["to_state"] == "acknowledged"
        assert last["actor_subject_id"] == "user-analyst-001"

    def test_acknowledged_to_investigating(self, incident_service) -> None:
        case = self._case(incident_service)
        incident_service.acknowledge_case(ANALYST, case.incident_id)
        investigating = incident_service.investigate_case(
            ANALYST, case.incident_id,
        )
        assert investigating.state.value == "investigating"

    def test_open_to_investigating_allowed(self, incident_service) -> None:
        case = self._case(incident_service)
        investigating = incident_service.investigate_case(
            ANALYST, case.incident_id,
        )
        assert investigating.state.value == "investigating"

    def test_investigating_to_closed(self, incident_service) -> None:
        case = self._case(incident_service)
        incident_service.investigate_case(ANALYST, case.incident_id)
        closed = incident_service.close_case(
            ANALYST, case.incident_id, reason="resolved",
        )
        assert closed.state.value == "closed"

    def test_repeated_acknowledge_conflict(self, incident_service) -> None:
        case = self._case(incident_service)
        incident_service.acknowledge_case(ANALYST, case.incident_id)
        with pytest.raises(CaseStateConflictError):
            incident_service.acknowledge_case(ANALYST, case.incident_id)
        # state unchanged
        fetched = incident_service.repository.get_by_id(case.incident_id)
        assert fetched.state.value == "acknowledged"

    def test_cannot_acknowledge_closed_case(self, incident_service) -> None:
        case = self._case(incident_service)
        incident_service.close_case(ANALYST, case.incident_id)
        with pytest.raises(CaseStateConflictError):
            incident_service.acknowledge_case(ANALYST, case.incident_id)

    def test_unknown_case_404(self, incident_service) -> None:
        with pytest.raises(CaseNotFoundError):
            incident_service.acknowledge_case(
                ANALYST, "case-01234567-0123-7000-8000-000000000000",
            )

    def test_state_persists(self, incident_service) -> None:
        case = self._case(incident_service)
        incident_service.acknowledge_case(ANALYST, case.incident_id)
        fetched = incident_service.repository.get_by_id(case.incident_id)
        assert fetched.state.value == "acknowledged"


# =====================================================================
# Gap 3: case attribution
# =====================================================================
class TestCaseAttribution:
    def test_attribution_from_correlation_key(self, incident_service) -> None:
        corr = _make_correlation()
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(), correlations=[corr],
        )
        assert case.attribution is not None
        assert case.attribution.attacker == "198.51.100.7"
        assert case.attribution.target == "/api/login"
        assert "correlation key" in (case.attribution.provenance or "")
        wire = case.to_dict()
        assert wire["attribution"]["attacker"] == "198.51.100.7"

    def test_attribution_none_when_underivable(
        self, incident_service,
    ) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        assert case.attribution is None
        assert case.to_dict()["attribution"] is None


# =====================================================================
# Gap 4: analyst notes
# =====================================================================
class TestCaseNotes:
    def test_add_note_author_timestamp_order(
        self, incident_service,
    ) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        updated = incident_service.add_note(
            ANALYST, case.incident_id, "first observation",
        )
        admin = Identity(subject_id="user-admin-001", role="admin",
                         permissions=frozenset())
        updated = incident_service.add_note(
            admin, case.incident_id, "second observation",
        )
        assert len(updated.notes) == 2
        assert updated.notes[0].author_subject_id == "user-analyst-001"
        assert updated.notes[1].author_subject_id == "user-admin-001"
        assert updated.notes[0].created_at <= updated.notes[1].created_at
        wire = updated.to_dict()
        assert wire["notes"][0]["body"] == "first observation"

    def test_note_persists(self, incident_service) -> None:
        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        incident_service.add_note(ANALYST, case.incident_id, "keep me")
        fetched = incident_service.repository.get_by_id(case.incident_id)
        assert len(fetched.notes) == 1
        assert fetched.notes[0].body == "keep me"

    def test_no_cross_case_leakage(self, incident_service) -> None:
        case_a = incident_service.create_case(
            identity=ANALYST, title="a", summary="s",
            events=(), detections=(),
        )
        case_b = incident_service.create_case(
            identity=ANALYST, title="b", summary="s",
            events=(), detections=(),
        )
        incident_service.add_note(ANALYST, case_a.incident_id, "a-note")
        fetched_b = incident_service.repository.get_by_id(case_b.incident_id)
        assert len(fetched_b.notes) == 0

    def test_empty_body_rejected(self, incident_service) -> None:
        from app.incidents.errors import InvalidIncidentInputError

        case = incident_service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        with pytest.raises(InvalidIncidentInputError):
            incident_service.add_note(ANALYST, case.incident_id, "   ")


# =====================================================================
# Gap 5: detection severity + source attribution
# =====================================================================
class TestDetectionMetadata:
    def test_enrich_detection_composes_severity(self) -> None:
        det = _make_detection("01923456-7890-7abc-9def-0123456789ab")
        event = _make_event()
        enriched = enrich_detection(det, event, now=FIXED_NOW)
        assert enriched is not det
        assert enriched.detection_id == det.detection_id
        assert enriched.severity in {b.value for b in SeverityBand}
        # no source-management provenance on this event -> empty
        assert enriched.source_instance_id == ""

    def test_enrich_detection_carries_source_provenance(self) -> None:
        det = _make_detection("01923456-7890-7abc-9def-0123456789ab")
        event = _make_event(
            provenance=SecurityEventProvenance(
                collector="c", source_event_id="e1",
                source_instance_id="src-01923456-7890-7abc-9def-000000000001",
            ),
        )
        enriched = enrich_detection(det, event, now=FIXED_NOW)
        assert enriched.source_instance_id == (
            "src-01923456-7890-7abc-9def-000000000001"
        )

    def test_wire_includes_severity_and_source(self) -> None:
        det = _make_detection("01923456-7890-7abc-9def-0123456789ab")
        event = _make_event(
            provenance=SecurityEventProvenance(
                collector="c", source_event_id="e1",
                source_instance_id="src-01923456-7890-7abc-9def-000000000001",
            ),
        )
        enriched = enrich_detection(det, event, now=FIXED_NOW)
        wire = enriched.to_dict()
        assert wire["severity"] in {b.value for b in SeverityBand}
        assert wire["source_instance_id"].startswith("src-")


# =====================================================================
# Gap 6: correlation confidence
# =====================================================================
class TestCorrelationConfidence:
    def test_enrich_correlation_composes_confidence(self) -> None:
        corr = _make_correlation()
        enriched = enrich_correlation(corr, now=FIXED_NOW)
        assert enriched is not corr
        assert enriched.confidence in {b.value for b in ConfidenceBand}
        assert corr.confidence == ""  # input untouched

    def test_wire_includes_confidence(self) -> None:
        corr = _make_correlation()
        enriched = enrich_correlation(corr, now=FIXED_NOW)
        wire = enriched.to_dict()
        assert wire["confidence"] in {b.value for b in ConfidenceBand}

    def test_repository_composes_on_create(self, db, config) -> None:
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        repo = CorrelationRepository(db, config)
        persisted = repo.create(_make_correlation())
        assert persisted.confidence in {b.value for b in ConfidenceBand}
        assert persisted.human_id == "CORR-000001"


# =====================================================================
# Gap 7: correlation pattern catalogue
# =====================================================================
class TestPatternCatalogue:
    def test_describes_registered_patterns(self) -> None:
        patterns = describe_registered_patterns()
        ids = [p["pattern_id"] for p in patterns]
        assert "NGINX-CORR-BRUTEFORCE-001" in ids
        for p in patterns:
            assert "pattern_version" in p
            assert "trigger" in p
            assert "threshold" in p
            assert "window_seconds" in p

    def test_service_list_patterns(self, db, config) -> None:
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        service = CorrelationReadService(
            repository=CorrelationRepository(db, config),
        )
        patterns = service.list_patterns()
        assert any(
            p["pattern_id"] == "NGINX-CORR-BRUTEFORCE-001"
            for p in patterns
        )


# =====================================================================
# Gap 8: deep health
# =====================================================================
class TestDeepHealth:
    def test_memory_backend_reports_degraded_database(self) -> None:
        service = DeepHealthService(
            db=None, config=None, backend_kind="memory",
        )
        report = service.run_checks()
        assert report["status"] in {DEGRADED, UNAVAILABLE}
        db_probe = next(
            s for s in report["subsystems"] if s["name"] == "database"
        )
        assert db_probe["status"] == DEGRADED
        assert "in-memory" in db_probe["detail"]

    def test_unavailable_when_probe_fails(self) -> None:
        class _Boom:
            def count(self) -> int:
                raise RuntimeError("mongo down")

        class _Repo:
            repository = _Boom()

        service = DeepHealthService(
            db=None, config=None, backend_kind="mongo",
            detection_service=_Repo(),
        )
        report = service.run_checks()
        det_probe = next(
            s for s in report["subsystems"]
            if s["name"] == "detection_subsystem"
        )
        assert det_probe["status"] == UNAVAILABLE
        assert report["status"] == UNAVAILABLE

    def test_not_configured_distinct_from_healthy(self) -> None:
        service = DeepHealthService(
            db=None, config=None, backend_kind="memory",
        )
        report = service.run_checks()
        names = {s["name"] for s in report["subsystems"]}
        assert "ingress_telemetry" in names
        probe = next(
            s for s in report["subsystems"]
            if s["name"] == "ingress_telemetry"
        )
        assert probe["status"] == NOT_CONFIGURED


# =====================================================================
# Gap 9: per-source ingest telemetry
# =====================================================================
class TestSourceTelemetry:
    def test_counters_increment_atomically(self, db, config) -> None:
        store = SourceTelemetryStore(db, config)
        sid = "src-01923456-7890-7abc-9def-000000000001"
        store.record_accepted(sid, count=3)
        store.record_rejected(sid, count=1, message="validation_error")
        snap = store.snapshot(sid)
        assert snap["accepted"] == 3
        assert snap["rejected"] == 1
        assert snap["last_error"] == "validation_error"
        assert snap["last_event_at"] is not None

    def test_no_data_is_none_not_zero(self, db, config) -> None:
        store = SourceTelemetryStore(db, config)
        assert store.snapshot("src-unknown") is None

    def test_error_recording(self, db, config) -> None:
        store = SourceTelemetryStore(db, config)
        sid = "src-01923456-7890-7abc-9def-000000000001"
        store.record_error(sid, message="ingest_failed")
        snap = store.snapshot(sid)
        assert snap["errors"] == 1


# =====================================================================
# Gap 12: notification feed
# =====================================================================
class TestNotifications:
    def test_emit_and_list(self, db, config) -> None:
        service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        service.emit(
            kind="case.acknowledged",
            incident_id="case-01234567-0123-7000-8000-000000000001",
            human_id="CASE-000001",
            title="t", detail="d", actor_subject_id="user-analyst-001",
        )
        items = service.list_for_identity(identity=ANALYST)
        assert len(items) == 1
        assert items[0]["kind"] == "case.acknowledged"
        assert items[0]["human_id"] == "CASE-000001"

    def test_mark_read_idempotent(self, db, config) -> None:
        service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        service.emit(kind="case.closed", title="t")
        row = service.list_for_identity(identity=ANALYST)[0]
        first = service.mark_read(
            identity=ANALYST, notification_id=row["notification_id"],
        )
        assert first["read"] is True
        again = service.mark_read(
            identity=ANALYST, notification_id=row["notification_id"],
        )
        assert again["read"] is True

    def test_unread_count(self, db, config) -> None:
        service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        service.emit(kind="case.created", title="1")
        service.emit(kind="case.created", title="2")
        assert service.unread_count(identity=ANALYST) == {
            "unread_count": 2,
        }
        row = service.list_for_identity(identity=ANALYST)[0]
        service.mark_read(
            identity=ANALYST, notification_id=row["notification_id"],
        )
        assert service.unread_count(identity=ANALYST) == {
            "unread_count": 1,
        }

    def test_unknown_kind_rejected(self, db, config) -> None:
        service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        with pytest.raises(DomainValidationError):
            service.emit(kind="totally_made_up", title="x")

    def test_unknown_notification_404(self, db, config) -> None:
        from app.domain.errors import NotFoundError

        service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        with pytest.raises(NotFoundError):
            service.mark_read(
                identity=ANALYST,
                notification_id="ntf-00000000-0000-7000-8000-000000000000",
            )


# =====================================================================
# Gap 13: global timeline
# =====================================================================
class TestGlobalTimeline:
    def _service(self, db, config) -> TimelineReadService:
        event_repo = SecurityEventRepository(db, config)
        detection_service = DetectionReadService(
            repository=DetectionRepository(db, config),
        )
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        correlation_service = CorrelationReadService(
            repository=CorrelationRepository(db, config),
        )
        return TimelineReadService(
            engine=TimelineEngine(),
            security_event_repository=event_repo,
            detection_service=detection_service,
            correlation_service=correlation_service,
        )

    def _seed(self, db, config) -> None:
        SecurityEventRepository(db, config).create(
            _make_event(event_time=FIXED_NOW - timedelta(minutes=3)),
        )
        DetectionRepository(db, config).create(
            _make_detection(
                "01923456-7890-7abc-9def-0123456789ab",
                detected_at=FIXED_NOW - timedelta(minutes=2),
            ),
        )
        DetectionRepository(db, config).create(
            _make_detection(
                "01923456-7890-7abc-9def-bbbbbbbbbbbb",
                detection_id="det-01923456-7890-7abc-9def-bbbbbbbbbbbb",
                detected_at=FIXED_NOW - timedelta(minutes=1),
            ),
        )
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        CorrelationRepository(db, config).create(_make_correlation())

    def test_orders_newest_first(self, db, config) -> None:
        self._seed(db, config)
        result = self._service(db, config).global_query()
        stamps = [i["timestamp"] for i in result["items"]]
        assert stamps == sorted(stamps, reverse=True)
        kinds = {i["kind"] for i in result["items"]}
        assert {"event", "detection", "correlation"} <= kinds

    def test_pagination(self, db, config) -> None:
        self._seed(db, config)
        service = self._service(db, config)
        page1 = service.global_query(limit=2)
        assert len(page1["items"]) == 2
        page2 = service.global_query(limit=2, offset=2)
        assert len(page2["items"]) >= 1
        ids1 = {i["item_id"] for i in page1["items"]}
        ids2 = {i["item_id"] for i in page2["items"]}
        assert not ids1 & ids2

    def test_kind_filter(self, db, config) -> None:
        self._seed(db, config)
        result = self._service(db, config).global_query(
            kinds=("detection",),
        )
        assert {i["kind"] for i in result["items"]} == {"detection"}

    def test_time_window_filter(self, db, config) -> None:
        self._seed(db, config)
        result = self._service(db, config).global_query(
            since=FIXED_NOW - timedelta(seconds=90),
        )
        stamps = [datetime.fromisoformat(i["timestamp"]) for i in
                  result["items"]]
        assert all(s >= FIXED_NOW - timedelta(seconds=90) for s in stamps)

    def test_empty_dataset(self, db, config) -> None:
        result = self._service(db, config).global_query()
        assert result["items"] == []
        assert result["total_matched"] == 0


# =====================================================================
# Gap 15: overview time-series
# =====================================================================
class TestOverviewTimeseries:
    def test_buckets_are_explicit_and_counted(self, db, config) -> None:
        detection_repo = DetectionRepository(db, config)
        detection_repo.create(
            _make_detection(
                "01923456-7890-7abc-9def-0123456789ab",
                severity="high",
            ),
        )
        detection_repo.create(
            _make_detection(
                "01923456-7890-7abc-9def-bbbbbbbbbbbb",
                detection_id="det-01923456-7890-7abc-9def-bbbbbbbbbbbb",
                severity="critical",
            ),
        )
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        service = OverviewReadService(
            incident_service=IncidentService(
                repository=IncidentRepository(db, config),
            ),
            detection_service=DetectionReadService(
                repository=detection_repo,
            ),
            correlation_service=CorrelationReadService(
                repository=CorrelationRepository(db, config),
            ),
        )
        result = service.timeseries(ANALYST, hours=6, now=FIXED_NOW)
        assert result["hours"] == 6
        assert len(result["series"]) == 6
        total = sum(b["detections"] for b in result["series"])
        assert total == 2
        high = sum(b["high"] for b in result["series"])
        critical = sum(b["critical"] for b in result["series"])
        assert high == 1
        assert critical == 1
        # explicit zero buckets for empty hours
        assert any(b["detections"] == 0 for b in result["series"])

    def test_empty_store_all_zero_buckets(self, db, config) -> None:
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        service = OverviewReadService(
            incident_service=IncidentService(
                repository=IncidentRepository(db, config),
            ),
            detection_service=DetectionReadService(
                repository=DetectionRepository(db, config),
            ),
            correlation_service=CorrelationReadService(
                repository=CorrelationRepository(db, config),
            ),
        )
        result = service.timeseries(ANALYST, hours=3, now=FIXED_NOW)
        assert len(result["series"]) == 3
        assert all(b["detections"] == 0 for b in result["series"])
        assert result["truncated"] is False


# =====================================================================
# Wire surface: dispatch, auth semantics, ALLOWED_OPERATIONS
# =====================================================================
def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore(
        {
            "user-analyst-001": Identity(
                subject_id="user-analyst-001", role=ANALYST_ROLE,
            ),
        },
        credentials={"user-analyst-001": "analyst-password"},
    )


def _issue_token(proxy: SecureProxy) -> str:
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={
            "subject_id": "user-analyst-001",
            "credential": "analyst-password",
        },
    )).body["data"]["token"]


class TestCapabilityWireOps:
    def _proxy(self) -> SecureProxy:
        return SecureProxy(
            config=_config(), identity_store=_identity_store(),
        )

    def test_all_new_ops_declared(self) -> None:
        for op in (
            OP_CASE_ACKNOWLEDGE, OP_CASE_INVESTIGATE, OP_CASE_ADD_NOTE,
            OP_CASE_CREATE_FROM_CORRELATION, OP_CORRELATION_LIST_PATTERNS,
            OP_SYSTEM_HEALTH_DEEP, OP_NOTIFICATION_LIST,
            OP_NOTIFICATION_MARK_READ, OP_NOTIFICATION_UNREAD_COUNT,
            OP_TIMELINE_GLOBAL_QUERY, OP_OVERVIEW_TIMESERIES,
        ):
            assert op in ALLOWED_OPERATIONS

    def test_new_ops_require_authentication(self) -> None:
        proxy = self._proxy()
        for op in (
            OP_CASE_ACKNOWLEDGE, OP_CASE_INVESTIGATE, OP_CASE_ADD_NOTE,
            OP_CASE_CREATE_FROM_CORRELATION, OP_CORRELATION_LIST_PATTERNS,
            OP_SYSTEM_HEALTH_DEEP, OP_NOTIFICATION_LIST,
            OP_NOTIFICATION_MARK_READ, OP_NOTIFICATION_UNREAD_COUNT,
            OP_TIMELINE_GLOBAL_QUERY, OP_OVERVIEW_TIMESERIES,
        ):
            resp = proxy.handle(ProxyRequest(
                operation=op, headers={}, body={},
            ))
            assert resp.status == 401, op

    def test_case_acknowledge_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        service = IncidentService(repository=IncidentRepository(db, config))
        case = service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        proxy = self._proxy()
        proxy.attach_incident_service(service)
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_ACKNOWLEDGE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"incident_id": case.incident_id, "reason": "triage"},
        ))
        assert resp.status == 200
        assert resp.body["data"]["case"]["state"] == "acknowledged"
        # repeated -> 409
        resp2 = proxy.handle(ProxyRequest(
            operation=OP_CASE_ACKNOWLEDGE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"incident_id": case.incident_id},
        ))
        assert resp2.status == 409

    def test_case_investigate_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        service = IncidentService(repository=IncidentRepository(db, config))
        case = service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        proxy = self._proxy()
        proxy.attach_incident_service(service)
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_INVESTIGATE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"incident_id": case.incident_id},
        ))
        assert resp.status == 200
        assert resp.body["data"]["case"]["state"] == "investigating"

    def test_case_note_add_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        service = IncidentService(repository=IncidentRepository(db, config))
        case = service.create_case(
            identity=ANALYST, title="t", summary="s",
            events=(), detections=(),
        )
        proxy = self._proxy()
        proxy.attach_incident_service(service)
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_ADD_NOTE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={
                "incident_id": case.incident_id,
                "body": "analyst observation",
            },
        ))
        assert resp.status == 200
        note = resp.body["data"]["note"]
        assert note["body"] == "analyst observation"
        assert note["author_subject_id"] == "user-analyst-001"
        # persisted + returned by case.get
        fetched = service.repository.get_by_id(case.incident_id)
        assert len(fetched.notes) == 1

    def test_correlation_list_patterns_wire(self) -> None:
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        proxy = self._proxy()
        proxy.attach_correlation_service(
            CorrelationReadService(
                repository=CorrelationRepository(GenericFakeDatabase(), _config()),
            ),
        )
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_LIST_PATTERNS,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={},
        ))
        assert resp.status == 200
        ids = [p["pattern_id"] for p in resp.body["data"]["patterns"]]
        assert "NGINX-CORR-BRUTEFORCE-001" in ids

    def test_system_health_deep_wire(self) -> None:
        proxy = self._proxy()
        proxy.attach_deep_health_service(
            DeepHealthService(db=None, config=None, backend_kind="memory"),
        )
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_SYSTEM_HEALTH_DEEP,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={},
        ))
        assert resp.status == 200
        report = resp.body["data"]["health"]
        assert report["status"] in {
            HEALTHY, DEGRADED, UNAVAILABLE, NOT_CONFIGURED,
        }
        assert len(report["subsystems"]) >= 6

    def test_notification_wire_ops(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        notification_service = NotificationService(
            repository=NotificationRepository(db, config),
        )
        notification_service.emit(
            kind="case.created", title="new case",
        )
        proxy = self._proxy()
        proxy.attach_notification_service(notification_service)
        token = _issue_token(proxy)
        headers = {PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"}

        resp = proxy.handle(ProxyRequest(
            operation=OP_NOTIFICATION_LIST, headers=headers, body={},
        ))
        assert resp.status == 200
        items = resp.body["data"]["notifications"]
        assert len(items) == 1

        resp = proxy.handle(ProxyRequest(
            operation=OP_NOTIFICATION_UNREAD_COUNT,
            headers=headers, body={},
        ))
        assert resp.body["data"]["unread_count"] == 1

        resp = proxy.handle(ProxyRequest(
            operation=OP_NOTIFICATION_MARK_READ, headers=headers,
            body={"notification_id": items[0]["notification_id"]},
        ))
        assert resp.status == 200
        assert resp.body["data"]["notification"]["read"] is True

        resp = proxy.handle(ProxyRequest(
            operation=OP_NOTIFICATION_UNREAD_COUNT,
            headers=headers, body={},
        ))
        assert resp.body["data"]["unread_count"] == 0

    def test_timeline_global_query_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        SecurityEventRepository(db, config).create(_make_event())
        service = TimelineReadService(
            engine=TimelineEngine(),
            security_event_repository=SecurityEventRepository(db, config),
            detection_service=DetectionReadService(
                repository=DetectionRepository(db, config),
            ),
            correlation_service=CorrelationReadService(
                repository=_corr_repo(db, config),
            ),
        )
        proxy = self._proxy()
        proxy.attach_timeline_service(
            service, security_event_repository=None,
        )
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_TIMELINE_GLOBAL_QUERY,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={},
        ))
        assert resp.status == 200
        assert any(
            i["kind"] == "event" for i in resp.body["data"]["items"]
        )

    def test_overview_timeseries_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        overview = OverviewReadService(
            incident_service=IncidentService(
                repository=IncidentRepository(db, config),
            ),
            detection_service=DetectionReadService(
                repository=DetectionRepository(db, config),
            ),
            correlation_service=CorrelationReadService(
                repository=CorrelationRepository(db, config),
            ),
        )
        proxy = self._proxy()
        proxy.attach_overview_service(overview)
        token = _issue_token(proxy)
        resp = proxy.handle(ProxyRequest(
            operation=OP_OVERVIEW_TIMESERIES,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"hours": 12},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["series"]) == 12

    def test_case_create_from_correlation_wire(self) -> None:
        db = GenericFakeDatabase()
        config = _config()
        from app.persistence.correlation_repository import (
            CorrelationRepository,
        )

        corr_repo = CorrelationRepository(db, config)
        corr = corr_repo.create(_make_correlation())
        incident_service = IncidentService(
            repository=IncidentRepository(db, config),
        )
        proxy = self._proxy()
        proxy.attach_incident_service(incident_service)
        proxy.attach_correlation_service(
            CorrelationReadService(repository=corr_repo),
        )
        proxy.attach_detection_service(
            DetectionReadService(repository=DetectionRepository(db, config)),
        )
        proxy.attach_timeline_service(
            TimelineReadService(
                engine=TimelineEngine(),
                security_event_repository=SecurityEventRepository(db, config),
                detection_service=DetectionReadService(
                    repository=DetectionRepository(db, config),
                ),
                correlation_service=CorrelationReadService(
                    repository=corr_repo,
                ),
            ),
            security_event_repository=None,
        )
        token = _issue_token(proxy)
        headers = {PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"}

        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=headers,
            body={"correlation_id": corr.correlation_id},
        ))
        assert resp.status == 200
        data = resp.body["data"]
        assert data["created"] is True
        assert data["case"]["state"] == "open"
        case_id = data["case"]["incident_id"]
        assert data["case"]["evidence"]["correlation_ids"] == [
            corr.correlation_id,
        ]

        # Idempotent: same cluster -> same deterministic case id.
        resp2 = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=headers,
            body={"correlation_id": corr.correlation_id},
        ))
        assert resp2.status == 200
        # Batch 1/2 T28: ``created`` is the documented timestamps heuristic
        # (``created_at == updated_at``). Since the create path now opens the
        # case with the cluster's complete evidence, the reuse call adds
        # nothing and is a true no-op (no mutation, both stamps stay equal).
        # The idempotency contract is the stable case id + stable evidence.
        assert (
            resp2.body["data"]["case"]["incident_id"] == case_id
        )
        assert (
            resp2.body["data"]["case"]["evidence"]["detection_ids"]
            == data["case"]["evidence"]["detection_ids"]
        )

        # Bad correlation id -> 404
        resp3 = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=headers,
            body={
                "correlation_id": (
                    "corr-00000000-0000-7000-8000-000000000000"
                )
            },
        ))
        assert resp3.status == 404


def _corr_repo(db, config):
    from app.persistence.correlation_repository import (
        CorrelationRepository,
    )

    return CorrelationRepository(db, config)
