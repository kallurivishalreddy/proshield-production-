"""Phase 4.10 - Proxy wire-promotion tests.

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md.

This file exercises the 16 ops that were promoted from 501-stub
to fully wired SecureProxy handlers in Phase 4.10, plus the
``report.export`` real implementation. It uses in-memory fakes
(no MongoDB required) so the wire boundary is exercised
end-to-end against the real service / engine layers.

Operations covered:
* ``detection.list`` / ``detection.get`` /
  ``detection.list_for_incident``
* ``correlation.list`` / ``correlation.get`` /
  ``correlation.list_for_incident``
* ``overview.summary``
* ``timeline.build_for_incident``
* ``rule.list`` / ``rule.get`` / ``rule.create`` /
  ``rule.update`` / ``rule.version`` / ``rule.enable`` /
  ``rule.disable`` / ``rule.retire``
* ``report.export`` (real JSON serialisation)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, COLLECTOR_ROLE, Identity, InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.correlation.service import CorrelationReadService
from app.detection.service import DetectionReadService
from app.overview.service import OverviewReadService
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.detection_repository import DetectionRepository
from app.persistence.security_event_repository import SecurityEventRepository
from app.persistence.rule_repository import RuleRepository
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_CORRELATION_GET,
    OP_CORRELATION_LIST,
    OP_CORRELATION_LIST_FOR_INCIDENT,
    OP_DETECTION_GET,
    OP_DETECTION_LIST,
    OP_DETECTION_LIST_FOR_INCIDENT,
    OP_OVERVIEW_SUMMARY,
    OP_REPORT_EXPORT,
    OP_RULE_CREATE,
    OP_RULE_DISABLE,
    OP_RULE_ENABLE,
    OP_RULE_GET,
    OP_RULE_LIST,
    OP_RULE_RETIRE,
    OP_RULE_UPDATE,
    OP_RULE_VERSION,
    OP_TIMELINE_BUILD_FOR_INCIDENT,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.reports.models import Report, ReportItem, ReportSection
from app.reports.repository import ReportRepository
from app.reports.service import ReportService
from app.rules.management.service import RuleManagementService
from app.rules.registry import RuleRegistry
from app.timeline.engine import TimelineEngine
from app.timeline.service import TimelineReadService
from tests.unit._phase47_fakes import FakeDatabase


# ==================================================================== helpers


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        auth_signing_key=new_development_signing_key(),
        source_signing_key=new_development_signing_key(),
        source_token_lifetime_seconds=3600,
        ingest_max_body_bytes=16_384,
        ingest_max_details_bytes=8_192,
        ingest_rate_limit_per_minute=600,
        proxy_rate_limit_per_minute=10000,
        proxy_max_request_bytes=32_768,
        proxy_max_response_bytes=1_048_576,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=32_768,
        ingress_max_response_bytes=1_048_576,
    )


def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-admin-001": Identity(
            subject_id="user-admin-001", role=ADMIN_ROLE,
        ),
        "user-collector-001": Identity(
            subject_id="user-collector-001", role=COLLECTOR_ROLE,
        ),
    }, credentials={
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
        "user-collector-001": "collector-password",
    })


def _issue_token(proxy: SecureProxy, subject_id: str) -> str:
    creds = {
        "user-analyst-001": "analyst-password",
        "user-admin-001": "admin-password",
        "user-collector-001": "collector-password",
    }
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={
            "subject_id": subject_id,
            "credential": creds[subject_id],
        },
    )).body["data"]["token"]


def _auth_headers(token: str) -> Dict[str, str]:
    return {PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"}


# ==================================================================== detection


class _DetectionWireProxy:
    """Wires every Phase 4.10 read service to a fresh proxy."""

    def __init__(self) -> None:
        self.db = FakeDatabase()
        self.config = _config()
        self.proxy = SecureProxy(
            config=self.config, identity_store=_identity_store(),
        )
        self.det_repo = DetectionRepository(self.db, self.config)
        self.corr_repo = CorrelationRepository(self.db, self.config)
        self.event_repo = SecurityEventRepository(self.db, self.config)

        self.det_service = DetectionReadService(self.det_repo)
        self.corr_service = CorrelationReadService(self.corr_repo)

        self.proxy.attach_detection_service(self.det_service)
        self.proxy.attach_correlation_service(self.corr_service)


def _make_detection(repo: DetectionRepository) -> Any:
    """Persist a synthetic Detection so the read services can find it."""
    from app.detection.models import Detection, RuleCategory

    detection = Detection(
        detection_id=(
            "det-01234567-0123-7000-8000-000000000001"
        ),
        rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1,
        category=RuleCategory.SOURCE_SPECIFIC,
        event_id="01234567-0123-7000-8000-000000000001",
        evidence_refs=(),
        reasoning="synthetic",
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    return repo.create(detection)


class TestDetectionWiring:
    def test_attach_detection_service_validates_type(self) -> None:
        proxy = SecureProxy(config=_config(), identity_store=_identity_store())
        with pytest.raises(ValueError):
            proxy.attach_detection_service(object())  # type: ignore[arg-type]
        proxy.attach_detection_service(None)

    def test_detect_list_returns_empty_when_no_filters(self) -> None:
        bundle = _DetectionWireProxy()
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_LIST,
            headers=_auth_headers(
                _issue_token(bundle.proxy, "user-analyst-001")
            ),
            body={},
        ))
        assert resp.status == 200
        assert resp.body["data"]["detections"] == []

    def test_detect_list_filters_by_rule_id(self) -> None:
        bundle = _DetectionWireProxy()
        detection = _make_detection(bundle.det_repo)
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_LIST,
            headers=_auth_headers(
                _issue_token(bundle.proxy, "user-analyst-001")
            ),
            body={"rule_id": "NGINX-AUTH-FAILURE-001"},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["detections"]) == 1
        assert (
            resp.body["data"]["detections"][0]["detection_id"]
            == detection.detection_id
        )

    def test_detect_get_returns_record(self) -> None:
        bundle = _DetectionWireProxy()
        detection = _make_detection(bundle.det_repo)
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_GET,
            headers=_auth_headers(token),
            body={"detection_id": detection.detection_id},
        ))
        assert resp.status == 200
        assert resp.body["data"]["detection"]["detection_id"] == (
            detection.detection_id
        )

    def test_detect_get_returns_404_when_missing(self) -> None:
        bundle = _DetectionWireProxy()
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_GET,
            headers=_auth_headers(token),
            body={"detection_id": (
                "det-00000000-0000-7000-8000-000000000000"
            )},
        ))
        assert resp.status == 404
        assert resp.body["error"]["code"] == "not_found"

    def test_detect_get_requires_detection_id(self) -> None:
        bundle = _DetectionWireProxy()
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_GET,
            headers=_auth_headers(token),
            body={},
        ))
        assert resp.status == 400

    def test_detect_list_for_incident_requires_incident_service(self) -> None:
        bundle = _DetectionWireProxy()
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_LIST_FOR_INCIDENT,
            headers=_auth_headers(token),
            body={"incident_id": (
                "case-00000000-0000-7000-8000-000000000001"
            )},
        ))
        assert resp.status == 400


class TestDetectionAuthorization:
    def test_collector_cannot_read_detections(self) -> None:
        bundle = _DetectionWireProxy()
        token = _issue_token(bundle.proxy, "user-collector-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_LIST,
            headers=_auth_headers(token),
            body={"rule_id": "NGINX-AUTH-FAILURE-001"},
        ))
        assert resp.status == 403


# ==================================================================== correlation


def _make_correlation(repo: CorrelationRepository) -> Any:
    from app.correlation.models import (
        Correlation, CorrelationKey,
    )

    correlation = Correlation(
        correlation_id=(
            "corr-01234567-0123-7000-8000-000000000001"
        ),
        pattern_id="BRUTE-FORCE-CLUSTERING",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("10.0.0.1",)),
        detection_ids=(
            "det-01234567-0123-7000-8000-000000000001",
        ),
        event_ids=(
            "01234567-0123-7000-8000-000000000001",
        ),
        window_start=datetime(
            2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc,
        ),
        window_end=datetime(
            2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc,
        ),
        count=3,
        reasoning="synthetic",
        correlated_at=datetime(
            2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc,
        ),
    )
    return repo.create(correlation)


class TestCorrelationWiring:
    def test_attach_correlation_service_validates_type(self) -> None:
        proxy = SecureProxy(config=_config(), identity_store=_identity_store())
        with pytest.raises(ValueError):
            proxy.attach_correlation_service(object())  # type: ignore[arg-type]
        proxy.attach_correlation_service(None)

    def test_correlation_list_filters_by_pattern_id(self) -> None:
        bundle = _DetectionWireProxy()
        _make_correlation(bundle.corr_repo)
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_LIST,
            headers=_auth_headers(token),
            body={"pattern_id": "BRUTE-FORCE-CLUSTERING"},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["correlations"]) == 1

    def test_correlation_get_returns_record(self) -> None:
        bundle = _DetectionWireProxy()
        c = _make_correlation(bundle.corr_repo)
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_GET,
            headers=_auth_headers(token),
            body={"correlation_id": c.correlation_id},
        ))
        assert resp.status == 200
        assert (
            resp.body["data"]["correlation"]["correlation_id"]
            == c.correlation_id
        )

    def test_correlation_get_returns_404_when_missing(self) -> None:
        bundle = _DetectionWireProxy()
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_GET,
            headers=_auth_headers(token),
            body={"correlation_id": (
                "corr-00000000-0000-7000-8000-000000000000"
            )},
        ))
        assert resp.status == 404


# ==================================================================== overview


class _OverviewWireProxy(_DetectionWireProxy):
    """Adds an OverviewReadService."""

    def __init__(self) -> None:
        super().__init__()
        from app.incidents import IncidentService

        # A no-op IncidentService that satisfies the type
        # check. We override the only methods the
        # OverviewReadService actually calls.
        class _NoopIncidents(IncidentService):
            def __init__(self):  # noqa: D401 - bypass strict init
                pass

            def list_cases(self, identity, state, limit):
                return []

            def get_case(self, identity, incident_id):
                from app.domain.errors import NotFoundError
                raise NotFoundError(
                    safe_message="not found",
                    internal_detail="overview stub",
                )

        ni = _NoopIncidents()
        overview = OverviewReadService(
            incident_service=ni,
            detection_service=self.det_service,
            correlation_service=self.corr_service,
        )
        self.proxy.attach_overview_service(overview)


class TestOverviewWiring:
    def test_overview_summary_returns_aggregate(self) -> None:
        bundle = _OverviewWireProxy()
        token = _issue_token(bundle.proxy, "user-analyst-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_OVERVIEW_SUMMARY,
            headers=_auth_headers(token),
            body={},
        ))
        assert resp.status == 200
        data = resp.body["data"]
        assert data["open_case_count"] == 0
        assert data["scope"] == "own"
        assert "produced_at" in data

    def test_overview_summary_admin_sees_all(self) -> None:
        bundle = _OverviewWireProxy()
        token = _issue_token(bundle.proxy, "user-admin-001")
        resp = bundle.proxy.handle(ProxyRequest(
            operation=OP_OVERVIEW_SUMMARY,
            headers=_auth_headers(token),
            body={},
        ))
        assert resp.status == 200
        assert resp.body["data"]["scope"] == "all"


# ==================================================================== timeline


def _build_timeline_proxy() -> SecureProxy:
    """A proxy wired with all the Phase 4.10 read services."""
    config = _config()
    proxy = SecureProxy(
        config=config, identity_store=_identity_store(),
    )
    det_service = DetectionReadService(
        DetectionRepository(FakeDatabase(), config),
    )
    corr_service = CorrelationReadService(
        CorrelationRepository(FakeDatabase(), config),
    )
    event_repo = SecurityEventRepository(FakeDatabase(), config)
    timeline_service = TimelineReadService(
        engine=TimelineEngine(),
        security_event_repository=event_repo,
        detection_service=det_service,
        correlation_service=corr_service,
    )
    proxy.attach_detection_service(det_service)
    proxy.attach_correlation_service(corr_service)
    proxy.attach_timeline_service(
        timeline_service,
        security_event_repository=event_repo,
    )
    return proxy


class TestTimelineWiring:
    def test_timeline_requires_incident_service(self) -> None:
        proxy = _build_timeline_proxy()
        token = _issue_token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_TIMELINE_BUILD_FOR_INCIDENT,
            headers=_auth_headers(token),
            body={"incident_id": (
                "case-00000000-0000-7000-8000-000000000001"
            )},
        ))
        assert resp.status == 400


# ==================================================================== rule management


def _build_rule_proxy() -> SecureProxy:
    config = _config()
    proxy = SecureProxy(
        config=config, identity_store=_identity_store(),
    )
    db = FakeDatabase()
    repo = RuleRepository(db, config)
    registry = RuleRegistry()
    service = RuleManagementService(repo, registry)
    proxy.attach_rule_management_service(service)
    return proxy


def _det_payload(
    *,
    rule_id: str = "CUSTOM-001",
    version: int = 1,
    state: str = "approved",
    enabled: bool = True,
    severity: str = "medium",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "version": version,
        "name": f"Rule {rule_id} v{version}",
        "description": "synthetic rule",
        "category": "source_specific",
        "type": "detection",
        "state": state,
        "enabled": enabled,
        "severity": severity,
        "sources": ["nginx"],
        "event_types": ["authentication_failure"],
        "tags": [],
        "references": [],
        "combinator": "and",
        "scope": [],
        "evidence_requirements": [],
        "thresholds": {},
        "window_seconds": None,
        "actions": ["alert"],
    }


class TestRuleWiring:
    def test_attach_rule_service_validates_type(self) -> None:
        proxy = SecureProxy(
            config=_config(), identity_store=_identity_store(),
        )
        with pytest.raises(ValueError):
            proxy.attach_rule_management_service(object())  # type: ignore[arg-type]
        proxy.attach_rule_management_service(None)

    def test_rule_create_then_list(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        assert resp.status == 200
        rule = resp.body["data"]["rule"]
        assert rule["rule_id"] == "CUSTOM-001"
        assert rule["version"] == 1

        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_LIST,
            headers=_auth_headers(admin),
            body={"latest_only": False},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["rules"]) == 1

    def test_rule_get_after_create(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_GET,
            headers=_auth_headers(admin),
            body={"rule_id": "CUSTOM-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["rule_id"] == "CUSTOM-001"

    def test_rule_get_returns_404_when_missing(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_GET,
            headers=_auth_headers(admin),
            body={"rule_id": "DOES-NOT-EXIST", "version": 1},
        ))
        assert resp.status == 404

    def test_rule_update_then_get(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_UPDATE,
            headers=_auth_headers(admin),
            body={
                "rule_id": "CUSTOM-001",
                "version": 1,
                "name": "Rule CUSTOM-001 v1",
                "description": "updated",
                "severity": "medium",
                "category": "source_specific",
                "type": "detection",
                "sources": ["nginx"],
                "event_types": ["authentication_failure"],
                "tags": [],
                "references": [],
                "combinator": "and",
                "scope": [],
                "evidence_requirements": [],
                "thresholds": {},
                "window_seconds": None,
                "actions": ["alert"],
            },
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["description"] == "updated"

    def test_rule_version_creates_new_version(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_VERSION,
            headers=_auth_headers(admin),
            body={
                "rule_id": "CUSTOM-001",
                "version": 2,
                "name": "Rule CUSTOM-001 v2",
                "description": "next version",
                "severity": "high",
                "category": "source_specific",
                "type": "detection",
                "sources": ["nginx"],
                "event_types": ["authentication_failure"],
                "tags": [],
                "references": [],
                "combinator": "and",
                "scope": [],
                "evidence_requirements": [],
                "thresholds": {},
                "window_seconds": None,
                "actions": ["alert"],
            },
        ))
        assert resp.status == 200
        rule = resp.body["data"]["rule"]
        assert rule["version"] == 2
        assert rule["description"] == "next version"

    def test_rule_disable_then_enable(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_DISABLE,
            headers=_auth_headers(admin),
            body={"rule_id": "CUSTOM-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["enabled"] is False

        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_ENABLE,
            headers=_auth_headers(admin),
            body={"rule_id": "CUSTOM-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["enabled"] is True

    def test_rule_retire(self) -> None:
        proxy = _build_rule_proxy()
        admin = _issue_token(proxy, "user-admin-001")
        proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(admin),
            body=_det_payload(),
        ))
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_RETIRE,
            headers=_auth_headers(admin),
            body={"rule_id": "CUSTOM-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["state"] == "retired"

    def test_analyst_cannot_create_rule(self) -> None:
        proxy = _build_rule_proxy()
        analyst = _issue_token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers=_auth_headers(analyst),
            body=_det_payload(),
        ))
        assert resp.status == 403

    def test_collector_cannot_list_rules(self) -> None:
        proxy = _build_rule_proxy()
        collector = _issue_token(proxy, "user-collector-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_LIST,
            headers=_auth_headers(collector),
            body={},
        ))
        assert resp.status == 403


# ==================================================================== report.export


def _build_report_proxy_with_export() -> SecureProxy:
    """A proxy wired with a ReportService so report.export works."""
    config = _config()
    db = FakeDatabase()
    report_repo = ReportRepository(db, config)
    report_service = ReportService(report_repo, incident_service=None)
    proxy = SecureProxy(
        config=config, identity_store=_identity_store(),
    )
    proxy.attach_report_service(report_service)
    return proxy


class TestReportExport:
    def test_report_export_returns_json_payload(self) -> None:
        proxy = _build_report_proxy_with_export()
        analyst = _issue_token(proxy, "user-analyst-001")
        report = Report(
            report_id="rpt-01234567-0123-7000-8000-000000000001",
            incident_id="case-01234567-0123-7000-8000-000000000001",
            mode="normal",
            version=1,
            title="test",
            sections=(ReportSection(title="what_was_detected",
                                   items=(ReportItem(kind="note",
                                                     text="x"),)),),
            generated_by="user-analyst-001",
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            evidence_references=(),
            rule_references=(),
            is_centralized=False,
            centralized_correlation_ids=(),
        )
        proxy._report_service._repository.create(report)

        resp = proxy.handle(ProxyRequest(
            operation=OP_REPORT_EXPORT,
            headers=_auth_headers(analyst),
            body={
                "report_id": report.report_id,
                "format": "json",
            },
        ))
        assert resp.status == 200
        data = resp.body["data"]
        assert data["format"] == "json"
        assert data["report_id"] == report.report_id
        assert data["payload"]["report_id"] == report.report_id

    def test_report_export_rejects_non_json_format(self) -> None:
        proxy = _build_report_proxy_with_export()
        analyst = _issue_token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_REPORT_EXPORT,
            headers=_auth_headers(analyst),
            body={
                "report_id": (
                    "rpt-00000000-0000-7000-8000-000000000000"
                ),
                "format": "pdf",
            },
        ))
        assert resp.status == 400

    def test_report_export_requires_report_id(self) -> None:
        proxy = _build_report_proxy_with_export()
        analyst = _issue_token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_REPORT_EXPORT,
            headers=_auth_headers(analyst),
            body={"format": "json"},
        ))
        assert resp.status == 400

    def test_report_export_requires_report_read_perm(self) -> None:
        proxy = _build_report_proxy_with_export()
        collector = _issue_token(proxy, "user-collector-001")
        resp = proxy.handle(ProxyRequest(
            operation=OP_REPORT_EXPORT,
            headers=_auth_headers(collector),
            body={
                "report_id": (
                    "rpt-00000000-0000-7000-8000-000000000000"
                ),
                "format": "json",
            },
        ))
        assert resp.status == 403


# ==================================================================== no-stub guards


class TestNo501StubsForPromotedOps:
    """Regression: ensure the 16 promoted ops no longer return 501.

    Without any service attached, the proxy should return a
    400 ``proxy not wired`` envelope (the documented
    boundary), not a 501 stub. This catches accidental
    regressions where a future change might re-introduce a
    ``_not_implemented_stub`` call.
    """

    PROMOTED_OPS = [
        OP_DETECTION_LIST, OP_DETECTION_GET,
        OP_DETECTION_LIST_FOR_INCIDENT,
        OP_CORRELATION_LIST, OP_CORRELATION_GET,
        OP_CORRELATION_LIST_FOR_INCIDENT,
        OP_OVERVIEW_SUMMARY,
        OP_TIMELINE_BUILD_FOR_INCIDENT,
        OP_RULE_LIST, OP_RULE_GET, OP_RULE_CREATE,
        OP_RULE_UPDATE, OP_RULE_VERSION,
        OP_RULE_ENABLE, OP_RULE_DISABLE, OP_RULE_RETIRE,
    ]

    @pytest.mark.parametrize("op", PROMOTED_OPS)
    def test_no_service_attached_does_not_return_501(self, op: str) -> None:
        proxy = SecureProxy(
            config=_config(), identity_store=_identity_store(),
        )
        token = _issue_token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation=op,
            headers=_auth_headers(token),
            body={},
        ))
        # Must NOT be a 501 ``not_implemented`` envelope.
        assert resp.status != 501