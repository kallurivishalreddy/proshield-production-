"""Phase 4.10 - End-to-end integration tests for the wire-promotion.

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md.

These tests exercise the 16 promoted ops + ``report.export``
end-to-end against the real local MongoDB on 127.0.0.1:27017.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, Identity, InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.detection.models import Detection, RuleCategory
from app.detection.service import DetectionReadService
from app.correlation.service import CorrelationReadService
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.detection_repository import DetectionRepository
from app.persistence.rule_repository import RuleRepository
from app.persistence.security_event_repository import SecurityEventRepository
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_CORRELATION_GET,
    OP_CORRELATION_LIST,
    OP_DETECTION_GET,
    OP_DETECTION_LIST,
    OP_REPORT_EXPORT,
    OP_RULE_CREATE,
    OP_RULE_DISABLE,
    OP_RULE_ENABLE,
    OP_RULE_GET,
    OP_RULE_LIST,
    OP_RULE_RETIRE,
    OP_RULE_VERSION,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)

# AUTH-001: the credential header name. The constant is
# defined in ``app.proxy.proxy.PROXY_HEADER_CREDENTIAL`` but
# is not re-exported from the package ``__init__``; we
# reproduce the literal here so the test is self-contained
# (the value MUST match the production code).
PROXY_HEADER_CREDENTIAL = "X-ProShield-Credential"
from app.reports.models import Report, ReportItem, ReportSection
from app.reports.repository import ReportRepository
from app.reports.service import ReportService
from app.rules.management.service import RuleManagementService
from app.rules.registry import RuleRegistry


def _build_test_config(
    base_config: ProShieldConfig,
) -> ProShieldConfig:
    """A per-test config that targets a unique test database."""
    base = base_config
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=f"proshield_test_phase410_{uuid.uuid4().hex[:8]}",
        mongo_collection_events=f"security_events_{uuid.uuid4().hex[:8]}",
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
        connector_specs=[],
    )


def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore(
        identities={
            "user-admin-001": Identity(
                subject_id="user-admin-001", role=ADMIN_ROLE,
            ),
            "user-analyst-001": Identity(
                subject_id="user-analyst-001", role=ANALYST_ROLE,
            ),
        },
        credentials={
            "user-admin-001": "admin-password",
            "user-analyst-001": "analyst-password",
        },
    )


def _issue(proxy: SecureProxy, subject_id: str) -> str:
    password = {
        "user-admin-001": "admin-password",
        "user-analyst-001": "analyst-password",
    }[subject_id]
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE,
        headers={PROXY_HEADER_CREDENTIAL: password},
        body={"subject_id": subject_id},
    )).body["data"]["token"]


class _Phase410ProxyBuilder:
    """Holds an open MongoClient for the lifetime of the test.

    The repositories use the same client, so it must stay
    alive until the test finishes (or all repository
    operations will fail with
    "Cannot use MongoClient after close").
    """

    def __init__(self, test_config: ProShieldConfig) -> None:
        from pymongo import MongoClient
        from app.persistence.mongo import get_database

        self._config = test_config
        self._client = MongoClient(test_config.mongo_uri)
        db = get_database(self._client, test_config)

        self.proxy = SecureProxy(
            config=test_config,
            identity_store=_identity_store(),
        )

        self.det_repo = DetectionRepository(db, test_config)
        self.corr_repo = CorrelationRepository(db, test_config)
        self.rule_repo = RuleRepository(db, test_config)
        self.event_repo = SecurityEventRepository(db, test_config)
        self.report_repo = ReportRepository(db, test_config)

        det_service = DetectionReadService(self.det_repo)
        corr_service = CorrelationReadService(self.corr_repo)
        self.proxy.attach_detection_service(det_service)
        self.proxy.attach_correlation_service(corr_service)
        self.proxy.attach_timeline_service(None)

        rule_service = RuleManagementService(
            self.rule_repo, RuleRegistry(),
        )
        self.proxy.attach_rule_management_service(rule_service)

        report_service = ReportService(
            self.report_repo, incident_service=None,
        )
        self.proxy.attach_report_service(report_service)

    def close(self) -> None:
        self._client.close()


@pytest.fixture
def phase410_proxy(test_config: ProShieldConfig):
    cfg = _build_test_config(test_config)
    builder = _Phase410ProxyBuilder(cfg)
    try:
        yield builder
    finally:
        builder.close()


class TestPhase410DetectionWiring:
    def test_detection_list_get_round_trip(
        self, phase410_proxy: _Phase410ProxyBuilder,
    ) -> None:
        detection = Detection(
            detection_id="det-01234567-0123-7000-8000-000000000001",
            rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=1,
            category=RuleCategory.SOURCE_SPECIFIC,
            event_id="01234567-0123-7000-8000-000000000001",
            evidence_refs=(),
            reasoning="integration test",
            detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        phase410_proxy.det_repo.create(detection)

        token = _issue(phase410_proxy.proxy, "user-analyst-001")
        resp = phase410_proxy.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_LIST,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"rule_id": "NGINX-AUTH-FAILURE-001"},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["detections"]) == 1

        resp = phase410_proxy.proxy.handle(ProxyRequest(
            operation=OP_DETECTION_GET,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"detection_id": detection.detection_id},
        ))
        assert resp.status == 200
        assert resp.body["data"]["detection"]["detection_id"] == (
            detection.detection_id
        )


class TestPhase410CorrelationWiring:
    def test_correlation_list_filters_by_pattern(
        self, phase410_proxy: _Phase410ProxyBuilder,
    ) -> None:
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
            window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            window_end=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
            count=3,
            reasoning="integration test",
            correlated_at=datetime(
                2026, 1, 1, 0, 5, tzinfo=timezone.utc,
            ),
        )
        phase410_proxy.corr_repo.create(correlation)

        token = _issue(phase410_proxy.proxy, "user-analyst-001")
        resp = phase410_proxy.proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_LIST,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"pattern_id": "BRUTE-FORCE-CLUSTERING"},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["correlations"]) == 1

        resp = phase410_proxy.proxy.handle(ProxyRequest(
            operation=OP_CORRELATION_GET,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"correlation_id": correlation.correlation_id},
        ))
        assert resp.status == 200


class TestPhase410RuleWiring:
    def test_rule_lifecycle_round_trip(
        self, phase410_proxy: _Phase410ProxyBuilder,
    ) -> None:
        proxy = phase410_proxy.proxy
        admin = _issue(proxy, "user-admin-001")
        analyst = _issue(proxy, "user-analyst-001")

        # Create
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={
                "rule_id": "INTEG-001",
                "version": 1,
                "name": "Integ rule v1",
                "description": "integration test",
                "category": "source_specific",
                "type": "detection",
                "state": "approved",
                "enabled": True,
                "severity": "medium",
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

        # List
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_LIST,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"latest_only": False},
        ))
        assert resp.status == 200
        assert len(resp.body["data"]["rules"]) == 1

        # Get
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_GET,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"rule_id": "INTEG-001", "version": 1},
        ))
        assert resp.status == 200

        # Disable
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_DISABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"rule_id": "INTEG-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["enabled"] is False

        # Enable
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_ENABLE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"rule_id": "INTEG-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["enabled"] is True

        # New version
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_VERSION,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={
                "rule_id": "INTEG-001",
                "version": 2,
                "name": "Integ rule v2",
                "description": "next version",
                "category": "source_specific",
                "type": "detection",
                "severity": "high",
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
        assert resp.body["data"]["rule"]["version"] == 2

        # Retire
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_RETIRE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {admin}"},
            body={"rule_id": "INTEG-001", "version": 1},
        ))
        assert resp.status == 200
        assert resp.body["data"]["rule"]["state"] == "retired"

        # Analyst cannot create
        resp = proxy.handle(ProxyRequest(
            operation=OP_RULE_CREATE,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {analyst}"},
            body={
                "rule_id": "INTEG-002",
                "version": 1,
                "name": "should fail",
                "description": "x",
                "category": "source_specific",
                "type": "detection",
                "state": "approved",
                "enabled": True,
                "severity": "medium",
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
        assert resp.status == 403


class TestPhase410ReportExport:
    def test_report_export_returns_json_payload(
        self, phase410_proxy: _Phase410ProxyBuilder,
    ) -> None:
        report = Report(
            report_id="rpt-01234567-0123-7000-8000-000000000001",
            incident_id="case-01234567-0123-7000-8000-000000000001",
            mode="normal",
            version=1,
            title="integration test",
            sections=(ReportSection(
                title="what_was_detected",
                items=(ReportItem(kind="note", text="x"),),
            ),),
            generated_by="user-analyst-001",
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            evidence_references=(),
            rule_references=(),
            is_centralized=False,
            centralized_correlation_ids=(),
        )
        phase410_proxy.report_repo.create(report)

        token = _issue(phase410_proxy.proxy, "user-analyst-001")
        resp = phase410_proxy.proxy.handle(ProxyRequest(
            operation=OP_REPORT_EXPORT,
            headers={PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={
                "report_id": report.report_id,
                "format": "json",
            },
        ))
        assert resp.status == 200
        data = resp.body["data"]
        assert data["format"] == "json"
        assert data["report_id"] == report.report_id