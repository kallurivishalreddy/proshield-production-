"""Targeted regression tests for the STRIX F-1 / F-2 / F-5 / F-7 fixes.

These tests run against real (in-memory) repository classes using the same
``FakeDatabase`` the ``scripts/proxy_server.py`` memory backend uses, so they
exercise the actual production composition without requiring MongoDB.

Coverage
--------
* F-1: an accepted matching event produces a persisted detection through
  ``LivePipeline.process`` with **no manual engine composition**.
* F-2: a brute-force correlation opens exactly one case, and a re-run never
  opens a duplicate case (idempotent on the correlation cluster key).
* F-5: unsorted/duplicate source tags are normalised server-side (200);
  the pydantic error is never mislabelled 401.
* F-7: an unexpected internal exception is mapped to 500 ``internal_error``,
  not 401 ``authentication_required``.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

from app.auth import ADMIN_ROLE, Identity
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7
from app.incidents.repository import IncidentRepository
from app.incidents.service import IncidentService
from app.pipeline import build_live_pipeline
from scripts import proxy_server


def _build_bundle():
    args = argparse.Namespace(backend="memory", seed_credentials=True)
    return proxy_server._build_memory_backend(
        proxy_server._build_config(args)
    )


def _auth_failure_event(i: int, event_time: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=str(uuid7(timestamp_ms=int(event_time.timestamp() * 1000))),
        event_time=event_time,
        ingested_at=event_time,
        source="nginx",
        event_type="authentication_failure",
        source_ip="10.0.0.66",
        destination="auth.example.internal",
        endpoint="/auth/login",
        asset="auth-svc-01",
        details={"status_code": 401, "method": "POST", "account_id": f"u{i}"},
        provenance=SecurityEventProvenance(
            collector="test",
            source_event_id=f"bf-{i}",
        ),
    )


class TestF1LiveDetection:
    def test_matching_event_produces_detection(self) -> None:
        bundle = _build_bundle()
        db = proxy_server.FakeDatabase()
        incident_service = IncidentService(
            repository=IncidentRepository(db=db, config=bundle.config),
        )
        pipe = build_live_pipeline(
            config=bundle.config,
            db=db,
            rule_registry=bundle.rule_registry,
            incident_service=incident_service,
        )
        now = datetime.now(timezone.utc)
        event = _auth_failure_event(1, now)

        outcome = pipe.process(event, now=now)

        assert outcome.event_id == event.event_id
        # The NGINX brute-force + failure rules both fire on a 401.
        assert len(outcome.detections) >= 1
        # detections are persisted to the shared store
        persisted = pipe._pipeline.detection_repository.get_by_detection_id(
            outcome.detections[0].detection_id,
        )
        assert persisted is not None
        assert persisted.rule_id.startswith("NGINX-AUTH")

    def test_benign_event_produces_no_detection(self) -> None:
        bundle = _build_bundle()
        db = proxy_server.FakeDatabase()
        pipe = build_live_pipeline(
            config=bundle.config,
            db=db,
            rule_registry=bundle.rule_registry,
            incident_service=IncidentService(
                repository=IncidentRepository(db=db, config=bundle.config),
            ),
        )
        now = datetime.now(timezone.utc)
        event = SecurityEvent(
            event_id=str(uuid7()),
            event_time=now,
            ingested_at=now,
            source="nginx",
            event_type="authentication_success",
            source_ip="10.0.0.10",
            endpoint="/auth/login",
            details={"status_code": 200},
            provenance=SecurityEventProvenance(
                collector="test", source_event_id="ok-1",
            ),
        )
        outcome = pipe.process(event, now=now)
        assert outcome.detections == ()


class TestF2CorrelationOpensIdempotentCase:
    def test_brute_force_opens_one_case(self) -> None:
        bundle = _build_bundle()
        db = proxy_server.FakeDatabase()
        incident_service = IncidentService(
            repository=IncidentRepository(db=db, config=bundle.config),
        )
        pipe = build_live_pipeline(
            config=bundle.config,
            db=db,
            rule_registry=bundle.rule_registry,
            incident_service=incident_service,
        )
        now = datetime.now(timezone.utc)
        case_id_by_evo = {}

        # Feed a sustained brute force (well above the correlation
        # threshold of 4 distinct events within the window).
        for i in range(8):
            ev = _auth_failure_event(i, now)
            outcome = pipe.process(ev, now=now)
            if outcome.case is not None:
                case_id_by_evo.setdefault(i, outcome.case.incident_id)

        # A case must have been opened by the correlation.
        assert case_id_by_evo, "no case was opened for the brute-force burst"

        # Re-run the entire burst -> no duplicate case (idempotent).
        before = incident_service.repository.get_by_id(
            next(iter(case_id_by_evo.values())),
        )
        assert before is not None
        for i in range(8):
            ev = _auth_failure_event(i, now)
            pipe.process(ev, now=now)

        all_ids = set()
        # The chain only ever references the same single case id.
        for i in range(8):
            ev = _auth_failure_event(i, now)
            outcome = pipe.process(ev, now=now)
            if outcome.case is not None:
                all_ids.add(outcome.case.incident_id)

        # No new distinct case id beyond what the simulation produced.
        assert len(set(case_id_by_evo.values()) | all_ids) == 1


class TestF5SourceTagsNormalised:
    def test_register_unsorted_and_duplicate_tags_is_200_not_401(self) -> None:
        bundle = _build_bundle()
        admin = bundle.identity_store.get("admin")
        assert admin is not None
        # Drive through the proxy boundary exactly as the frontend does.
        req = proxy_server.ProxyRequest(
            operation="source.register",
            headers={"X-ProShield-Session": _issue_session(bundle)},
            body={
                "source_type": "nginx",
                "display_name": "unsorted-tags-src",
                "tags": ["PROD", "PROD"],  # duplicate
                "asset_tags": ["web", "api"],  # unsorted
            },
            body_bytes=200,
        )
        resp = bundle.proxy.handle(req)
        # Normalised server-side -> success, and definitely not 401.
        assert resp.status == 200
        view = resp.body["data"]["source"]
        assert view["tags"] == ["PROD"]
        assert view["asset_tags"] == ["api", "web"]


class TestF7UnexpectedErrorIs500:
    def test_unexpected_exception_is_not_shaped_401(self) -> None:
        bundle = _build_bundle()
        # Stub an operation that raises an unexpected exception.
        original = bundle.proxy._handle_overview_summary

        def _boom(request, identity):  # pragma: no cover - stubbed path
            raise RuntimeError("boom")

        bundle.proxy._handle_overview_summary = _boom
        req = proxy_server.ProxyRequest(
            operation="overview.summary",
            headers={"X-ProShield-Session": _issue_session(bundle)},
            body={},
            body_bytes=2,
        )
        resp = bundle.proxy.handle(req)
        bundle.proxy._handle_overview_summary = original
        # Internal failure surfaces as 500 internal_error, never 401.
        assert resp.status == 500
        assert resp.body["error"]["code"] == "internal_error"


def _issue_session(bundle: proxy_server._BackendBundle) -> str:
    admin = bundle.identity_store.all_subject_ids()
    # Use the seeded dev credential catalog like the proxy does.
    identity = bundle.identity_store.get("admin")
    assert identity is not None
    auth_resp = bundle.proxy.handle(proxy_server.ProxyRequest(
        operation="auth.issue",
        headers={},
        body={
            "subject_id": "admin",
            "credential": bundle.identity_store._credentials.get("admin"),
        },
        body_bytes=120,
    ))
    return auth_resp.body["data"]["token"]
