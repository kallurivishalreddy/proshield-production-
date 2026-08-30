"""Phase 4.8 proxy unit tests."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from datetime import datetime, timezone

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, Identity, InMemoryIdentityStore,
)
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.proxy import (
    MAX_PROXY_REQUEST_BYTES, OP_AUTH_ISSUE, OP_GET_CASE, OP_HEALTH,
    OP_LIST_CASES, OP_REQUEST_CENTRALIZED, OP_ROUTE_CASE,
    OP_GENERATE_NORMAL_REPORT, PROXY_HEADER_AUTHORIZATION,
    ProxyRequest, SecureProxy,
)


def _config(rate=10000, centralized=10):
    return ProShieldConfig(
        env_name="test", mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        auth_signing_key=new_development_signing_key(),
        auth_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=rate,
        proxy_max_request_bytes=MAX_PROXY_REQUEST_BYTES,
        proxy_max_response_bytes=1_048_576,
        proxy_centralized_rate_limit_per_minute=centralized,
        ingest_max_body_bytes=16_384,
        ingest_max_details_bytes=8_192,
        ingest_rate_limit_per_minute=600,
    )


def _identity_store():
    return InMemoryIdentityStore({
        "user-analyst-001": Identity(
            subject_id="user-analyst-001", role=ANALYST_ROLE,
        ),
        "user-admin-001": Identity(
            subject_id="user-admin-001", role=ADMIN_ROLE,
        ),
    })


def _proxy(config=None):
    return SecureProxy(
        config=config or _config(),
        identity_store=_identity_store(),
    )


def _token(proxy, subject_id):
    return proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject_id},
    )).body["data"]["token"]


class TestHealth:
    def test_health_is_open(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_HEALTH, headers={}, body=None,
        ))
        assert resp.status == 200
        assert resp.body["ok"] is True


class TestRequestValidation:
    def test_missing_operation_rejected(self):
        proxy = _proxy()
        bad = replace(
            ProxyRequest(operation=OP_HEALTH, headers={}, body=None),
            operation="",
        )
        resp = proxy.handle(bad)
        assert resp.status == 400

    def test_unknown_operation_rejected(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation="bogus.op", headers={}, body=None,
        ))
        assert resp.status == 400

    def test_oversize_body_rejected(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_HEALTH, headers={},
            body={"x": "y"}, body_bytes=10_000_000,
        ))
        assert resp.status == 400


class TestAuthentication:
    def test_missing_token_is_unauthorized(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE, headers={},
            body={"incident_id": "x"},
        ))
        assert resp.status == 401

    def test_malformed_token_is_unauthorized(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE,
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer junk"},
            body={"incident_id": "x"},
        ))
        assert resp.status == 401


class TestAuthIssue:
    def test_issue_token_for_known_subject(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "user-analyst-001"},
        ))
        assert resp.status == 200

    def test_issue_token_for_unknown_subject_rejected(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={},
            body={"subject_id": "ghost"},
        ))
        assert resp.status == 401

    def test_issue_token_requires_subject_id(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={}, body={},
        ))
        assert resp.status == 400


class TestSafeErrorEnvelope:
    def test_internal_detail_not_leaked(self):
        proxy = _proxy()
        resp = proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE, headers={}, body={},
        ))
        assert "internal_detail" not in resp.body["error"]
class TestRateLimit:
    def test_general_rate_limit_triggers_429(self):
        proxy = _proxy(_config(rate=3))
        tok = _token(proxy, "user-analyst-001")
        statuses = []
        for _ in range(4):
            r = proxy.handle(ProxyRequest(operation=OP_LIST_CASES, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={}))
            statuses.append(r.status)
        assert 429 in statuses

    def test_centralized_rate_limit_triggers_429(self):
        proxy = _proxy(_config(rate=10000, centralized=2))
        tok = _token(proxy, "user-admin-001")
        statuses = []
        for _ in range(3):
            r = proxy.handle(ProxyRequest(operation=OP_REQUEST_CENTRALIZED, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "x"}))
            statuses.append(r.status)
        assert 429 in statuses

    def test_general_rate_limit_is_per_subject(self):
        proxy = _proxy(_config(rate=2))
        tok_a = _token(proxy, "user-analyst-001")
        for _ in range(2):
            proxy.handle(ProxyRequest(operation=OP_LIST_CASES, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok_a}, body={}))
        r = proxy.handle(ProxyRequest(operation=OP_LIST_CASES, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok_a}, body={}))
        assert r.status == 429
        tok_b = _token(proxy, "user-admin-001")
        r = proxy.handle(ProxyRequest(operation=OP_LIST_CASES, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok_b}, body={}))
        assert r.status != 429

class TestAuthorizationRules:
    def test_collector_cannot_get_case(self):
        proxy = _proxy()
        store = proxy.identity_store
        store._identities["user-coll-001"] = Identity(subject_id="user-coll-001", role="collector")
        tok = _token(proxy, "user-coll-001")
        resp = proxy.handle(ProxyRequest(operation=OP_GET_CASE, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "x"}))
        assert resp.status == 403

    def test_collector_cannot_request_centralized(self):
        proxy = _proxy()
        store = proxy.identity_store
        store._identities["user-coll-001"] = Identity(subject_id="user-coll-001", role="collector")
        tok = _token(proxy, "user-coll-001")
        resp = proxy.handle(ProxyRequest(operation=OP_REQUEST_CENTRALIZED, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "x"}))
        assert resp.status == 403

class TestReportIdorThroughProxy:
    """Post-review proxy-level tests for the Report IDOR
    fix. These tests wire the proxy with a stub incident
    service and a stub report service that record the
    canonical ``authorize_case_access`` boundary, then
    verify that ``OP_GET_REPORT`` does not bypass it.
    """

    def _proxy_with_stubs(self):
        from app.incidents.errors import CaseAccessDeniedError
        from app.incidents.service import IncidentService
        from app.auth.permissions import (
            Permission, has_permission,
        )
        from app.reports.models import Report
        from app.reports.repository import ReportRepository
        from app.reports.service import ReportService
        from datetime import datetime, timezone
        report = Report(
            report_id="rpt-00000000-0000-7000-8000-000000000001",
            incident_id="case-00000000-0000-7000-8000-000000000001",
            mode="normal", version=1, title="r",
            sections=(), generated_by="user-analyst-001",
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            evidence_references=(), rule_references=(),
            is_centralized=False,
            centralized_correlation_ids=(),
        )
        from app.incidents.models import (
            Incident, IncidentEvidence, IncidentLifecycleState,
        )
        case = Incident(
            incident_id="case-00000000-0000-7000-8000-000000000001",
            title="t", summary="",
            state=IncidentLifecycleState.OPEN,
            evidence=IncidentEvidence(), rule_references=(),
            lifecycle_history=(), report_references=(),
            centralized_correlation_ids=(), centralized_reasoning="",
            centralized_failed=False, centralized_failure_reason="",
            created_by="user-analyst-001",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        class _FakeIncSvc(IncidentService):
            def __init__(self, _case):
                self._case = _case
                self.calls = []
            def get_case(self, identity, incident_id):
                self.calls.append((identity.subject_id, incident_id))
                perms = tuple(identity.permissions)
                see_any = has_permission(
                    role=identity.role,
                    identity_permissions=perms,
                    permission=Permission.CASE_READ_ANY,
                )
                if not see_any and self._case.created_by != identity.subject_id:
                    raise CaseAccessDeniedError(
                        safe_message="case access denied",
                        internal_detail="wrong owner",
                    )
                return self._case
        incident_service = _FakeIncSvc(case)

        class _Repo(ReportRepository):
            def __init__(self, _report):
                self._report = _report
            def get_by_id_or_raise(self, _rid):
                return self._report
        report_service = ReportService(
            _Repo(report), incident_service=incident_service,
        )
        proxy = _proxy()
        proxy.attach_incident_service(incident_service)
        proxy.attach_report_service(report_service)
        return proxy

    def test_op_get_report_owner_succeeds(self):
        proxy = self._proxy_with_stubs()
        tok = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation="report.get",
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer " + tok},
            body={"report_id": "rpt-00000000-0000-7000-8000-000000000001"},
        ))
        assert resp.status == 200
        assert resp.body["data"]["report"]["report_id"] == "rpt-00000000-0000-7000-8000-000000000001"

    def test_op_get_report_admin_succeeds(self):
        proxy = self._proxy_with_stubs()
        tok = _token(proxy, "user-admin-001")
        resp = proxy.handle(ProxyRequest(
            operation="report.get",
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer " + tok},
            body={"report_id": "rpt-00000000-0000-7000-8000-000000000001"},
        ))
        assert resp.status == 200

    def test_op_get_report_other_analyst_denied_404(self):
        from app.auth import ANALYST_ROLE
        proxy = self._proxy_with_stubs()
        proxy.identity_store._identities["user-analyst-002"] = Identity(
            subject_id="user-analyst-002", role=ANALYST_ROLE,
        )
        tok = _token(proxy, "user-analyst-002")
        resp = proxy.handle(ProxyRequest(
            operation="report.get",
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer " + tok},
            body={"report_id": "rpt-00000000-0000-7000-8000-000000000001"},
        ))
        assert resp.status == 404
        assert resp.body.get("data") is None or (
            "report" not in (resp.body.get("data") or {})
        )


class TestUnfilteredListCases:
    """Post-review proxy-level test for the
    unfiltered-``case.list`` fix. The proxy MUST
    forward the request to the service; the service
    MUST return the caller's authorized cases.
    """

    def _proxy_with_incident_service(self, recent=()):
        from app.incidents.repository import IncidentRepository
        from app.incidents.service import IncidentService
        from app.incidents.models import (
            Incident, IncidentEvidence, IncidentLifecycleState,
        )
        from unittest.mock import create_autospec
        from datetime import datetime, timezone
        repo = create_autospec(IncidentRepository, instance=True)
        repo.find_by_state = lambda state, *, limit: []
        def _wrap(plain):
            return Incident(
                incident_id=plain.incident_id,
                title="t", summary="",
                state=IncidentLifecycleState.OPEN,
                evidence=IncidentEvidence(), rule_references=(),
                lifecycle_history=(), report_references=(),
                centralized_correlation_ids=(), centralized_reasoning="",
                centralized_failed=False, centralized_failure_reason="",
                created_by=plain.created_by,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        repo.find_recent = lambda *, limit: [_wrap(p) for p in recent]
        svc = IncidentService(repo)
        proxy = _proxy()
        proxy.attach_incident_service(svc)
        return proxy

    def test_op_list_cases_unfiltered_returns_caller_cases(self):
        from types import SimpleNamespace
        from app.incidents.models import (
            Incident, IncidentEvidence, IncidentLifecycleState,
        )
        case = Incident(
            incident_id="case-00000000-0000-7000-8000-000000000001",
            title="t", summary="",
            state=IncidentLifecycleState.OPEN,
            evidence=IncidentEvidence(), rule_references=(),
            lifecycle_history=(), report_references=(),
            centralized_correlation_ids=(), centralized_reasoning="",
            centralized_failed=False, centralized_failure_reason="",
            created_by="user-analyst-001",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        proxy = self._proxy_with_incident_service(recent=[case])
        tok = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation="case.list",
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer " + tok},
            body={},
        ))
        assert resp.status == 200
        cases = resp.body["data"]["cases"]
        assert len(cases) == 1
        assert cases[0]["incident_id"] == "case-00000000-0000-7000-8000-000000000001"

    def test_op_list_cases_unfiltered_does_not_leak_other_cases(self):
        from types import SimpleNamespace
        other = SimpleNamespace(
            incident_id="case-00000000-0000-7000-8000-000000000002", created_by="user-analyst-002",
        )
        proxy = self._proxy_with_incident_service(recent=[other])
        tok = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(
            operation="case.list",
            headers={PROXY_HEADER_AUTHORIZATION: "Bearer " + tok},
            body={},
        ))
        assert resp.status == 200
        assert resp.body["data"]["cases"] == []


class TestInternalServicesHidden:
    def test_internal_service_cannot_generate_reports(self):
        proxy = _proxy()
        store = proxy.identity_store
        store._identities["svc-001"] = Identity(subject_id="svc-001", role="internal_service")
        tok = _token(proxy, "svc-001")
        resp = proxy.handle(ProxyRequest(operation=OP_GENERATE_NORMAL_REPORT, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "x"}))
        assert resp.status == 403

    def test_internal_service_cannot_route_case(self):
        proxy = _proxy()
        store = proxy.identity_store
        store._identities["svc-001"] = Identity(subject_id="svc-001", role="internal_service")
        tok = _token(proxy, "svc-001")
        resp = proxy.handle(ProxyRequest(operation=OP_ROUTE_CASE, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "x"}))
        assert resp.status in (400, 403)


class TestSecretNonDisclosure:
    def test_signing_key_never_appears_in_response(self):
        proxy = _proxy()
        tok = _token(proxy, "user-analyst-001")
        for op, body in [(OP_GET_CASE, {"incident_id": "x"}), (OP_LIST_CASES, {}), (OP_HEALTH, None), (OP_AUTH_ISSUE, {"subject_id": "user-analyst-001"})]:
            r = proxy.handle(ProxyRequest(operation=op, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body=body))
            assert proxy.config.auth_signing_key not in str(r.body)

class TestProxyFailSafe:
    def test_proxy_never_returns_internals(self):
        proxy = _proxy()
        tok = _token(proxy, "user-analyst-001")
        resp = proxy.handle(ProxyRequest(operation=OP_GET_CASE, headers={PROXY_HEADER_AUTHORIZATION: chr(66) + chr(101) + chr(97) + chr(114) + chr(101) + chr(114) + chr(32) + tok}, body={"incident_id": "case-x"}))
        assert resp.status in (400, 500)
        body_str = str(resp.body).lower()
        assert "traceback" not in body_str
        assert "internal_detail" not in body_str

class TestOperationCatalogue:
    def test_all_documented_operations_in_catalogue(self):
        from app.proxy import ALLOWED_OPERATIONS
        for op in (OP_HEALTH, OP_AUTH_ISSUE, OP_GET_CASE, OP_LIST_CASES, OP_REQUEST_CENTRALIZED, OP_ROUTE_CASE, OP_GENERATE_NORMAL_REPORT):
            assert op in ALLOWED_OPERATIONS