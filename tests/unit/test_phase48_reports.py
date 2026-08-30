"""Phase 4.8 report service unit tests (post-review remediation).

These tests cover the Report IDOR regression found in
the Phase 4.8 independent review. The slice-level
behaviour is exercised at the service layer; the
proxy-level behaviour is exercised in
``test_phase48_proxy.py``.

The IDOR was:

  * a report is bound to an incident (case).
  * ``ReportService.get_report`` previously only checked
    the ``report:read`` permission, so any analyst with
    the default ``report:read`` permission could fetch
    any other analyst's report by guessing the
    ``report_id``.
  * the fix reuses the canonical
    ``authorize_case_access(identity, case)`` boundary
    after the report-level permission check.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.auth import (
    ADMIN_ROLE, ANALYST_ROLE, COLLECTOR_ROLE, Identity,
)
from app.auth.permissions import Permission, has_permission
from app.incidents.errors import CaseAccessDeniedError
from app.incidents.models import (
    Incident, IncidentEvidence, IncidentLifecycleState,
)
from app.reports.errors import ReportAccessDeniedError
from app.reports.models import Report
from app.reports.repository import ReportRepository
from app.reports.service import ReportService


def _identity(subject_id, role, *, perms=()):
    return Identity(subject_id=subject_id, role=role, permissions=perms)


def _analyst(subject_id="user-analyst-001", *, perms=()):
    return _identity(subject_id, ANALYST_ROLE, perms=perms)


def _admin():
    return _identity("user-admin-001", ADMIN_ROLE)


def _collector():
    return _identity("user-collector-001", COLLECTOR_ROLE)


def _incident(*, created_by="user-analyst-001", incident_id="case-00000000-0000-7000-8000-000000000001"):
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=incident_id, title="t", summary="",
        state=IncidentLifecycleState.OPEN,
        evidence=IncidentEvidence(), rule_references=(),
        lifecycle_history=(), report_references=(),
        centralized_correlation_ids=(), centralized_reasoning="",
        centralized_failed=False, centralized_failure_reason="",
        created_by=created_by,
        created_at=now, updated_at=now,
    )


def _report(*, incident_id="case-00000000-0000-7000-8000-000000000001", report_id="rpt-00000000-0000-7000-8000-000000000001",
            generated_by="user-analyst-001"):
    now = datetime.now(timezone.utc)
    return Report(
        report_id=report_id, incident_id=incident_id,
        mode="normal", version=1, title="r",
        sections=(), generated_by=generated_by,
        generated_at=now, evidence_references=(),
        rule_references=(), is_centralized=False,
        centralized_correlation_ids=(),
    )


def _report_repo(report):
    from unittest.mock import create_autospec
    repo = create_autospec(ReportRepository, instance=True)
    repo.get_by_id_or_raise.return_value = report
    return repo


def _incident_service_for(case):
    """Minimal stand-in for ``IncidentService``.

    The real ``IncidentService`` has a complex
    constructor; the report service only ever calls
    ``get_case(identity, incident_id)`` on it. The
    stub mirrors the canonical ``authorize_case_access``
    boundary: owner / admin -> pass; everyone else ->
    ``CaseAccessDeniedError`` (404 in the proxy).
    """
    calls = []
    def get_case(identity, incident_id):
        calls.append((identity.subject_id, incident_id))
        perms = tuple(identity.permissions)
        see_any = has_permission(
            role=identity.role,
            identity_permissions=perms,
            permission=Permission.CASE_READ_ANY,
        )
        if not see_any and case.created_by != identity.subject_id:
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="wrong owner",
            )
        return case
    svc = SimpleNamespace(get_case=get_case, _calls=calls)
    return svc


class TestReportGetAuthorization:
    """Post-review tests for the Report IDOR fix."""

    def test_owner_can_retrieve_own_report(self):
        case = _incident(created_by="user-analyst-001")
        report = _report(
            incident_id=case.incident_id,
            generated_by="user-analyst-001",
        )
        repo = _report_repo(report)
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        out = svc.get_report(
            identity=_analyst("user-analyst-001"),
            report_id=report.report_id,
        )
        assert out.report_id == report.report_id
        assert inc._calls == [("user-analyst-001", case.incident_id)]

    def test_unrelated_analyst_denied_with_safe_404(self):
        case = _incident(created_by="user-analyst-001")
        report = _report(
            incident_id=case.incident_id,
            generated_by="user-analyst-001",
        )
        repo = _report_repo(report)
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        with pytest.raises(CaseAccessDeniedError):
            svc.get_report(
                identity=_analyst("user-analyst-002"),
                report_id=report.report_id,
            )

    def test_admin_with_read_any_can_retrieve_any_report(self):
        case = _incident(created_by="user-analyst-001")
        report = _report(
            incident_id=case.incident_id,
            generated_by="user-analyst-001",
        )
        repo = _report_repo(report)
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        out = svc.get_report(
            identity=_admin(),
            report_id=report.report_id,
        )
        assert out.report_id == report.report_id

    def test_collector_cannot_read_report(self):
        case = _incident(created_by="user-collector-001")
        report = _report(
            incident_id=case.incident_id,
            generated_by="user-collector-001",
        )
        repo = _report_repo(report)
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        with pytest.raises(ReportAccessDeniedError):
            svc.get_report(
                identity=_collector(),
                report_id=report.report_id,
            )


    def test_missing_case_is_hidden_as_case_denied(self):
        """If the case is gone but the report remains,
        the service MUST raise ``CaseAccessDeniedError``
        so the proxy maps it to 404. The case id must
        never be echoed back to the client.
        """
        case = _incident(created_by="ghost")
        report = _report(
            incident_id=case.incident_id,
            generated_by="user-analyst-001",
        )
        repo = _report_repo(report)

        def boom(identity, incident_id):
            raise CaseAccessDeniedError(
                safe_message="case access denied",
                internal_detail="deleted",
            )
        inc = SimpleNamespace(get_case=boom)
        svc = ReportService(repo, incident_service=inc)
        with pytest.raises(CaseAccessDeniedError):
            svc.get_report(
                identity=_admin(),
                report_id=report.report_id,
            )

    def test_report_lookup_failure_does_not_leak(self):
        """If the case lookup raises an unexpected error,
        the service MUST default-deny with
        ``CaseAccessDeniedError`` (404 in the proxy) and
        MUST NOT raise the raw exception.
        """
        case = _incident()
        report = _report(incident_id=case.incident_id)
        repo = _report_repo(report)

        def boom(identity, incident_id):
            raise RuntimeError("database on fire")
        inc = SimpleNamespace(get_case=boom)
        svc = ReportService(repo, incident_service=inc)
        with pytest.raises(CaseAccessDeniedError):
            svc.get_report(
                identity=_admin(),
                report_id=report.report_id,
            )


class TestReportListForIncidentAuthorization:
    """``list_for_incident`` already authorized via the
    case boundary before the fix; the post-fix tests
    confirm that behaviour is preserved."""

    def test_owner_can_list_reports_for_own_case(self):
        case = _incident(created_by="user-analyst-001")
        report = _report(incident_id=case.incident_id)
        repo = _report_repo(report)
        repo.find_for_incident.return_value = [report]
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        out = svc.list_for_incident(
            identity=_analyst("user-analyst-001"),
            case=case, limit=20,
        )
        assert len(out) == 1

    def test_other_analyst_cannot_list_reports_for_others_case(self):
        case = _incident(created_by="user-analyst-001")
        report = _report(incident_id=case.incident_id)
        repo = _report_repo(report)
        inc = _incident_service_for(case)
        svc = ReportService(repo, incident_service=inc)
        with pytest.raises(CaseAccessDeniedError):
            svc.list_for_incident(
                identity=_analyst("user-analyst-002"),
                case=case, limit=20,
            )


class TestReportServiceBackwardCompat:
    def test_get_report_without_incident_service_keeps_old_behaviour(self):
        """When no incident_service is injected, the report
        service still returns the report after the
        permission check. This is the documented
        backward-compatible behaviour for tests and call
        sites that do not need cross-boundary checks.
        """
        report = _report(
            incident_id="case-00000000-0000-7000-8000-000000000001",
            generated_by="user-analyst-001",
        )
        repo = _report_repo(report)
        svc = ReportService(repo)  # no incident_service
        out = svc.get_report(
            identity=_analyst("user-analyst-001"),
            report_id=report.report_id,
        )
        assert out.report_id == report.report_id
