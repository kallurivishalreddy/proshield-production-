"""Phase 4.8 incident / case unit tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.auth import ADMIN_ROLE, ANALYST_ROLE, Identity
from app.correlation import BruteForceClusteringPattern, CorrelationEngine
from app.detection.models import Detection
from app.domain.security_event import SecurityEvent
from app.incidents.errors import CaseAccessDeniedError, CaseNotFoundError
from app.incidents.models import Incident, IncidentEvidence, IncidentLifecycleState, LifecycleTransition
from app.incidents.service import IncidentService, authorize_case_access, _append_transition

def _ev(i=1):
    return SecurityEvent(event_id=f"{i:08x}-0000-7000-8000-000000000001", source="nginx", event_type="authentication_failure", event_time=datetime(2026, 1, 1, 12, 0, i, tzinfo=timezone.utc), ingested_at=datetime(2026, 1, 1, 12, 0, i, tzinfo=timezone.utc), source_ip="203.0.113.1", endpoint="/api/login", provenance={"collector": "nginx", "source_event_id": "x"})

def _d(i=1):
    return Detection(detection_id=f"det{i}", rule_id="NGINX-AUTH-FAILURE-001", rule_version=1, category="source_specific", event_id=f"{i:08x}-0000-7000-8000-000000000001", evidence_refs=(), reasoning="test", detected_at=datetime(2026, 1, 1, 12, 0, i, tzinfo=timezone.utc))

def _analyst():
    return Identity(subject_id="user-analyst-001", role=ANALYST_ROLE)

def _admin():
    return Identity(subject_id="user-admin-001", role=ADMIN_ROLE)

def _incident(created_by):
    now = datetime.now(timezone.utc)
    return Incident(incident_id="case-00000000-0000-7000-8000-000000000001", title="demo", summary="", state=IncidentLifecycleState.OPEN, evidence=IncidentEvidence(), rule_references=(), lifecycle_history=(), report_references=(), centralized_correlation_ids=(), centralized_reasoning="", centralized_failed=False, centralized_failure_reason="", created_by=created_by, created_at=now, updated_at=now)


class TestCaseAuthorization:
    def test_analyst_can_access_owned_case(self):
        authorize_case_access(_analyst(), _incident("user-analyst-001"))

    def test_analyst_cannot_access_other_case(self):
        with pytest.raises(CaseAccessDeniedError):
            authorize_case_access(_analyst(), _incident("other-user"))

    def test_admin_can_access_any_case(self):
        authorize_case_access(_admin(), _incident("any"))

    def test_collector_cannot_access_case(self):
        from app.auth import COLLECTOR_ROLE
        coll = Identity(subject_id="c", role=COLLECTOR_ROLE)
        with pytest.raises(CaseAccessDeniedError):
            authorize_case_access(coll, _incident("c"))

    def test_invalid_inputs_rejected(self):
        with pytest.raises(CaseAccessDeniedError):
            authorize_case_access("not-identity", _incident("x"))
        with pytest.raises(CaseAccessDeniedError):
            authorize_case_access(_analyst(), "not-an-incident")


class TestEvidenceIntegrity:
    def test_incident_does_not_copy_evidence(self):
        ev = IncidentEvidence(event_ids=("e1", "e2"), detection_ids=("d1",), correlation_ids=())
        d = ev.to_dict()
        d["event_ids"].append("e-evil")
        assert "e-evil" not in ev.event_ids

    def test_incident_is_frozen(self):
        inc = _incident("u1")
        with pytest.raises(Exception):
            inc.state = IncidentLifecycleState.CLOSED


class TestLifecycleHistory:
    def test_history_bounded(self):
        from app.incidents.models import MAX_CASE_LIFECYCLE_HISTORY
        assert MAX_CASE_LIFECYCLE_HISTORY >= 4

    def test_history_appends_in_order(self):
        now = datetime.now(timezone.utc)
        t1 = LifecycleTransition(from_state=None, to_state="open", actor_subject_id="u1", actor_role="analyst", reason="", transitioned_at=now)
        h = _append_transition((), t1)
        assert len(h) == 1
        t2 = LifecycleTransition(from_state="open", to_state="closed", actor_subject_id="u1", actor_role="analyst", reason="", transitioned_at=now)
        h2 = _append_transition(h, t2)
        assert len(h2) == 2
        assert h2[1].to_state == "closed"


class TestCentralizedCorrelationFailure:
    def test_unknown_case_returns_not_found(self):
        from app.incidents.repository import IncidentRepository
        from unittest.mock import create_autospec
        repo = create_autospec(IncidentRepository, instance=True)
        repo.get_by_id_or_raise.side_effect = CaseNotFoundError(safe_message="not found", internal_detail="")
        from app.incidents.service import IncidentService
        svc = IncidentService(repo)
        with pytest.raises(CaseNotFoundError):
            svc.request_centralized_analysis(identity=_analyst(), incident_id="x", detections=(), events=())


class TestCorrelationExtension:
    def test_run_centralized_dedupes_existing(self):
        from datetime import timedelta
        engine = CorrelationEngine(patterns=[BruteForceClusteringPattern(threshold=2, window=timedelta(seconds=300))])
        e1 = _ev(1)
        e2 = _ev(2)
        d1 = Detection(detection_id="det-00000000-0000-7000-8000-000000000001", rule_id="NGINX-AUTH-FAILURE-001", rule_version=1, category="source_specific", event_id=e1.event_id, evidence_refs=(), reasoning="a", detected_at=datetime.now(timezone.utc))

class TestListCasesUnfiltered:
    """Post-review tests for the unfiltered ``list_cases``
    fix. The repository's new ``find_recent`` and the
    service's ``if state else find_recent`` branch must:

      * return the caller's authorized cases when no
        ``state`` filter is supplied,
      * still honour explicit ``state`` filtering,
      * still apply the canonical ``case:read:any`` /
        ownership filter (no cross-tenant leakage).
    """

    def _repo_with(self, recent=(), by_state=None):
        from unittest.mock import create_autospec
        from app.incidents.repository import IncidentRepository
        repo = create_autospec(IncidentRepository, instance=True)
        repo.find_recent.return_value = list(recent)
        if by_state is None:
            by_state = {}
        repo.find_by_state.side_effect = (
            lambda state, *, limit: list(by_state.get(state, ()))
        )
        return repo

    def test_unfiltered_returns_caller_cases(self):
        mine = _incident("user-analyst-001")
        other = _incident("user-analyst-002")
        repo = self._repo_with(recent=[mine, other])
        svc = IncidentService(repo)
        out = svc.list_cases(identity=_analyst(), state=None, limit=10)
        assert out == [mine]

    def test_explicit_state_uses_find_by_state(self):
        mine = _incident("user-analyst-001")
        other = _incident("user-analyst-002")
        repo = self._repo_with(
            recent=[mine, other], by_state={"open": [mine, other]},
        )
        svc = IncidentService(repo)
        out = svc.list_cases(
            identity=_analyst(), state="open", limit=10,
        )
        assert out == [mine]
        repo.find_by_state.assert_called_once()
        repo.find_recent.assert_not_called()

    def test_admin_sees_all_when_unfiltered(self):
        mine = _incident("user-analyst-001")
        other = _incident("user-analyst-002")
        repo = self._repo_with(recent=[mine, other])
        svc = IncidentService(repo)
        out = svc.list_cases(identity=_admin(), state=None, limit=10)
        assert out == [mine, other]

    def test_empty_recent_returns_empty(self):
        repo = self._repo_with(recent=[])
        svc = IncidentService(repo)
        out = svc.list_cases(identity=_analyst(), state=None, limit=10)
        assert out == []

    def test_limit_is_passed_through(self):
        repo = self._repo_with(recent=[])
        svc = IncidentService(repo)
        svc.list_cases(identity=Identity(subject_id="user-analyst-001", role=ANALYST_ROLE), state=None, limit=7)
        repo.find_recent.assert_called_once_with(limit=7)

    def test_unfiltered_does_not_leak_other_analysts_cases(self):
        """A second analyst's case must NEVER appear in
        the unfiltered list of a different analyst. This
        is the property the remediation explicitly
        preserved.
        """
        other = _incident("user-analyst-002")
        repo = self._repo_with(recent=[other])
        svc = IncidentService(repo)
        out = svc.list_cases(
            identity=Identity(subject_id="user-analyst-001", role=ANALYST_ROLE),
            state=None, limit=10,
        )
        assert out == []


class TestCorrelationExtension:
    def test_run_centralized_dedupes_existing(self):
        from datetime import timedelta
        engine = CorrelationEngine(patterns=[BruteForceClusteringPattern(threshold=2, window=timedelta(seconds=300))])
        e1 = _ev(1)
        e2 = _ev(2)
        d1 = Detection(detection_id="det-00000000-0000-7000-8000-000000000001", rule_id="NGINX-AUTH-FAILURE-001", rule_version=1, category="source_specific", event_id=e1.event_id, evidence_refs=(), reasoning="a", detected_at=datetime.now(timezone.utc))
        d2 = Detection(detection_id="det-00000000-0000-7000-8000-000000000002", rule_id="NGINX-AUTH-BRUTEFORCE-001", rule_version=1, category="source_specific", event_id=e2.event_id, evidence_refs=(), reasoning="b", detected_at=datetime.now(timezone.utc))
        events_by_id = {e1.event_id: e1, e2.event_id: e2}
        base = engine.run(detections=[d1, d2], events=events_by_id)
        c_existing = base.correlations[0]
        result = engine.run_centralized(detections=[d1, d2], events=events_by_id, existing_correlation_ids=(c_existing.correlation_id,))
        assert len(result.new_correlations) == 0
        assert len(result.correlations) == 1
        assert result.correlations[0].correlation_id == c_existing.correlation_id


class TestIncidentModelValidation:
    def test_incident_id_pattern_rejects_bad_format(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(Exception):
            Incident(incident_id="wrong-format", title="t", summary="", state=IncidentLifecycleState.OPEN, evidence=IncidentEvidence(), rule_references=(), lifecycle_history=(), report_references=(), centralized_correlation_ids=(), centralized_reasoning="", centralized_failed=False, centralized_failure_reason="", created_by="u1", created_at=now, updated_at=now)

    def test_extra_fields_rejected(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(Exception):
            Incident(incident_id="case-00000000-0000-7000-8000-000000000001", title="t", summary="", state=IncidentLifecycleState.OPEN, evidence=IncidentEvidence(), rule_references=(), lifecycle_history=(), report_references=(), centralized_correlation_ids=(), centralized_reasoning="", centralized_failed=False, centralized_failure_reason="", created_by="u1", created_at=now, updated_at=now, evil="field")


class TestIncidentRepositoryIndexes:
    def test_index_specs_documented(self):
        from app.incidents.repository import INDEX_SPECS
        names = {ix["name"] for ix in INDEX_SPECS}
        assert "inc_incident_id_unique" in names
        assert "inc_state" in names
        assert "inc_created_by" in names
