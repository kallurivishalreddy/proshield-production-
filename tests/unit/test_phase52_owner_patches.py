"""Phase 5.2 owner reconciliation — regression tests (OWNER-52-01..04).

These pin the defects confirmed by the OWNER-led reconciliation of the two
independent Phase 5.2 audits against the CURRENT code:

* ``OWNER-52-01`` — ``case.create_from_correlation`` reused an existing
  (pipeline-owned) case without applying the case ownership model, so an
  analyst session received the complete body of a case it cannot read and
  merged evidence into it. Confirmed by both audits; the wire operation must
  now answer exactly like ``case.get``.
* ``OWNER-52-02`` — the collector role carried ``event:read`` with an
  "own submitted events" intent that no code path implements, which exposed
  every recently ingested event to a semi-trusted role. The grant is gone
  (minimum-permission is the documented direction).
* ``OWNER-52-03`` — ``system.health.deep`` had no permission gate at all, so
  any authenticated session (collector included) could read subsystem
  names/status/counts.
* ``OWNER-52-04`` — the two deployment planes bootstrap the SAME database.
  The repositories' check-then-``create_collection`` pattern is not atomic,
  so the loser of a fresh-database race aborted its plane with
  ``PersistenceError``. The bootstrap now tolerates a concurrent creator
  while still failing loudly for any real error.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest

from app.auth.identity import (
    ANALYST_ROLE,
    COLLECTOR_ROLE,
    INTERNAL_SERVICE_ROLE,
    Identity,
    InMemoryIdentityStore,
)
from app.auth.permissions import Permission, has_permission
from app.auth.session import new_development_signing_key
from app.config import ProShieldConfig
from app.correlation.models import Correlation, CorrelationKey
from app.correlation.service import CorrelationReadService
from app.detection.service import DetectionReadService
from app.incidents.repository import IncidentRepository
from app.incidents.service import IncidentService
from app.observability.health import DeepHealthService
from app.persistence.correlation_repository import CorrelationRepository
from app.persistence.detection_repository import DetectionRepository
from app.proxy import (
    OP_AUTH_ISSUE,
    OP_CASE_CREATE_FROM_CORRELATION,
    OP_GET_CASE,
    OP_SYSTEM_HEALTH_DEEP,
    PROXY_HEADER_AUTHORIZATION,
    ProxyRequest,
    SecureProxy,
)
from app.proxy.proxy import OP_EVENT_LIST
from tests.unit._phase47_fakes import FakeCursor, _apply_update_ops


# --------------------------------------------------------------------- fakes
class _FakeCollection:
    """Content-agnostic in-memory collection (mirrors the Phase 4.10 fake)."""

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
                continue
            if doc.get(k) != v:
                return False
        return True


class _FakeDatabase:
    def __init__(self) -> None:
        self.collections: Dict[str, _FakeCollection] = {}

    def __getitem__(self, name: str) -> _FakeCollection:
        if name not in self.collections:
            self.collections[name] = _FakeCollection()
        return self.collections[name]

    def list_collection_names(self) -> list:
        return list(self.collections.keys())

    def command(self, *a: Any, **k: Any) -> Any:
        return {"cursor": {"firstBatch": []}}

FIXED_NOW = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)
ANALYST = Identity(subject_id="user-analyst-001", role=ANALYST_ROLE)
COLLECTOR = Identity(subject_id="user-collector-001", role=COLLECTOR_ROLE)
PIPELINE = Identity(
    subject_id="pipeline",
    role=INTERNAL_SERVICE_ROLE,
    permissions=(Permission.CASE_READ, Permission.CASE_READ_ANY),
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


def _identity_store() -> InMemoryIdentityStore:
    return InMemoryIdentityStore(
        identities={
            "user-analyst-001": ANALYST,
            "user-collector-001": COLLECTOR,
        },
        credentials={
            "user-analyst-001": "analyst-password",
            "user-collector-001": "collector-password",
        },
    )


def _make_correlation() -> Correlation:
    return Correlation(
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


def _proxy_for(db, config):
    incident = IncidentService(repository=IncidentRepository(db, config))
    corr_repo = CorrelationRepository(db, config)
    proxy = SecureProxy(config=config, identity_store=_identity_store())
    proxy.attach_incident_service(incident)
    proxy.attach_correlation_service(
        CorrelationReadService(repository=corr_repo),
    )
    proxy.attach_detection_service(
        DetectionReadService(repository=DetectionRepository(db, config)),
    )
    return proxy, incident, corr_repo


def _issue_token(proxy: SecureProxy, subject: str, credential: str) -> str:
    resp = proxy.handle(ProxyRequest(
        operation=OP_AUTH_ISSUE, headers={},
        body={"subject_id": subject, "credential": credential},
    ))
    assert resp.status == 200, resp.body
    return resp.body["data"]["token"]


def _headers(token: str) -> Dict[str, str]:
    return {PROXY_HEADER_AUTHORIZATION: f"Bearer {token}"}


class TestCreateFromCorrelationOwnership:
    """OWNER-52-01 — the reuse path must honour the case ownership model."""

    def test_analyst_cannot_reuse_a_pipeline_owned_case(self) -> None:
        db, config = _FakeDatabase(), _config()
        proxy, incident, corr_repo = _proxy_for(db, config)
        corr = corr_repo.create(_make_correlation())

        # The live pipeline auto-cases the cluster as the SYSTEM actor.
        created = incident.create_case_for_correlation(
            identity=PIPELINE, correlation=corr, events=(), detections=(),
        )
        assert created.created_by == "pipeline"
        # Batch 1/2 T28: a newly opened case now composes its evidence from the
        # correlation row it was opened for, so the pipeline-owned case carries
        # the cluster's evidence catalogue even when the caller holds no model
        # objects (previously it was created empty and only a later call added
        # the members, which froze below-threshold-growth cases at 1 member).
        assert created.evidence.event_ids == tuple(corr.event_ids)
        assert created.evidence.detection_ids == tuple(corr.detection_ids)
        assert created.evidence.correlation_ids == (corr.correlation_id,)
        before = incident.repository.get_by_id(created.incident_id)

        token = _issue_token(proxy, "user-analyst-001", "analyst-password")
        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=_headers(token),
            body={"correlation_id": corr.correlation_id},
        ))

        # BEFORE the patch this returned 200 + the complete case body.
        assert resp.status == 404, resp.body
        assert resp.body["error"]["code"] == "case_not_found"
        assert "case" not in (resp.body.get("data") or {})

        # No unauthorized state persisted: no evidence merge, no touch.
        after = incident.repository.get_by_id(created.incident_id)
        assert after.evidence.event_ids == tuple(corr.event_ids)
        assert after.evidence.detection_ids == tuple(corr.detection_ids)
        assert after.updated_at == before.updated_at

        # The primary route agrees (same ownership-scoped answer).
        get = proxy.handle(ProxyRequest(
            operation=OP_GET_CASE, headers=_headers(token),
            body={"incident_id": created.incident_id},
        ))
        assert get.status == 404

    def test_owner_can_still_reuse_its_own_case(self) -> None:
        db, config = _FakeDatabase(), _config()
        proxy, _incident, corr_repo = _proxy_for(db, config)
        corr = corr_repo.create(_make_correlation())
        token = _issue_token(proxy, "user-analyst-001", "analyst-password")

        first = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=_headers(token),
            body={"correlation_id": corr.correlation_id},
        ))
        assert first.status == 200, first.body
        assert first.body["data"]["created"] is True
        case_id = first.body["data"]["case"]["incident_id"]

        second = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=_headers(token),
            body={"correlation_id": corr.correlation_id},
        ))
        assert second.status == 200, second.body
        # Batch 1/2 T28 note: the wire's ``created`` flag is the documented
        # timestamps heuristic ``created_at == updated_at``. While the create
        # path opened an *incomplete* case, the reuse call always had new
        # evidence to merge and therefore bumped ``updated_at`` (flag False).
        # Now that a case is opened complete, re-running the same correlation
        # is a true no-op: no duplicate case, no duplicate evidence and no
        # mutation — so both timestamps stay equal and the flag reads True.
        # The idempotency contract is asserted below (same case id, no growth).
        assert second.body["data"]["case"]["incident_id"] == case_id
        assert (
            second.body["data"]["case"]["evidence"]["detection_ids"]
            == first.body["data"]["case"]["evidence"]["detection_ids"]
        )

    def test_live_pipeline_identity_carries_the_cross_owner_grant(self) -> None:
        """The pipeline is the only internal caller of the reuse path."""
        from app.pipeline.service import LivePipeline

        pipe = LivePipeline(
            config=None, detection_pipeline=None, correlation_engine=None,
            correlation_repository=None, security_event_repository=None,
            incident_service=None,
        )
        ident = pipe.case_identity
        assert ident.subject_id == "pipeline"
        assert has_permission(
            role=ident.role, identity_permissions=ident.permissions,
            permission=Permission.CASE_READ_ANY,
        )

    def test_pipeline_still_accumulates_evidence_into_a_human_owned_case(
        self,
    ) -> None:
        """OWNER-52-01 must not regress the V2-02 evidence accumulation."""
        db, config = _FakeDatabase(), _config()
        proxy, incident, corr_repo = _proxy_for(db, config)
        corr = corr_repo.create(_make_correlation())
        token = _issue_token(proxy, "user-analyst-001", "analyst-password")

        resp = proxy.handle(ProxyRequest(
            operation=OP_CASE_CREATE_FROM_CORRELATION,
            headers=_headers(token),
            body={"correlation_id": corr.correlation_id},
        ))
        assert resp.status == 200, resp.body
        case_id = resp.body["data"]["case"]["incident_id"]

        merged = incident.create_case_for_correlation(
            identity=PIPELINE, correlation=corr, events=(), detections=(),
        )
        assert merged.incident_id == case_id
        assert set(merged.evidence.event_ids) == set(corr.event_ids)
        assert set(merged.evidence.detection_ids) == set(corr.detection_ids)


class TestCollectorReadSurface:
    """OWNER-52-02/03 — the semi-trusted collector role has no read surface."""

    def test_collector_role_has_no_analyst_plane_read_permission(self) -> None:
        for permission in (
            Permission.EVENT_READ,
            Permission.DETECTION_READ,
            Permission.CASE_READ,
            Permission.OVERVIEW_READ,
            Permission.RULE_READ,
            Permission.SOURCE_READ,
        ):
            assert not has_permission(
                role=COLLECTOR_ROLE, identity_permissions=(),
                permission=permission,
            ), permission

    def test_collector_cannot_list_events(self) -> None:
        db, config = _FakeDatabase(), _config()
        proxy, _incident, _corr = _proxy_for(db, config)
        token = _issue_token(proxy, "user-collector-001", "collector-password")
        resp = proxy.handle(ProxyRequest(
            operation=OP_EVENT_LIST, headers=_headers(token),
            body={"limit": 5},
        ))
        # BEFORE the patch: 200 with the recent events of every source.
        assert resp.status == 403, resp.body
        assert "events" not in (resp.body.get("data") or {})

    def test_collector_cannot_read_deep_health(self) -> None:
        db, config = _FakeDatabase(), _config()
        proxy, _incident, _corr = _proxy_for(db, config)
        proxy.attach_deep_health_service(
            DeepHealthService(db=None, config=None, backend_kind="memory"),
        )
        token = _issue_token(proxy, "user-collector-001", "collector-password")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SYSTEM_HEALTH_DEEP, headers=_headers(token), body={},
        ))
        # BEFORE the patch: 200 with every subsystem name/status/count.
        assert resp.status == 403, resp.body
        assert "health" not in (resp.body.get("data") or {})

    def test_analyst_can_still_read_deep_health(self) -> None:
        db, config = _FakeDatabase(), _config()
        proxy, _incident, _corr = _proxy_for(db, config)
        proxy.attach_deep_health_service(
            DeepHealthService(db=None, config=None, backend_kind="memory"),
        )
        token = _issue_token(proxy, "user-analyst-001", "analyst-password")
        resp = proxy.handle(ProxyRequest(
            operation=OP_SYSTEM_HEALTH_DEEP, headers=_headers(token), body={},
        ))
        assert resp.status == 200, resp.body
        assert resp.body["data"]["health"]["backend_kind"] == "memory"


class _RacingDatabase:
    """A database whose ``create_collection`` always loses a race once."""

    def __init__(self, *, appears: bool) -> None:
        self._appears = appears
        self.calls = 0
        self.names = []

    def list_collection_names(self) -> list:
        return list(self.names)

    def create_collection(self, name: str, **kwargs: Any) -> None:
        self.calls += 1
        if self._appears:
            # The other plane created it in the meantime.
            self.names.append(name)
        raise RuntimeError("namespace already exists (simulated)")


class TestBootstrapConcurrentCollectionCreate:
    """OWNER-52-04 — two planes must both bootstrap the same fresh DB."""

    def test_tolerates_a_concurrent_creator(self) -> None:
        from app.persistence.bootstrap import _ensure_collection

        db = _RacingDatabase(appears=True)
        created = _ensure_collection(db, "detections", {})
        assert created is False
        assert db.calls == 1  # it did try, and it tolerated the loss

    def test_still_fails_loudly_when_the_create_really_failed(self) -> None:
        from app.persistence.bootstrap import _ensure_collection

        db = _RacingDatabase(appears=False)
        with pytest.raises(RuntimeError):
            _ensure_collection(db, "detections", {})

    def test_backend_without_create_collection_is_a_noop(self) -> None:
        from app.persistence.bootstrap import _ensure_collection

        class _Lazy:
            def list_collection_names(self) -> list:
                return []

        assert _ensure_collection(_Lazy(), "detections", {}) is False

    def test_existing_collection_is_never_recreated(self) -> None:
        from app.persistence.bootstrap import _ensure_collection

        class _Existing:
            def list_collection_names(self) -> list:
                return ["detections"]

            def create_collection(self, name: str, **kwargs: Any) -> None:
                raise AssertionError("must not recreate an existing collection")

        assert _ensure_collection(_Existing(), "detections", {}) is False