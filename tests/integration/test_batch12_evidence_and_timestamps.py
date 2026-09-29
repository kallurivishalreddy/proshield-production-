"""Batch 1 & 2 regression coverage (T22, T28) over the REAL composition.

Reference: docs/PHASE 5/MANUAL TESTS/BATCH 1,2 PATCH REPORT.md

Both deployment planes are the shipped ones (the same bundles
``scripts/*_server.py`` build) against a dedicated MongoDB database:

* ``TestT28CaseEvidence`` — the correlation → case evidence composition.
  A cluster that *exactly* meets the brute-force threshold must open a case
  holding the cluster's complete evidence (the fix), and two clusters active
  in the same correlation window must never exchange evidence (the
  contamination the same defect caused).
* ``TestT22EventTimeContract`` — the canonical ``event_time`` contract at the
  trusted ingress boundary: valid instants (any offset) are accepted and
  normalised to UTC; a malformed/impossible/non-timestamp/impossible value is
  rejected per event with the documented ``validation_error`` reason; a
  future-dated value is rejected by the ordering guard.

Requires a running MongoDB on 127.0.0.1:27017.
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TEST_DB = "proshield_test_batch12"
RUN_ID = uuid.uuid4().hex[:8]


def _config():
    from app.config import ProShieldConfig

    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level="WARNING",
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB,
        auth_signing_key="batch12-auth-key-0001",
        source_signing_key="batch12-source-key-0001",
        source_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=base.proxy_rate_limit_per_minute,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=base
        .proxy_centralized_rate_limit_per_minute,
        ingress_rate_limit_per_minute=base.ingress_rate_limit_per_minute,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_replay_store_required=True,
        ingress_replay_collection="source_token_replay_batch12",
        default_subject_credentials={
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
        },
    )


@pytest.fixture(scope="module")
def config():
    return _config()


@pytest.fixture(scope="module")
def batch12_mongo(config):
    client = MongoClient(config.mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    client.drop_database(TEST_DB)
    yield client
    try:
        client.drop_database(TEST_DB)
    except Exception:  # noqa: BLE001
        pass
    client.close()


@pytest.fixture(scope="module")
def proxy_bundle(config, batch12_mongo):
    from scripts import proxy_server

    return proxy_server._build_mongo_backend(config)


@pytest.fixture(scope="module")
def proxy_client(proxy_bundle):
    from fastapi.testclient import TestClient  # type: ignore
    from scripts import proxy_server

    return TestClient(proxy_server._build_app(proxy_bundle))


@pytest.fixture(scope="module")
def ingress_bundle(config, batch12_mongo):
    from scripts import ingress_server

    return ingress_server._build_mongo_ingress(config)


@pytest.fixture(scope="module")
def ingress_client(ingress_bundle):
    from fastapi.testclient import TestClient  # type: ignore
    from scripts import ingress_server

    return TestClient(ingress_server._build_app(ingress_bundle))


# ------------------------------------------------------------- wire helpers
def _admin(client) -> str:
    r = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "admin",
            "credential": "admin-dev-credential",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["token"]


def _register_source(client, admin, name, endpoint) -> str:
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.register",
            "source_type": "nginx",
            "display_name": name,
            "tags": ["BATCH12"],
        },
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    sid = r.json()["data"]["source"]["source_instance_id"]
    client.post(
        "/api/proxy",
        json={
            "operation": "source.configure",
            "source_instance_id": sid,
            "configuration": {
                "connection_type": "push",
                "endpoint": endpoint,
            },
        },
        headers={"X-ProShield-Session": admin},
    )
    client.post(
        "/api/proxy",
        json={"operation": "source.validate", "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )
    r = client.post(
        "/api/proxy",
        json={"operation": "source.enable", "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return sid


def _issue_token(client, admin, sid) -> str:
    r = client.post(
        "/api/proxy",
        json={
            "operation": "source.issue_token",
            "source_instance_id": sid,
        },
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["source_token"]


def _ingest(proxy_client, ingress_client, admin, sid, events):
    """Issue a FRESH single-use token and push one batch (token = single use)."""
    token = _issue_token(proxy_client, admin, sid)
    r = ingress_client.post(
        "/api/ingress",
        json={"operation": "source.ingest", "events": events},
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def _auth_fail_event(i, *, source_ip, endpoint, when, tag="t28"):
    from app.domain.uuid7 import uuid7

    return {
        "event_id": str(uuid7()),
        "source_event_id": f"b12-{tag}-{RUN_ID}-{i}",
        "event_type": "authentication_failure",
        "event_time": when.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "endpoint": endpoint,
        "asset": "web-app",
        "account": {"id": f"b12-user-{i % 2}"},
        "details": {"http_method": "POST", "status_code": 401},
    }


def _repos(db, config):
    from app.incidents.repository import IncidentRepository
    from app.persistence.correlation_repository import CorrelationRepository
    from app.persistence.detection_repository import DetectionRepository
    from app.persistence.security_event_repository import SecurityEventRepository

    return {
        "events": SecurityEventRepository(db=db, config=config),
        "detections": DetectionRepository(db=db, config=config),
        "correlations": CorrelationRepository(db=db, config=config),
        "cases": IncidentRepository(db=db, config=config),
    }


def _correlation_for(repo, endpoint):
    rows = [
        c for c in repo.find_recent(limit=200)
        if c.key.parts and c.key.parts[-1] == endpoint
    ]
    assert rows, f"no correlation for endpoint {endpoint!r}"
    return rows[0]


def _case_for(case_repo, correlation_id):
    rows = [
        c for c in case_repo.find_recent(limit=200)
        if correlation_id in tuple(c.evidence.correlation_ids)
    ]
    assert rows, f"no case for correlation {correlation_id}"
    return rows[0]


# ------------------------------------------------------- T28 case evidence
class TestT28CaseEvidence:
    def test_threshold_exact_cluster_case_holds_full_evidence(
        self, config, batch12_mongo, proxy_client, ingress_client
    ):
        """4 events (the brute-force threshold) → 1 complete case.

        Reproduced defect (live product): the correlation row held 4
        detection/event ids while the auto-opened case held exactly one of
        each, so the analyst-visible timeline carried 1 event + 1 detection
        instead of the cluster.
        """
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t28-exact", "/api/login"
        )
        db = batch12_mongo[config.mongo_db]
        repos = _repos(db, config)
        endpoint = f"/b12-t28-exact-{RUN_ID}"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        batch = [
            _auth_fail_event(
                100 + i,
                source_ip="203.0.113.201",
                endpoint=endpoint,
                when=now - timedelta(seconds=40 - i),
            )
            for i in range(4)
        ]
        data = _ingest(proxy_client, ingress_client, admin, sid, batch)
        accepted = data["accepted_event_ids"]
        assert len(accepted) == 4, data

        dets = [
            d for eid in accepted
            for d in repos["detections"].find_by_event_id(eid)
        ]
        det_ids = {d.detection_id for d in dets}
        assert len(dets) >= 4, [d.detection_id for d in dets]

        corr = _correlation_for(repos["correlations"], endpoint)
        assert set(accepted) <= set(corr.event_ids)
        assert det_ids <= set(corr.detection_ids)

        case = _case_for(repos["cases"], corr.correlation_id)
        assert set(accepted) <= set(case.evidence.event_ids), (
            "T28 regression: the case does not hold the cluster's events "
            f"(case={list(case.evidence.event_ids)})"
        )
        assert det_ids <= set(case.evidence.detection_ids), (
            "T28 regression: the case does not hold the cluster's detections "
            f"(case={list(case.evidence.detection_ids)})"
        )
        assert corr.correlation_id in case.evidence.correlation_ids
        assert case.severity, "case severity was not composed at creation"

        # The analyst-visible timeline is the projection of the same evidence.
        from app.correlation.service import CorrelationReadService
        from app.detection.service import DetectionReadService
        from app.timeline.engine import TimelineEngine
        from app.timeline.service import TimelineReadService

        timeline = TimelineReadService(
            TimelineEngine(),
            repos["events"],
            DetectionReadService(repository=repos["detections"]),
            CorrelationReadService(repository=repos["correlations"]),
        )
        result = timeline.build_for_incident(case=case)
        kinds = {}
        for item in result.items:
            key = getattr(item.kind, "value", item.kind)
            kinds[str(key)] = kinds.get(str(key), 0) + 1
        assert kinds.get("event", 0) >= 4, kinds
        assert kinds.get("detection", 0) >= 4, kinds
        assert kinds.get("correlation", 0) >= 1, kinds

    def test_two_clusters_do_not_contaminate_each_others_case(
        self, config, batch12_mongo, proxy_client, ingress_client
    ):
        """Two clusters inside one correlation window keep separate evidence.

        Reproduced defect (live product): the engine result contains *every*
        cluster active in the window while the processed event belongs to one
        of them; the pipeline handed the trigger event/detections to every
        cluster's case, so cluster A's case absorbed cluster B's detections
        (and vice-versa) and both the case and the analyst timeline showed
        foreign evidence.
        """
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t28-two", "/api/login"
        )
        db = batch12_mongo[config.mongo_db]
        repos = _repos(db, config)
        now = datetime.now(timezone.utc).replace(microsecond=0)

        ep_a = f"/b12-cluster-a-{RUN_ID}"
        ep_b = f"/b12-cluster-b-{RUN_ID}"
        batch_a = [
            _auth_fail_event(
                200 + i,
                source_ip="203.0.113.211",
                endpoint=ep_a,
                when=now - timedelta(seconds=50 - i),
            )
            for i in range(4)
        ]
        batch_b = [
            _auth_fail_event(
                300 + i,
                source_ip="203.0.113.212",
                endpoint=ep_b,
                when=now - timedelta(seconds=30 - i),
            )
            for i in range(4)
        ]

        data_a = _ingest(proxy_client, ingress_client, admin, sid, batch_a)
        data_b = _ingest(proxy_client, ingress_client, admin, sid, batch_b)
        accepted_a = set(data_a["accepted_event_ids"])
        accepted_b = set(data_b["accepted_event_ids"])
        assert len(accepted_a) == 4 and len(accepted_b) == 4

        dets_a = {
            d.detection_id for eid in accepted_a
            for d in repos["detections"].find_by_event_id(eid)
        }
        dets_b = {
            d.detection_id for eid in accepted_b
            for d in repos["detections"].find_by_event_id(eid)
        }
        assert dets_a and dets_b and not (dets_a & dets_b)

        corr_a = _correlation_for(repos["correlations"], ep_a)
        corr_b = _correlation_for(repos["correlations"], ep_b)
        case_a = _case_for(repos["cases"], corr_a.correlation_id)
        case_b = _case_for(repos["cases"], corr_b.correlation_id)
        assert case_a.incident_id != case_b.incident_id

        evidence_a = set(case_a.evidence.detection_ids)
        evidence_b = set(case_b.evidence.detection_ids)
        assert dets_a <= evidence_a, (sorted(evidence_a), sorted(dets_a))
        assert dets_b <= evidence_b, (sorted(evidence_b), sorted(dets_b))
        assert not (evidence_a & evidence_b), (
            "cross-cluster case contamination: "
            f"A∩B={sorted(evidence_a & evidence_b)}"
        )
        assert not (set(case_a.evidence.event_ids) & accepted_b)
        assert not (set(case_b.evidence.event_ids) & accepted_a)
        assert corr_b.correlation_id not in case_a.evidence.correlation_ids
        assert corr_a.correlation_id not in case_b.evidence.correlation_ids


# ------------------------------------------------- T22 event_time contract
class TestT22EventTimeContract:
    """The canonical ``event_time`` contract at the trusted ingress boundary."""

    @staticmethod
    def _push(proxy_client, ingress_client, admin, sid, **event_overrides):
        from app.domain.uuid7 import uuid7

        event = {
            "event_id": str(uuid7()),
            "event_type": "authentication_failure",
            "source_event_id": f"b12-t22-{RUN_ID}-{uuid.uuid4().hex[:8]}",
            "source_ip": "198.51.100.77",
            "endpoint": f"/b12-t22-{RUN_ID}",
            "asset": "web-app",
            "details": {"http_method": "POST", "status_code": 401},
        }
        event.update(event_overrides)
        return _ingest(proxy_client, ingress_client, admin, sid, [event])

    @pytest.mark.parametrize("offset_label", ["Z", "+00:00", "+05:30", "-08:00"])
    def test_valid_instants_are_accepted_and_normalised_to_utc(
        self, config, batch12_mongo, proxy_client, ingress_client, offset_label
    ):
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t22-valid", "/api/login"
        )
        stamp = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
            minutes=20
        )
        if offset_label == "Z":
            value = stamp.isoformat().replace("+00:00", "Z")
        elif offset_label == "+00:00":
            value = stamp.isoformat()
        elif offset_label == "+05:30":
            value = (stamp + timedelta(hours=5, minutes=30)).isoformat(
            ).replace("+00:00", "+05:30")
        else:
            value = (stamp - timedelta(hours=8)).isoformat().replace(
                "+00:00", "-08:00"
            )
        data = self._push(
            proxy_client, ingress_client, admin, sid, event_time=value
        )
        assert len(data["accepted_event_ids"]) == 1, data
        assert data["rejected"] == [], data

        from app.persistence.security_event_repository import (
            SecurityEventRepository,
        )

        repo = SecurityEventRepository(
            db=batch12_mongo[config.mongo_db], config=config
        )
        row = repo.get_by_event_id(data["accepted_event_ids"][0])
        assert row is not None
        assert row.event_time == stamp, (row.event_time, value)
        assert row.event_time.tzinfo is not None

    @pytest.mark.parametrize(
        "label,value",
        [
            ("invalid string", "not-a-real-timestamp"),
            ("malformed", "2026-13-45T99:99:99Z"),
            ("impossible date", "2026-02-30T10:00:00Z"),
            ("wrong type int", 1234567890),
            ("wrong type list", ["2026-01-01T00:00:00Z"]),
            ("null", None),
            ("missing", ...),
        ],
    )
    def test_non_timestamp_event_time_is_rejected_per_event(
        self, proxy_client, ingress_client, label, value
    ):
        """Batch 1/2 T22: a missing/non-timestamp observation time is refused.

        Reproduced defect (live product): ``wrong type`` / ``null`` / ``missing``
        were accepted with ``event_time`` silently stamped from the server
        receive clock (``event_time == ingested_at``), fabricating the source's
        observation time; a non-canonical ``timestamp`` key was accepted the
        same way. The canonical contract requires the source-attributed field.
        """
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t22-invalid", "/api/login"
        )
        overrides = {} if value is ... else {"event_time": value}
        data = self._push(
            proxy_client, ingress_client, admin, sid, **overrides
        )
        assert data["accepted_event_ids"] == [], (label, data)
        assert len(data["rejected"]) == 1, (label, data)
        assert data["rejected"][0]["reason"] == "validation_error", (label, data)

    def test_non_canonical_timestamp_key_is_not_an_observation_time(
        self, proxy_client, ingress_client
    ):
        """The exact shape the manual T22 test used.

        ``{"timestamp": "not-a-real-timestamp"}`` carries no canonical
        ``event_time``; it must be refused instead of being accepted with a
        server-clock observation time.
        """
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t22-noncanonical", "/api/login"
        )
        data = self._push(
            proxy_client, ingress_client, admin, sid,
            timestamp="not-a-real-timestamp",
        )
        assert data["accepted_event_ids"] == [], data
        assert data["rejected"][0]["reason"] == "validation_error", data

    def test_future_dated_event_time_is_rejected(
        self, proxy_client, ingress_client
    ):
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "b12-t22-future", "/api/login"
        )
        future = (
            datetime.now(timezone.utc) + timedelta(hours=3)
        ).isoformat().replace("+00:00", "Z")
        data = self._push(
            proxy_client, ingress_client, admin, sid, event_time=future
        )
        assert data["accepted_event_ids"] == [], data
        assert data["rejected"][0]["reason"] == "validation_error", data

