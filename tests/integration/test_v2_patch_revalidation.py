"""V2 patch revalidation: targeted regression tests for the V2 findings.

Reference: docs/PHASE 4/PROSHIELD-DEEPTEST-ISSUES-V2.md and the
``## V2 PATCH IMPLEMENTATION / REVALIDATION`` section of the same
report.

Each test class covers one patched finding through the *real*
composition (both deployment planes against the same MongoDB, the
same bundles ``scripts/*_server.py`` builds), never through mocks:

* TestV2P0Bootstrap            — V2-P0: validators + unique indexes on
  every collection via the real startup bootstrap.
* TestV2P0DuplicateEvents      — V2-23 / V2-P0: accepted events create
  exactly ONE security_events row.
* TestV2P0StableCorrelation    — V2-08 / V2-02: a growing cluster keeps
  ONE correlation row, the SAME case id, and accumulates evidence.
* TestV2P0RuleLifecycle        — V2-01: rule.disable on the analyst
  plane stops the LIVE ingress detector on the next event; rule.enable
  resumes it (no restart).
* TestV2P0UnmatchedVisibility  — V2-06: a valid no-rule event stays
  analyst-visible via ``event.list {unmatched: true}``.
* TestV2P0EndpointMismatch     — V2-19: wire endpoint != registered
  endpoint keeps ``source_ip`` (attacker attribution is preserved and
  the brute-force pattern can fire).
* TestV2P0CentralizedEvidence  — V2-05: ``case.centralized`` with an
  empty payload analyses the case's REAL persisted evidence.
* TestV2P0SourceIpReconciled   — V2-19: endpoint mismatch recorded as
  ``details._untrusted_endpoint`` (defence preserved).

Requires a running MongoDB on 127.0.0.1:27017.
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pymongo import MongoClient  # noqa: E402

TEST_DB = "proshield_test_v2_patch"

# Unique per process so re-runs never collide with leftover
# source_event_ids from an earlier run (the ingestion dedups on
# ``(source, provenance.source_event_id)``).
RUN_ID = uuid.uuid4().hex[:8]


def _config() -> "ProShieldConfig":  # noqa: F821
    from app.config import ProShieldConfig

    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        auth_signing_key="v2-patch-auth-key-0001",
        source_signing_key="v2-patch-source-key-0001",
        source_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=base.proxy_rate_limit_per_minute,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=base
        .proxy_centralized_rate_limit_per_minute,
        ingress_rate_limit_per_minute=base.ingress_rate_limit_per_minute,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_max_response_bytes=base.ingress_max_response_bytes,
        ingress_replay_store_required=True,
        ingress_replay_collection="source_token_replay_v2",
        default_subject_credentials={
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
            "collector": "collector-dev-credential",
            "internal": "internal-dev-credential",
        },
    )


@pytest.fixture(scope="module")
def config():
    return _config()


# NB: fixture names deliberately avoid the conftest's session-scoped
# ``v2_mongo`` / ``db`` — this file owns its own dedicated test
# database and module-scoped lifecycle.
@pytest.fixture(scope="module")
def v2_mongo(config):
    from pymongo import MongoClient as _MC

    client = _MC(config.mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    # Reset at module start so a previously failed run's leftover rows
    # cannot poison assertions.
    client.drop_database(TEST_DB)
    yield client
    try:
        client.drop_database(TEST_DB)
    except Exception:  # noqa: BLE001
        pass
    client.close()


@pytest.fixture(scope="module")
def proxy_bundle(config, v2_mongo):
    from scripts import proxy_server

    return proxy_server._build_mongo_backend(config)


@pytest.fixture(scope="module")
def proxy_client(proxy_bundle):
    from fastapi.testclient import TestClient  # type: ignore
    from scripts import proxy_server

    return TestClient(proxy_server._build_app(proxy_bundle))


@pytest.fixture(scope="module")
def ingress_bundle(config, v2_mongo):
    from scripts import ingress_server

    return ingress_server._build_mongo_ingress(config)


@pytest.fixture(scope="module")
def ingress_client(ingress_bundle):
    from fastapi.testclient import TestClient  # type: ignore
    from scripts import ingress_server

    return TestClient(ingress_server._build_app(ingress_bundle))


# ------------------------------------------------------------- helpers
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
            "tags": ["V2PATCH"],
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
    """Issue a FRESH single-use token and push one batch.

    Tokens are single-use (R-1 replay protection); a test that sends
    more than one batch must not reuse one.
    """
    token = _issue_token(proxy_client, admin, sid)
    r = ingress_client.post(
        "/api/ingress",
        json={"operation": "source.ingest", "events": events},
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def _auth_fail_event(i, *, source_ip, endpoint, when):
    """One realistic 401 authentication-failure telemetry record."""
    from app.domain.uuid7 import uuid7 as _uuid7

    return {
        "event_id": str(_uuid7()),
        "source_event_id": f"v2-{RUN_ID}-{i}",
        "event_type": "authentication_failure",
        "event_time": when.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "endpoint": endpoint,
        "asset": "web-app",
        "account": {"id": f"user-{i % 3}"},
        "details": {"http_method": "POST", "status_code": 401},
    }


def _rule_state(db, config, rule_id):
    doc = db[config.mongo_db]["managed_rules"].find_one(
        {"rule_id": rule_id}
    )
    if doc is None:
        return None
    return {"state": doc.get("state"), "enabled": doc.get("enabled")}


def _disable_rule(client, admin, rule_id):
    r = client.post(
        "/api/proxy",
        json={"operation": "rule.disable", "rule_id": rule_id},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return r


def _enable_rule(client, admin, rule_id):
    r = client.post(
        "/api/proxy",
        json={"operation": "rule.enable", "rule_id": rule_id},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return r


# ----------------------------------------------------------------- V2-P0
class TestV2P0Bootstrap:
    def test_validators_and_unique_indexes_exist_on_fresh_db(
        self, config, v2_mongo
    ):
        """V2-P0: the real startup path applies validators + indexes."""
        from app.persistence.bootstrap import ensure_all_collections

        # Fresh dedicated database for this test.
        db_name = TEST_DB + "_bootstrap"
        db = v2_mongo[db_name]
        try:
            db.client.drop_database(db_name)
        except Exception:  # noqa: BLE001
            pass

        summary = ensure_all_collections(db, config)
        assert set(summary.keys()) >= {
            "security_events",
            "detections",
            "correlations",
            "incidents",
            "reports",
            "managed_rules",
            "source_instances",
        }
        for name, info in summary.items():
            coll_info = list(
                db.command(
                    "listCollections", filter={"name": name}
                )["cursor"]["firstBatch"]
            )
            assert coll_info, f"{name}: collection missing"
            validator = coll_info[0].get("options", {}).get("validator")
            assert validator and "$jsonSchema" in validator, (
                f"{name}: $jsonSchema validator missing (V2-P0)"
            )
            ix = db[name].index_information()
            unique_names = {
                ix_name
                for ix_name, spec in ix.items()
                if spec.get("unique")
            }
            assert unique_names, f"{name}: no unique index (V2-P0)"
        # Duplicate event id is rejected at the database boundary.
        from app.persistence.security_event_repository import (
            SecurityEventRepository,
        )
        from app.domain.errors import DuplicateEventError
        from app.domain.security_event import SecurityEvent

        repo = SecurityEventRepository(db=db, config=config)
        from app.domain.security_event import SecurityEventProvenance

        ev = SecurityEvent(
            event_id="0198c2a1-7e3b-7a8e-b7b6-4f0000000001",
            # Whole seconds: BSON Date truncates microseconds and the
            # canonical-equality comparison would otherwise classify
            # the idempotent re-insert as a content conflict.
            event_time=datetime.now(timezone.utc).replace(
                microsecond=0
            ),
            ingested_at=datetime.now(timezone.utc),
            source="nginx",
            event_type="authentication_failure",
            source_ip="203.0.113.1",
            endpoint="/login",
            provenance=SecurityEventProvenance(
                collector="nginx",
                source_event_id="v2-p0-dup-check",
            ),
        )
        repo.create(ev)
        with pytest.raises(DuplicateEventError):
            repo.create(ev)


# --------------------------------------------------------- V2-23 / P0
class TestV2P0DuplicateEvents:
    def test_accepted_event_persists_exactly_once(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-23: no double persist through ingress + pipeline."""
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "v2-dup-01", "/login"
        )
        token = _issue_token(proxy_client, admin, sid)
        data = _ingest(
            proxy_client, ingress_client, admin, sid,
            [
                _auth_fail_event(
                    1,
                    source_ip="203.0.113.41",
                    endpoint="/login",
                    when=datetime.now(timezone.utc),
                )
            ],
        )
        accepted = data["accepted_event_ids"]
        assert len(accepted) == 1
        col = v2_mongo[config.mongo_db]["security_events"]
        rows = list(col.find({"event_id": accepted[0]}))
        assert len(rows) == 1, (
            f"V2-23 regression: {len(rows)} rows for event "
            f"{accepted[0]} (double persist)"
        )


# --------------------------------------------------- V2-08 / V2-02
class TestV2P0StableCorrelation:
    def test_growing_cluster_keeps_one_correlation_and_accumulates_case(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-08 + V2-02: same correlation_id, same case, more
        evidence."""
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "v2-grow-01", "/login"
        )
        token = _issue_token(proxy_client, admin, sid)
        now = datetime.now(timezone.utc)
        db = v2_mongo[config.mongo_db]

        # Burst 1: 4 x 401 (threshold) from one source_ip.
        burst1 = [
            _auth_fail_event(
                i,
                source_ip="203.0.113.99",
                endpoint="/login",
                when=now - timedelta(seconds=60 - i),
            )
            for i in range(4)
        ]
        _ingest(proxy_client, ingress_client, admin, sid, burst1)

        corrs = list(
            db["correlations"].find(
                {"detection_ids": {"$ne": []}}
            )
        )
        assert len(corrs) >= 1, "expected the burst to produce a cluster"
        corr = corrs[0]
        first_corr_id = corr["correlation_id"]
        first_det_count = len(corr["detection_ids"])

        cases = list(db["incidents"].find({}))
        assert len(cases) == 1, (
            f"expected exactly 1 case, got {len(cases)}"
        )
        case_id = cases[0]["incident_id"]

        # Burst 2: 2 more events in the same window -> same cluster.
        burst2 = [
            _auth_fail_event(
                10 + i,
                source_ip="203.0.113.99",
                endpoint="/login",
                when=now - timedelta(seconds=20 - i),
            )
            for i in range(2)
        ]
        _ingest(proxy_client, ingress_client, admin, sid, burst2)

        rows = list(
            db["correlations"].find(
                {"correlation_id": first_corr_id}
            )
        )
        assert len(rows) == 1, (
            f"V2-08 regression: {len(rows)} correlation rows for one "
            "logical cluster (id proliferation)"
        )
        grown = rows[0]
        assert grown["correlation_id"] == first_corr_id
        assert (
            len(grown["detection_ids"]) > first_det_count
        ), "cluster row did not grow its detection evidence"

        # Same case id, and its evidence has grown.
        cases_after = list(db["incidents"].find({}))
        assert len(cases_after) == 1, "duplicate case opened (V2-02)"
        assert cases_after[0]["incident_id"] == case_id
        assert len(
            cases_after[0]["evidence"]["detection_ids"]
        ) > len(cases[0]["evidence"]["detection_ids"]), (
            "V2-02 regression: case evidence frozen at first trigger"
        )


# ------------------------------------------------------------- V2-01
class TestV2P0RuleLifecycle:
    def test_disabled_rule_stops_live_detector_next_event(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-01: the operator's disable/enable governs the LIVE
        ingress detector on the next event, no restart."""
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "v2-lifecycle-01", "/login"
        )
        token = _issue_token(proxy_client, admin, sid)
        now = datetime.now(timezone.utc)
        db = v2_mongo[config.mongo_db]
        rule_id = "NGINX-AUTH-BRUTEFORCE-001"

        def _send_marker(prefix, ip, offset_s):
            """Send 4 aligned 401s and return the detections for them.

            Timestamps are in the PAST (the ingress rejects events with
            future ``event_time``); each burst is internally within the
            5-minute correlation window and the per-burst source_ip is
            unique so bursts form separate clusters.
            """
            events = [
                _auth_fail_event(
                    i,
                    source_ip=ip,
                    endpoint="/login",
                    when=now - timedelta(seconds=3600 - offset_s - i),
                )
                for i in range(4)
            ]
            data = _ingest(proxy_client, ingress_client, admin, sid, events)
            ids = data["accepted_event_ids"]
            assert len(ids) == 4
            return {
                d["detection_id"]
                for d in db["detections"].find(
                    {"event_id": {"$in": ids}}
                )
            }

        # Baseline: the rule fires for a fresh cluster.
        dets_before = _send_marker("pre", "203.0.113.71", 0)
        assert any(
            d.startswith("det-") for d in dets_before
        ), "expected detections before disable"
        assert _rule_state(v2_mongo, config, rule_id) is not None

        # Disable via the analyst plane.
        _disable_rule(client=proxy_client, admin=admin, rule_id=rule_id)
        assert _rule_state(v2_mongo, config, rule_id)[
            "enabled"
        ] is False

        # Fresh cluster from a NEW source_ip: the disabled rule must
        # NOT fire (its detections are absent from the live result).
        dets_disabled = _send_marker("off", "203.0.113.72", 300)
        disabled_rule_dets = {
            d
            for d in dets_disabled
            if db["detections"].find_one(
                {"detection_id": d, "rule_id": rule_id}
            )
            is not None
        }
        assert not disabled_rule_dets, (
            "V2-01 regression: disabled rule fired in the live detector"
        )

        # Re-enable: the rule fires again.
        _enable_rule(client=proxy_client, admin=admin, rule_id=rule_id)
        assert _rule_state(v2_mongo, config, rule_id)[
            "enabled"
        ] is True
        dets_enabled = _send_marker("on", "203.0.113.73", 600)
        enabled_rule_dets = {
            d
            for d in dets_enabled
            if db["detections"].find_one(
                {"detection_id": d, "rule_id": rule_id}
            )
            is not None
        }
        assert enabled_rule_dets, (
            "V2-01 regression: re-enabled rule did not fire"
        )


# ------------------------------------------------------------- V2-06
class TestV2P0UnmatchedVisibility:
    def test_no_rule_event_is_analyst_visible(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-06: a valid trusted event that matches no rule stays
        analyst-visible via ``event.list {unmatched: true}``."""
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "v2-unmatched-01", "/health-probe"
        )
        # A valid, trusted event whose event_type has NO matching rule
        # in the shipped library (tls_anomaly): accepted + persisted,
        # zero detections. This is the V2-06 visibility obligation.
        from app.domain.uuid7 import uuid7 as _uuid7

        marker_ip = "203.0.113.207"
        data = _ingest(
            proxy_client, ingress_client, admin, sid,
            [
                {
                    "event_id": str(_uuid7()),
                    "source_event_id": f"v2-unmatched-{RUN_ID}",
                    "event_type": "tls_anomaly",
                    "event_time": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "source_ip": marker_ip,
                    "endpoint": "/health-probe",
                    "asset": "web-app",
                    "details": {"handshake_failure": True},
                }
            ],
        )
        assert len(data["accepted_event_ids"]) == 1
        eid = data["accepted_event_ids"][0]
        db = v2_mongo[config.mongo_db]
        assert db["security_events"].find_one({"event_id": eid})

        r = proxy_client.post(
            "/api/proxy",
            json={
                "operation": "event.list",
                "unmatched": True,
                "limit": 200,
            },
            headers={"X-ProShield-Session": admin},
        )
        assert r.status_code == 200, r.text
        events = r.json()["data"]["events"]
        if not events:  # debug aid: dump the raw unmatched=false view
            r_all = proxy_client.post(
                "/api/proxy",
                json={"operation": "event.list", "limit": 200},
                headers={"X-ProShield-Session": admin},
            )
            assert False, (
                f"event.list(unmatched) empty; unfiltered view: "
                f"{r_all.text[:600]}; event doc: "
                f"{db['security_events'].find_one({'event_id': eid})}"
            )
        listed = {e["event_id"] for e in events}
        assert eid in listed, (
            "V2-06 regression: valid unmatched event invisible to the "
            "analyst"
        )


# ------------------------------------------------------------- V2-19
class TestV2P0EndpointMismatch:
    def test_source_ip_preserved_when_endpoint_mismatches(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-19: wire endpoint != registered endpoint preserves the
        attacker source_ip and records the mismatch."""
        admin = _admin(proxy_client)
        # Registered endpoint deliberately DIFFERENT from the wire one.
        sid = _register_source(
            proxy_client, admin, "v2-mismatch-01", "/registered/path"
        )
        token = _issue_token(proxy_client, admin, sid)
        data = _ingest(
            proxy_client, ingress_client, admin, sid,
            [
                _auth_fail_event(
                    1,
                    source_ip="203.0.113.51",
                    endpoint="/wire/login",
                    when=datetime.now(timezone.utc),
                )
            ],
        )
        eid = data["accepted_event_ids"][0]
        doc = v2_mongo[config.mongo_db]["security_events"].find_one(
            {"event_id": eid}
        )
        assert doc is not None
        assert doc["source_ip"] == "203.0.113.51", (
            "V2-19 regression: attacker source_ip nulled on endpoint "
            "mismatch (systematic correlation false-negative)"
        )
        assert doc["details"].get("_untrusted_endpoint") == "/wire/login"


# ------------------------------------------------------------- V2-05
class TestV2P0CentralizedEvidence:
    def test_centralized_analyses_real_case_evidence(
        self, config, v2_mongo, proxy_client, ingress_client
    ):
        """V2-05: empty payload -> the server resolves the case's real
        evidence; zero-evidence cases fail truthfully instead of a
        fake success."""
        admin = _admin(proxy_client)
        sid = _register_source(
            proxy_client, admin, "v2-central-01", "/login"
        )
        token = _issue_token(proxy_client, admin, sid)
        now = datetime.now(timezone.utc)
        events = [
            _auth_fail_event(
                i,
                source_ip="203.0.113.81",
                endpoint="/login",
                when=now - timedelta(seconds=50 - i),
            )
            for i in range(5)
        ]
        _ingest(proxy_client, ingress_client, admin, sid, events)
        db = v2_mongo[config.mongo_db]
        case = db["incidents"].find_one()
        assert case is not None, "expected an auto-opened case"

        # 1. Empty payload: the server resolves real evidence and the
        #    analysis succeeds (it previously reported a misleading
        #    success with zero evidence).
        r = proxy_client.post(
            "/api/proxy",
            json={
                "operation": "case.centralized",
                "incident_id": case["incident_id"],
                "reason": "v2 patch revalidation",
            },
            headers={"X-ProShield-Session": admin},
        )
        assert r.status_code == 200, r.text
        body = r.json()["data"]
        assert body["failed"] is False
        # The real evidence was analysed: the case has detections.
        assert len(case["evidence"]["detection_ids"]) > 0

        # 2. A case with no evidence cannot succeed silently.
        empty_case = db["incidents"].insert_one(
            {
                "incident_id": "case-00000000-0000-7000-8000-000000000001",
                "title": "synthetic empty case",
                "summary": "",
                "state": "open",
                "evidence": {
                    "event_ids": [],
                    "detection_ids": [],
                    "correlation_ids": [],
                    "rule_references": [],
                },
                "rule_references": [],
                "lifecycle_history": [],
                "report_references": [],
                "centralized_correlation_ids": [],
                "centralized_reasoning": "",
                "centralized_failed": False,
                "centralized_failure_reason": "",
                "severity": "",
                "confidence": "",
                "created_by": "admin",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
        )
        assert empty_case.inserted_id is not None
        r2 = proxy_client.post(
            "/api/proxy",
            json={
                "operation": "case.centralized",
                "incident_id": "case-00000000-0000-7000-8000-000000000001",
            },
            headers={"X-ProShield-Session": admin},
        )
        assert r2.status_code == 400, (
            "V2-05 regression: zero-evidence centralized analysis did "
            "not fail truthfully"
        )
