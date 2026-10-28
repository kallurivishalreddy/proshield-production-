"""J-04: storage failure is visible, not a false success.

Runs the real proxy/ingress apps against an isolated MongoDB database and
injects a persistence failure only into the ingress service instance. The
test asserts the per-event rejection is explicit and that no event or
detection was persisted.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient  # type: ignore
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import proxy_server, ingress_server  # noqa: E402
from app.config import ProShieldConfig  # noqa: E402
from app.domain.errors import PersistenceError  # noqa: E402
from app.domain.uuid7 import uuid7  # noqa: E402

TEST_DB = "proshield_test_j04_failure"


@pytest.fixture(scope="module")
def config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        auth_signing_key="j04-test-auth-key-0001",
        source_signing_key="j04-test-source-key-0001",
        source_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=base.proxy_rate_limit_per_minute,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=base.ingress_rate_limit_per_minute,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_max_response_bytes=base.ingress_max_response_bytes,
        ingress_replay_store_required=True,
        ingress_replay_collection="source_token_replay_j04",
        default_subject_credentials={
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
            "collector": "collector-dev-credential",
            "internal": "internal-dev-credential",
        },
    )


@pytest.fixture(scope="module")
def j04_mongo(config):
    client = MongoClient(config.mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    yield client
    try:
        client.drop_database(TEST_DB)
    except Exception:  # noqa: BLE001
        pass
    client.close()


@pytest.fixture()
def proxy_client(config, j04_mongo):
    bundle = proxy_server._build_mongo_backend(config)
    return TestClient(proxy_server._build_app(bundle))


def _admin(client) -> str:
    response = client.post(
        "/api/proxy",
        json={
            "operation": "auth.issue",
            "subject_id": "admin",
            "credential": "admin-dev-credential",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]["token"]


def _enabled_source(client, admin_token: str) -> str:
    response = client.post(
        "/api/proxy",
        json={
            "operation": "source.register",
            "source_type": "nginx",
            "display_name": f"j04-{uuid4().hex[:8]}",
            "tags": ["J04"],
        },
        headers={"X-ProShield-Session": admin_token},
    )
    assert response.status_code == 200, response.text
    sid = response.json()["data"]["source"]["source_instance_id"]
    for operation, payload in (
        (
            "source.configure",
            {
                "source_instance_id": sid,
                "configuration": {
                    "connection_type": "push",
                    "endpoint": "https://example.com/ing",
                },
            },
        ),
        ("source.validate", {"source_instance_id": sid}),
        ("source.enable", {"source_instance_id": sid}),
    ):
        response = client.post(
            "/api/proxy",
            json={"operation": operation, **payload},
            headers={"X-ProShield-Session": admin_token},
        )
        assert response.status_code == 200, response.text
    response = client.post(
        "/api/proxy",
        json={"operation": "source.issue_token", "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]["source_token"]


def test_storage_failure_is_rejected_not_reported_as_persisted(
    config, j04_mongo, proxy_client, monkeypatch
):
    admin = _admin(proxy_client)
    source_token = _enabled_source(proxy_client, admin)
    bundle = ingress_server._build_mongo_ingress(config)
    ingress_client = TestClient(ingress_server._build_app(bundle))

    def fail_create(_event):
        raise PersistenceError(
            safe_message="could not persist event",
            internal_detail="injected persistence failure for T31-J-04",
        )

    monkeypatch.setattr(
        bundle.ingress._ingestion_service._repository,
        "create",
        fail_create,
    )

    event_id = str(uuid7())
    print(f"J04_STORAGE_FAILURE_EVENT_ID={event_id}")
    event_time = (
        datetime.now(timezone.utc) - timedelta(seconds=5)
    ).isoformat().replace("+00:00", "Z")
    response = ingress_client.post(
        "/api/ingress",
        headers={"X-ProShield-Source-Token": source_token},
        json={
            "operation": "source.ingest",
            "events": [
                {
                    "event_id": event_id,
                    "event_type": "authentication_failure",
                    "source_event_id": f"j04-{uuid4().hex[:8]}",
                    "event_time": event_time,
                    "source_ip": "198.51.100.207",
                    "endpoint": "/api/login",
                    "asset": "web-app",
                    "details": {
                        "status_code": 401,
                        "http_method": "POST",
                    },
                }
            ],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    data = body["data"]
    assert data["accepted_event_ids"] == []
    assert data["rejected"][0]["reason"] == "persistence_error"
    assert data["rejected"][0]["message"] == "could not persist event"

    db = j04_mongo[config.mongo_db]
    assert db["security_events"].count_documents({"event_id": event_id}) == 0
    assert db["detections"].count_documents({"event_id": event_id}) == 0


def test_pipeline_failure_is_logged_and_event_is_not_dropped(
    config, j04_mongo, proxy_client, monkeypatch, caplog
):
    admin = _admin(proxy_client)
    source_token = _enabled_source(proxy_client, admin)
    bundle = ingress_server._build_mongo_ingress(config)
    ingress_client = TestClient(ingress_server._build_app(bundle))

    def fail_process(_event, *, event_persisted):
        assert event_persisted is True
        raise RuntimeError("injected pipeline failure for T31-J-04")

    monkeypatch.setattr(bundle.pipeline, "process", fail_process)
    caplog.set_level(logging.WARNING)

    event_id = str(uuid7())
    print(f"J04_PIPELINE_FAILURE_EVENT_ID={event_id}")
    event_time = (
        datetime.now(timezone.utc) - timedelta(seconds=5)
    ).isoformat().replace("+00:00", "Z")
    response = ingress_client.post(
        "/api/ingress",
        headers={"X-ProShield-Source-Token": source_token},
        json={
            "operation": "source.ingest",
            "events": [
                {
                    "event_id": event_id,
                    "event_type": "authentication_failure",
                    "source_event_id": f"j04-pipeline-{uuid4().hex[:8]}",
                    "event_time": event_time,
                    "source_ip": "198.51.100.208",
                    "endpoint": "/api/login",
                    "asset": "web-app",
                    "details": {
                        "status_code": 401,
                        "http_method": "POST",
                    },
                }
            ],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["data"]["accepted_event_ids"] == [event_id]
    assert body["data"]["rejected"] == []

    db = j04_mongo[config.mongo_db]
    assert db["security_events"].count_documents({"event_id": event_id}) == 1
    assert db["detections"].count_documents({"event_id": event_id}) == 0
    assert any(
        record.getMessage() == "pipeline.process_failed"
        for record in caplog.records
    )
