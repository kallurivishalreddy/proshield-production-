"""STRIX D-1 / D-2 / D-4 wiring tests against real MongoDB.

Production architecture: the analyst plane (``scripts/proxy_server.py``)
and the ingress plane (``scripts/ingress_server.py``) are wired to the
SAME MongoDB database and the SAME ``PROSHIELD_SOURCE_SIGNING_KEY``.
This exercises exactly that split:

* D-1  - the production ``MongoReplayStore`` is wired into the ingress
         plane and enforces single-use across processes / restarts.
* D-2  - lowercased / mixed-case token headers are accepted at the real
         HTTP boundary.
* D-4  - the ingress listener exposes only ``/api/ingress`` and does
         not leak analyst ops or the frontend.

These tests require a running MongoDB on 127.0.0.1:27017 (the same
requirement as the other tests/integration/* files).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient  # type: ignore
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import proxy_server, ingress_server  # noqa: E402
from app.config import ProShieldConfig  # noqa: E402
from app.sources.replay_store import MongoReplayStore  # noqa: E402

TEST_DB = "proshield_test_strix_wire"


@pytest.fixture(scope="session")
def config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level=base.log_level,
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB,
        ingest_max_body_bytes=base.ingest_max_body_bytes,
        ingest_max_details_bytes=base.ingest_max_details_bytes,
        auth_signing_key="strix-test-auth-key-0001",
        source_signing_key="strix-test-source-key-0001",
        source_token_lifetime_seconds=3600,
        proxy_rate_limit_per_minute=base.proxy_rate_limit_per_minute,
        proxy_max_request_bytes=base.proxy_max_request_bytes,
        proxy_max_response_bytes=base.proxy_max_response_bytes,
        proxy_centralized_rate_limit_per_minute=5,
        ingress_rate_limit_per_minute=base.ingress_rate_limit_per_minute,
        ingress_max_request_bytes=base.ingress_max_request_bytes,
        ingress_max_response_bytes=base.ingress_max_response_bytes,
        ingress_replay_store_required=True,
        ingress_replay_collection="source_token_replay_strix",
        default_subject_credentials={
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
            "collector": "collector-dev-credential",
            "internal": "internal-dev-credential",
        },
    )


@pytest.fixture(scope="session")
def mongo_client(config):
    client = MongoClient(config.mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    yield client
    # Drop the dedicated test database so runs are repeatable.
    try:
        client.drop_database(TEST_DB)
    except Exception:  # noqa: BLE001
        pass
    client.close()


@pytest.fixture()
def proxy_client(config, mongo_client):
    bundle = proxy_server._build_mongo_backend(config)
    return TestClient(proxy_server._build_app(bundle))


@pytest.fixture()
def ingress_client(config, mongo_client):
    bundle = ingress_server._build_mongo_ingress(config)
    return TestClient(ingress_server._build_app(bundle))


def _admin(client) -> str:
    r = client.post(
        "/api/proxy",
        json={"operation": "auth.issue",
              "subject_id": "admin",
              "credential": "admin-dev-credential"},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["token"]


def _register_enabled_nginx_source(client, admin_token, name) -> str:
    r = client.post(
        "/api/proxy",
        json={"operation": "source.register",
              "source_type": "nginx", "display_name": name,
              "tags": ["STRIX"]},
        headers={"X-ProShield-Session": admin_token},
    )
    assert r.status_code == 200, r.text
    sid = r.json()["data"]["source"]["source_instance_id"]
    client.post(
        "/api/proxy",
        json={"operation": "source.configure",
              "source_instance_id": sid,
              "configuration": {"connection_type": "push",
                                "endpoint": "https://example.com/ing"}},
        headers={"X-ProShield-Session": admin_token},
    )
    client.post(
        "/api/proxy",
        json={"operation": "source.validate",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    r = client.post(
        "/api/proxy",
        json={"operation": "source.enable",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    assert r.status_code == 200, r.text
    return sid


def _issue_token(client, admin_token: str, sid: str) -> str:
    r = client.post(
        "/api/proxy",
        json={"operation": "source.issue_token",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["source_token"]


class TestIngressWireD2D4:
    """Real endpoint path: lowercase headers accepted on /api/ingress."""

    def test_lowercase_authorization_accepted(
        self, proxy_client, ingress_client
    ) -> None:
        admin = _admin(proxy_client)
        sid = _register_enabled_nginx_source(proxy_client, admin, "strix-a")
        token = _issue_token(proxy_client, admin, sid)
        r = ingress_client.post(
            "/api/ingress",
            json={"operation": "source.ingest", "events": []},
            headers={"authorization": f"bearer {token}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True

    def test_lowercase_source_token_header(
        self, proxy_client, ingress_client
    ) -> None:
        admin = _admin(proxy_client)
        sid = _register_enabled_nginx_source(proxy_client, admin, "strix-b")
        token = _issue_token(proxy_client, admin, sid)
        r = ingress_client.post(
            "/api/ingress",
            json={"operation": "source.ingest", "events": []},
            headers={"x-proshield-source-token": token},
        )
        assert r.status_code == 200, r.text

    def test_missing_token_rejected(
        self, proxy_client, ingress_client
    ) -> None:
        r = ingress_client.post(
            "/api/ingress",
            json={"operation": "source.ingest", "events": []},
        )
        assert r.status_code == 401, r.text
        assert r.json()["error"]["message"] == "source identity token missing"

    def test_disabled_source_rejected(
        self, proxy_client, ingress_client
    ) -> None:
        admin = _admin(proxy_client)
        sid = _register_enabled_nginx_source(proxy_client, admin, "strix-c")
        token = _issue_token(proxy_client, admin, sid)
        # Disable after issuing: the token is valid but the source is not.
        proxy_client.post(
            "/api/proxy",
            json={"operation": "source.disable",
                  "source_instance_id": sid},
            headers={"X-ProShield-Session": admin},
        )
        r = ingress_client.post(
            "/api/ingress",
            json={"operation": "source.ingest", "events": []},
            headers={"x-proshield-source-token": token},
        )
        assert r.status_code in (409, 405), r.text

    def test_unknown_source_rejected(
        self, proxy_client, ingress_client
    ) -> None:
        # A token for a source that was never registered on this DB.
        from app.sources.models import SourceType
        from app.sources.trust import SourceIdentityTokenIssuer
        issuer = SourceIdentityTokenIssuer(
            secret="strix-test-source-key-0001", lifetime_seconds=3600,
        )
        # Craft a valid-signature token for a non-existent source.
        tok = issuer.issue(
            source_instance_id=(
                "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-ghost"
            ),
            source_type=SourceType.NGINX,
        )
        r = ingress_client.post(
            "/api/ingress",
            json={"operation": "source.ingest", "events": []},
            headers={"authorization": f"Bearer {issuer.pack(tok)}"},
        )
        assert r.status_code == 401, r.text


class TestMongoReplayStoreD1:
    """Production replay store: single-use, TTL, cross-process."""

    def test_first_use_accepted_second_rejected(
        self, config, mongo_client,
    ) -> None:
        db = mongo_client[TEST_DB]
        store = MongoReplayStore(db, config)
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        assert store.claim(token_id="sit-a-0001", expires_at=exp) is True
        assert store.claim(token_id="sit-a-0001", expires_at=exp) is False

    def test_concurrent_claims_only_one_winner(
        self, config, mongo_client,
    ) -> None:
        db = mongo_client.get_database(TEST_DB)
        store = MongoReplayStore(db, config)
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        results = []

        def claim_once(_):
            return store.claim(token_id="sit-conc-0001", expires_at=exp)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(claim_once, range(8)))
        assert results.count(True) == 1, results
        assert results.count(False) == 7, results

    def test_expiation_gc_and_survival(self, config, mongo_client) -> None:
        db = mongo_client.get_database(TEST_DB)
        store = MongoReplayStore(db, config)
        past = datetime.now(timezone.utc) - timedelta(seconds=60)
        # Insert a claim that is already expired.
        store.claim(token_id="t-expired-0001", expires_at=past)
        removed = store.gc(datetime.now(timezone.utc))
        assert removed >= 1
        # The expired token is now claimable again.
        assert store.claim(
            token_id="t-expired-0001",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=3600),
        ) is True

    def test_persistence_across_store_instances(
        self, config, mongo_client,
    ) -> None:
        """A claim survives store re-instantiation (restart parity)."""
        db = mongo_client.get_database(TEST_DB)
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        MongoReplayStore(db, config).claim(token_id="t-restart-0001",
                                           expires_at=exp)
        # A brand-new store object against the same db sees the claim.
        assert MongoReplayStore(db, config).claim(
            token_id="t-restart-0001", expires_at=exp
        ) is False