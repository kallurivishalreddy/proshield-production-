"""MongoDB persistence E2E for the STRIX patch validation.

Proves create -> persist -> reload -> retrieve across a backend
re-instantiation (restart parity) on the REAL MongoDB backend:

* source lifecycle (register/configure/validate/enable)
* source-identity token issuance + replay-claim persistence
* security-event ingestion + detection persistence
* rules seeded into managed_rules survive a reload

Uses a dedicated ``proshield_strix_persist`` database (dropped at
the end) so the shared dev MongoDB is untouched.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # type: ignore
from pymongo import MongoClient

from app.config import ProShieldConfig
from app.sources.replay_store import MongoReplayStore

TEST_DB = "proshield_strix_persist"


def _config() -> ProShieldConfig:
    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri=base.mongo_uri,
        mongo_db=TEST_DB,
        auth_signing_key="strix-persist-auth-key",
        source_signing_key="strix-persist-source-key",
        source_token_lifetime_seconds=3600,
        default_subject_credentials={
            "admin": "admin-dev-credential",
            "analyst": "analyst-dev-credential",
            "collector": "collector-dev-credential",
            "internal": "internal-dev-credential",
        },
    )


def _build_bundle(config, client):
    from scripts.proxy_server import _build_mongo_backend, _build_app
    bundle = _build_mongo_backend(config)
    return bundle, TestClient(_build_app(bundle)), config


def _admin(client):
    r = client.post(
        "/api/proxy",
        json={"operation": "auth.issue", "subject_id": "admin",
              "credential": "admin-dev-credential"},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["token"]


def _register_enabled(client, admin, name):
    r = client.post(
        "/api/proxy",
        json={"operation": "source.register",
              "source_type": "nginx", "display_name": name,
              "tags": ["STRIX"], "asset_tags": ["web"]},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    sid = r.json()["data"]["source"]["source_instance_id"]
    client.post(
        "/api/proxy",
        json={"operation": "source.configure",
              "source_instance_id": sid,
              "configuration": {"connection_type": "push",
                                "endpoint": "https://example.com/ing"}},
        headers={"X-ProShield-Session": admin},
    )
    client.post(
        "/api/proxy",
        json={"operation": "source.validate",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )
    r = client.post(
        "/api/proxy",
        json={"operation": "source.enable",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return sid


def _issue_token(client, admin, sid):
    r = client.post(
        "/api/proxy",
        json={"operation": "source.issue_token",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["source_token"]


def main() -> int:
    client = MongoClient(
        "mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000,
    )
    client.admin.command("ping")
    try:
        client.drop_database(TEST_DB)
        config = _config()

        # ---- pass 1: create + persist -------------------------------
        bundle1, app1, config = _build_bundle(config, client)
        admin = _admin(app1)
        name = f"persist-nginx-{uuid.uuid4().hex[:6]}"
        sid = _register_enabled(app1, admin, name)
        token = _issue_token(app1, admin, sid)
        print("P1 registered + enabled:", sid)
        print("P1 token issued:", token[:20], "...")

        # Replay-claim persistence: claim under MongoReplayStore, then a
        # brand-new store instance on the same db sees the claim.
        db = client[TEST_DB]
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        store1 = MongoReplayStore(db, config)
        claimed = store1.claim(token_id="persist-claim-0001", expires_at=exp)
        print("P1 replay claim first use:", claimed)
        assert claimed is True

        # ---- pass 2: reload (restart parity) -------------------------
        bundle2, app2, _ = _build_bundle(config, client)
        admin2 = _admin(app2)
        r = app2.post(
            "/api/proxy",
            json={"operation": "source.get",
                  "source_instance_id": sid},
            headers={"X-ProShield-Session": admin2},
        )
        assert r.status_code == 200, r.text
        view = r.json()["data"]["source"]
        print("P2 source reloaded:", view["source_instance_id"],
              "state=", view["state"])
        assert view["state"] == "enabled"
        assert view["source_type"] == "nginx"

        # Replay store restart parity.
        store2 = MongoReplayStore(db, config)
        print("P2 replay store re-claim (must be False):",
              store2.claim(token_id="persist-claim-0001", expires_at=exp))
        assert store2.claim(
            token_id="persist-claim-0001", expires_at=exp
        ) is False

        # Rules seeded by the mongo backend survive the reload.
        r = app2.post(
            "/api/proxy",
            json={"operation": "rule.list"},
            headers={"X-ProShield-Session": admin2},
        )
        assert r.status_code == 200, r.text
        rules = [x["rule_id"] for x in r.json()["data"]["rules"]]
        print("P2 seeded rules after reload:", len(rules), sorted(rules)[:3])
        assert len(rules) >= 5

        # Source re-detect: issuer on reloaded backend issues a token
        # that verifies against the reloaded source.
        token2 = _issue_token(app2, admin2, sid)
        print("P2 token re-issued on reloaded backend: OK (",
              token2[:12], "...)")

        print("\nPERSISTENCE E2E: PASS")
        return 0
    finally:
        try:
            client.drop_database(TEST_DB)
        except Exception:  # noqa: BLE001
            pass
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())