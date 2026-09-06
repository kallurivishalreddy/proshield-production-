"""STRIX D-2 / D-3 wire-boundary regression tests.

Covers the two confirmed transport defects from
STRIX-PROSHIELD-ISSUE-REGISTER.md:

* D-2 - ``InboundIngressProxy._extract_token`` case-sensitive header
        lookup.  A real HTTP server (Starlette / FastAPI / uvicorn /
        reverse proxy) lowercases header keys; the ingress must still
        find the token.
* D-3 - the analyst-plane credential header is dropped when the HTTP
        listener delivers it lowercased; the listener must promote it
        back to the canonical ``X-ProShield-Credential`` case so
        ``SecureProxy._handle_auth_issue`` can read it.

Both are exercised at the *real* FastAPI wire boundary via
``TestClient`` (the same boundary the browser and a deployed
ingress listener use).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import proxy_server  # noqa: E402
from scripts import ingress_server  # noqa: E402


@pytest.fixture()
def shared_config() -> "proxy_server.ProShieldConfig":
    """A single config shared by BOTH planes.

    Production deployments wire the analyst plane and the ingress
    plane with the same ``PROSHIELD_SOURCE_SIGNING_KEY`` so that a
    token issued by ``source.issue_token`` on the analyst plane
    verifies on the ingress plane.  The fixture sets a deterministic
    key and builds one shared config.
    """
    import os
    os.environ.setdefault(
        "PROSHIELD_SOURCE_SIGNING_KEY", "strix-test-source-key-0001"
    )
    os.environ.setdefault(
        "PROSHIELD_AUTH_SIGNING_KEY", "strix-test-auth-key-0001"
    )
    return proxy_server._build_config(
        argparse.Namespace(seed_credentials=True)
    )


@pytest.fixture()
def proxy_client(shared_config) -> TestClient:
    """Fresh analyst-plane listener with seeded admin/analyst creds."""
    bundle = proxy_server._build_memory_backend(shared_config)
    return TestClient(proxy_server._build_app(bundle))


@pytest.fixture()
def ingress_client(shared_config) -> TestClient:
    """Memory-backend ingress listener (D-4 listener) sharing the
    same source signing key as the analyst plane."""
    bundle = ingress_server._build_memory_ingress(shared_config)
    return TestClient(ingress_server._build_app(bundle))


def _register_enabled_nginx_source(
    client, *, admin_token: str, source_type: str = "nginx",
) -> str:
    """Register/configure/validate/enable an nginx source, return sid."""
    sid = client.post(
        "/api/proxy",
        json={"operation": "source.register",
              "source_type": source_type,
              "display_name": f"strix-d2-{source_type}"},
        headers={"X-ProShield-Session": admin_token},
    ).json()["data"]["source"]["source_instance_id"]
    client.post(
        "/api/proxy",
        json={"operation": "source.configure",
              "source_instance_id": sid,
              "configuration": {
                  "connection_type": "push",
                  "endpoint": "https://example.com/api/ingest",
              }},
        headers={"X-ProShield-Session": admin_token},
    )
    client.post(
        "/api/proxy",
        json={"operation": "source.validate",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    client.post(
        "/api/proxy",
        json={"operation": "source.enable",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    )
    return sid


def _issue_ingress_token(client, *, admin_token: str, sid: str) -> str:
    return client.post(
        "/api/proxy",
        json={"operation": "source.issue_token",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin_token},
    ).json()["data"]["source_token"]


# D-2 (case-insensitive ingress headers) full-plane electric tests run
# in tests/integration/test_strix_ingress_wire.py because they need a
# shared source store (MongoDB) between the analyst and ingress planes,
# exactly as production wires them.

class TestD3CredentialHeaderTransport:
    """D-3: header-only credential must authenticate over the wire."""

    def test_canonical_case_header_accepted(self, proxy_client) -> None:
        r = proxy_client.post(
            "/api/proxy",
            json={"operation": "auth.issue", "subject_id": "analyst"},
            headers={"X-ProShield-Credential": "analyst-dev-credential"},
        )
        assert r.status_code == 200, r.text
        assert "token" in r.json()["data"]

    def test_lowercase_canonical_header_accepted(self, proxy_client) -> None:
        r = proxy_client.post(
            "/api/proxy",
            json={"operation": "auth.issue", "subject_id": "analyst"},
            headers={"x-proshield-credential": "analyst-dev-credential"},
        )
        assert r.status_code == 200, r.text
        assert "token" in r.json()["data"]

    def test_body_credential_still_accepted(self, proxy_client) -> None:
        r = proxy_client.post(
            "/api/proxy",
            json={"operation": "auth.issue", "subject_id": "analyst",
                  "credential": "analyst-dev-credential"},
        )
        assert r.status_code == 200, r.text

    def test_missing_credential_rejected(self, proxy_client) -> None:
        r = proxy_client.post(
            "/api/proxy",
            json={"operation": "auth.issue", "subject_id": "analyst"},
        )
        assert r.status_code == 401, r.text
        assert r.json()["error"]["message"] == "credential required"

    def test_body_credential_does_not_leak_into_body(self, proxy_client) -> None:
        r = proxy_client.post(
            "/api/proxy",
            json={"operation": "auth.issue", "subject_id": "analyst",
                  "credential": "analyst-dev-credential"},
        )
        assert r.status_code == 200, r.text
        # Ensure the secret is not echoed in the response.
        assert "analyst-dev-credential" not in r.text


class TestIngressListenerPlaneSeparation:
    """The ingress listener must NOT expose analyst ops or the frontend."""

    def test_frontend_not_served_by_ingress(self, ingress_client) -> None:
        r = ingress_client.get("/static/login.html")
        assert r.status_code == 404

    def test_analyst_op_not_exposed(self, ingress_client) -> None:
        r = ingress_client.post("/api/ingress",
                                json={"operation": "source.list"})
        assert r.status_code in (400, 401)