"""Phase 4.9 — Inbound ingress proxy tests."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict

import pytest

from app.config import ProShieldConfig
from app.domain.security_event import SecurityEvent
from app.ingestion.service import SecurityEventIngestionService
from app.persistence.security_event_repository import (
    SecurityEventRepository,
)
from app.sources.errors import SourceIdentityTokenError
from app.sources.ingress import (
    INGRESS_HEADER_AUTHORIZATION,
    INGRESS_HEADER_TOKEN,
    OP_HEALTH,
    OP_INGEST,
    InboundIngressProxy,
    IngressRequest,
)
from app.sources.models import (
    SourceConnectionType,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceState,
    SourceType,
)
from app.sources.registry import SourceRegistry
from app.sources.repository import SourceRepository
from app.sources.trust import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenVerifier,
    new_development_signing_key,
)
from tests.unit._phase49_fakes import FakeDatabase


_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = new_development_signing_key()


class _InMemoryReplayStore:
    """R-1 test double: server-side single-use token store."""

    def __init__(self) -> None:
        self._used: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim(self, *, token_id, expires_at):
        with self._lock:
            if token_id in self._used:
                return False
            self._used[token_id] = expires_at
            return True

    def release(self, token_id):
        with self._lock:
            self._used.pop(token_id, None)

    def gc(self, now):
        with self._lock:
            expired = [
                tid for tid, exp in self._used.items() if exp <= now
            ]
            for tid in expired:
                del self._used[tid]
            return len(expired)


def _config() -> ProShieldConfig:
    return ProShieldConfig(
        env_name="test",
        log_level="INFO",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db="proshield_test",
        mongo_collection_events="security_events",
        ingest_max_body_bytes=16_384,
        ingest_max_details_bytes=8_192,
        source_signing_key=_SECRET,
        source_token_lifetime_seconds=3600,
        ingress_rate_limit_per_minute=600,
        ingress_max_request_bytes=32_768,
        ingress_max_response_bytes=1_048_576,
        ingress_event_rate_limit_per_minute=600,
        ingress_max_events_per_request=100,
        ingress_replay_store_required=True,
    )


def _enabled_nginx_instance() -> SourceInstance:
    cfg = SourceInstanceConfiguration(
        connection_type=SourceConnectionType.PUSH,
        endpoint="https://example.com/api/ingest",
        proxy_path="",
        destination="",
        asset_tags=("web-app",),
        tags=(),
        references=(),
        secret_ref="",
    )
    return SourceInstance(
        source_instance_id=(
            "src-0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12-prod"
        ),
        source_type=SourceType.NGINX,
        source="nginx",
        display_name="Prod Nginx",
        description="",
        configuration=cfg,
        state=SourceState.ENABLED,
        created_by="user-admin-001",
        created_at=_NOW,
        updated_by="user-admin-001",
        updated_at=_NOW,
        last_validation_at=_NOW,
        tags=(),
        asset_tags=("web-app",),
        retired_at=None,
    )


def _ingestion_service() -> SecurityEventIngestionService:
    repo = SecurityEventRepository(FakeDatabase(), _config())
    return SecurityEventIngestionService(repo, _config())


def _proxy(
    registry: SourceRegistry = None,
    ingestion_service: SecurityEventIngestionService = None,
    rate_limit: int = 600,
) -> InboundIngressProxy:
    config = _config()
    object.__setattr__(
        config, "ingress_rate_limit_per_minute", rate_limit,
    )
    return InboundIngressProxy(
        config=config,
        registry=registry or SourceRegistry(),
        token_verifier=SourceIdentityTokenVerifier.from_secret(
            _SECRET,
            max_lifetime_seconds=3600,
            # ST-02 fail-closed: tests wire a replay store so
            # tokens can be replay-claimed during the test.
            replay_store=_InMemoryReplayStore(),
        ),
        ingestion_service=(
            ingestion_service or _ingestion_service()
        ),
    )


def _issue(
    issuer: SourceIdentityTokenIssuer,
    instance: SourceInstance,
) -> str:
    return issuer.pack(issuer.issue(
        source_instance_id=instance.source_instance_id,
        source_type=instance.source_type,
    ))


def _issuer() -> SourceIdentityTokenIssuer:
    return SourceIdentityTokenIssuer(
        secret=_SECRET, lifetime_seconds=3600,
    )


class TestIngressBasics:
    def test_unknown_operation_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation="bogus.op",
            headers={}, body=None,
        ))
        assert resp.status == 400
        assert "unknown_operation" in resp.body["error"]["code"]

    def test_missing_operation_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation="",
            headers={}, body=None,
        ))
        assert resp.status == 400

    def test_oversized_request_rejected(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={},
            body={},
            body_bytes=10_000_000,
        ))
        assert resp.status == 400
        assert resp.body["error"]["code"] == "request_too_large"

    def test_health_is_open(self) -> None:
        proxy = _proxy()
        resp = proxy.handle(IngressRequest(
            operation=OP_HEALTH, headers={}, body=None,
        ))
        assert resp.status == 200
        assert resp.body["ok"] is True
        assert "ingress" in resp.body["data"]["boundary"]


class TestIngressAuthAndIdentity:
    def test_missing_token_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST, headers={}, body={
                "events": [{
                    "event_type": "authentication_failure",
                    "source_ip": "203.0.113.10",
                }],
            },
        ))
        assert resp.status == 401
        assert "source_identity_token" in resp.body["error"]["code"]

    def test_token_for_unknown_instance_rejected(self) -> None:
        reg = SourceRegistry()
        proxy = _proxy(registry=reg)
        inst = _enabled_nginx_instance()
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 404
        assert "source_instance_not_found" in resp.body["error"]["code"]

    def test_token_for_disabled_instance_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance().model_copy(
            update={"state": SourceState.DISABLED}
        )
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 409
        assert "not_enabled" in resp.body["error"]["code"]

    def test_token_for_retired_instance_rejected(self) -> None:
        from datetime import datetime as _dt, timezone as _tz
        reg = SourceRegistry()
        inst = _enabled_nginx_instance().model_copy(
            update={
                "state": SourceState.RETIRED,
                "retired_at": _dt(2026, 8, 30, 13, 0, 0, tzinfo=_tz.utc),
            }
        )
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 410
        assert "retired" in resp.body["error"]["code"]

    def test_tampered_token_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        head, mid, tail = token.split(".")
        mid_chars = list(mid)
        mid_chars[0] = "A" if mid_chars[0] != "A" else "B"
        tampered = f"{head}.{''.join(mid_chars)}.{tail}"
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {tampered}",
            },
            body={"events": []},
        ))
        assert resp.status == 401

    def test_token_with_legacy_token_header(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_TOKEN: token},
            body={"events": []},
        ))
        assert resp.status == 200

    def test_token_in_body_field(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={},
            body={"source_token": token, "events": []},
        ))
        assert resp.status == 200

    def test_token_wrong_source_type_rejected(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        from app.sources.models import SourceType as _ST
        forge = SourceIdentityTokenIssuer(
            secret=_SECRET, lifetime_seconds=3600,
        )
        fake_token = forge.pack(forge.issue(
            source_instance_id=inst.source_instance_id,
            source_type=_ST.WAF,
        ))
        proxy = _proxy(registry=reg)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {fake_token}",
            },
            body={"events": []},
        ))
        assert resp.status == 403
        assert "integrity" in resp.body["error"]["code"]


class TestIngressIngestion:
    def test_accepts_well_formed_event(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={
                "events": [{
                    "event_type": "authentication_failure",
                    "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f12",
                    "source_event_id": "src-001",
                    "event_time": "2026-08-30T12:00:00Z",
                    "source_ip": "203.0.113.10",
                    "endpoint": "/auth/login",
                    "asset": "web-app",
                    "account": {"id": "user-123"},
                    "details": {
                        "http_method": "POST",
                        "status_code": 401,
                    },
                }],
            },
        ))
        assert resp.status == 200
        body = resp.body["data"]
        assert len(body["accepted_event_ids"]) == 1
        assert body["rejected"] == []

    def test_rejects_unknown_event_type(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={
                "events": [{
                    "event_type": "totally-bogus-type",
                    "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f13",
                    "source_event_id": "src-002",
                    "event_time": "2026-08-30T12:00:00Z",
                }],
            },
        ))
        assert resp.status == 200
        body = resp.body["data"]
        assert body["accepted_event_ids"] == []
        assert len(body["rejected"]) == 1

    def test_rejects_non_dict_event(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": ["not-a-dict"]},
        ))
        assert resp.status == 200
        body = resp.body["data"]
        assert body["accepted_event_ids"] == []
        assert body["rejected"][0]["reason"] == "not-a-dict"

    def test_rejects_non_list_events(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": "not-a-list"},
        ))
        assert resp.status == 400
        assert resp.body["error"]["code"] == "validation_error"

    def test_empty_events_batch_is_ok(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg)
        token = _issue(_issuer(), inst)
        resp = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
            },
            body={"events": []},
        ))
        assert resp.status == 200
        assert resp.body["data"]["accepted_event_ids"] == []


class TestIngressRateLimit:
    def _ok_event(self, i: int) -> dict:
        """Helper: build a well-formed event with a unique
        event_id, for the ST-01 batch tests.
        """
        return {
            "event_type": "authentication_failure",
            "event_id": (
                f"0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5f{i:02x}"
            ),
            "event_time": "2026-08-30T12:00:00Z",
            "endpoint": "https://example.com/api/ingest",
            "asset": "web-app",
            "details": {"status_code": 401},
        }

    def test_rate_limit_blocks_after_budget(self) -> None:
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg, rate_limit=2)
        issuer = _issuer()
        # Each iteration issues a FRESH token (R-1 single-use
        # is enforced by the verifier's replay store; the
        # rate-limit budget is the per-source window).
        for _ in range(2):
            token = _issue(issuer, inst)
            r = proxy.handle(IngressRequest(
                operation=OP_INGEST,
                headers={
                    INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}",
                },
                body={"events": []},
            ))
            assert r.status == 200
        # 3rd request — must be rate-limited (budget=2).
        # Fresh token so R-1 doesn't reject before we
        # reach the rate-limit check.
        token3 = _issue(issuer, inst)
        r = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={
                INGRESS_HEADER_AUTHORIZATION: f"Bearer {token3}",
            },
            body={"events": []},
        ))
        assert r.status == 429
        assert "rate_limited" in r.body["error"]["code"]

    def test_st01_per_event_rate_limit_charges_full_batch(self) -> None:
        """ST-01: a request carrying N events must charge N
        units of the rate-limit budget, not 1.

        The per-source sliding window is charged
        ``1 + len(events)``: the leading ``1`` is the
        per-request cost (preserves the pre-Phase-4.9 burst
        behaviour); the ``len(events)`` term is the new
        per-event charge so a single request carrying N
        events cannot amplify the per-event limit.
        """
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        # budget=5: a 3-event request costs 1+3=4 units;
        # a follow-up 1-event request costs 1+1=2 units,
        # which would push the total to 6 > 5, so the
        # second request MUST be rate-limited.
        proxy = _proxy(registry=reg, rate_limit=5)
        issuer = _issuer()
        token = _issue(issuer, inst)
        r1 = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"events": [self._ok_event(i) for i in range(3)]},
        ))
        assert r1.status == 200
        assert len(r1.body["data"]["accepted_event_ids"]) == 3
        # Request 2: a single-event request now exceeds the
        # remaining 1-unit budget (1 request + 1 event = 2).
        token2 = _issue(issuer, inst)
        r2 = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {token2}"},
            body={"events": [self._ok_event(99)]},
        ))
        assert r2.status == 429
        assert "rate_limited" in r2.body["error"]["code"]

    def test_st01_per_request_event_cap_rejected(self) -> None:
        """ST-01: a request whose ``events`` array exceeds
        ``ingress_max_events_per_request`` is rejected with
        400 BEFORE the rate-limit budget is touched.
        """
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        reg.register(inst)
        proxy = _proxy(registry=reg, rate_limit=1000)
        issuer = _issuer()
        # Build a payload with 200 events. Default cap is 100.
        big_batch = [self._ok_event(i) for i in range(200)]
        token = _issue(issuer, inst)
        r = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"events": big_batch},
        ))
        assert r.status == 400
        assert r.body["error"]["code"] == "validation_error"
        assert "too many events" in r.body["error"]["message"]

    def test_st04_untrusted_endpoint_reconciled(self) -> None:
        """ST-04: source-reported ``endpoint`` that does NOT
        match the registered source configuration is recorded
        under ``details._untrusted_endpoint`` and is NOT
        promoted to the canonical ``endpoint`` field.
        """
        reg = SourceRegistry()
        inst = _enabled_nginx_instance()
        # Registered endpoint is "https://example.com/api/ingest".
        reg.register(inst)
        proxy = _proxy(registry=reg)
        issuer = _issuer()
        token = _issue(issuer, inst)
        r = proxy.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"events": [{
                "event_type": "authentication_failure",
                "event_id": "0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d5fa1",
                "event_time": "2026-08-30T12:00:00Z",
                "endpoint": "https://evil.example.com/leak",
                "asset": "web-app",
            }]},
        ))
        assert r.status == 200
        accepted_id = r.body["data"]["accepted_event_ids"][0]
        # The untrusted endpoint was recorded in details.
        repo = proxy._ingestion_service._repository  # type: ignore[attr-defined]
        ev = repo.get_by_event_id(accepted_id)
        assert ev is not None
        assert ev.details.get("_untrusted_endpoint") == (
            "https://evil.example.com/leak"
        )