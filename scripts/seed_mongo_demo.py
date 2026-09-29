"""
Phase 4 — integration/browser-test seeding for the Gemini frontend
validation against the REAL mongo-backed backend.

This is TEST SUPPORT ONLY. It builds the same mongo backend bundle the
proxy server builds (`scripts.proxy_server._build_mongo_backend`) and
drives the REAL documented pipeline:

    source.register/configure/validate/enable (via the HTTP wire ops of
    the RUNNING server) -> DetectionPipeline (ingestion -> rules ->
    detection persistence) -> CorrelationEngine -> correlation
    persistence -> IncidentService.create_case.

It never fabricates data beyond what those layers genuinely produce,
and it is idempotent-friendly (source registration uses a unique name).

Run AFTER `python -m scripts.proxy_server --backend mongo` is up:

    set PROSHIELD_AUTH_SIGNING_KEY=<hex32>
    set PROSHIELD_SOURCE_SIGNING_KEY=<hex32>
    python -m scripts.seed_mongo_demo --base-url http://127.0.0.1:8088
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import proxy_server  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.patterns import BruteForceClusteringPattern  # noqa: E402
from app.detection import DetectionEngine, DetectionPipeline  # noqa: E402
from app.ingestion.service import SecurityEventIngestionService  # noqa: E402
from app.domain.security_event import (  # noqa: E402
    SecurityEvent,
    SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7  # noqa: E402


def http_proxy(base_url: str, op: str, body: dict, token: str | None = None):
    payload = {"operation": op, **(body or {})}
    req = Request(
        f"{base_url}/api/proxy",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            **({"X-ProShield-Session": token} if token else {}),
        },
        method="POST",
    )
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    args = parser.parse_args()

    bundle = proxy_server._build_mongo_backend(
        proxy_server._build_config(
            argparse.Namespace(seed_credentials=True, backend="mongo")
        )
    )

    # ---- auth via the RUNNING server (same identity store / signing key)
    r = http_proxy(args.base_url, "auth.issue", {
        "subject_id": "admin", "credential": "admin-dev-credential",
    })
    admin_token = r["data"]["token"]
    r = http_proxy(args.base_url, "auth.issue", {
        "subject_id": "analyst", "credential": "analyst-dev-credential",
    })
    analyst_token = r["data"]["token"]
    print("[seed] authenticated admin + analyst")

    # ---- register + configure + validate + enable a real nginx source
    src_name = f"nginx-prod-{uuid.uuid4().hex[:6]}"
    r = http_proxy(args.base_url, "source.register", {
        "source_type": "nginx",
        "display_name": "Production NGINX Gateway",
        "description": "Seeded integration source (nginx)",
        "tags": ["PROD", "DMZ"],
        "asset_tags": ["api", "web"],
    }, token=admin_token)
    src_id = r["data"]["source"]["source_instance_id"]
    http_proxy(args.base_url, "source.configure", {
        "source_instance_id": src_id,
        "configuration": {"connection_type": "push", "endpoint": "/api/ingress",
                          "asset_tags": ["api", "web"]},
    }, token=admin_token)
    http_proxy(args.base_url, "source.validate", {"source_instance_id": src_id},
               token=admin_token)
    r = http_proxy(args.base_url, "source.enable", {"source_instance_id": src_id},
                   token=admin_token)
    print(f"[seed] source {src_name} state={r['data']['source']['state']}")

    # ---- second source instance on the SAME capability (multi-instance)
    r = http_proxy(args.base_url, "source.register", {
        "source_type": "nginx",
        "display_name": "Staging NGINX Gateway",
        "description": "Seeded integration source #2 (same capability)",
        "tags": ["STAGING"],
    }, token=admin_token)
    src2_id = r["data"]["source"]["source_instance_id"]
    http_proxy(args.base_url, "source.configure", {
        "source_instance_id": src2_id,
        "configuration": {"connection_type": "push", "endpoint": "/api/ingress"},
    }, token=admin_token)
    http_proxy(args.base_url, "source.validate", {"source_instance_id": src2_id},
               token=admin_token)
    http_proxy(args.base_url, "source.enable", {"source_instance_id": src2_id},
               token=admin_token)
    print(f"[seed] second source {src2_id} (same nginx capability)")

    # ---- drive the real detection pipeline
    ingestion = SecurityEventIngestionService(bundle.event_repo, bundle.config)
    detection_engine = DetectionEngine(bundle.rule_registry)
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=detection_engine,
        detection_repository=bundle.detection_repo,
    )

    now = datetime.now(timezone.utc)
    attacker_ip = "10.0.0.66"
    events: list[SecurityEvent] = []
    for i in range(8):
        ev_time = now - timedelta(seconds=10 - i)
        events.append(SecurityEvent(
            event_id=str(uuid7(timestamp_ms=int(ev_time.timestamp() * 1000))),
            event_time=ev_time,
            ingested_at=ev_time,
            source="nginx",
            event_type="authentication_failure",
            source_ip=attacker_ip,
            destination="auth.example.internal",
            endpoint="/auth/login",
            asset="auth-svc-01",
            details={"status_code": 401, "user_agent": "curl/8.0.0",
                     "method": "POST", "account_id": "user-123"},
            provenance=SecurityEventProvenance(
                collector="seed", source_event_id=f"seed-bf-{i}-{uuid.uuid4().hex[:6]}",
            ),
        ))
    sens_time = now - timedelta(seconds=1)
    events.append(SecurityEvent(
        event_id=str(uuid7(timestamp_ms=int(sens_time.timestamp() * 1000))),
        event_time=sens_time, ingested_at=sens_time,
        source="nginx", event_type="request_blocked",
        source_ip=attacker_ip, destination="web.example.internal",
        endpoint="/.env", asset="web-api-01",
        details={"status_code": 403, "user_agent": "curl/8.0.0"},
        provenance=SecurityEventProvenance(
            collector="seed", source_event_id=f"seed-sens-{uuid.uuid4().hex[:6]}",
        ),
    ))

    all_detections = []
    for ev in events:
        result = pipeline.run(ev, now=ev.event_time)
        all_detections.extend(result.persisted_detections)
    print(f"[seed] pipeline produced {len(all_detections)} detection(s) from {len(events)} event(s)")

    # ---- correlation over the real detections
    events_by_id = {ev.event_id: ev for ev in events}
    corr_engine = CorrelationEngine(patterns=[BruteForceClusteringPattern()])
    corr_result = corr_engine.run(all_detections, events_by_id, now=now)
    correlations = corr_result.correlations
    for c in correlations:
        bundle.correlation_repo.create(c)
    print(f"[seed] correlation engine produced {len(correlations)} correlation(s)")

    # ---- a real case referencing the real evidence
    attacker_events = [ev for ev in events if ev.source_ip == attacker_ip]
    case = bundle.incident_service.create_case(
        identity=bundle.identity_store.get("analyst"),
        title="Brute-force authentication burst from 10.0.0.66",
        summary=("8 authentication_failure events from 10.0.0.66 against "
                 "/auth/login; NGINX-CORR-BRUTEFORCE-001 fired."),
        events=attacker_events,
        detections=all_detections,
        correlations=correlations or [],
    )
    print(f"[seed] case created: {case.incident_id} state={case.state}")

    # ---- verify through the wire the UI uses
    r = http_proxy(args.base_url, "case.list", {"limit": 50}, token=analyst_token)
    print(f"[seed] case.list -> {len(r['data']['cases'])} case(s)")
    r = http_proxy(args.base_url, "detection.list",
                   {"rule_id": "NGINX-AUTH-FAILURE-001", "limit": 50},
                   token=analyst_token)
    print(f"[seed] detection.list -> {len(r['data']['detections'])} detection(s)")
    r = http_proxy(args.base_url, "correlation.list",
                   {"pattern_id": "NGINX-CORR-BRUTEFORCE-001", "limit": 50},
                   token=analyst_token)
    print(f"[seed] correlation.list -> {len(r['data']['correlations'])} correlation(s)")
    r = http_proxy(args.base_url, "overview.summary", {}, token=analyst_token)
    print(f"[seed] overview.summary -> {json.dumps(r['data'])}")
    print("[seed] SEED COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
