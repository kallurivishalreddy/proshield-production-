"""Detection boundary test: positive, no-matching-rule, benign.

Drives the REAL application path used by the deployment:
registered source -> telemetry -> DetectionPipeline (rule registry +
DetectionEngine + DetectionRepository) -> persisted detections.

* CASE 1 (positive):  nginx authentication_failure fires
  NGINX-AUTH-FAILURE-001.
* CASE 2 (no rule):   nginx unknown/suspicious event type that no
  shipped rule matches -> INGESTED ONLY, zero detections.
* CASE 3 (benign):    nginx authentication_success -> zero detections.
* CASE 4 (cross-source isolation): iam authentication_failure does
  NOT fire the NGINX rule (no cross-source false positive).
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # type: ignore

from scripts import proxy_server  # noqa: E402
from app.domain.security_event import (  # noqa: E402
    SecurityEvent, SecurityEventProvenance,
)
from app.domain.uuid7 import uuid7  # noqa: E402
from app.detection import DetectionEngine, DetectionPipeline  # noqa: E402
from app.ingestion.service import SecurityEventIngestionService  # noqa: E402


def _event(*, source, event_type, event_id, source_ip="198.51.100.7",
           destination="10.0.0.1", endpoint="/auth/login", status_code=401,
           account="alice"):
    now = datetime.now(timezone.utc)
    return SecurityEvent(
        event_id=event_id,
        event_time=now,
        ingested_at=now,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        destination=destination,
        endpoint=endpoint,
        account={"id": account},
        details={"status_code": status_code, "request_method": "POST"},
        provenance=SecurityEventProvenance(
            collector="strix-test-collector",
            source_event_id=event_id,
        ),
    )


def main() -> int:
    bundle = proxy_server._build_memory_backend(
        proxy_server._build_config(
            argparse.Namespace(seed_credentials=True)
        )
    )
    app = proxy_server._build_app(bundle)
    client = TestClient(app)
    admin = client.post(
        "/api/proxy",
        json={"operation": "auth.issue", "subject_id": "admin",
              "credential": "admin-dev-credential"},
    ).json()["data"]["token"]
    r = client.post(
        "/api/proxy",
        json={"operation": "source.register", "source_type": "nginx",
              "display_name": f"det-boundary-{uuid.uuid4().hex[:4]}",
              "tags": ["STRIX"]},
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
    client.post(
        "/api/proxy",
        json={"operation": "source.enable",
              "source_instance_id": sid},
        headers={"X-ProShield-Session": admin},
    )

    ingestion = SecurityEventIngestionService(bundle.event_repo, bundle.config)
    pipeline = DetectionPipeline(
        ingestion_service=ingestion,
        detection_engine=DetectionEngine(bundle.rule_registry),
        detection_repository=bundle.detection_repo,
    )

    def run_case(label, source, event_type, extra=None):
        ev = _event(source=source, event_type=event_type,
                    event_id=str(uuid7()), **(extra or {}))
        result = pipeline.run(ev)
        dets = result.persisted_detections
        print(f"\n[{label}] source={source} event_type={event_type}")
        print(f"  event_id: {ev.event_id[:24]}...")
        print(f"  detections fired: {len(dets)}")
        for d in dets:
            print(f"    {d.detection_id} rule={d.rule_id}")
        return dets

    dets1 = run_case("POSITIVE", "nginx", "authentication_failure")
    assert len(dets1) >= 1
    assert any(d.rule_id == "NGINX-AUTH-FAILURE-001"
               for d in dets1), "expected NGINX-AUTH-FAILURE-001"

    dets2 = run_case("NO-MATCH", "nginx", "tls_anomaly")
    assert len(dets2) == 0, "no shipped NGINX rule matches tls_anomaly"

    dets3 = run_case("BENIGN", "nginx", "authentication_success")
    assert len(dets3) == 0, "benign must not fire a detection"

    dets4 = run_case("IAM-NO-NGINX", "iam", "authentication_failure")
    assert len(dets4) == 0, (
        "iam auth failure must NOT fire the NGINX-AUTH-FAILURE rule"
    )

    print("\nDETECTION BOUNDARY TEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())