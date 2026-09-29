"""FINAL pre-backend rehearsal: real HTTP scenario A + B on ONE shared memory stack.

Spins BOTH planes in-process on real sockets sharing ONE FakeDatabase
and ONE signing-key pair (production topology, loopback transport):

  analyst plane : 127.0.0.1:18088 (/api/proxy, SecureProxy)
  ingress plane : 127.0.0.1:18089 (/api/ingress, InboundIngressProxy + LivePipeline)

Flow:
  1. auth.issue admin+analyst on the analyst plane
  2. source.register/configure/validate/enable (capability=nginx)
  3. source.issue_token -> scenario A: nginx authentication_failure
     (matches NGINX-AUTH-FAILURE-001 + NGINX-AUTH-BRUTEFORCE-001)
     over the REAL ingress HTTP boundary
  4. scenario B: nginx tls_anomaly (no shipped rule matches) over the
     SAME boundary -> accepted, zero detections (Event != Detection)
  5. read back detection.list / correlation.list / case.list /
     timeline.build_for_incident / overview.summary through the analyst
     plane and print the evidence chain.

Evidence JSON is written to final_rehearsal_evidence.json.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from app.config import ProShieldConfig  # noqa: E402
from scripts import proxy_server, ingress_server  # noqa: E402

ANALYST_PORT = 18088
INGRESS_PORT = 18089
ANALYST = f"http://127.0.0.1:{ANALYST_PORT}"
INGRESS = f"http://127.0.0.1:{INGRESS_PORT}"

AUTH_KEY = "final-rehearsal-auth-key-2026"
SOURCE_KEY = "final-rehearsal-source-key-2026"


def _config() -> ProShieldConfig:
    import os
    os.environ["PROSHIELD_AUTH_SIGNING_KEY"] = AUTH_KEY
    os.environ["PROSHIELD_SOURCE_SIGNING_KEY"] = SOURCE_KEY
    import argparse
    return proxy_server._build_config(
        argparse.Namespace(seed_credentials=True, backend="memory")
    )


def main() -> int:
    import scripts.proxy_server as ps
    import scripts.ingress_server as ings

    config = _config()
    # ONE shared analyst bundle (memory FakeDatabase + SecureProxy).
    analyst_bundle = ps._build_memory_backend(config)
    db = analyst_bundle.detection_repo._db

    # Ingress bundle sharing the SAME db + signing keys so the analyst
    # plane can read what the ingress plane persists.
    from app.sources.registry import SourceRegistry
    from app.sources.repository import SourceRepository
    from app.sources.trust import SourceIdentityTokenVerifier
    from app.ingestion.service import SecurityEventIngestionService
    from app.persistence.security_event_repository import SecurityEventRepository
    from app.persistence.telemetry import SourceTelemetryStore
    from app.sources.ingress import InboundIngressProxy

    repo = SourceRepository(db=db, config=config)
    verifier = SourceIdentityTokenVerifier.from_secret(
        config.source_signing_key,
        max_lifetime_seconds=config.source_token_lifetime_seconds,
        source_resolver=lambda sid: repo.get(sid),
        replay_store=ings._MemoryReplayStore(),
    )
    ingestion = SecurityEventIngestionService(
        SecurityEventRepository(db=db, config=config), config
    )
    telemetry = SourceTelemetryStore(db=db, config=config)
    telemetry.ensure_ready()
    ingress_proxy = InboundIngressProxy(
        config=config,
        registry=SourceRegistry(),
        token_verifier=verifier,
        ingestion_service=ingestion,
        authoritative_source_resolver=lambda sid: repo.get(sid),
        telemetry_recorder=telemetry,
    )
    # Memory FakeCollection.update_one lacks upsert/$inc/$max support, so
    # the shared SourceTelemetryStore counters cannot persist in this
    # harness. Use a tiny dict-backed recorder with the same method
    # names; the product Mongo path is covered by verify_live_capability.
    class _RehearsalTelemetry:
        def __init__(self):
            self.counts = {"received": 0, "accepted": 0, "rejected": 0,
                           "errors": 0}

        def record_received(self, sid, **kw):
            self.counts["received"] += int(kw.get("count", 1))

        def record_accepted(self, sid, **kw):
            self.counts["accepted"] += int(kw.get("count", 1))

        def record_rejected(self, sid, **kw):
            self.counts["rejected"] += int(kw.get("count", 1))

        def record_error(self, sid, **kw):
            self.counts["errors"] += 1

    rehearsal_telemetry = _RehearsalTelemetry()
    ingress_proxy._telemetry_recorder = rehearsal_telemetry
    pipeline = ings._build_ingress_pipeline(config, db, ingestion)
    ingress_bundle = ings._IngressBundle(
        config=config, ingress=ingress_proxy,
        backend_kind="memory", pipeline=pipeline,
    )

    # Wire the pipeline case-creation path to the SAME notification
    # sink the analyst plane uses, so pipeline-created cases emit the
    # same notification a UI-created case would (production parity).
    try:
        pipeline._incident_service._notification_sink = (
            analyst_bundle.incident_service._notification_sink
        )
    except AttributeError:
        pass
    analyst_app = ps._build_app(analyst_bundle)
    ingress_app = ings._build_app(ingress_bundle)
    servers = [
        uvicorn.Server(uvicorn.Config(
            analyst_app, host="127.0.0.1", port=ANALYST_PORT, log_level="error")),
        uvicorn.Server(uvicorn.Config(
            ingress_app, host="127.0.0.1", port=INGRESS_PORT, log_level="error")),
    ]
    threads = [threading.Thread(target=s.run, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for s in servers:
        for _ in range(100):
            if s.started:
                break
            time.sleep(0.1)
    assert all(s.started for s in servers), "uvicorn planes did not start"

    from app.domain.uuid7 import uuid7 as _uuid7

    def post(url, payload, headers=None):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def px(op, body=None, session=None):
        h = {}
        if session:
            h["X-ProShield-Session"] = session
        return post(f"{ANALYST}/api/proxy",
                    {"operation": op, **(body or {})}, h)

    def ig(events, token):
        return post(f"{INGRESS}/api/ingress",
                    {"operation": "source.ingest", "events": events},
                    {"Authorization": f"Bearer {token}"})

    ev = {"evidence": {}, "checks": []}

    def check(name, ok, detail=""):
        ev["checks"].append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})
        print(("PASS " if ok else "FAIL ") + name
              + ((" :: " + str(detail)[:200]) if detail and not ok else ""), flush=True)

    # 1. auth
    st, admin_b = px("auth.issue", {"subject_id": "admin",
                                    "credential": "admin-dev-credential"})
    st2, analyst_b = px("auth.issue", {"subject_id": "analyst",
                                       "credential": "analyst-dev-credential"})
    check("auth.issue.admin+analyst", st == 200 and st2 == 200)
    admin = admin_b["data"]["token"]
    analyst = analyst_b["data"]["token"]

    # 2. demo capability + source instance (nginx, reusable, no subconnector)
    st, b = px("source.register", {
        "source_type": "nginx",
        "display_name": "final-rehearsal-nginx",
        "description": "final pre-backend rehearsal source",
        "tags": ["FINAL", "REHEARSAL"], "asset_tags": ["web"],
    }, session=admin)
    check("source.register", st == 200 and b.get("data", {}).get("source"))
    src = b["data"]["source"]
    sid = src["source_instance_id"]
    ev["evidence"]["source"] = {
        "source_instance_id": sid, "human_id": src.get("human_id"),
        "source_type": src.get("source_type"), "state": src.get("state"),
    }
    check("source.human_id.SRC", bool(src.get("human_id", "").startswith("SRC-")),
          src.get("human_id"))
    check("capability.reusable.no_subconnector",
          src.get("source_type") == "nginx" and "subconnector" not in json.dumps(src).lower())
    for op, body in [
        ("source.configure", {"source_instance_id": sid, "configuration": {
            "connection_type": "push", "endpoint": "https://edge.example.com/ingest"}}),
        ("source.validate", {"source_instance_id": sid}),
        ("source.enable", {"source_instance_id": sid}),
    ]:
        st, b = px(op, body, session=admin)
        check(op, st == 200, json.dumps(b)[:200])

    def fresh_token():
        st, b = px("source.issue_token", {"source_instance_id": sid}, session=admin)
        assert st == 200, b
        return b["data"]["source_token"]

    # 3. SCENARIO A: matches NGINX-AUTH-FAILURE-001 (+ BRUTEFORCE-001)
    attacker = "203.0.113.66"
    nonce = f"{int(time.time()) % 0xFFFFFFFF:08x}"
    sent_a = []
    ok_a = True
    for i in range(4):
        eid = str(_uuid7())
        sent_a.append(eid)
        st, b = ig([{
            "event_id": eid, "event_type": "authentication_failure",
            "source_ip": attacker, "endpoint": "/api/login",
            "account": {"id": f"u{i % 2}"},
            "details": {"status_code": 401, "http_method": "POST"},
            "source_event_id": f"final-a-{nonce}-{i}",
        }], fresh_token())
        data = b.get("data", {})
        if not (st == 200 and eid in (data.get("accepted_event_ids") or [])):
            ok_a = False
            check(f"scenarioA.ingest[{i}]", False, json.dumps(b)[:250])
    check("scenarioA.4_events_accepted", ok_a)
    ev["evidence"]["scenarioA"] = {"attacker": attacker, "event_ids": sent_a}

    # 4. SCENARIO B: tls_anomaly -> NO shipped rule matches
    eid_b = str(_uuid7())
    st, b = ig([{
        "event_id": eid_b, "event_type": "tls_anomaly",
        "source_ip": "198.51.100.77", "endpoint": "/api/tls",
        "details": {"reason": "certificate_cn_mismatch"},
        "source_event_id": f"final-b-{nonce}",
    }], fresh_token())
    data = b.get("data", {})
    check("scenarioB.event_accepted",
          st == 200 and eid_b in (data.get("accepted_event_ids") or []),
          json.dumps(b)[:250])
    ev["evidence"]["scenarioB"] = {"event_id": eid_b, "event_type": "tls_anomaly"}

    time.sleep(2.0)

    # 5. detections: A fired, B did not
    st, b = px("detection.list",
               {"event_ids": sent_a, "limit": 50} if False else {"limit": 200},
               session=analyst)
    dets = b.get("data", {}).get("detections", [])
    dets_a = [d for d in dets if d.get("event_id") in sent_a]
    rules_a = sorted({d.get("rule_id") for d in dets_a})
    check("scenarioA.detections_fired", len(dets_a) >= 4,
          f"matched={len(dets_a)}/4 rules={rules_a}")
    check("scenarioA.rule_attribution_NGINX-AUTH-FAILURE-001",
          "NGINX-AUTH-FAILURE-001" in rules_a, str(rules_a))
    ev["evidence"]["scenarioA"]["detections"] = [
        {"detection_id": d.get("detection_id"), "human_id": d.get("human_id"),
         "rule_id": d.get("rule_id"), "event_id": d.get("event_id"),
         "severity": d.get("severity"),
         "source_instance_id": d.get("source_instance_id")} for d in dets_a[:8]]
    dets_b = [d for d in dets if d.get("event_id") == eid_b]
    check("scenarioB.no_false_detection", len(dets_b) == 0,
          f"false_detections={len(dets_b)}")
    ev["evidence"]["scenarioB"]["false_detections"] = len(dets_b)

    # human IDs stable + cross-linked
    det_ids = [d.get("detection_id") for d in dets_a]
    check("human_ids.DET", all((d.get("human_id") or "").startswith("DET-") for d in dets_a),
          str([d.get("human_id") for d in dets_a[:4]]))

    # 6. correlation + case
    st, b = px("correlation.list", {"limit": 50}, session=analyst)
    corrs = b.get("data", {}).get("correlations", [])
    mine = [c for c in corrs
            if any(e in (c.get("event_ids") or []) for e in sent_a)]
    check("correlation.cluster_produced", len(mine) >= 1, f"count={len(mine)}")
    corr = mine[0] if mine else None
    if corr:
        ev["evidence"]["correlation"] = {
            "correlation_id": corr.get("correlation_id"),
            "human_id": corr.get("human_id"),
            "pattern_id": corr.get("pattern_id"),
            "key": corr.get("key"), "count": corr.get("count"),
            "confidence": corr.get("confidence"),
            "detection_ids": (corr.get("detection_ids") or [])[:8],
        }
        check("correlation.human_id_CORR",
              bool((corr.get("human_id") or "").startswith("CORR-")), corr.get("human_id"))

    st, b = px("case.list", {"limit": 50}, session=admin)
    cases = b.get("data", {}).get("cases", [])
    my_case = None
    for c in cases:
        ev_ids = ((c.get("evidence") or {}).get("event_ids")) or []
        if any(e in ev_ids for e in sent_a):
            my_case = c
            break
    check("case.created_from_pipeline", my_case is not None, f"cases={len(cases)}")
    if my_case:
        ev["evidence"]["case"] = {
            "incident_id": my_case.get("incident_id"),
            "human_id": my_case.get("human_id"),
            "title": my_case.get("title"), "state": my_case.get("state"),
            "severity": my_case.get("severity"),
            "attribution": my_case.get("attribution"),
            "evidence": my_case.get("evidence"),
        }
        check("case.human_id_CASE",
              bool((my_case.get("human_id") or "").startswith("CASE-")),
              my_case.get("human_id"))
        # NB: pipeline-owned cases carry created_by=pipeline, so the
        # analyst role (CASE_READ without CASE_READ_ANY) is correctly
        # denied by the IDOR boundary; use the admin session which
        # holds CASE_READ_ANY (same ownership rule the UI enforces).
        st, b = px("timeline.build_for_incident",
                   {"incident_id": my_case["incident_id"]}, session=admin)
        items = (b.get("data", {}) or {}).get("items", [])
        kinds = sorted({i.get("kind") for i in items})
        check("timeline.per_incident_items", st == 200 and len(items) >= 4,
              f"kinds={kinds} count={len(items)}")
        ev["evidence"]["timeline"] = {"kinds": kinds, "count": len(items),
                                      "sample": items[:6]}
        # notification produced for the new case. NB: the memory-harness
        # FakeCollection._match cannot evaluate the product $or audience
        # query, so notification.list reads 0 rows in THIS harness; the
        # sink write itself is asserted directly below. The product
        # Mongo path is covered by tests/unit/test_capability_patch.py.
        st, b = px("notification.list", {"limit": 20}, session=admin)
        notifs = (b.get("data", {}) or {}).get("notifications", [])
        linked = [n for n in notifs if n.get("incident_id") == my_case["incident_id"]]
        sink_rows = list(
            analyst_bundle.notification_service.repository._collection.find({}))
        sink_linked = [d for d in sink_rows
                       if d.get("incident_id") == my_case["incident_id"]]
        ev["evidence"]["notification_sink_rows"] = len(sink_linked)
        check("notification.case_created", len(sink_linked) >= 1,
              f"sink_rows={len(sink_linked)} wire_list={len(linked)}")

    # 7. overview + health + telemetry through the same analyst plane
    st, b = px("overview.summary", {}, session=analyst)
    ev["evidence"]["overview"] = b.get("data", {})
    check("overview.summary", st == 200)
    st, b = px("source.get", {"source_instance_id": sid}, session=analyst)
    tel = ((b.get("data", {}) or {}).get("source") or {}).get("ingest_telemetry")
    ev["evidence"]["telemetry"] = {"product_store": tel,
                                   "harness_recorder": rehearsal_telemetry.counts}
    check("source.telemetry_counters",
          rehearsal_telemetry.counts.get("accepted", 0) >= 5,
          json.dumps(rehearsal_telemetry.counts))

    with open(ROOT / "final_rehearsal_evidence.json", "w", encoding="utf-8") as fh:
        json.dump(ev, fh, indent=1, default=str)

    failed = [c for c in ev["checks"] if not c["ok"]]
    print(f"\nFINAL REHEARSAL: {len(ev['checks']) - len(failed)}/{len(ev['checks'])} passed")
    for s in servers:
        s.should_exit = True
    for t in threads:
        t.join(timeout=5)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
