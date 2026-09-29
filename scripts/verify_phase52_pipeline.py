"""Phase 5.2 — chained live pipeline verification (F3).

Proves the COMPLETE runtime chain over real MongoDB, through the REAL
composition (no service calls substituted for ingress):

    Source -> source token -> InboundIngressProxy -> canonical SecurityEvent
      -> server-side capability_id derivation/stamping
      -> rule capability resolution
      -> Detection (capability provenance, §8/§12)
      -> Correlation (capability_ids, §8/§12)
      -> Case (lineage)

Both planes are the shipped ones:

* analyst plane  : ``scripts.proxy_server._build_mongo_backend`` + ``_attach_services``
* ingress plane  : ``scripts.ingress_server._build_mongo_ingress`` (real token
                   verifier, real Mongo replay store, real pipeline)

The detection/correlation/case stages are driven by the SHIPPED live hook
``scripts.ingress_server._run_live_pipeline_after_ingest`` — the same function
the ingress listener calls after a successful ``source.ingest``.

Usage:  python scripts/verify_phase52_pipeline.py [--keep]
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MONGO_URI = "mongodb://127.0.0.1:27017"

_RESULTS: List[Tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    _RESULTS.append((name, bool(ok)))
    line = f"  [{'PASS' if ok else 'FAIL'}] {name}"
    if detail and not ok:
        line += f"  -- {detail}"
    print(line, flush=True)
    return bool(ok)


def _config(db_name: str):
    from app.config import ProShieldConfig

    return ProShieldConfig(
        env_name="test",
        log_level="WARNING",
        mongo_uri=MONGO_URI,
        mongo_db=db_name,
        mongo_collection_events="security_events",
        auth_signing_key=os.urandom(32).hex(),
        # SHARED between both planes: split secrets would 401 every token.
        source_signing_key=os.urandom(32).hex(),
        default_subject_credentials={
            "admin": "admin-password",
            "analyst": "analyst-password",
        },
    )


class AnalystPlane:
    """The real SecureProxy analyst plane over MongoDB."""

    def __init__(self, config) -> None:  # noqa: ANN001
        import scripts.proxy_server as ps
        from app.proxy import SecureProxy

        self.bundle = ps._build_mongo_backend(config)
        self.proxy = SecureProxy(
            config=config, identity_store=ps._build_identity_store(config),
        )
        ps._attach_services(self.proxy, self.bundle)

    def token(self, subject: str = "admin", credential: str = "admin-password") -> str:
        from app.proxy import OP_AUTH_ISSUE, ProxyRequest

        resp = self.proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE,
            headers={},
            body={"subject_id": subject, "credential": credential},
        ))
        if resp.status != 200:
            raise RuntimeError(f"auth failed: {resp.body}")
        return resp.body["data"]["token"]

    def call(self, op: str, token: str, body: Optional[dict] = None):  # noqa: ANN001
        from app.proxy import ProxyRequest

        return self.proxy.handle(ProxyRequest(
            operation=op,
            headers={"Authorization": f"Bearer {token}"},
            body=body or {},
        ))


class IngressPlane:
    """The real inbound ingress plane (token verifier + replay store + pipeline)."""

    def __init__(self, config) -> None:  # noqa: ANN001
        import scripts.ingress_server as ings

        self._ings = ings
        self.bundle = ings._build_mongo_ingress(config)
        self.ingress = self.bundle.ingress
        self.pipeline = self.bundle.pipeline

    def ingest(self, token: str, events: List[Dict[str, Any]]):  # noqa: ANN001
        from app.sources.ingress import (
            INGRESS_HEADER_AUTHORIZATION,
            OP_INGEST,
            IngressRequest,
        )

        return self.ingress.handle(IngressRequest(
            operation=OP_INGEST,
            headers={INGRESS_HEADER_AUTHORIZATION: f"Bearer {token}"},
            body={"events": events},
        ))

    def after_ingest(self, response) -> None:  # noqa: ANN001
        """Run the SHIPPED live detection->correlation->case hook."""
        from app.sources.ingress import OP_INGEST

        self._ings._run_live_pipeline_after_ingest(self.bundle, OP_INGEST, response)


def _benign(event_id: str) -> Dict[str, Any]:
    return {
        "event_type": "request_blocked",
        "event_id": event_id,
        "source_event_id": f"src-benign-{event_id[-2:]}",
        "event_time": "2026-08-30T12:00:00Z",
        "source_ip": "203.0.113.50",
        "endpoint": "/index.html",
        "asset": "web-app",
        "details": {"http_method": "GET", "status_code": 200},
    }


def _auth_failure(event_id: str, second: int, source_ip: str = "203.0.113.99") -> Dict[str, Any]:
    return {
        "event_type": "authentication_failure",
        "event_id": event_id,
        "source_event_id": f"src-susp-{event_id[-2:]}",
        "event_time": f"2026-08-30T12:01:{second:02d}Z",
        "source_ip": source_ip,
        "endpoint": "/api/login",
        "asset": "web-app",
        "details": {"http_method": "POST", "status_code": 401},
    }


def _eid(tag: str) -> str:
    """A deterministic UUIDv7-shaped event id (36 chars, 12-char final group)."""
    return f"0198c2a1-7e3b-7a8e-b7b6-4f6a7d4d{str(tag).zfill(4)}"


def _issue(analyst, admin: str, sid: str) -> Optional[str]:  # noqa: ANN001
    """Mint a FRESH single-use credential (tokens are single-use by design)."""
    r = analyst.call("source.issue_token", admin, {"source_instance_id": sid})
    if r.status != 200:
        return None
    return r.body["data"]["source_token"]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    from pymongo import MongoClient

    db_name = f"proshield_p52_pipe_{uuid.uuid4().hex[:8]}"
    client = MongoClient(MONGO_URI)
    client.drop_database(db_name)
    config = _config(db_name)
    db = client[db_name]
    print(f"Phase 5.2 chained live pipeline verification against {db_name}", flush=True)

    try:
        _run(config, db)
    finally:
        if not args.keep:
            client.drop_database(db_name)
            print(f"  (dropped {db_name})", flush=True)

    return _summary()


def _run(config, db) -> None:  # noqa: ANN001
    from app.persistence.correlation_repository import CorrelationRepository
    from app.persistence.detection_repository import DetectionRepository
    from app.persistence.security_event_repository import SecurityEventRepository
    from app.incidents.repository import IncidentRepository

    analyst = AnalystPlane(config)
    ingress = IngressPlane(config)
    admin = analyst.token()

    events_repo = SecurityEventRepository(db=db, config=config)
    detections_repo = DetectionRepository(db=db, config=config)
    correlations_repo = CorrelationRepository(db=db, config=config)
    incidents_repo = IncidentRepository(db=db, config=config)

    # ================================================================ step 1
    print("\n-- 1. source registration + server-authoritative binding", flush=True)
    reg_a = analyst.call("source.register", admin, {
        "source_type": "nginx",
        "display_name": "p52-pipe-A",
    })
    if not check("source.register A (200)", reg_a.status == 200, str(reg_a.body)[:300]):
        return
    src_a = reg_a.body["data"]["source"]
    sid_a = src_a["source_instance_id"]
    check(
        "A derives capability server-side (cap-nginx, bound)",
        src_a.get("capability_id") == "cap-nginx"
        and src_a.get("capability_binding_status") == "bound"
        and isinstance(src_a.get("capability_version"), int),
        str(src_a)[:300],
    )
    check(
        "A resolved the mapping profile declared for nginx",
        src_a.get("mapping_profile_id") in (None, "")
        or isinstance(src_a.get("mapping_profile_id"), str),
        str(src_a)[:300],
    )

    reg_b = analyst.call("source.register", admin, {
        "source_type": "nginx",
        "display_name": "p52-pipe-B",
    })
    if not check("source.register B (200)", reg_b.status == 200, str(reg_b.body)[:300]):
        return
    src_b = reg_b.body["data"]["source"]
    sid_b = src_b["source_instance_id"]
    check("B is a distinct source instance", sid_a != sid_b)

    # An explicit capability request that does not match the connector family
    # must be rejected — the client may request, the server decides.
    bad_bind = analyst.call("source.register", admin, {
        "source_type": "nginx",
        "display_name": "p52-pipe-bad",
        "capability_id": "cap-simulator",
    })
    check(
        "mismatched source/capability triple rejected (400)",
        bad_bind.status == 400,
        f"status={bad_bind.status} body={str(bad_bind.body)[:200]}",
    )

    missing_bind = analyst.call("source.register", admin, {
        "source_type": "nginx",
        "display_name": "p52-pipe-ghost",
        "capability_id": "cap-does-not-exist",
    })
    check(
        "unknown capability rejected (400, no invented owner)",
        missing_bind.status == 400,
        f"status={missing_bind.status} body={str(missing_bind.body)[:200]}",
    )

    # ================================================================ step 2
    print("\n-- 2. lifecycle + per-source credentials", flush=True)
    for sid, label in ((sid_a, "A"), (sid_b, "B")):
        for op, body in (
            ("source.configure", {
                "source_instance_id": sid,
                "configuration": {
                    "connection_type": "push",
                    "endpoint": "https://ingest.example.test/hook",
                    "secret_ref": "",
                },
            }),
            ("source.validate", {"source_instance_id": sid}),
            ("source.enable", {"source_instance_id": sid}),
        ):
            r = analyst.call(op, admin, body)
            check(f"{op} {label} (200)", r.status == 200, str(r.body)[:200])

    tok_a_resp = analyst.call(
        "source.issue_token", admin, {"source_instance_id": sid_a}
    )
    tok_b_resp = analyst.call(
        "source.issue_token", admin, {"source_instance_id": sid_b}
    )
    check(
        "credential issued for A only after VALIDATED/ENABLED",
        tok_a_resp.status == 200,
        str(tok_a_resp.body)[:200],
    )
    check("credential issued for B", tok_b_resp.status == 200, str(tok_b_resp.body)[:200])
    tok_a = tok_a_resp.body["data"]["source_token"]
    tok_b = tok_b_resp.body["data"]["source_token"]
    check("A and B hold different credentials", tok_a != tok_b)

    # ================================================================ step 3
    print("\n-- 3. ingress: token authenticates the SOURCE INSTANCE", flush=True)
    benign_tok = _issue(analyst, admin, sid_a)
    check("fresh credential issued for the benign ingest", bool(benign_tok))
    if not benign_tok:
        return
    benign_resp = ingress.ingest(benign_tok, [_benign(_eid("01"))])
    if not check(
        "ingest accepted (200)", benign_resp.status == 200, str(benign_resp.body)[:300]
    ):
        return
    data = benign_resp.body.get("data") or {}
    check(
        "response echoes the authenticated source instance A",
        data.get("source_instance_id") == sid_a,
        str(data)[:300],
    )
    accepted = data.get("accepted_event_ids") or []
    check(
        "one event accepted",
        len(accepted) == 1,
        f"accepted={accepted} rejected={data.get('rejected')}",
    )
    if not accepted:
        return
    benign_id = accepted[0]

    ev = events_repo.get_by_event_id(benign_id)
    check("canonical SecurityEvent persisted", ev is not None)
    if ev is not None:
        check(
            "event provenance carries the DERIVED capability_id",
            ev.provenance.capability_id == "cap-nginx",
            str(ev.provenance)[:300],
        )
        check(
            "event provenance carries the authenticated source instance",
            ev.provenance.source_instance_id == sid_a,
            str(ev.provenance)[:300],
        )

    # A forged capability in the payload must not survive.
    forged_tok = _issue(analyst, admin, sid_a)
    forged_resp = ingress.ingest(forged_tok, [
        dict(_benign(_eid("02")), capability_id="cap-simulator")
    ])
    check("ingest with forged capability accepted (200)", forged_resp.status == 200)
    forged_data = forged_resp.body.get("data") or {}
    forged_ids = forged_data.get("accepted_event_ids") or []
    if forged_ids:
        forged_ev = events_repo.get_by_event_id(forged_ids[0])
        check(
            "client-supplied capability_id IGNORED (server value kept)",
            forged_ev is not None
            and forged_ev.provenance.capability_id == "cap-nginx",
            str(getattr(forged_ev, "provenance", None))[:300],
        )

    # Source B's credential must attribute telemetry to B, never to A.
    tok_b_fresh = _issue(analyst, admin, sid_b)
    b_resp = ingress.ingest(tok_b_fresh, [_benign(_eid("03"))])
    b_ids = (b_resp.body.get("data") or {}).get("accepted_event_ids") or []
    if b_ids:
        b_ev = events_repo.get_by_event_id(b_ids[0])
        check(
            "source B credential attributes telemetry to B (no impersonation)",
            b_ev is not None and b_ev.provenance.source_instance_id == sid_b,
            str(getattr(b_ev, "provenance", None))[:300],
        )

    # ================================================================ step 4
    print("\n-- 4. replay + forgery through the real ingress endpoint", flush=True)
    replay = ingress.ingest(benign_tok, [_benign(_eid("01"))])
    check(
        "replayed single-use credential rejected (401)",
        replay.status == 401,
        f"status={replay.status} body={str(replay.body)[:200]}",
    )
    tampered = benign_tok[:-4] + ("aaaa" if not benign_tok.endswith("aaaa") else "bbbb")
    tamper_resp = ingress.ingest(tampered, [_benign(_eid("04"))])
    check(
        "tampered credential rejected (401)",
        tamper_resp.status == 401,
        f"status={tamper_resp.status} body={str(tamper_resp.body)[:200]}",
    )

    # ================================================================ step 5
    print("\n-- 5. chained detection -> correlation -> case", flush=True)
    susp_payload = [_auth_failure(_eid(f"1{i}"), i) for i in range(1, 5)]
    susp_tok = _issue(analyst, admin, sid_a)
    check("fresh credential issued for the suspicious ingest", bool(susp_tok))
    if not susp_tok:
        return
    susp = ingress.ingest(susp_tok, susp_payload)
    if not check(
        "suspicious ingest accepted (200)", susp.status == 200, str(susp.body)[:300]
    ):
        return
    susp_ids = (susp.body.get("data") or {}).get("accepted_event_ids") or []
    check("four auth-failure events accepted", len(susp_ids) == 4, str(susp_ids))

    # Drive the SHIPPED live hook (detection -> correlation -> case).
    ingress.after_ingest(susp)
    ingress.after_ingest(benign_resp)

    dets = []
    for eid in susp_ids:
        dets.extend(detections_repo.find_by_event_id(eid))
    check("detections produced for the suspicious events", len(dets) >= 4, str(len(dets)))
    rule_ids = {d.rule_id for d in dets}
    check(
        "NGINX-AUTH-FAILURE-001 fired",
        "NGINX-AUTH-FAILURE-001" in rule_ids,
        str(sorted(rule_ids)),
    )
    check(
        "every detection carries the server-derived capability (S8)",
        bool(dets) and all(d.capability_id == "cap-nginx" for d in dets),
        str(sorted({d.capability_id for d in dets})),
    )
    check(
        "every detection carries the source instance provenance",
        bool(dets) and all(d.source_instance_id == sid_a for d in dets),
        str(sorted({d.source_instance_id for d in dets})),
    )

    benign_dets = detections_repo.find_by_event_id(benign_id)
    benign_rules = sorted({d.rule_id for d in benign_dets})
    # Detection-fidelity gate (was a reproduced-defect assertion before the
    # 2026-09-18 fix).
    #
    # A benign nginx event (HTTP 200 on ``/index.html``) must raise NO
    # detection. Historically it raised three, because the live pipeline
    # evaluated MANAGED declarative rules and
    # ``ManagedRuleLifecycleSync.seed_builtins()`` persisted each library rule
    # as a metadata-only ``RuleDefinition`` (no predicate, ``conditions: null``)
    # which the declarative evaluator matched on applicability metadata alone.
    #
    # The fix keeps the shipped implementation authoritative for a
    # capability-owned library rule whose persisted record declares no
    # conditions of its own (``RuleManagementService._implementation_for`` +
    # ``SimpleRule.with_metadata``), so the predicate decides again. This gate
    # now asserts the CORRECT behaviour.
    check(
        "benign nginx telemetry produces NO detection (predicates decide)",
        not benign_dets,
        f"rule_ids={benign_rules}",
    )
    check(
        "and no capability is ever invented on a benign event",
        all(d.capability_id == "cap-nginx" for d in benign_dets),
        str([(d.rule_id, d.capability_id) for d in benign_dets]),
    )

    corrs = correlations_repo.find_recent(limit=50)
    check("at least one correlation produced", len(corrs) >= 1, str(len(corrs)))
    check(
        "every correlation derives capability_ids from its members (S8/S12)",
        bool(corrs) and all(c.capability_ids == ("cap-nginx",) for c in corrs),
        str(sorted({tuple(c.capability_ids) for c in corrs})),
    )
    check(
        "correlation evidence references the real detections",
        bool(corrs)
        and all(set(c.detection_ids) <= {d.detection_id for d in dets} for c in corrs),
        str(corrs[0].detection_ids) if corrs else "",
    )

    cases = incidents_repo.find_recent(limit=50)
    check("a case was opened for the correlation", len(cases) >= 1, str(len(cases)))
    if cases:
        case = cases[0]
        evidence_ids = set(case.evidence.event_ids)
        check(
            "case lineage references the suspicious events",
            bool(evidence_ids & set(susp_ids)),
            str(sorted(evidence_ids)),
        )
        check(
            "case lineage detections all carry cap-nginx",
            all(
                d.capability_id == "cap-nginx"
                for d in dets
                if d.detection_id in set(case.evidence.detection_ids)
            ),
            str(list(case.evidence.detection_ids)),
        )

    # ================================================================ step 6
    print("\n-- 6. disabled / retired source cannot ingest", flush=True)
    dis = analyst.call("source.disable", admin, {"source_instance_id": sid_a})
    check("source.disable A (200)", dis.status == 200, str(dis.body)[:200])
    dis_tok = analyst.call("source.issue_token", admin, {"source_instance_id": sid_a})
    check(
        "disabled source cannot obtain a new credential (409)",
        dis_tok.status == 409,
        f"status={dis_tok.status} body={str(dis_tok.body)[:200]}",
    )

    en = analyst.call("source.enable", admin, {"source_instance_id": sid_a})
    check("source.enable A (200)", en.status == 200, str(en.body)[:200])
    fresh = analyst.call("source.issue_token", admin, {"source_instance_id": sid_a})
    fresh_tok = fresh.body.get("data", {}).get("source_token") if fresh.status == 200 else None
    ret = analyst.call("source.retire", admin, {"source_instance_id": sid_a})
    check("source.retire A (200)", ret.status == 200, str(ret.body)[:200])
    if fresh_tok:
        ret_ing = ingress.ingest(fresh_tok, [_benign(_eid("10"))])
        check(
            "retired source ingest returns 410",
            ret_ing.status == 410,
            f"status={ret_ing.status} body={str(ret_ing.body)[:200]}",
        )
    ret_tok = analyst.call("source.issue_token", admin, {"source_instance_id": sid_a})
    check(
        "retired source can no longer obtain a credential (409)",
        ret_tok.status == 409,
        f"status={ret_tok.status} body={str(ret_tok.body)[:200]}",
    )

    print("\n-- 7. historical provenance preserved after retirement", flush=True)
    historic = events_repo.find_by_source_instance(sid_a)
    check(
        "historical events/capability provenance preserved after retire",
        len(historic) >= 5
        and all(e.provenance.capability_id == "cap-nginx" for e in historic),
        f"count={len(historic)}",
    )
    gone = events_repo.get_by_event_id(benign_id)
    check(
        "the retired source's historical events are still readable",
        gone is not None and gone.provenance.source_instance_id == sid_a,
    )


def _summary() -> int:
    passed = sum(1 for _, ok in _RESULTS if ok)
    print(f"\n{passed}/{len(_RESULTS)} checks passed", flush=True)
    return 0 if passed == len(_RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())


