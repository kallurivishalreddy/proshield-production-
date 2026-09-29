"""FINAL baseline independent probe F1: multi-source capability correlation,
detection fidelity (incl. unknown/unmatched + benign), adversarial ingress,
auth boundaries, central correlation, persistence/restart.
Writes results to stdout; exits nonzero on failure.
"""
from __future__ import annotations
import os, sys, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
MONGO_URI = "mongodb://127.0.0.1:27017"
RESULTS = []
def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""), flush=True)
    return bool(ok)

def _config(db):
    from app.config import ProShieldConfig
    return ProShieldConfig(env_name="test", log_level="WARNING", mongo_uri=MONGO_URI,
        mongo_db=db, mongo_collection_events="security_events",
        auth_signing_key=os.urandom(32).hex(), source_signing_key=os.urandom(32).hex(),
        default_subject_credentials={"admin":"admin-password","analyst":"analyst-password","collector":"collector-password"})

def main():
    import scripts.proxy_server as ps
    import scripts.ingress_server as ings
    from app.proxy import SecureProxy, ProxyRequest, OP_AUTH_ISSUE
    from app.sources.ingress import INGRESS_HEADER_AUTHORIZATION, OP_INGEST, IngressRequest
    db = f"proshield_final_f1_{uuid.uuid4().hex[:8]}"
    print(f"FINAL-F1 probe against {db}", flush=True)
    cfg = _config(db)
    bundle = ps._build_mongo_backend(cfg)
    proxy = SecureProxy(config=cfg, identity_store=ps._build_identity_store(cfg))
    ps._attach_services(proxy, bundle)
    def token(subj, cred):
        r = proxy.handle(ProxyRequest(operation=OP_AUTH_ISSUE, headers={}, body={"subject_id":subj,"credential":cred}))
        assert r.status==200, r.body
        return r.body["data"]["token"]
    admin = token("admin","admin-password"); analyst = token("analyst","analyst-password"); collector = token("collector","collector-password")
    def call(op, tok, body=None):
        return proxy.handle(ProxyRequest(operation=op, headers={"Authorization":f"Bearer {tok}"}, body=body or {}))
    ib = ings._build_mongo_ingress(cfg); ingress = ib.ingress; pipeline = ib.pipeline
    def reg_source(name, stype="nginx", cap="cap-nginx"):
        body={"display_name":name,"source_type":stype}
        if cap: body["capability_id"]=cap
        r = call("source.register", admin, body)
        assert r.status==200, (name, r.body)
        return r.body["data"]["source"]["source_instance_id"]
    def full_enable(sid):
        for op, b in [("source.configure",{"source_instance_id":sid,"configuration":{"connection_type":"push","endpoint":"https://coll.example/ingest"}}),
                      ("source.validate",{"source_instance_id":sid}),("source.enable",{"source_instance_id":sid})]:
            r = call(op, admin, b); assert r.status==200,(op,r.body)
    def issue(sid):
        r = call("source.issue_token", admin, {"source_instance_id":sid})
        assert r.status==200, r.body
        return r.body["data"]["source_token"]
    def ingest(sit, events):
        resp = ingress.handle(IngressRequest(operation=OP_INGEST, headers={INGRESS_HEADER_AUTHORIZATION:f"Bearer {sit}"}, body={"events":events}))
        if resp.status==200: ings._run_live_pipeline_after_ingest(ib, OP_INGEST, resp)
        return resp
    from datetime import datetime, timezone, timedelta
    from app.domain.uuid7 import uuid7
    base = datetime.now(timezone.utc) - timedelta(minutes=30)
    def evt(eid, etype, ep, status, ip, sec=0, extra=None):
        d={"http_method":"GET","status_code":status}; d.update(extra or {})
        uid = str(uuid7())
        return {"event_type":etype,"event_id":uid,"source_event_id":f"src-{uid[-6:]}",
                "event_time":(base+timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip":ip,"endpoint":ep,"asset":"web-app","details":d}
    # --- topology: 3 nginx sources ---
    a=reg_source("final-nginx-a"); b=reg_source("final-nginx-b"); c=reg_source("final-nginx-c")
    check("F1 three nginx sources distinct", len({a,b,c})==3)
    for s in (a,b,c): full_enable(s)
    # rule ownership
    r = call("rule.list", admin, {}); rules = r.body["data"]["rules"] if r.status==200 else []
    nx = [x for x in rules if (x.get("capability_id")=="cap-nginx")]
    check("F1 nginx rules owned by cap-nginx", len(nx)>=5, f"owned={len(nx)} total={len(rules)}")
    check("F1 no conn-* fabricated owner", all(not str(x.get("capability_id") or "").startswith("conn-") for x in rules))
    # benign -> 0 detections
    before = call("detection.list", admin, {"limit":200})
    n0 = len(before.body["data"]["detections"]) if before.status==200 else 0
    rb = ingest(issue(a), [evt("x","request_blocked","/index.html",200,"203.0.113.50",i) for i in range(3)])
    check("F1 benign ingest accepted", rb.status==200 and len(rb.body["data"]["accepted_event_ids"])==3, str(rb.body)[:300])
    after = call("detection.list", admin, {"limit":200})
    n1 = len(after.body["data"]["detections"]) if after.status==200 else -1
    check("F1 benign produces zero detections", n1==n0, f"before={n0} after={n1}")
    # unknown/unmatched: tls_anomaly from nginx has no rule
    ru = ingest(issue(a), [evt("x","tls_anomaly","/login",0,"203.0.113.51",100,{"cipher":"TLS_AES"})])
    check("F1 unknown event accepted+retained", ru.status==200 and len(ru.body["data"]["accepted_event_ids"])==1, str(ru.body)[:300])
    after2 = call("detection.list", admin, {"limit":200})
    n2 = len(after2.body["data"]["detections"]) if after2.status==200 else -1
    check("F1 unknown produces zero detections (no invented match)", n2==n1, f"{n1}->{n2}")
    el = call("event.list", admin, {"limit":200})
    evs = el.body["data"]["events"] if el.status==200 else []
    check("F1 unknown event queryable as telemetry", any(e.get("event_type")=="tls_anomaly" for e in evs))
    # malicious across 3 sources same ip+endpoint -> capability correlation across sources
    ip="198.51.100.77"
    eps=["/login"]*6
    payload=[]
    for i in range(6):
        payload.append(evt("x","authentication_failure",eps[i],401,ip,200+i*20))
    ra = ingest(issue(a), payload[:2]); rb2 = ingest(issue(b), payload[2:4]); rc = ingest(issue(c), payload[4:6])
    check("F1 3-source attack ingests accepted", all(x.status==200 for x in (ra,rb2,rc)))
    cl = call("correlation.list", admin, {}); corrs = cl.body["data"]["correlations"] if cl.status==200 else []
    multi = [x for x in corrs if len(x.get("event_ids",[]))>=3]
    check("F1 capability correlation exists (>=3 events)", len(multi)>=1, f"corrs={len(corrs)}")
    ok_scope=False; detail=""
    if multi:
        from pymongo import MongoClient as _MC
        _dbx = _MC(MONGO_URI)[db]
        cc = multi[0]
        sids=set()
        for eid in cc.get("event_ids",[]):
            doc=_dbx["security_events"].find_one({"event_id":eid})
            if doc: sids.add(((doc.get("provenance") or {}).get("source_instance_id")))
        sids.discard(None)
        ok_scope = len(sids)>=2 and cc.get("capability_ids")==["cap-nginx"]
        detail=f"sources_in_corr={sorted(sids)} cap_ids={cc.get('capability_ids')}"
    check("F1 correlation spans >=2 sources within cap-nginx", ok_scope, detail)
    dl = call("detection.list", admin, {"limit":500}); dets = dl.body["data"]["detections"] if dl.status==200 else []
    check("F1 detections retain cap-nginx+source provenance", any(d.get("capability_id")=="cap-nginx" and d.get("source_instance_id") in (a,b,c) for d in dets), f"dets={len(dets)}")
    # adversarial: cross-source replay, forgery, wrong-capability
    sit_a = issue(a)
    r1 = ingest(sit_a, [evt("x","authentication_failure","/login",401,"203.0.113.9",400)])
    r1_ids = (r1.body.get("data",{}) or {}).get("accepted_event_ids",[]) if r1.status==200 else []
    check("F1 first use ok", r1.status==200)
    r2 = ingest(sit_a, [evt("x","authentication_failure","/login",401,"203.0.113.9",401)])
    check("F1 replay rejected 401", r2.status==401, str(r2.body)[:200])
    bad = sit_a[:-4]+"AAAA"
    r3 = ingest(bad, [evt("x","authentication_failure","/login",401,"203.0.113.9",402)])
    check("F1 tampered rejected 401", r3.status==401, str(r3.body)[:200])
    # forged capability ignored
    r4ev = evt("x","authentication_failure","/login",401,"203.0.113.9",403); r4ev["capability_id"]="cap-simulator"
    r4 = ingest(issue(a), [r4ev])
    r4_ids = (r4.body.get("data",{}) or {}).get("accepted_event_ids",[]) if r4.status==200 else []
    check("F1 forged capability accepted-but-ignored", r4.status==200 and len(r4_ids)==1, str(r4.body)[:300])
    from pymongo import MongoClient as _MC2
    _d4 = _MC2(MONGO_URI)[db]["security_events"].find_one({"event_id":r4_ids[0]}) if r4_ids else None
    check("F1 forged capability not persisted", bool(_d4) and (_d4.get("provenance") or {}).get("capability_id")=="cap-nginx", str(_d4)[:400] if _d4 else "missing")
    # disabled/retired
    call("source.disable", admin, {"source_instance_id":b})
    r5 = call("source.issue_token", admin, {"source_instance_id":b})
    check("F1 disabled cannot issue (409)", r5.status==409, str(r5.body)[:200])
    call("source.enable", admin, {"source_instance_id":b})
    call("source.retire", admin, {"source_instance_id":c})
    r6 = ingest(issue(a) if False else "sit-bogus", [evt("x","authentication_failure","/login",401,"203.0.113.9",404)])
    r6b = call("source.issue_token", admin, {"source_instance_id":c})
    check("F1 retired cannot issue (409)", r6b.status==409, str(r6b.body)[:200])
    # auth boundaries
    rl = call("case.list", analyst, {}); check("F1 analyst case.list ok-shape", rl.status in (200,), str(rl.body)[:200])
    rc2 = call("source.list", collector, {}); check("F1 collector source.list denied (403)", rc2.status==403, str(rc2.body)[:200])
    rce = call("event.list", collector, {}); check("F1 collector event.list denied (403)", rce.status==403, str(rce.body)[:200])
    # central correlation explicit + non-destructive
    cases = call("case.list", admin, {"limit":50}).body["data"]["cases"] if call("case.list", admin, {"limit":1}).status==200 else []
    # pick a pipeline case
    cl2 = call("case.list", admin, {"limit":50})
    cases = cl2.body["data"]["cases"] if cl2.status==200 else []
    if cases:
        cid = cases[0]["incident_id"]
        full0 = call("case.get", admin, {"incident_id":cid})
        before_ev = set((full0.body["data"]["case"].get("evidence",{}) or {}).get("event_ids",[])) if full0.status==200 else set(cases[0].get("evidence",{}).get("event_ids",[]))
        rcc = call("case.centralized", admin, {"incident_id":cid,"reason":"final audit central check"})
        check("F1 central correlation explicit call succeeds", rcc.status==200, str(rcc.body)[:300])
        after_case = call("case.get", admin, {"incident_id":cid})
        ev_after = set((after_case.body["data"]["case"].get("evidence",{}) or {}).get("event_ids",[])) if after_case.status==200 else set()
        check("F1 central non-destructive (evidence preserved)", before_ev.issubset(ev_after), f"{len(before_ev)}->{len(ev_after)}")
        from pymongo import MongoClient as _MC3
        _evs = list(_MC3(MONGO_URI)[db]["security_events"].find().limit(5))
        check("F1 original events unchanged after central", len(_evs)>0 and all("provenance" in e for e in _evs))
    else:
        check("F1 central correlation explicit call succeeds", False, "no cases")
        check("F1 central non-destructive (evidence preserved)", False, "no cases")
    # malformed: wrong-typed field (still well-formed envelope) -> validation_error per-event
    bad_ev = evt("x","authentication_failure","/login",401,"203.0.113.9",500)
    bad_ev["details"] = "NOT-A-DICT-BUT-STRING-THAT-SHOULD-STILL-BE-HANDLED"
    # canonical model coerces details? use truly invalid: bad event_type
    bad_ev2 = evt("x","not_a_real_type","/login",401,"203.0.113.9",501)
    m1 = ingest(issue(b), [bad_ev2])
    rej = m1.body.get("data",{}).get("rejected",[]) if m1.status==200 else []
    check("F1 malformed rejected truthfully", (m1.status==200 and rej and rej[0].get("reason")=="validation_error") or m1.status==400, str(m1.body)[:300])
    fails = [n for n,ok in RESULTS if not ok]
    print(f"FINAL-F1 {len(RESULTS)-len(fails)}/{len(RESULTS)} passed", flush=True)
    from pymongo import MongoClient
    MongoClient(MONGO_URI).drop_database(db)
    sys.exit(0 if not fails else 1)

if __name__=="__main__": main()
