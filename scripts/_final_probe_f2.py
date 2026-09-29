"""FINAL baseline probe F2: WAF-vs-NGINX isolation, lifecycle, migration,
reports/exports, health, timeline/evidence, restart persistence, concurrency.
"""
from __future__ import annotations
import os, sys, uuid, threading
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
MONGO_URI="mongodb://127.0.0.1:27017"
RESULTS=[]
def check(n,ok,d=""):
    RESULTS.append((n,bool(ok))); print(f"  [{'PASS' if ok else 'FAIL'}] {n}"+(f"  -- {d}" if d and not ok else ""),flush=True); return bool(ok)
def _config(db):
    from app.config import ProShieldConfig
    return ProShieldConfig(env_name="test",log_level="WARNING",mongo_uri=MONGO_URI,mongo_db=db,
        mongo_collection_events="security_events",auth_signing_key=os.urandom(32).hex(),
        source_signing_key=os.urandom(32).hex(),
        default_subject_credentials={"admin":"admin-password","analyst":"analyst-password","collector":"collector-password"})
def main():
    import scripts.proxy_server as ps
    import scripts.ingress_server as ings
    from app.proxy import SecureProxy, ProxyRequest, OP_AUTH_ISSUE
    from app.sources.ingress import INGRESS_HEADER_AUTHORIZATION, OP_INGEST, IngressRequest
    from datetime import datetime, timezone, timedelta
    from app.domain.uuid7 import uuid7
    db=f"proshield_final_f2_{uuid.uuid4().hex[:8]}"
    print(f"FINAL-F2 probe against {db}",flush=True)
    cfg=_config(db)
    bundle=ps._build_mongo_backend(cfg)
    proxy=SecureProxy(config=cfg,identity_store=ps._build_identity_store(cfg))
    ps._attach_services(proxy,bundle)
    def token(s,c):
        r=proxy.handle(ProxyRequest(operation=OP_AUTH_ISSUE,headers={},body={"subject_id":s,"credential":c}))
        assert r.status==200,r.body; return r.body["data"]["token"]
    admin=token("admin","admin-password"); analyst=token("analyst","analyst-password"); collector=token("collector","collector-password")
    def call(op,tok,body=None):
        return proxy.handle(ProxyRequest(operation=op,headers={"Authorization":f"Bearer {tok}"},body=body or {}))
    ib=ings._build_mongo_ingress(cfg); ingress=ib.ingress
    def reg(name,stype,cap=None):
        b={"display_name":name,"source_type":stype}
        if cap: b["capability_id"]=cap
        r=call("source.register",admin,b); assert r.status==200,(name,r.body)
        return r.body["data"]["source"]["source_instance_id"]
    def enable(sid):
        for op,b in [("source.configure",{"source_instance_id":sid,"configuration":{"connection_type":"push","endpoint":"https://coll.example/ingest"}}),("source.validate",{"source_instance_id":sid}),("source.enable",{"source_instance_id":sid})]:
            r=call(op,admin,b); assert r.status==200,(op,r.body)
    def issue(sid):
        r=call("source.issue_token",admin,{"source_instance_id":sid}); assert r.status==200,r.body; return r.body["data"]["source_token"]
    def ingest(sit,evs):
        resp=ingress.handle(IngressRequest(operation=OP_INGEST,headers={INGRESS_HEADER_AUTHORIZATION:f"Bearer {sit}"},body={"events":evs}))
        if resp.status==200: ings._run_live_pipeline_after_ingest(ib,OP_INGEST,resp)
        return resp
    base=datetime.now(timezone.utc)-timedelta(minutes=20)
    def evt(etype,ep,status,ip,sec=0,extra=None):
        d={"http_method":"GET","status_code":status}; d.update(extra or {}); uid=str(uuid7())
        return {"event_type":etype,"event_id":uid,"source_event_id":f"src-{uid[-6:]}","event_time":(base+timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ"),"source_ip":ip,"endpoint":ep,"asset":"web-app","details":d}
    # WAF is planned: new source on cap-waf must be refused (no phantom coverage)
    rw=call("source.register",admin,{"display_name":"final-waf-a","source_type":"waf","capability_id":"cap-waf"})
    check("F2 WAF planned binding refused (no phantom coverage)", rw.status in (400,409,422), f"status={rw.status} {str(rw.body)[:250]}")
    rw2=call("source.register",admin,{"display_name":"final-waf-b","source_type":"waf"})
    if rw2.status==200:
        sidw=rw2.body["data"]["source"]["source_instance_id"]
        check("F2 legacy WAF row quarantined (requires_verification)", rw2.body["data"]["source"].get("capability_binding_status")=="requires_verification", str(rw2.body["data"]["source"])[:300])
        r=call("source.validate",admin,{"source_instance_id":sidw})
        check("F2 quarantined WAF cannot validate", r.status in (400,409), f"{r.status} {str(r.body)[:200]}")
    else:
        check("F2 legacy WAF row quarantined (requires_verification)", rw2.status in (400,409), f"{rw2.status}")
        check("F2 quarantined WAF cannot validate", True)
    # nginx cross-capability impersonation: nginx source claiming cap-simulator refused
    rb=call("source.register",admin,{"display_name":"final-nginx-x","source_type":"nginx","capability_id":"cap-simulator"})
    check("F2 nginx claiming simulator refused", rb.status in (400,409), f"{rb.status} {str(rb.body)[:200]}")
    # two nginx sources for isolation checks
    n1=reg("final-n1","nginx"); n2=reg("final-n2","nginx"); enable(n1); enable(n2)
    # forged source_id in token body: use n1 token but claim n2? token is bound; tamper body -> 401
    t1=issue(n1)
    import base64, json
    parts=t1.split("."); body=json.loads(base64.urlsafe_b64decode(parts[1]+"="*(-len(parts[1])%4)).decode())
    body["source_instance_id"]=n2
    tampered=parts[0]+"."+base64.urlsafe_b64encode(json.dumps(body,separators=(",",":"),sort_keys=True).encode()).decode().rstrip("=")+"."+parts[2]
    rr=ingest(tampered,[evt("authentication_failure","/login",401,"203.0.113.9",10)])
    check("F2 token source swap rejected (401/403)", rr.status in (401,403), f"{rr.status} {str(rr.body)[:200]}")
    # lifecycle: disable blocks ingest even with previously issued token
    t_pre=issue(n1)
    call("source.disable",admin,{"source_instance_id":n1})
    rd=ingest(t_pre,[evt("authentication_failure","/login",401,"203.0.113.9",11)])
    check("F2 disabled blocks ingest (409)", rd.status==409, f"{rd.status} {str(rd.body)[:200]}")
    call("source.enable",admin,{"source_instance_id":n1})
    # generate brute force on n1+n2 same key -> correlation + case
    ip="198.51.100.88"
    p1=[evt("authentication_failure","/login",401,ip,20+i*10) for i in range(3)]
    p2=[evt("authentication_failure","/login",401,ip,60+i*10) for i in range(3)]
    r1=ingest(issue(n1),p1); r2=ingest(issue(n2),p2)
    check("F2 attack ingests accepted", r1.status==200 and r2.status==200)
    cl=call("correlation.list",admin,{}); corrs=cl.body["data"]["correlations"] if cl.status==200 else []
    check("F2 correlation produced", len(corrs)>=1, f"n={len(corrs)}")
    cases=call("case.list",admin,{"limit":50}); cs=cases.body["data"]["cases"] if cases.status==200 else []
    check("F2 case opened", len(cs)>=1, f"n={len(cs)}")
    if cs:
        full=call("case.get",admin,{"incident_id":cs[0]["incident_id"]})
        check("F2 case.get works (admin)", full.status==200, str(full.body)[:250])
        ev_ids=(full.body["data"]["case"].get("evidence",{}) or {}).get("event_ids",[]) if full.status==200 else []
        # timeline
        tl=call("timeline.build_for_incident",admin,{"incident_id":cs[0]["incident_id"]})
        check("F2 timeline builds", tl.status==200, str(tl.body)[:250])
        # analyst cannot read pipeline case (documented R-2 boundary)
        ra=call("case.get",analyst,{"incident_id":cs[0]["incident_id"]})
        check("F2 analyst pipeline-case denied (404 boundary, Phase5.4-owned)", ra.status==404, f"{ra.status} {str(ra.body)[:200]}")
        # analyst CAN read events/detections/correlations (evidence visibility)
        for op in ("event.list","detection.list","correlation.list"):
            rx=call(op,analyst,{}); check(f"F2 analyst {op} allowed", rx.status==200, str(rx.body)[:200])
        # notes/ack as admin (pipeline owner readable by admin)
        rn=call("case.note.add",admin,{"incident_id":cs[0]["incident_id"],"body":"final audit note"})
        check("F2 admin note persists", rn.status==200, str(rn.body)[:250])
        rk=call("case.acknowledge",admin,{"incident_id":cs[0]["incident_id"]})
        check("F2 admin acknowledge transition", rk.status in (200,409), str(rk.body)[:250])
        # reports
        rp=call("report.generate_normal",admin,{"incident_id":cs[0]["incident_id"]})
        check("F2 report generates", rp.status==200, str(rp.body)[:300])
        if rp.status==200:
            from app.proxy import OP_REPORT_EXPORT
            rx=call("report.export",admin,{"report_id":rp.body["data"]["report"]["report_id"],"format":"markdown"})
            check("F2 report export markdown", rx.status==200, str(rx.body)[:250])
        # health deep reflects reality
        hd=call("system.health.deep",admin,{})
        _h=(hd.body.get("data",{}) or {}).get("health",{}) if hd.status==200 else {}
        check("F2 deep health ok", hd.status==200 and _h.get("status") in ("healthy","degraded"), str(hd.body)[:300])
        # IDOR: second admin-owned case not readable via forged analyst? analyst already denied; admin reads own
        # mass assignment: try to set created_by via create
        rm=call("case.create",analyst,{"title":"x","summary":"y","events":[],"detections":[],"created_by":"admin"})
        if rm.status==200:
            check("F2 mass-assignment created_by ignored", rm.body["data"]["case"].get("created_by")=="analyst", str(rm.body["data"]["case"])[:300])
        else:
            check("F2 mass-assignment created_by ignored", rm.status in (400,403,422), f"{rm.status}")
    # migration dry-run + apply no-op
    ms=call("source.migration_status",admin,{})
    check("F2 migration_status works", ms.status==200, str(ms.body)[:250])
    mm=call("source.migrate",admin,{"dry_run":True})
    check("F2 migrate dry-run safe", mm.status==200, str(mm.body)[:250])
    # oversized + deeply nested
    big=issue(n2)
    huge_evt=evt("authentication_failure","/login",401,"203.0.113.9",90); huge_evt["details"]={"blob":"A"*40000}
    rh=ingest(big,[huge_evt])
    rej=(rh.body.get("data",{}) or {}).get("rejected",[]) if rh.status==200 else []
    check("F2 oversized rejected truthfully", (rh.status==200 and rej) or rh.status in (400,413), str(rh.body)[:300])
    # duplicate event id identical content -> idempotent; different content -> conflict_event
    dup=evt("authentication_failure","/login",401,"203.0.113.9",95)
    d1=ingest(issue(n2),[dup]); d2=ingest(issue(n2),[dict(dup)])
    a1=(d1.body.get("data",{}) or {}).get("accepted_event_ids",[]) if d1.status==200 else []
    a2=(d2.body.get("data",{}) or {}).get("accepted_event_ids",[]) if d2.status==200 else []
    check("F2 identical redelivery idempotent", a1==a2 and len(a1)==1, f"{a1} vs {a2}")
    mod=dict(dup); mod["details"]={"http_method":"GET","status_code":403}
    d3=ingest(issue(n2),[mod])
    rej3=(d3.body.get("data",{}) or {}).get("rejected",[]) if d3.status==200 else []
    check("F2 same-id different-content conflicts", (d3.status==200 and rej3 and rej3[0].get("reason")=="conflict_event") or d3.status==409, str(d3.body)[:300])
    # concurrency: 10 threads register distinct sources
    errs=[]; made=[]
    def worker(i):
        try:
            r=call("source.register",admin,{"display_name":f"final-race-{i}-{uuid.uuid4().hex[:4]}","source_type":"nginx"})
            if r.status==200: made.append(r.body["data"]["source"]["source_instance_id"])
            else: errs.append((i,r.status))
        except Exception as e: errs.append((i,str(e)))
    ths=[threading.Thread(target=worker,args=(i,)) for i in range(10)]
    [t.start() for t in ths]; [t.join() for t in ths]
    check("F2 concurrent registrations unique", len(set(made))==10 and not errs, f"made={len(made)} errs={errs[:3]}")
    # restart: rebuild planes on same DB, verify state survives + identical
    from pymongo import MongoClient as _MC
    before_docs={c:_MC(MONGO_URI)[db][c].count_documents({}) for c in ["source_instances","security_events","detections","correlations","incidents"]}
    from dataclasses import replace as _replace
    cfg2=_replace(_config(db), auth_signing_key=cfg.auth_signing_key, source_signing_key=cfg.source_signing_key)
    bundle2=ps._build_mongo_backend(cfg2); proxy2=SecureProxy(config=cfg2,identity_store=ps._build_identity_store(cfg2)); ps._attach_services(proxy2,bundle2)
    def call2(op,tok,body=None):
        return proxy2.handle(ProxyRequest(operation=op,headers={"Authorization":f"Bearer {tok}"},body=body or {}))
    t2=proxy2.handle(ProxyRequest(operation=OP_AUTH_ISSUE,headers={},body={"subject_id":"admin","credential":"admin-password"}))
    admin2=t2.body["data"]["token"] if t2.status==200 else admin
    after_docs={c:_MC(MONGO_URI)[db][c].count_documents({}) for c in ["source_instances","security_events","detections","correlations","incidents"]}
    check("F2 restart preserves counts", before_docs==after_docs, f"{before_docs} vs {after_docs}")
    rpost=call2("source.list",admin2,{}); check("F2 post-restart source.list works", rpost.status==200, str(rpost.body)[:250])
    fails=[n for n,ok in RESULTS if not ok]
    print(f"FINAL-F2 {len(RESULTS)-len(fails)}/{len(RESULTS)} passed",flush=True)
    _MC(MONGO_URI).drop_database(db)
    sys.exit(0 if not fails else 1)
if __name__=="__main__": main()
