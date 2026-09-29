"""FINAL baseline probe F3: disabled-capability gate, rule lifecycle,
token rotation semantics, capability registry truthfulness, oversized/nested.
"""
from __future__ import annotations
import os, sys, uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
MONGO_URI="mongodb://127.0.0.1:27017"
R=[]
def check(n,ok,d=""):
    R.append((n,bool(ok))); print(f"  [{'PASS' if ok else 'FAIL'}] {n}"+(f"  -- {d}" if d and not ok else ""),flush=True); return bool(ok)
def _config(db):
    from app.config import ProShieldConfig
    return ProShieldConfig(env_name="test",log_level="WARNING",mongo_uri=MONGO_URI,mongo_db=db,
        mongo_collection_events="security_events",auth_signing_key=os.urandom(32).hex(),
        source_signing_key=os.urandom(32).hex(),
        default_subject_credentials={"admin":"admin-password","analyst":"analyst-password"})
def main():
    import scripts.proxy_server as ps
    import scripts.ingress_server as ings
    from app.proxy import SecureProxy, ProxyRequest, OP_AUTH_ISSUE
    from app.sources.ingress import INGRESS_HEADER_AUTHORIZATION, OP_INGEST, IngressRequest
    from datetime import datetime, timezone, timedelta
    from app.domain.uuid7 import uuid7
    db=f"proshield_final_f3_{uuid.uuid4().hex[:8]}"
    print(f"FINAL-F3 probe against {db}",flush=True)
    cfg=_config(db)
    bundle=ps._build_mongo_backend(cfg)
    proxy=SecureProxy(config=cfg,identity_store=ps._build_identity_store(cfg))
    ps._attach_services(proxy,bundle)
    def token(s,c):
        r=proxy.handle(ProxyRequest(operation=OP_AUTH_ISSUE,headers={},body={"subject_id":s,"credential":c}))
        assert r.status==200,r.body; return r.body["data"]["token"]
    admin=token("admin","admin-password"); analyst=token("analyst","analyst-password")
    def call(op,tok,body=None):
        return proxy.handle(ProxyRequest(operation=op,headers={"Authorization":f"Bearer {tok}"},body=body or {}))
    ib=ings._build_mongo_ingress(cfg); ingress=ib.ingress
    def reg(name,stype="nginx"):
        r=call("source.register",admin,{"display_name":name,"source_type":stype}); assert r.status==200,r.body
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
    base=datetime.now(timezone.utc)-timedelta(minutes=10)
    def evt(etype,ep,status,ip,sec=0):
        uid=str(uuid7())
        return {"event_type":etype,"event_id":uid,"source_event_id":f"src-{uid[-6:]}","event_time":(base+timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ"),"source_ip":ip,"endpoint":ep,"asset":"web-app","details":{"http_method":"GET","status_code":status}}
    # capability registry truthfulness
    cl=call("capability.list",admin,{})
    caps=cl.body["data"]["capabilities"] if cl.status==200 else []
    check("F3 capability.list works", cl.status==200 and len(caps)==6, f"{cl.status} n={len(caps)}")
    live=[c for c in caps if c.get("status")=="active"]
    planned=[c for c in caps if c.get("status")=="planned"]
    check("F3 2 live + 4 planned", len(live)==2 and len(planned)==4, f"live={len(live)} planned={len(planned)}")
    check("F3 no subconnector field", all("subconnector" not in str(c).lower() for c in caps))
    cg=call("capability.get",admin,{"capability_id":"cap-nginx"})
    check("F3 cap-nginx get", cg.status==200, str(cg.body)[:250])
    cr=call("capability.list_rules",admin,{"capability_id":"cap-nginx"})
    rl=cr.body["data"]["rules"] if cr.status==200 else []
    check("F3 cap-nginx lists >=5 rules", cr.status==200 and len(rl)>=5, f"n={len(rl)}")
    cs=call("capability.list_sources",admin,{"capability_id":"cap-nginx"})
    check("F3 cap-nginx list_sources works", cs.status==200, str(cs.body)[:250])
    ca=call("capability.audit",admin,{"capability_id":"cap-nginx"})
    check("F3 capability audit works", ca.status==200, str(ca.body)[:250])
    # analyst read allowed, write denied
    cla=call("capability.list",analyst,{})
    check("F3 analyst capability.list allowed", cla.status==200, str(cla.body)[:200])
    cw=call("capability.disable",analyst,{"capability_id":"cap-nginx"})
    check("F3 analyst capability.disable denied", cw.status in (401,403), f"{cw.status}")
    # DISABLED capability gate: disable cap-nginx, then new source binding must fail
    s_pre=reg("final-pre-disable"); enable(s_pre)
    dc=call("capability.disable",admin,{"capability_id":"cap-nginx"})
    check("F3 admin disables cap-nginx", dc.status==200, str(dc.body)[:300])
    rn=call("source.register",admin,{"display_name":"final-post-disable","source_type":"nginx"})
    check("F3 new nginx binding refused while capability disabled", rn.status in (400,409), f"{rn.status} {str(rn.body)[:250]}")
    # existing enabled source ingest while capability disabled: document behaviour
    rd=ingest(issue(s_pre),[evt("authentication_failure","/login",401,"203.0.113.9",1)])
    print(f"  [INFO] ingest while cap disabled -> status={rd.status} body={str(rd.body)[:250]}",flush=True)
    # detection while cap disabled uses binding snapshot; must not invent new capability
    # re-enable
    en=call("capability.enable",admin,{"capability_id":"cap-nginx"})
    check("F3 admin re-enables cap-nginx", en.status==200, str(en.body)[:300])
    rn2=call("source.register",admin,{"display_name":"final-post-reenable","source_type":"nginx"})
    check("F3 binding works after re-enable", rn2.status==200, str(rn2.body)[:250])
    # rule lifecycle: disable a firing rule -> no detection; re-enable -> detection
    sid=reg("final-rule-life"); enable(sid)
    off=call("rule.disable",admin,{"rule_id":"NGINX-AUTH-FAILURE-001","version":1})
    check("F3 rule.disable works", off.status==200, str(off.body)[:300])
    d0=len(call("detection.list",admin,{"limit":500}).body["data"]["detections"])
    rx=ingest(issue(sid),[evt("authentication_failure","/login",401,"203.0.113.77",5)])
    check("F3 disabled-rule ingest accepted", rx.status==200, str(rx.body)[:250])
    d1=len(call("detection.list",admin,{"limit":500}).body["data"]["detections"])
    # other rules may still fire (multiple rules cover /login 401?) - check SPECIFIC rule did not fire
    from pymongo import MongoClient as _MC
    docs=list(_MC(MONGO_URI)[db]["detections"].find().sort("_id",-1).limit(10))
    fired_specific=any(x.get("rule_id")=="NGINX-AUTH-FAILURE-001" and x.get("event_id") in ((rx.body.get("data",{}) or {}).get("accepted_event_ids",[])) for x in docs)
    check("F3 disabled rule does not fire", not fired_specific, str(docs[:2])[:400])
    on=call("rule.enable",admin,{"rule_id":"NGINX-AUTH-FAILURE-001","version":1})
    check("F3 rule re-enable works", on.status==200, str(on.body)[:300])
    rx2=ingest(issue(sid),[evt("authentication_failure","/login",401,"203.0.113.77",6)])
    docs2=list(_MC(MONGO_URI)[db]["detections"].find().sort("_id",-1).limit(10))
    ids2=((rx2.body.get("data",{}) or {}).get("accepted_event_ids",[]))
    fired2=any(x.get("rule_id")=="NGINX-AUTH-FAILURE-001" and x.get("event_id") in ids2 for x in docs2)
    check("F3 re-enabled rule fires", fired2, str(docs2[:2])[:400])
    # token rotation semantics: rotate -> new differs; old unused still valid (documented rotation!=revocation)
    rt=call("source.rotate_token",admin,{"source_instance_id":sid})
    check("F3 rotate issues new credential", rt.status==200, str(rt.body)[:300])
    new_tok=(rt.body.get("data",{}) or {}).get("source_token") if rt.status==200 else None
    t_old=issue(sid)
    rt2=call("source.rotate_token",admin,{"source_instance_id":sid})
    new2=(rt2.body.get("data",{}) or {}).get("source_token") if rt2.status==200 else None
    check("F3 rotation yields different value", bool(new2) and new2!=t_old, f"{str(t_old)[:20]} vs {str(new2)[:20]}")
    ro=ingest(t_old,[evt("authentication_failure","/login",401,"203.0.113.78",7)])
    check("F3 pre-rotation unused token still valid (rotation!=revocation)", ro.status==200, str(ro.body)[:250])
    rp=ingest(new2,[evt("authentication_failure","/login",401,"203.0.113.78",8)])
    check("F3 rotated token valid", rp.status==200, str(rp.body)[:250])
    # unknown capability / unknown source type rejected
    ru=call("source.register",admin,{"display_name":"x","source_type":"nginx","capability_id":"cap-nope"})
    check("F3 unknown capability rejected", ru.status in (400,409,422), f"{ru.status}")
    # oversized + nested
    big=evt("authentication_failure","/login",401,"203.0.113.9",9); big["details"]={"blob":"B"*40000}
    rb=ingest(issue(sid),[big])
    rej=(rb.body.get("data",{}) or {}).get("rejected",[]) if rb.status==200 else []
    check("F3 oversized rejected", (rb.status==200 and rej) or rb.status in (400,413), str(rb.body)[:300])
    nest=evt("authentication_failure","/login",401,"203.0.113.9",10); d=nest["details"]
    for i in range(30): d={"nest":d}
    nest["details"]=d
    rn3=ingest(issue(sid),[nest])
    check("F3 deeply-nested handled (accept or truthful reject)", rn3.status in (200,400,413), str(rn3.body)[:300])
    fails=[n for n,ok in R if not ok]
    print(f"FINAL-F3 {len(R)-len(fails)}/{len(R)} passed",flush=True)
    _MC(MONGO_URI).drop_database(db)
    import sys as _s; _s.exit(0 if not fails else 1)
if __name__=="__main__": main()
