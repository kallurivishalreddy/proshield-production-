"""STRIX E2E helper: (re)launch the live proxy + ingress listeners as
fully-detached background processes sharing one source signing key."""
from __future__ import annotations
import os, re, socket, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROXY_PORT = 8000
INGRESS_PORT = 8089
SHARED_SOURCE_KEY = "shared-e2e-source-key-2026"
SHARED_AUTH_KEY = "shared-e2e-auth-key-2026"

def _pids_on(port):
    out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    pids=set()
    for line in out.splitlines():
        if "LISTENING" in line and f":{port}" in line:
            m=re.search(r"(\d+)\s*$", line)
            if m: pids.add(m.group(1))
    return sorted(pids)

def _kill(port):
    for pid in _pids_on(port):
        try: subprocess.run(["taskkill","/F","/PID",pid],capture_output=True,text=True)
        except Exception: pass

def _wait_port(port, timeout=40.0):
    deadline=time.time()+timeout
    while time.time()<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=1): return True
        except OSError: time.sleep(0.4)
    return False

def _spawn(module, port, log_name, seed=False):
    env=dict(os.environ)
    env["PROSHIELD_SOURCE_SIGNING_KEY"]=SHARED_SOURCE_KEY
    env["PROSHIELD_AUTH_SIGNING_KEY"]=SHARED_AUTH_KEY
    env["PROSHIELD_MONGO_URI"]=env.get("PROSHIELD_MONGO_URI","mongodb://127.0.0.1:27017/")
    env["PROSHIELD_MONGO_DB"]=env.get("PROSHIELD_MONGO_DB","proshield")
    logf=open(ROOT/log_name,"w",encoding="utf-8")
    cmd=[sys.executable,"-m",module,"--backend","mongo","--port",str(port)]
    if seed: cmd.append("--seed-credentials")
    flags=subprocess.CREATE_NEW_PROCESS_GROUP|getattr(subprocess,"DETACHED_PROCESS",0)
    proc=subprocess.Popen(cmd,cwd=str(ROOT),env=env,stdout=logf,
        stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,close_fds=True,
        creationflags=flags)
    return proc.pid

def main():
    _kill(PROXY_PORT); _kill(INGRESS_PORT); time.sleep(0.5)
    pp=_spawn("scripts.proxy_server",PROXY_PORT,"proxy_e2e.log",seed=True)
    ip=_spawn("scripts.ingress_server",INGRESS_PORT,"ingress_e2e.log")
    ok_p=_wait_port(PROXY_PORT); ok_i=_wait_port(INGRESS_PORT)
    print(f"proxy:{PROXY_PORT} up={ok_p} pid={pp}; ingress:{INGRESS_PORT} up={ok_i} pid={ip}")
    return 0 if (ok_p and ok_i) else 3

if __name__=="__main__":
    raise SystemExit(main())