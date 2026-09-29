@echo off
cd /d "c:\Users\k.vishal reddy\Downloads\proshield rule based mvp"
set PROSHIELD_AUTH_SIGNING_KEY=pw51-auth-key-0123456789abcdef
set PROSHIELD_SOURCE_SIGNING_KEY=pw51-source-key-0123456789abcdef
set PROSHIELD_MONGO_DB=proshield_phase51_pw
python -m scripts.proxy_server --port 8797 --backend mongo --seed-credentials > pw51_server.log 2>&1
