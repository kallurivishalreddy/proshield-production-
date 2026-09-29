@echo off
REM ===========================================================================
REM  Start BOTH ProShield planes from this repository (current code).
REM
REM    analyst plane : http://127.0.0.1:8188
REM                    UI    -> http://127.0.0.1:8188/static/soc/index.html
REM                    API   -> http://127.0.0.1:8188/api/proxy
REM    ingress plane : http://127.0.0.1:8189
REM                    API   -> http://127.0.0.1:8189/api/ingress
REM                    health-> http://127.0.0.1:8189/api/ingress/health
REM
REM  Login (dev credentials seeded by --seed-credentials):
REM      admin   / admin-dev-credential
REM      analyst / analyst-dev-credential
REM
REM  Ports 8088/8089 are left alone: on an installed machine they belong to the
REM  ProShieldService (SCM-supervised) planes.
REM
REM  Both planes MUST share PROSHIELD_SOURCE_SIGNING_KEY, otherwise every
REM  source-identity token issued on the analyst plane fails at the ingress.
REM ===========================================================================
setlocal
cd /d "%~dp0.."

if "%PROSHIELD_MONGO_DB%"=="" set "PROSHIELD_MONGO_DB=proshield_ist_verify"
if "%PROSHIELD_AUTH_SIGNING_KEY%"=="" set "PROSHIELD_AUTH_SIGNING_KEY=live-pair-auth-key-0123456789abcdef"
if "%PROSHIELD_SOURCE_SIGNING_KEY%"=="" set "PROSHIELD_SOURCE_SIGNING_KEY=live-pair-source-key-0123456789abcdef"

echo Starting analyst plane  (127.0.0.1:8188, db=%PROSHIELD_MONGO_DB%) ...
start "proshield-analyst" /min cmd /c "python -m scripts.proxy_server --host 127.0.0.1 --port 8188 --backend mongo --seed-credentials > analyst_live.log 2>&1"

echo Starting ingress plane  (127.0.0.1:8189, db=%PROSHIELD_MONGO_DB%) ...
start "proshield-ingress" /min cmd /c "python -m scripts.ingress_server --host 127.0.0.1 --port 8189 --backend mongo > ingress_live.log 2>&1"

echo.
echo UI   : http://127.0.0.1:8188/static/soc/index.html
echo login: admin / admin-dev-credential
echo logs : analyst_live.log , ingress_live.log
endlocal