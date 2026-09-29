$ErrorActionPreference = 'Continue'
$root = 'c:\Users\k.vishal reddy\Downloads\proshield rule based mvp'
$log = Join-Path $root 'restart_out.txt'
"=== RESTART $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

# 1. Kill anything listening on 8088
$conns = Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue
if ($conns) {
    foreach ($c in $conns) {
        "killing pid $($c.OwningProcess)" | Out-File $log -Append -Encoding utf8
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    "KILLED_8088" | Out-File $log -Append -Encoding utf8
} else {
    "PORT_FREE" | Out-File $log -Append -Encoding utf8
}

# 2. Verify MongoDB is up
$m = Get-NetTCPConnection -LocalPort 27017 -State Listen -ErrorAction SilentlyContinue
("MONGO_27017=" + [bool]$m) | Out-File $log -Append -Encoding utf8

# 3. Relaunch proxy server detached with pinned signing keys
$cmd = 'set PROSHIELD_AUTH_SIGNING_KEY=dev-auth-key-manual-2026&& set PROSHIELD_SOURCE_SIGNING_KEY=dev-source-key-manual-2026&& cd /d "' + $root + '" && python -m scripts.proxy_server --host 127.0.0.1 --port 8088 --backend mongo --seed-credentials'
Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmd" -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'proxy_live.log') -RedirectStandardError (Join-Path $root 'proxy_live_err.log')

# 4. Wait for port 8088
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    try {
        $null = New-Object Net.Sockets.TcpClient('127.0.0.1', 8088)
        $up = $true; break
    } catch { }
}
("PORT_8088_UP=" + $up) | Out-File $log -Append -Encoding utf8

# 5. Probe /health and frontend
try {
    $h = Invoke-WebRequest -Uri 'http://127.0.0.1:8088/health' -UseBasicParsing -TimeoutSec 5
    ("HEALTH=" + $h.StatusCode + " BODY=" + $h.Content.Substring(0, [Math]::Min(120, $h.Content.Length))) | Out-File $log -Append -Encoding utf8
} catch {
    ("HEALTH_ERR=" + $_.Exception.Message) | Out-File $log -Append -Encoding utf8
}
try {
    $f = Invoke-WebRequest -Uri 'http://127.0.0.1:8088/static/soc/index.html' -UseBasicParsing -TimeoutSec 5
    ("FRONTEND=" + $f.StatusCode + " BYTES=" + $f.RawContentLength) | Out-File $log -Append -Encoding utf8
} catch {
    ("FRONTEND_ERR=" + $_.Exception.Message) | Out-File $log -Append -Encoding utf8
}
"DONE" | Out-File $log -Append -Encoding utf8
