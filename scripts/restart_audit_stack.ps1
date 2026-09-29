$ErrorActionPreference = 'Continue'
$root = 'c:\Users\k.vishal reddy\Downloads\proshield rule based mvp'
$log = Join-Path $root 'live_restart_out.txt'
"=== LIVE RESTART $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

foreach ($port in 8088, 8089) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($c in $conns) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue }
        "killed port $port" | Out-File $log -Append -Encoding utf8
    }
}
Start-Sleep -Seconds 1

$cmdProxy = 'set PROSHIELD_AUTH_SIGNING_KEY=patch-live-auth-key-2026&& set PROSHIELD_SOURCE_SIGNING_KEY=patch-live-source-key-2026&& set PROSHIELD_MONGO_DB=proshield&& cd /d "' + $root + '" && python -m scripts.proxy_server --host 127.0.0.1 --port 8088 --backend mongo --seed-credentials'
Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmdProxy" -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'proxy_audit.log') -RedirectStandardError (Join-Path $root 'proxy_audit_err.log')

$cmdIngress = 'set PROSHIELD_AUTH_SIGNING_KEY=patch-live-auth-key-2026&& set PROSHIELD_SOURCE_SIGNING_KEY=patch-live-source-key-2026&& set PROSHIELD_MONGO_DB=proshield&& cd /d "' + $root + '" && python -m scripts.ingress_server --host 127.0.0.1 --port 8089 --backend mongo'
Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmdIngress" -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'ingress_audit.log') -RedirectStandardError (Join-Path $root 'ingress_audit_err.log')

function Wait-Port($port) {
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        try { $null = New-Object Net.Sockets.TcpClient('127.0.0.1', $port); return $true } catch { }
    }
    return $false
}
("PROXY_8088_UP=" + (Wait-Port 8088)) | Out-File $log -Append -Encoding utf8
("INGRESS_8089_UP=" + (Wait-Port 8089)) | Out-File $log -Append -Encoding utf8
try {
    $h = Invoke-WebRequest -Uri 'http://127.0.0.1:8088/health' -UseBasicParsing -TimeoutSec 5
    ("HEALTH=" + $h.Content) | Out-File $log -Append -Encoding utf8
} catch { ("HEALTH_ERR=" + $_.Exception.Message) | Out-File $log -Append -Encoding utf8 }
"DONE" | Out-File $log -Append -Encoding utf8
