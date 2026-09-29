# ProShield Windows Service - removal helper.
#
# Stops and deletes the ProShield Service WITHOUT touching ProShield data.
# MongoDB security data is never removed by ProShield tooling.
#
# Requires an ELEVATED PowerShell session.
#
#   powershell -ExecutionPolicy Bypass -File deploy\scripts\uninstall_service.ps1

[CmdletBinding()]
param(
    [switch] $PurgeRuntimeData
)

$ErrorActionPreference = 'Continue'
$serviceName = 'ProShieldService'
$dataDir     = Join-Path $env:ProgramData 'ProShield'

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run from an elevated PowerShell session."
    }
}
Assert-Admin

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host "Service '$serviceName' is not registered."
} else {
    Write-Host "==> Stopping $serviceName"
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
    }

    Write-Host "==> Deleting $serviceName"
    & sc.exe delete $serviceName
}

# The desktop application is a normal process; it holds no lock on the service.
Get-Process -Name 'ProShield' -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "==> Closing desktop application (pid $($_.Id))"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "MongoDB was NOT touched: the 'proshield' database and every security"
Write-Host "event, detection, correlation, case and evidence record are intact."

if ($PurgeRuntimeData) {
    if (Test-Path $dataDir) {
        Write-Host ''
        Write-Host "==> Removing ProShield runtime data at $dataDir (logs, state, staged updates)"
        Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "ProShield runtime data preserved at $dataDir"
}
