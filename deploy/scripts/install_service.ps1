# ProShield Windows Service - manual registration / repair helper.
#
# The installer performs all of this automatically.  Use this script to
#   * register the service on a machine where ProShield was copied manually,
#   * repair a damaged service registration,
#   * re-apply auto-start / recovery after an administrator changed them.
#
# Requires an ELEVATED PowerShell session.
#
#   powershell -ExecutionPolicy Bypass -File deploy\scripts\install_service.ps1
#   powershell -ExecutionPolicy Bypass -File deploy\scripts\install_service.ps1 -InstallDir "C:\Program Files\ProShield"

[CmdletBinding()]
param(
    [string] $InstallDir = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [int]    $WaitSeconds = 180
)

$ErrorActionPreference = 'Stop'
$serviceName = 'ProShieldService'
$serviceExe  = Join-Path $InstallDir 'service\ProShieldService.exe'

function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run from an elevated PowerShell session."
    }
}

Assert-Admin

if (-not (Test-Path $serviceExe)) {
    throw "ProShieldService.exe not found at $serviceExe. Pass -InstallDir."
}

Write-Host "ProShield install directory : $InstallDir"
Write-Host "Service executable          : $serviceExe"

# MongoDB ordering: make the service depend on the existing MongoDB service so
# the SCM starts MongoDB first.  The service additionally waits for query
# readiness, so a missing dependency is degraded but not fatal.  MongoDB itself
# is never installed, modified or restarted by ProShield.
$mongoService = Get-Service -Name 'MongoDB' -ErrorAction SilentlyContinue
if ($null -eq $mongoService) {
    Write-Warning "MongoDB service ('MongoDB') was not found. ProShield will still wait for 127.0.0.1:27017."
}

Write-Host ''
Write-Host '==> Registering the service (auto-start, recovery, MongoDB ordering)'
& $serviceExe install --wait $WaitSeconds
if ($LASTEXITCODE -ne 0) {
    throw "Service registration failed with exit code $LASTEXITCODE"
}

Write-Host ''
Write-Host '==> Applying SCM failure recovery'
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null

Write-Host ''
Write-Host '==> Service status'
& sc.exe query $serviceName

Write-Host ''
Write-Host '==> Supervisor status'
$statusFile = Join-Path $env:ProgramData 'ProShield\state\health.json'
if (Test-Path $statusFile) {
    Get-Content $statusFile -Raw
} else {
    Write-Warning "No supervisor status yet at $statusFile (the service may still be starting)."
}

Write-Host ''
Write-Host 'ProShield Service is registered. Verify with:'
Write-Host "  sc query $serviceName"
Write-Host "  Get-Content `"$statusFile`""
