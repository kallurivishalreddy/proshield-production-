<#
.SYNOPSIS
    Reproducible ProShield Windows release build.

.DESCRIPTION
    Builds every release artefact into the dedicated release directory
    dist/windows/<version>/ and nowhere else:

        ProShield.exe                   native desktop shell (WebView2)
        ProShieldService.exe            Windows service host
        ProShieldSetup-v<version>.exe   installer
        manifest.json                   signed update metadata
        checksums.txt                   SHA-256 of every artefact
        build-report.json               toolchain + hashes

    Steps performed:
        1. build the authoritative React UI (frontend/src_upgraded_gemini)
        2. stage a relocatable Python runtime + pinned backend dependencies
        3. stage the authoritative implementation (allow-list only)
        4. freeze ProShieldService.exe and ProShield.exe with PyInstaller
        5. compile the installer with Inno Setup 6
        6. sign manifest.json with the update-channel Ed25519 key
        7. write checksums.txt and build-report.json

.PREREQUISITES
    python -m pip install -r packaging/requirements-build.txt
    winget install -e --id JRSoftware.InnoSetup
    node + npm (for the React build)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build_release.ps1 -Version 1.0.0 -UpdateUrl http://127.0.0.1:8099

.EXAMPLE
    # quick rebuild reusing the already-staged runtime and UI
    powershell -ExecutionPolicy Bypass -File packaging\build_release.ps1 -SkipFrontend -SkipRuntime
#>
[CmdletBinding()]
param(
    [string] $Version              = '',
    [string] $Channel              = 'testing',
    [string] $UpdateUrl            = '',
    [string] $Notes                = '',
    [switch] $WithTestModeInstaller,
    [switch] $SkipFrontend,
    [switch] $SkipRuntime,
    [switch] $SkipService,
    [switch] $SkipDesktop,
    [switch] $SkipInstaller,
    [switch] $NoSign,
    [switch] $Clean
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $arguments = @('-m', 'deploy.build_windows', '--channel', $Channel)
    if ($Version)              { $arguments += @('--version', $Version) }
    if ($UpdateUrl)            { $arguments += @('--update-url', $UpdateUrl) }
    if ($Notes)                { $arguments += @('--notes', $Notes) }
    if ($WithTestModeInstaller){ $arguments += '--with-testmode-installer' }
    if ($SkipFrontend)         { $arguments += '--skip-frontend' }
    if ($SkipRuntime)          { $arguments += '--skip-runtime' }
    if ($SkipService)          { $arguments += '--skip-service' }
    if ($SkipDesktop)          { $arguments += '--skip-desktop' }
    if ($SkipInstaller)        { $arguments += '--skip-installer' }
    if ($NoSign)               { $arguments += '--no-sign' }
    if ($Clean)                { $arguments += '--clean' }

    Write-Host "ProShield release build" -ForegroundColor Cyan
    Write-Host ("  repo root : " + $repoRoot)
    Write-Host ("  channel   : " + $Channel)
    Write-Host ("  update url: " + $(if ($UpdateUrl) { $UpdateUrl } else { '<unset>' }))
    Write-Host ""

    & python @arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "build failed with exit code $code" }

    Write-Host ""
    Write-Host "Release directory:" -ForegroundColor Green
    Get-ChildItem (Join-Path $repoRoot 'dist\windows') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1 |
        ForEach-Object {
            Write-Host ("  " + $_.FullName)
            Get-ChildItem $_.FullName -File | ForEach-Object {
                Write-Host ("    " + $_.Name)
            }
        }
}
finally {
    Pop-Location
}
