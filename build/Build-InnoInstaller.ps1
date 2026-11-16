# STATUS: DIAMANT VGT SUPREME
<#
.SYNOPSIS
Builds the branded Inno Setup installer for GeDefense Windows.

.DESCRIPTION
Requires a completed payload (payload\VGT\GeDefense) from
build\Build-GeDefenseStandalone.ps1. Inno Setup 7 must be installed.
The resulting installer is signed with the release certificate from
certificates\release-thumbprint.txt unless -NoSign is used.

.PARAMETER NoSign
Skips Authenticode signing (development/test only).

.PARAMETER SkipPayloadCheck
Skips the payload presence check (not recommended).
#>
[CmdletBinding()]
param(
    [switch]$NoSign,
    [switch]$SkipPayloadCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
# FIND-WIN-022: the shared supply-chain module owns the registered release-asset
# naming contract; the builder proves its output matches it before declaring
# success (an unregistered Inno asset would make the channel gate fail closed).
Import-Module -Name (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Force
$payloadRoot = Join-Path $projectRoot 'payload\VGT\GeDefense'
$installerSource = Join-Path $projectRoot 'installer\inno\GeDefense.iss'
$releaseRoot = Join-Path $projectRoot 'release'

if (-not $SkipPayloadCheck) {
    foreach ($required in @(
        (Join-Path $payloadRoot 'installer\Bootstrap-GeDefense.ps1'),
        (Join-Path $payloadRoot 'installer\Install-GeDefense.ps1'),
        (Join-Path $payloadRoot 'installer\Uninstall-GeDefense.ps1'),
        (Join-Path $payloadRoot 'vgt-release.cer'),
        (Join-Path $payloadRoot 'vgt-payload.cat'),
        (Join-Path $payloadRoot 'bin\gedefense-windows.exe')
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Payload is incomplete. Run build\Build-GeDefenseStandalone.ps1 first. Missing: $required"
        }
    }
}

if (-not (Test-Path -LiteralPath $installerSource -PathType Leaf)) {
    throw "Inno installer script is missing: $installerSource"
}

$isccCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\InnoSetup7\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe'),
    'C:\Program Files (x86)\Inno Setup 7\ISCC.exe',
    'C:\Program Files\Inno Setup 7\ISCC.exe',
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)
$iscc = $isccCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $iscc) {
    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
}
if (-not $iscc) {
    throw 'Inno Setup compiler (ISCC.exe) was not found. Install Inno Setup 7 and retry.'
}

New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
Write-Host "Inno compiler: $iscc"
Write-Host "Payload:       $payloadRoot"

Push-Location (Split-Path -Parent $installerSource)
try {
    & $iscc $installerSource
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}

$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'VERSION') -Raw -Encoding UTF8).Trim()
$installerPath = Join-Path $releaseRoot ("GeDefense-Setup-Inno-x64-v{0}.exe" -f $version)
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "Inno installer output is missing: $installerPath"
}
# FIND-WIN-022: older builders produced a bare "GeDefense-Setup-Inno-x64-v<ver>.json"
# (Path.ChangeExtension) instead of the registered "<installer>.exe.json". Both
# files are same-version sidecars, so a stale legacy file must be removed by the
# owner instead of silently coexisting with the registered asset (the release
# channel gate rejects it as an unrecognised asset, fail-closed).
$legacySidecarPath = Join-Path $releaseRoot ("GeDefense-Setup-Inno-x64-v{0}.json" -f $version)
if (Test-Path -LiteralPath $legacySidecarPath -PathType Leaf) {
    throw "Stale legacy Inno sidecar is present: $legacySidecarPath. Remove it (it predates the registered <installer>.exe.json naming) and rebuild; the release channel gate rejects unrecognised assets."
}

if (-not $NoSign) {
    $thumbprintPath = Join-Path $projectRoot 'certificates\release-thumbprint.txt'
    if (-not (Test-Path -LiteralPath $thumbprintPath -PathType Leaf)) {
        throw 'Release certificate thumbprint is missing.'
    }
    $thumbprint = (Get-Content -LiteralPath $thumbprintPath -Raw -Encoding UTF8).Trim()
    if ($thumbprint -notmatch '^[A-F0-9]{40}$') { throw 'Release certificate thumbprint is invalid.' }
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
    $signed = Set-AuthenticodeSignature -LiteralPath $installerPath -Certificate $certificate -HashAlgorithm SHA256 -ErrorAction Stop
    if ($signed.Status -ne 'Valid') {
        throw "Inno installer signing failed: $($signed.StatusMessage)"
    }
    Write-Host "Signed with $thumbprint ($($signed.Status))"
} else {
    Write-Warning 'Inno installer was not signed (-NoSign).'
}

$hash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$shaPath = "$installerPath.sha256"
Set-Content -LiteralPath $shaPath -Value ("{0}  {1}" -f $hash, (Split-Path -Leaf $installerPath)) -Encoding ASCII

$sidecar = [ordered]@{
    schema = 'vgt-inno-installer-sidecar/1'
    product = 'VGT GeDefense Titan'
    version = $version
    architecture = 'x64'
    bytes = (Get-Item -LiteralPath $installerPath).Length
    sha256 = $hash
    signature = if ($NoSign) { 'NotSigned' } else { 'Valid' }
    signerThumbprint = if ($NoSign) { '' } else { $thumbprint }
    builtUtc = [DateTime]::UtcNow.ToString('o')
    language = @('de', 'en', 'ru', 'zh')
}
$sidecarPath = "$installerPath.json"
$sidecar | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $sidecarPath -Encoding UTF8

# FIND-WIN-022: prove the three emitted file names are exactly the registered
# Inno release assets. If the pattern and the builder ever drift apart, the build
# aborts here instead of producing a channel that fails closed later.
foreach ($emittedPath in @($installerPath, $shaPath, $sidecarPath)) {
    $emittedName = Split-Path -Leaf $emittedPath
    $registeredVersion = Get-VgtReleaseAssetVersion -FileName $emittedName
    if ($registeredVersion -ne $version) {
        throw "Inno release asset is not registered for VERSION $version : $emittedName (Get-VgtReleaseAssetVersion returned '$registeredVersion')."
    }
}

Write-Host "Installer: $installerPath"
Write-Host "SHA-256:   $hash"
Write-Host "Sidecar:   $sidecarPath"
