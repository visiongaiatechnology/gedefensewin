# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [switch]$TrustDevelopmentCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$payloadRoot = Join-Path $projectRoot 'payload\VGT\GeDefense'
$bundleRoot = Join-Path $projectRoot 'work\standalone-bundle'
$bundlePayload = Join-Path $bundleRoot 'payload'
$embeddedBundleDirectory = Join-Path $sourceRoot 'cmd\gedefense-installer\bundle'
$embeddedBundle = Join-Path $embeddedBundleDirectory 'payload.zip'
$releaseRoot = Join-Path $projectRoot 'release'
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'VERSION') -Raw -Encoding UTF8).Trim()
if ($version -notmatch '^5\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$') { throw [IO.InvalidDataException]::new('Release VERSION is invalid.') }
$releaseExecutable = Join-Path $releaseRoot ("GeDefense-Setup-x64-v{0}.exe" -f $version)
$releaseManifest = Join-Path $releaseRoot ("GeDefense-Setup-x64-v{0}.json" -f $version)
$releaseSums = Join-Path $releaseRoot 'SHA256SUMS.txt'
$thumbprintFile = Join-Path $projectRoot 'certificates\release-thumbprint.txt'

function Assert-VgtChildPath {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Parent)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolvedPath.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Standalone build path escaped the VGT workspace.') }
}

Assert-VgtChildPath -Path $bundleRoot -Parent $projectRoot
Assert-VgtChildPath -Path $embeddedBundle -Parent $projectRoot
Assert-VgtChildPath -Path $releaseExecutable -Parent $projectRoot

# SC-FIND-005: deterministic release-assembly order. The chain below is a hard
# contract (also asserted by tools/Test-PublishGates.ps1 via the VGT-STAGE
# markers):
#   payload -> payload-complete SBOM -> signed installer -> provenance ->
#   installer .sha256 sidecar -> JSON release sidecar (LAST) -> SHA256SUMS.txt.
# Provenance MUST be generated after the Authenticode signing step because it
# records the measured hash of the FINAL installer bytes; generating it before
# signing would embed a stale hash that Test-VgtProvenance.ps1 rejects. The
# JSON sidecar is written only after the final SBOM/provenance files exist and
# embeds their measured hashes; it is therefore never stale. The source archive
# is produced first by build/Build-SourceRelease.ps1 so the provenance can bind
# the final source archive too (see docs/BUILDING.md).
Import-Module -Name (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Force
Import-Module -Name (Join-Path $PSScriptRoot 'PublishVerification.psm1') -Force
$sbomGenerator = Join-Path $projectRoot 'tools\New-VgtSbom.ps1'
if (-not (Test-Path -LiteralPath $sbomGenerator -PathType Leaf)) { throw [IO.FileNotFoundException]::new('tools/New-VgtSbom.ps1 is missing.') }
& $sbomGenerator
$manifestInfo = Write-VgtSourceManifest -ProjectRoot $projectRoot
Write-Host ('Source manifest rebound: {0} files, digest {1}' -f $manifestInfo.FileCount,$manifestInfo.Digest)

& (Join-Path $PSScriptRoot 'Test-GeDefenseRelease.ps1')

# The provenance/sidecar can only bind the source archive when it already exists:
# the documented release order is Build-SourceRelease.ps1 first, then this script.
# Without the archive the build still works for non-publishable development
# builds, but the publish gate will refuse the release (source ZIP is a required
# asset), so warn early instead of silently producing a non-publishable channel.
$sourceArchivePath = Join-Path $releaseRoot ("VGT_GeDefense_Windows_{0}_Source.zip" -f $version)
if (-not (Test-Path -LiteralPath $sourceArchivePath -PathType Leaf)) {
    Write-Warning ('No current source archive in release/. Run build/Build-SourceRelease.ps1 BEFORE this script for a publishable release; otherwise provenance and release sidecar will not bind a source archive and Publish-GitHubRelease.ps1 will refuse to publish.')
}

# ---------------------------------------------------------------------------
# Stage 1: signed payload (Build-VgtPayload builds, signs and verifies it)
# ---------------------------------------------------------------------------
& (Join-Path $PSScriptRoot 'Build-VgtPayload.ps1') -TrustDevelopmentCertificate:$TrustDevelopmentCertificate
if (-not (Test-Path -LiteralPath $payloadRoot -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Signed GeDefense payload was not produced.') }
$payloadFileCount = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File -Force).Count
if ($payloadFileCount -lt 30) { throw [IO.InvalidDataException]::new(('Signed GeDefense payload is incomplete: {0} files.' -f $payloadFileCount)) }
# VGT-STAGE: payload-built

if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }
New-Item -Path $bundlePayload,$embeddedBundleDirectory,$releaseRoot -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $payloadRoot '*') -Destination $bundlePayload -Recurse -Force
if (Test-Path -LiteralPath $embeddedBundle) { Remove-Item -LiteralPath $embeddedBundle -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($bundleRoot,$embeddedBundle,[IO.Compression.CompressionLevel]::Optimal,$false)
if ((Get-Item -LiteralPath $embeddedBundle).Length -gt 134217728) { throw [IO.InvalidDataException]::new('Embedded installer payload exceeds the 128 MiB release boundary.') }

# ---------------------------------------------------------------------------
# Stage 2: static analysis + unsigned installer compilation
# ---------------------------------------------------------------------------
Push-Location $sourceRoot
try {
    $goFiles = @(Get-ChildItem -LiteralPath '.\cmd','.\internal' -Recurse -File -Filter '*.go' | Sort-Object FullName | ForEach-Object FullName)
    $unformatted = @()
    for ($offset = 0; $offset -lt $goFiles.Count; $offset += 40) {
        $batch = @($goFiles[$offset..([Math]::Min($offset + 39,$goFiles.Count - 1))])
        $unformatted += @(& gofmt -l @batch)
        if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Go formatting gate failed.') }
    }
    if ($unformatted.Count -gt 0) { throw [InvalidOperationException]::new('Go formatting gate failed.') }
    & go test -race -tags vgt_bundle ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone GeDefense tests failed.') }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone GeDefense static analysis failed.') }
    if (Test-Path -LiteralPath $releaseExecutable) { Remove-Item -LiteralPath $releaseExecutable -Force }
    & go build -tags vgt_bundle -trimpath -ldflags '-s -w -H=windowsgui' -o $releaseExecutable ./cmd/gedefense-installer
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone installer compilation failed.') }
} finally { Pop-Location }

# ---------------------------------------------------------------------------
# Stage 3: payload-complete SBOM artifact (the payload is final at this point;
# the SBOM does not depend on the Authenticode block of the installer)
# ---------------------------------------------------------------------------
$sbomArtifact = Join-Path $releaseRoot ("GeDefense-SBOM-v{0}.cdx.json" -f $version)
$provenanceArtifact = Join-Path $releaseRoot ("GeDefense-Provenance-v{0}.json" -f $version)
$sbomTester = Join-Path $projectRoot 'tools\Test-VgtSbom.ps1'
$provenanceGenerator = Join-Path $projectRoot 'tools\New-VgtProvenance.ps1'
$provenanceVerifier = Join-Path $projectRoot 'tools\Test-VgtProvenance.ps1'
foreach ($requiredTool in @($sbomTester,$provenanceGenerator,$provenanceVerifier)) {
    if (-not (Test-Path -LiteralPath $requiredTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Required supply-chain tool is missing: {0}' -f $requiredTool)) }
}
& $sbomGenerator -ArtifactMode -PayloadRoot $payloadRoot -OutputPath $sbomArtifact
$sbomValidation = & $sbomTester -ArtifactMode -Path $sbomArtifact -PayloadRoot $payloadRoot
# VGT-STAGE: sbom-artifact

# ---------------------------------------------------------------------------
# Stage 4: Authenticode signing of the FINAL installer bytes (self-signed;
# public CA/RFC3161/revocation remain documented external blockers)
# ---------------------------------------------------------------------------
$thumbprint = (Get-Content -LiteralPath $thumbprintFile -Raw -Encoding UTF8).Trim()
if ($thumbprint -notmatch '^[A-F0-9]{40}$') { throw [Security.SecurityException]::new('Release certificate thumbprint is invalid.') }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
$verifiedSignature = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
    Set-AuthenticodeSignature -LiteralPath $releaseExecutable -Certificate $certificate -HashAlgorithm SHA256 -ErrorAction Stop | Out-Null
    Start-Sleep -Milliseconds 400
    $verifiedSignature = Get-AuthenticodeSignature -LiteralPath $releaseExecutable
    if ($verifiedSignature.Status -eq 'Valid' -and $verifiedSignature.SignerCertificate -and $verifiedSignature.SignerCertificate.Thumbprint -eq $thumbprint) {
        break
    }
    Start-Sleep -Milliseconds ([Math]::Min(2500, 300 * $attempt))
}
if (-not $verifiedSignature -or $verifiedSignature.Status -ne 'Valid' -or -not $verifiedSignature.SignerCertificate -or $verifiedSignature.SignerCertificate.Thumbprint -ne $thumbprint) {
    $detail = if ($verifiedSignature) { [string]$verifiedSignature.StatusMessage } else { 'no signature status' }
    throw [Security.SecurityException]::new("Standalone installer signature verification failed: $detail")
}
# VGT-STAGE: installer-signed

# ---------------------------------------------------------------------------
# Stage 5: provenance over the final tree, signed installer and SBOM. It
# records the measured installer hash (including the Authenticode block), the
# payload-complete SBOM hash and - when build/Build-SourceRelease.ps1 ran first
# - the final source archive. It intentionally does NOT bind the JSON sidecar
# (which embeds the provenance hash; binding both ways is circular).
# ---------------------------------------------------------------------------
& $provenanceGenerator -OutputPath $provenanceArtifact -RequireSourceManifest
$provenanceValidation = & $provenanceVerifier -Path $provenanceArtifact -RequireSourceManifest
# VGT-STAGE: provenance

# ---------------------------------------------------------------------------
# Stage 6: installer SHA-256 sidecar (measured from the final signed bytes)
# ---------------------------------------------------------------------------
$releaseSidecar = "$releaseExecutable.sha256"
$measuredExecutableHash = Get-VgtFileSha256Lower -Path $releaseExecutable
$releaseSidecarLine = ('{0}  {1}' -f $measuredExecutableHash,[IO.Path]::GetFileName($releaseExecutable))
[IO.File]::WriteAllText($releaseSidecar,($releaseSidecarLine + "`n"),[Text.UTF8Encoding]::new($false))
$verifiedExecutableHash = [string](Assert-VgtAssetHash -Path $releaseExecutable -SidecarPath $releaseSidecar)
# VGT-STAGE: hash-sidecar

# ---------------------------------------------------------------------------
# Stage 7 (LAST metadata stage): release sidecar with measured values only.
# It binds the final SBOM and provenance hashes; every value comes from a real
# measurement, no literal hash/status is written.
# ---------------------------------------------------------------------------
$measuredSbomHash = Get-VgtFileSha256Lower -Path $sbomArtifact
$measuredProvenanceHash = Get-VgtFileSha256Lower -Path $provenanceArtifact
$release = [ordered]@{
    schema = 'vgt-release-sidecar/1'
    product = 'VGT GeDefense Titan'
    version = $version
    architecture = 'x64'
    bytes = (Get-Item -LiteralPath $releaseExecutable).Length
    sha256 = $verifiedExecutableHash
    signerThumbprint = $thumbprint
    signature = [string]$verifiedSignature.Status
    builtUtc = [DateTime]::UtcNow.ToString('o')
    sbom = [ordered]@{
        name = [IO.Path]::GetFileName($sbomArtifact)
        sha256 = $measuredSbomHash
        components = [int]$sbomValidation.Components
    }
    provenance = [ordered]@{
        name = [IO.Path]::GetFileName($provenanceArtifact)
        sha256 = $measuredProvenanceHash
        sourceTreeDigest = [string]$provenanceValidation.SourceTreeDigest
    }
}
$release | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $releaseManifest -Encoding UTF8
$sidecarBinding = Assert-VgtReleaseSidecarBinding -SidecarPath $releaseManifest -ReleaseDirectory $releaseRoot -ExpectedVersion $version -SbomPath $sbomArtifact -ProvenancePath $provenanceArtifact
$jsonManifest = Assert-VgtJsonManifestMatchesAsset -ManifestPath $releaseManifest -AssetPath $releaseExecutable -ExpectedVersion $version
Write-Host ('Release sidecar verified: SBOM {0} components, provenance source tree {1}' -f $sidecarBinding.SbomComponents,$sidecarBinding.SourceTreeDigest)
# VGT-STAGE: release-sidecar

# ---------------------------------------------------------------------------
# Stage 8: SHA256SUMS over every current release asset (source archive and its
# sidecar included when build/Build-SourceRelease.ps1 ran first). This is the
# final hash manifest consumed by the channel gate and the publish verification.
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $releaseSums) { Remove-Item -LiteralPath $releaseSums -Force }
$sumsAssetEntries = [Collections.Generic.List[object]]::new()
foreach ($releaseFile in @(Get-ChildItem -LiteralPath $releaseRoot -File -Force | Sort-Object Name)) {
    if ($releaseFile.Name -eq 'SHA256SUMS.txt') { continue }
    $sumsAssetEntries.Add([pscustomobject]@{ Name = $releaseFile.Name; Path = $releaseFile.FullName })
}
if ($sumsAssetEntries.Count -lt 5) { throw [IO.InvalidDataException]::new(('Release directory contains too few assets for a checksum manifest: {0}' -f $sumsAssetEntries.Count)) }
$sums = Write-VgtSha256Sums -Assets @($sumsAssetEntries.ToArray()) -OutputPath $releaseSums
$sumsCoverage = Assert-VgtSha256SumsCoverage -ReleaseDirectory $releaseRoot
# VGT-STAGE: sha256sums

# Final self-attestation: re-validate the finished release set with the same
# verifiers the publish gate uses (provenance/SBOM are unchanged since their
# stage; the sidecar and sums files are not part of the provenance binding).
$finalSbomValidation = & $sbomTester -ArtifactMode -Path $sbomArtifact -PayloadRoot $payloadRoot
$finalProvenanceValidation = & $provenanceVerifier -Path $provenanceArtifact -RequireSourceManifest
if ([int]$finalSbomValidation.Components -ne [int]$sbomValidation.Components) { throw [Security.SecurityException]::new('SBOM component count changed during release assembly.') }
if ([string]$finalProvenanceValidation.SourceTreeDigest -ne [string]$provenanceValidation.SourceTreeDigest) { throw [Security.SecurityException]::new('Provenance source-tree digest changed during release assembly.') }
if ([int]$sumsCoverage.Entries -ne $sumsAssetEntries.Count) { throw [Security.SecurityException]::new('SHA256SUMS.txt does not cover every release asset.') }

# Clean transient build inputs; the release artifacts stay in release/.
if (Test-Path -LiteralPath $embeddedBundle) { Remove-Item -LiteralPath $embeddedBundle -Force }
if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }

[pscustomobject][ordered]@{
    Status = 'PASS'
    Version = $version
    ReleaseDirectory = $releaseRoot
    Installer = $releaseExecutable
    InstallerSha256 = $verifiedExecutableHash
    Sbom = $sbomArtifact
    Provenance = $provenanceArtifact
    Sidecar = $releaseManifest
    Sha256Sums = $releaseSums
    Sha256SumsEntries = $sumsCoverage.Entries
    SbomComponents = [int]$sbomValidation.Components
    SourceTreeDigest = [string]$provenanceValidation.SourceTreeDigest
    Signature = [string]$verifiedSignature.Status
}
