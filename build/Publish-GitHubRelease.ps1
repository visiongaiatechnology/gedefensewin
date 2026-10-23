# STATUS: DIAMANT VGT SUPREME
# Fail-closed GitHub release publisher (SC-FIND-009).
#
# Differences to the 5.1.2 publisher:
#   - every asset hash is measured against its sidecar/SHA256SUMS and the JSON
#     manifest, the installer Authenticode signature is measured (no hardcoded
#     "Valid"/thumbprint values), the SBOM and provenance artifacts are
#     validated, and the git tag must match HEAD on a clean tree,
#   - a release is only created as a DRAFT; `-PublishImmediately` is an
#     explicit, separate step after re-verifying uploaded asset digests,
#   - `-VerifyOnly` performs the complete offline verification (no token, no
#     network) so the gate can test the fail-closed behaviour without GitHub,
#   - measured values (not constants) are written into the release body.
#
# External blockers are stated in the release body rather than being masked: no
# publicly trusted CA certificate, no RFC3161 timestamp, no revocation endpoint
# and no externally anchored anti-rollback channel exist in this delivery.
[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$ReleaseDirectory = '',
    [string]$Repository = 'visiongaiatechnology/gedefensewin',
    [string]$ApiBase = 'https://api.github.com',
    [switch]$VerifyOnly,
    [switch]$PublishImmediately,
    [switch]$AllowMissingVcs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Import-Module -Name (Join-Path $PSScriptRoot 'PublishVerification.psm1') -Force
Import-Module -Name (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Force

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = Read-VgtVersion -ProjectRoot $projectRoot }
if ($Version -notmatch '^5\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$') { throw [IO.InvalidDataException]::new('Release version is invalid.') }
$tag = 'v' + $Version
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) { $ReleaseDirectory = Join-Path $projectRoot 'release' }
$ReleaseDirectory = [IO.Path]::GetFullPath($ReleaseDirectory)
$toolchain = Get-VgtToolchain -ProjectRoot $projectRoot

function Get-VgtAssetPath {
    param([Parameter(Mandatory)][string]$Name)
    $path = Join-Path $ReleaseDirectory $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Required release asset is missing: {0}' -f $path)) }
    return $path
}

# ---------------------------------------------------------------------------
# 1. Required release assets and their cryptographic verification
# ---------------------------------------------------------------------------
$exeName = 'GeDefense-Setup-x64-{0}.exe' -f $tag
$jsonName = 'GeDefense-Setup-x64-{0}.json' -f $tag
$sourceZipName = 'VGT_GeDefense_Windows_{0}_Source.zip' -f $Version
$sbomName = 'GeDefense-SBOM-{0}.cdx.json' -f $tag
$provenanceName = 'GeDefense-Provenance-{0}.json' -f $tag

$exePath = Get-VgtAssetPath -Name $exeName
$exeSidecarPath = Get-VgtAssetPath -Name ($exeName + '.sha256')
$jsonPath = Get-VgtAssetPath -Name $jsonName
$sourceZipPath = Get-VgtAssetPath -Name $sourceZipName
$sourceZipSidecarPath = Get-VgtAssetPath -Name ($sourceZipName + '.sha256')
$sbomPath = Get-VgtAssetPath -Name $sbomName
$provenancePath = Get-VgtAssetPath -Name $provenanceName

$thumbprintFile = Join-Path $projectRoot 'certificates\release-thumbprint.txt'
$jsonManifest = Assert-VgtJsonManifestMatchesAsset -ManifestPath $jsonPath -AssetPath $exePath -ExpectedVersion $Version
$expectedThumbprint = ([string]$jsonManifest.signerThumbprint).ToUpperInvariant()
if ($expectedThumbprint -notmatch '^[A-F0-9]{40}$') { throw [Security.SecurityException]::new('Release manifest signer thumbprint is invalid.') }
if (Test-Path -LiteralPath $thumbprintFile -PathType Leaf) {
    $metadataThumbprint = (Get-Content -LiteralPath $thumbprintFile -Raw -Encoding UTF8).Trim().ToUpperInvariant()
    if ($metadataThumbprint -ne $expectedThumbprint) { throw [Security.SecurityException]::new(('Provisioned thumbprint {0} does not match release manifest signer {1}.' -f $metadataThumbprint,$expectedThumbprint)) }
}
$signature = Assert-VgtPublisherSignature -Path $exePath -ExpectedThumbprint $expectedThumbprint
$exeSidecarHash = Assert-VgtAssetHash -Path $exePath -SidecarPath $exeSidecarPath
$sourceZipHash = Assert-VgtAssetHash -Path $sourceZipPath -SidecarPath $sourceZipSidecarPath

$sbomTester = Join-Path $projectRoot 'tools\Test-VgtSbom.ps1'
$provenanceTester = Join-Path $projectRoot 'tools\Test-VgtProvenance.ps1'
if (-not (Test-Path -LiteralPath $sbomTester -PathType Leaf)) { throw [IO.FileNotFoundException]::new('tools/Test-VgtSbom.ps1 is missing.') }
if (-not (Test-Path -LiteralPath $provenanceTester -PathType Leaf)) { throw [IO.FileNotFoundException]::new('tools/Test-VgtProvenance.ps1 is missing.') }
$sbomValidation = & $sbomTester -ArtifactMode -Path $sbomPath
$provenanceValidation = & $provenanceTester -Path $provenancePath -RequireSourceManifest
$sbomHash = Get-VgtFileSha256Lower -Path $sbomPath
$provenanceHash = Get-VgtFileSha256Lower -Path $provenancePath

# The provenance artifact must bind this exact installer/source zip.
$provenanceDocument = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 | ConvertFrom-Json
$provenanceArtifacts = @($provenanceDocument.artifacts)
$provenanceArtifactNames = @($provenanceArtifacts | ForEach-Object { [string]$_.name })
if ($provenanceArtifactNames -notcontains $exeName) { throw [Security.SecurityException]::new(('Provenance does not include the published installer {0}.' -f $exeName)) }
if ($provenanceArtifactNames -notcontains $sourceZipName) { throw [Security.SecurityException]::new(('Provenance does not include the published source archive {0}.' -f $sourceZipName)) }
foreach ($provenanceArtifact in $provenanceArtifacts) {
    $artifactName = [string]$provenanceArtifact.name
    if ($artifactName -in @($exeName,$sourceZipName,$sbomName)) {
        $expectedHash = [string]$provenanceArtifact.sha256
        $actualHash = Get-VgtFileSha256Lower -Path (Join-Path $ReleaseDirectory $artifactName)
        if ($expectedHash -ne $actualHash) { throw [Security.SecurityException]::new(('Provenance hash does not match published asset {0}.' -f $artifactName)) }
    }
}
if ($provenanceArtifactNames -notcontains $sbomName) { throw [Security.SecurityException]::new(('Provenance does not include the published SBOM {0}.' -f $sbomName)) }

# SC-FIND-005/SC-FIND-003: the release sidecar is written after the final SBOM
# and provenance artifacts and must embed their measured hashes. A stale sidecar
# (wrong provenance/SBOM hash, wrong asset name or wrong source-tree digest)
# aborts the publish instead of silently shipping inconsistent metadata.
$sidecarBinding = Assert-VgtReleaseSidecarBinding -SidecarPath $jsonPath -ReleaseDirectory $ReleaseDirectory -ExpectedVersion $Version -SbomPath $sbomPath -ProvenancePath $provenancePath
if ([string]$sidecarBinding.SbomSha256 -ne $sbomHash) { throw [Security.SecurityException]::new('Release sidecar SBOM binding does not match the measured SBOM hash.') }
if ([string]$sidecarBinding.ProvenanceSha256 -ne $provenanceHash) { throw [Security.SecurityException]::new('Release sidecar provenance binding does not match the measured provenance hash.') }
if ([int]$sidecarBinding.SbomComponents -ne [int]$sbomValidation.Components) { throw [Security.SecurityException]::new('Release sidecar SBOM component count does not match the validated SBOM.') }
if ([string]$sidecarBinding.SourceTreeDigest -ne [string]$provenanceValidation.SourceTreeDigest) { throw [Security.SecurityException]::new('Release sidecar source-tree digest does not match the validated provenance.') }

# 2. Clean tagged revision (fail closed; explicit override for dry runs only).
$vcs = Assert-VgtCleanTag -ProjectRoot $projectRoot -Tag $tag -AllowMissingVcs:$AllowMissingVcs
if ($vcs.State -ne 'verified') { Write-Warning 'VCS state is NOT verified (explicit -AllowMissingVcs override): the release cannot claim a clean tagged revision.' }

# 3. Complete hash coverage: generate SHA256SUMS over every published asset.
$sumsPath = Join-Path $ReleaseDirectory 'SHA256SUMS.txt'
$sumsAssets = @(
    [pscustomobject]@{ Name = $exeName; Path = $exePath },
    [pscustomobject]@{ Name = ($exeName + '.sha256'); Path = $exeSidecarPath },
    [pscustomobject]@{ Name = $jsonName; Path = $jsonPath },
    [pscustomobject]@{ Name = $sourceZipName; Path = $sourceZipPath },
    [pscustomobject]@{ Name = ($sourceZipName + '.sha256'); Path = $sourceZipSidecarPath },
    [pscustomobject]@{ Name = $sbomName; Path = $sbomPath },
    [pscustomobject]@{ Name = $provenanceName; Path = $provenancePath }
)
$sums = Write-VgtSha256Sums -Assets $sumsAssets -OutputPath $sumsPath
$sumsText = Get-Content -LiteralPath $sumsPath -Raw -Encoding UTF8
foreach ($sumsAsset in $sumsAssets) {
    $expectedLine = [string]$sumsAsset.Name
    if ($sumsText -notmatch ('(?m)^[0-9a-f]{64}  ' + [Regex]::Escape($expectedLine) + '$')) { throw [Security.SecurityException]::new(('SHA256SUMS.txt does not cover {0}.' -f $expectedLine)) }
}
# Fail closed on any file in the release directory that is not a published
# asset (e.g. artifacts of another version left over from a previous build),
# then prove SHA256SUMS.txt covers every present asset exactly once.
foreach ($localFile in @(Get-ChildItem -LiteralPath $ReleaseDirectory -File -Force | Sort-Object Name)) {
    if ($localFile.Name -eq 'SHA256SUMS.txt') { continue }
    if (@($sumsAssets | Where-Object { $_.Name -eq $localFile.Name }).Count -eq 0) {
        throw [Security.SecurityException]::new(('Unexpected file in the release directory: {0}. Remove foreign/non-release artifacts before publishing.' -f $localFile.Name))
    }
}
$sumsCoverage = Assert-VgtSha256SumsCoverage -ReleaseDirectory $ReleaseDirectory
if ([int]$sumsCoverage.Entries -ne $sumsAssets.Count) { throw [Security.SecurityException]::new('SHA256SUMS.txt entry count does not match the published asset count.') }

# 4. Measured release metadata. Nothing in this table is hardcoded.
$exeBytes = [long](Get-Item -LiteralPath $exePath).Length
$measured = [ordered]@{
    version = $Version
    tag = $tag
    exeName = $exeName
    exeBytes = $exeBytes
    exeSha256 = $exeSidecarHash.ToUpperInvariant()
    signatureStatus = $signature.Status
    signerThumbprint = $signature.Thumbprint
    signerSubject = $signature.Subject
    timeStamperPresent = $signature.TimeStamperPresent
    sourceZipName = $sourceZipName
    sourceZipSha256 = $sourceZipHash.ToUpperInvariant()
    sbomName = $sbomName
    sbomSha256 = $sbomHash.ToUpperInvariant()
    sbomComponents = [int]$sbomValidation.Components
    provenanceName = $provenanceName
    provenanceSha256 = $provenanceHash.ToUpperInvariant()
    sourceTreeDigest = [string]$provenanceValidation.SourceTreeDigest
    sourceManifestState = [string]$provenanceValidation.SourceManifestState
    sidecarState = 'verified'
    sidecarSbomSha256 = ([string]$sidecarBinding.SbomSha256).ToUpperInvariant()
    sidecarProvenanceSha256 = ([string]$sidecarBinding.ProvenanceSha256).ToUpperInvariant()
    sidecarSourceTreeDigest = ([string]$sidecarBinding.SourceTreeDigest).ToUpperInvariant()
    sumsSha256 = (Get-VgtFileSha256Lower -Path $sumsPath).ToUpperInvariant()
    sumsCoverageState = [string]$sumsCoverage.Status
    sumsCoverageEntries = [int]$sumsCoverage.Entries
    vcsState = [string]$vcs.State
    vcsCommit = [string]$vcs.Commit
    vcsTag = [string]$vcs.Tag
    vcsTagSignature = $(if ($vcs.PSObject.Properties['TagSignature']) { [string]$vcs.TagSignature } else { 'not-verified' })
    timestampState = $(if ($signature.TimeStamperPresent) { 'present-measured' } else { 'ABSENT (external blocker: no RFC3161 timestamp)' })
}

$verificationSummary = @(
    ('Installer SHA-256 matches .sha256 sidecar: {0}' -f $measured.exeSha256),
    ('Authenticode status measured: {0} (signer {1})' -f $measured.signatureStatus,$measured.signerThumbprint),
    ('Source archive SHA-256 matches .sha256 sidecar: {0}' -f $measured.sourceZipSha256),
    ('SBOM validated: {0} components, SHA-256 {1}' -f $measured.sbomComponents,$measured.sbomSha256),
    ('Provenance validated: source tree {0}, source manifest {1}' -f $measured.sourceTreeDigest,$measured.sourceManifestState),
    ('Release sidecar binding verified: SBOM SHA-256 {0}, provenance SHA-256 {1}, source tree {2}' -f $measured.sidecarSbomSha256,$measured.sidecarProvenanceSha256,$measured.sidecarSourceTreeDigest),
    ('SHA256SUMS.txt covers all {0} published assets (SHA-256 {1})' -f $sumsAssets.Count,$measured.sumsSha256),
    ('VCS: state={0} commit={1} tag={2} tagSignature={3}' -f $measured.vcsState,$measured.vcsCommit,$measured.vcsTag,$measured.vcsTagSignature)
)

$summaryObject = [pscustomobject][ordered]@{ Status = 'VERIFIED'; Mode = $(if ($VerifyOnly) { 'verify-only' } else { 'publish' }); Measured = $measured; Verification = $verificationSummary }
if ($VerifyOnly) {
    # Offline mode: no token is read and no network request is made.
    return $summaryObject
}

# ---------------------------------------------------------------------------
# 5. Network publish: draft only, then digest re-verification, then optional flip
# ---------------------------------------------------------------------------
$token = $env:VGT_GITHUB_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    $credentialManager = 'C:\Program Files\Git\mingw64\bin\git-credential-manager.exe'
    if (Test-Path -LiteralPath $credentialManager -PathType Leaf) {
        try {
            $credentialOutput = ((cmd.exe /c "echo protocol=https&echo host=github.com&echo." | & $credentialManager get) | Out-String)
            $match = [Regex]::Match($credentialOutput,'(?m)^password=(?<token>\S+)\s*$')
            if ($match.Success) { $token = $match.Groups['token'].Value }
        } catch {
            $token = ''
        }
    }
}
if ([string]::IsNullOrWhiteSpace($token)) { throw [Security.SecurityException]::new('No GitHub token available (set VGT_GITHUB_TOKEN or provision git-credential-manager). Publishing is refused.') }
$headers = @{
    Authorization = "Bearer $token"
    'User-Agent' = 'VGT-Release-Bot'
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
}
$releaseBody = @"
# VGT GeDefense Windows $Version

Official release candidate for **VGT GeDefense Windows $Version** by VisionGaia Technology.

## Verification data (measured during publish)

| Property | Measured value |
| :--- | :--- |
| File | ``$exeName`` |
| Architecture | Windows 11 x64 |
| File size | $exeBytes Bytes |
| SHA-256 | ``$($measured.exeSha256)`` |
| Authenticode status | $($measured.signatureStatus) (measured, SHA-256) |
| Signer thumbprint | ``$($measured.signerThumbprint)`` |
| Signer subject | ``$($measured.signerSubject)`` |
| RFC3161 timestamp | $($measured.timestampState) |
| Source archive | ``$sourceZipName`` - SHA-256 ``$($measured.sourceZipSha256)`` |
| SBOM | ``$sbomName`` - $($measured.sbomComponents) components - SHA-256 ``$($measured.sbomSha256)`` |
| Provenance | ``$provenanceName`` - source tree ``$($measured.sourceTreeDigest)`` - SHA-256 ``$($measured.provenanceSha256)`` |
| Release sidecar binding | SBOM SHA-256 ``$($measured.sidecarSbomSha256)``, provenance SHA-256 ``$($measured.sidecarProvenanceSha256)``, source tree ``$($measured.sidecarSourceTreeDigest)`` |
| Source manifest | state: $($measured.sourceManifestState) |
| Git revision | state: $($measured.vcsState); commit: ``$($measured.vcsCommit)``; tag: ``$($measured.vcsTag)``; tag signature: $($measured.vcsTagSignature) |
| SHA256SUMS.txt | SHA-256 ``$($measured.sumsSha256)`` (covers $($sumsAssets.Count) assets, coverage state: $($measured.sumsCoverageState)) |

This release was verified locally with:

```powershell
& .\build\Test-GeDefenseRelease.ps1
& .\tools\Test-VgtSbom.ps1 -ArtifactMode -Path .\release\$sbomName
& .\tools\Test-VgtProvenance.ps1 -Path .\release\$provenanceName -RequireSourceManifest
Get-FileHash .\release\$exeName -Algorithm SHA256
Get-AuthenticodeSignature .\release\$exeName
```

## External blockers (not hidden, not PASS)

- No publicly trusted CA code-signing certificate: the release certificate is self-signed and only trusted where explicitly provisioned.
- No RFC3161 timestamp: signature validity can only be judged by the local clock/certificate window.
- No CRL/OCSP revocation endpoint.
- No externally anchored anti-rollback channel: downgrade protection relies on the documented installer/self-hosted controls only.

Until these are provided, this release is an internal candidate and must not be presented as publicly verifiable.

## Installation

1. Download ``$exeName`` and ``SHA256SUMS.txt``.
2. Verify the SHA-256 against ``SHA256SUMS.txt``.
3. Run the installer as administrator.
"@

$apiReleases = "$ApiBase/repos/$Repository/releases"
$existingRelease = $null
try {
    $existingRelease = Invoke-RestMethod -Uri "$apiReleases/tags/$tag" -Headers $headers -Method Get
} catch {
    $existingRelease = $null
}
if ($null -ne $existingRelease) {
    if (-not [bool]$existingRelease.draft) { throw [Security.SecurityException]::new(('A published (non-draft) release already exists for {0}; refusing to mutate it.' -f $tag)) }
    Write-Host ('Reusing draft release ID {0}; existing draft assets will be replaced after verification.' -f $existingRelease.id)
    $release = Invoke-RestMethod -Uri $existingRelease.url -Headers $headers -Method Patch -Body (@{ body = $releaseBody; name = ('VGT GeDefense Windows {0}' -f $Version) } | ConvertTo-Json -Depth 4) -ContentType 'application/json; charset=utf-8'
    foreach ($asset in @(Invoke-RestMethod -Uri ($existingRelease.url + '/assets') -Headers $headers -Method Get)) {
        Write-Host ('Removing existing draft asset {0}...' -f $asset.name)
        Invoke-RestMethod -Uri $asset.url -Headers $headers -Method Delete | Out-Null
    }
} else {
    $releasePayload = @{ tag_name = $tag; target_commitish = 'main'; name = ('VGT GeDefense Windows {0}' -f $Version); body = $releaseBody; draft = $true; prerelease = $false } | ConvertTo-Json -Depth 4
    $release = Invoke-RestMethod -Uri $apiReleases -Headers $headers -Method Post -Body $releasePayload -ContentType 'application/json; charset=utf-8'
    Write-Host ('Created draft release ID {0} for {1}.' -f $release.id,$tag)
}
$uploadUrlBase = ([string]$release.upload_url -replace '\{\?name,label\}','')

$assetsToUpload = @(
    [pscustomobject]@{ Name = $exeName; Path = $exePath; ContentType = 'application/octet-stream' },
    [pscustomobject]@{ Name = ($exeName + '.sha256'); Path = $exeSidecarPath; ContentType = 'text/plain' },
    [pscustomobject]@{ Name = $jsonName; Path = $jsonPath; ContentType = 'application/json' },
    [pscustomobject]@{ Name = $sourceZipName; Path = $sourceZipPath; ContentType = 'application/zip' },
    [pscustomobject]@{ Name = ($sourceZipName + '.sha256'); Path = $sourceZipSidecarPath; ContentType = 'text/plain' },
    [pscustomobject]@{ Name = $sbomName; Path = $sbomPath; ContentType = 'application/json' },
    [pscustomobject]@{ Name = $provenanceName; Path = $provenancePath; ContentType = 'application/json' },
    [pscustomobject]@{ Name = 'SHA256SUMS.txt'; Path = $sumsPath; ContentType = 'text/plain' }
)
foreach ($asset in $assetsToUpload) {
    $bytes = [IO.File]::ReadAllBytes($asset.Path)
    $uploadHeaders = @{
        Authorization = "Bearer $token"
        'User-Agent' = 'VGT-Release-Bot'
        'Content-Type' = $asset.ContentType
    }
    $uploadUri = ('{0}?name={1}' -f $uploadUrlBase,[Uri]::EscapeDataString($asset.Name))
    Write-Host ('Uploading {0} ({1} bytes)...' -f $asset.Name,$bytes.Length)
    Invoke-RestMethod -Uri $uploadUri -Headers $uploadHeaders -Method Post -Body $bytes | Out-Null
}

# Re-verify uploaded asset digests before any publication step.
$remoteAssets = @(Invoke-RestMethod -Uri ($release.url + '/assets') -Headers $headers -Method Get)
$digestVerifiedCount = 0
$digestUnavailableCount = 0
foreach ($asset in $assetsToUpload) {
    $remote = @($remoteAssets | Where-Object { $_.name -eq $asset.Name })
    if ($remote.Count -ne 1) { throw [Security.SecurityException]::new(('Uploaded asset is not present exactly once: {0}' -f $asset.Name)) }
    $remoteAsset = $remote[0]
    $localHash = Get-VgtFileSha256Lower -Path $asset.Path
    $remoteDigest = [string]$remoteAsset.digest
    if ($remoteDigest -match '^sha256:(?<hash>[0-9a-fA-F]{64})$') {
        if ($Matches['hash'].ToLowerInvariant() -ne $localHash) { throw [Security.SecurityException]::new(('Uploaded digest mismatch for {0}.' -f $asset.Name)) }
        $digestVerifiedCount++
    } else {
        # Older GitHub API responses may omit the digest: download and re-hash.
        $downloadPath = Join-Path $env:TEMP ('vgt-publish-verify-' + [Guid]::NewGuid().ToString('N') + '.bin')
        try {
            Invoke-WebRequest -Uri ([string]$remoteAsset.browser_download_url) -Headers @{ Authorization = "Bearer $token"; 'User-Agent' = 'VGT-Release-Bot' } -OutFile $downloadPath -UseBasicParsing | Out-Null
            $downloadedHash = Get-VgtFileSha256Lower -Path $downloadPath
            if ($downloadedHash -ne $localHash) { throw [Security.SecurityException]::new(('Re-downloaded asset hash mismatch for {0}.' -f $asset.Name)) }
            $digestVerifiedCount++
        } finally {
            if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue }
        }
    }
}
foreach ($remoteAsset in $remoteAssets) {
    if (@($assetsToUpload | Where-Object { $_.Name -eq $remoteAsset.name }).Count -eq 0) { throw [Security.SecurityException]::new(('Unexpected asset present on the draft release: {0}' -f $remoteAsset.name)) }
}
Write-Host ('Uploaded digests re-verified: {0} assets ({1} via API digest, {2} via re-download).' -f $digestVerifiedCount,$digestVerifiedCount,$digestUnavailableCount)

if ($PublishImmediately) {
    $published = Invoke-RestMethod -Uri $release.url -Headers $headers -Method Patch -Body (@{ draft = $false } | ConvertTo-Json -Depth 4) -ContentType 'application/json; charset=utf-8'
    Write-Host ('Release {0} published (draft=false) after digest re-verification: {1}' -f $tag,$published.html_url)
} else {
    Write-Host ('Draft release {0} prepared and digest-verified. Publish requires a separate four-eyes step:' -f $tag)
    Write-Host ('  review {0} and re-run with -PublishImmediately (or flip draft in the UI).' -f $release.html_url)
}

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = $(if ($PublishImmediately) { 'published' } else { 'draft' })
    ReleaseId = $release.id
    URL = $release.html_url
    Assets = $assetsToUpload.Count
    DigestsVerified = $digestVerifiedCount
    SidecarBinding = 'verified'
    SumsCoverage = [string]$sumsCoverage.Status
    Measured = $measured
}
