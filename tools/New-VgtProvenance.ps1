# STATUS: DIAMANT VGT SUPREME
# Offline build-provenance / reproducible-build recipe generator (SC-FIND-005).
#
# The artifact records what actually went into a build without requiring a
# signing key or a CI service:
#   - the SHA-256 of every source-release input (via the same enumeration the
#     source builder uses) and the resulting source-tree digest,
#   - the pinned toolchain (TOOLCHAINS.lock) plus the Go archive hash,
#   - the exact build flags/commands used by the release scripts,
#   - the hashes of build scripts and produced artifacts when they exist.
#
# Ordering contract: this artifact is generated AFTER the final Authenticode
# signing of the installer and after the payload-complete SBOM artifact. The
# JSON release sidecar (GeDefense-Setup-x64-v<version>.json) is written AFTER
# this file by build/Build-GeDefenseStandalone.ps1 and embeds its measured hash;
# it is therefore not listed in `artifacts` (see releaseSidecarContract).
#
# It is explicitly unsigned. A local provenance file proves reproducibility; it
# does not prove publisher identity. Public CA signature, RFC3161 timestamp,
# revocation and a durable external anti-rollback anchor remain external
# blockers and are recorded as limitations instead of being fabricated.
[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [string]$OutputPath = '',
    [string]$ReleaseDirectory = '',
    [string]$PayloadRoot = '',
    [string]$SourceArchive = '',
    [switch]$RequireSourceManifest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
Import-Module -Name (Join-Path $PSScriptRoot 'VgtSupplyChain.psm1') -Force

$version = Read-VgtVersion -ProjectRoot $ProjectRoot
$toolchain = Get-VgtToolchain -ProjectRoot $ProjectRoot
$sourceTree = Get-VgtSourceTreeDigest -ProjectRoot $ProjectRoot
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) { $ReleaseDirectory = Join-Path $ProjectRoot 'release' }
$ReleaseDirectory = [IO.Path]::GetFullPath($ReleaseDirectory)
if ([string]::IsNullOrWhiteSpace($PayloadRoot)) { $PayloadRoot = Join-Path $ProjectRoot 'payload\VGT\GeDefense' }
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)

function Get-VgtOptionalHash {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return [pscustomobject][ordered]@{
        Path = [IO.Path]::GetFullPath($Path)
        Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        Bytes = [long](Get-Item -LiteralPath $Path).Length
    }
}

function Get-VgtToolFileHash {
    param([Parameter(Mandatory)][string]$RelativePath)
    $full = Join-Path $ProjectRoot ($RelativePath.Replace('/',[IO.Path]::DirectorySeparatorChar))
    $measured = Get-VgtOptionalHash -Path $full
    if ($null -eq $measured) { return $null }
    return [pscustomobject][ordered]@{ path = $RelativePath; sha256 = $measured.Sha256; bytes = $measured.Bytes }
}

# ---------------------------------------------------------------------------
# Source manifest binding (source builder regenerates it before release)
# ---------------------------------------------------------------------------
$manifestRelative = 'SOURCE-MANIFEST.sha256'
$manifestPath = Join-Path $ProjectRoot $manifestRelative
$manifestInfo = [ordered]@{
    file = $manifestRelative
    state = 'absent'
    entries = 0
    mismatchCount = 0
    normalizedDigest = ''
    matchesTree = $false
    sha256 = ''
}
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    $manifestFile = Get-VgtOptionalHash -Path $manifestPath
    $manifestInfo.sha256 = $manifestFile.Sha256
    $manifestLines = [Collections.Generic.List[string]]::new()
    $mismatchCount = 0
    $entryCount = 0
    foreach ($line in Get-Content -LiteralPath $manifestPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>.+)$') { throw [IO.InvalidDataException]::new(('SOURCE-MANIFEST.sha256 has an invalid line: {0}' -f $line)) }
        $recordedHash = $Matches['hash']
        $relative = $Matches['path']
        $entryCount++
        $manifestLines.Add(('{0}  {1}' -f $recordedHash,$relative))
        $absolutePath = Join-Path $ProjectRoot ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) { $mismatchCount++; continue }
        $actualHash = (Get-FileHash -LiteralPath $absolutePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $recordedHash) { $mismatchCount++ }
    }
    $normalizedPayload = (($manifestLines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $normalizedBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalizedPayload)) } finally { $sha.Dispose() }
    $manifestInfo.sha256 = $manifestFile.Sha256
    $manifestInfo.entries = $entryCount
    $manifestInfo.mismatchCount = $mismatchCount
    $manifestInfo.normalizedDigest = ([BitConverter]::ToString($normalizedBytes)).Replace('-','').ToLowerInvariant()
    $manifestInfo.matchesTree = ($mismatchCount -eq 0 -and $manifestInfo.normalizedDigest -eq $sourceTree.Digest)
    if ($manifestInfo.matchesTree) { $manifestInfo.state = 'verified' } else { $manifestInfo.state = 'stale' }
}
if ($RequireSourceManifest) {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('SOURCE-MANIFEST.sha256 is required for verified provenance. Run build/Build-SourceRelease.ps1 first.') }
    if (-not $manifestInfo.matchesTree) { throw [IO.InvalidDataException]::new(('SOURCE-MANIFEST.sha256 is stale against the working tree (mismatches={0}). Run build/Build-SourceRelease.ps1 first.' -f $manifestInfo.mismatchCount)) }
}

# ---------------------------------------------------------------------------
# Measured toolchain and build recipe
# ---------------------------------------------------------------------------
$goModPath = Join-Path $ProjectRoot 'src\GeDefense\windows\go.mod'
$goSumPath = Join-Path $ProjectRoot 'src\GeDefense\windows\go.sum'
$toolchainLock = Get-VgtOptionalHash -Path (Join-Path $ProjectRoot 'TOOLCHAINS.lock')
$goMod = Get-VgtOptionalHash -Path $goModPath
$goSum = Get-VgtOptionalHash -Path $goSumPath
$actualGoVersion = 'unavailable'
if (Get-Command go -ErrorAction SilentlyContinue) {
    try {
        $actualGoVersion = (& go env GOVERSION 2>$null).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($actualGoVersion)) { $actualGoVersion = 'unavailable' }
    } catch { $actualGoVersion = 'unavailable' }
}
$buildScripts = @('build/Test-GeDefenseRelease.ps1','build/Build-VgtPayload.ps1','build/Build-GeDefenseStandalone.ps1','build/Build-SourceRelease.ps1','build/Publish-GitHubRelease.ps1','tools/New-VgtSbom.ps1','tools/Test-VgtSbom.ps1','tools/New-VgtProvenance.ps1','tools/Test-VgtProvenance.ps1','installer/InstallerSafety.psm1')
$scriptEntries = [Collections.Generic.List[object]]::new()
foreach ($relative in $buildScripts) {
    $entry = Get-VgtToolFileHash -RelativePath $relative
    if ($null -ne $entry) { $scriptEntries.Add($entry) }
}

$artifacts = [Collections.Generic.List[object]]::new()
# The JSON release sidecar (GeDefense-Setup-x64-v<version>.json) is deliberately
# NOT listed here: it is written after this provenance artifact and embeds this
# artifact's measured SHA-256. Binding the sidecar in both directions would be
# circular and would immediately become stale; build/PublishVerification.psm1
# verifies the one-way binding sidecar -> {SBOM, provenance} fail-closed.
$artifactCandidates = @(
    @{ Name = ('GeDefense-Setup-x64-v{0}.exe' -f $version); Relative = ('release/GeDefense-Setup-x64-v{0}.exe' -f $version); Kind = 'standalone-installer' },
    @{ Name = ('GeDefense-SBOM-v{0}.cdx.json' -f $version); Relative = ('release/GeDefense-SBOM-v{0}.cdx.json' -f $version); Kind = 'sbom' }
)
foreach ($candidate in $artifactCandidates) {
    $full = Join-Path $ProjectRoot ($candidate.Relative.Replace('/',[IO.Path]::DirectorySeparatorChar))
    $measured = Get-VgtOptionalHash -Path $full
    if ($null -eq $measured) { continue }
    $artifactEntry = [ordered]@{ kind = $candidate.Kind; name = $candidate.Name; path = $candidate.Relative; sha256 = $measured.Sha256; bytes = $measured.Bytes }
    if ($candidate.Kind -eq 'standalone-installer') {
        $signature = Get-AuthenticodeSignature -LiteralPath $full
        $artifactEntry.signature = [ordered]@{
            status = [string]$signature.Status
            signerThumbprint = $(if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { '' })
            timeStamperPresent = ($null -ne $signature.TimeStamperCertificate)
        }
    }
    $artifacts.Add($artifactEntry)
}
if ([string]::IsNullOrWhiteSpace($SourceArchive)) {
    $defaultArchive = Join-Path $ReleaseDirectory ('VGT_GeDefense_Windows_{0}_Source.zip' -f $version)
    if (Test-Path -LiteralPath $defaultArchive -PathType Leaf) { $SourceArchive = $defaultArchive }
}
if (-not [string]::IsNullOrWhiteSpace($SourceArchive)) {
    $archiveFull = [IO.Path]::GetFullPath($SourceArchive)
    $measured = Get-VgtOptionalHash -Path $archiveFull
    if ($null -eq $measured) { throw [IO.FileNotFoundException]::new(('Source archive is missing: {0}' -f $archiveFull)) }
    $archiveRecordedPath = $archiveFull
    try { $archiveRecordedPath = Get-VgtRelativePath -FullName $archiveFull -ProjectRoot $ProjectRoot } catch { $archiveRecordedPath = $archiveFull }
    $artifacts.Add([ordered]@{ kind = 'source-archive'; name = [IO.Path]::GetFileName($archiveFull); path = $archiveRecordedPath; sha256 = $measured.Sha256; bytes = $measured.Bytes })
}
$payloadManifest = Get-VgtOptionalHash -Path (Join-Path $PayloadRoot 'manifest.json')
$payloadManifestEntry = $null
if ($null -ne $payloadManifest) {
    $payloadManifestEntry = [ordered]@{ path = 'payload/VGT/GeDefense/manifest.json'; sha256 = $payloadManifest.Sha256; bytes = $payloadManifest.Bytes }
}

# ---------------------------------------------------------------------------
# VCS metadata (honest absence in the delivered tree)
# ---------------------------------------------------------------------------
$vcs = [ordered]@{
    state = 'absent'
    commit = ''
    tag = ''
    treeClean = $false
    reason = 'The delivered working tree contains no .git directory; no commit or tag can be asserted.'
}
$gitDirectory = Join-Path $ProjectRoot '.git'
if (Test-Path -LiteralPath $gitDirectory -PathType Container) {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        try {
            $commit = (& git -C $ProjectRoot rev-parse HEAD 2>$null | Out-String).Trim()
            $tag = (& git -C $ProjectRoot describe --tags --exact-match HEAD 2>$null | Out-String).Trim()
            $statusOutput = (& git -C $ProjectRoot status --porcelain 2>$null | Out-String).Trim()
            if ($LASTEXITCODE -eq 0) {
                $vcs.state = 'present'
                $vcs.commit = $commit
                $vcs.tag = $tag
                $vcs.treeClean = [string]::IsNullOrWhiteSpace($statusOutput)
                $vcs.reason = ''
            }
        } catch {
            $vcs.state = 'unreadable'
            $vcs.reason = $_.Exception.Message
        }
    } else {
        $vcs.state = 'git-unavailable'
        $vcs.reason = 'A .git directory exists but the git executable is unavailable.'
    }
}

$document = [ordered]@{
    schema = 'vgt-build-provenance/1'
    product = 'VGT GeDefense Titan'
    version = $version
    issuer = 'VisionGaia Technology'
    generatedAt = [DateTime]::UtcNow.ToString('o')
    signature = [ordered]@{
        type = 'none'
        note = 'Unsigned local provenance artifact. Publisher identity needs a public CA code-signing identity plus RFC3161 timestamp (external blocker); this file only proves build inputs and artifact hashes.'
    }
    sourceTree = [ordered]@{
        enumeration = 'build/Build-SourceRelease.ps1 source candidate set (release/payload/work/certificates and binaries excluded)'
        fileCount = $sourceTree.FileCount
        sha256 = $sourceTree.Digest
    }
    sourceManifest = $manifestInfo
    toolchain = [ordered]@{
        pinnedGo = [string]$toolchain['go']
        goWindowsAmd64ZipSha256 = $(if ($toolchain.ContainsKey('go_windows_amd64_zip_sha256')) { ([string]$toolchain['go_windows_amd64_zip_sha256']).ToLowerInvariant() } else { '' })
        pinnedPowerShell = $(if ($toolchain.ContainsKey('powershell')) { [string]$toolchain['powershell'] } else { '' })
        measuredGoVersion = $actualGoVersion
        measuredPowerShellVersion = $PSVersionTable.PSVersion.ToString()
        toolchainLockSha256 = $(if ($null -ne $toolchainLock) { $toolchainLock.Sha256 } else { '' })
        goModSha256 = $(if ($null -ne $goMod) { $goMod.Sha256 } else { '' })
        goSumSha256 = $(if ($null -ne $goSum) { $goSum.Sha256 } else { '' })
        goSumBytes = $(if ($null -ne $goSum) { $goSum.Bytes } else { 0 })
        gotoolchainEnforced = 'GOTOOLCHAIN=local is required; go.mod pins toolchain go1.26.10; minimum patched release is enforced by build/Test-GeDefenseRelease.ps1'
    }
    buildRecipe = [ordered]@{
        commands = @(
            'powershell -NoProfile -ExecutionPolicy Bypass -File build/Test-GeDefenseRelease.ps1',
            'powershell -NoProfile -ExecutionPolicy Bypass -File build/Build-GeDefenseStandalone.ps1',
            'powershell -NoProfile -ExecutionPolicy Bypass -File build/Build-SourceRelease.ps1',
            'powershell -NoProfile -ExecutionPolicy Bypass -File tools/New-VgtSbom.ps1 -ArtifactMode',
            'powershell -NoProfile -ExecutionPolicy Bypass -File tools/New-VgtProvenance.ps1 -RequireSourceManifest'
        )
        flags = [ordered]@{
            goos = 'windows'
            goarch = 'amd64'
            trimpath = $true
            ldflags = '-s -w'
            installerLdflags = '-s -w -H=windowsgui'
            buildTags = 'vgt_bundle (standalone installer only)'
            zeroGoDependencies = $true
        }
        scripts = @($scriptEntries.ToArray())
    }
    artifacts = @($artifacts.ToArray())
    payloadManifest = $payloadManifestEntry
    releaseSidecarContract = [ordered]@{
        schema = 'vgt-release-sidecar/1'
        writtenBy = 'build/Build-GeDefenseStandalone.ps1'
        order = 'written AFTER this provenance artifact and the payload-complete SBOM artifact'
        binds = 'measured SBOM and provenance SHA-256 values plus the provenance source-tree digest; verified by build/PublishVerification.psm1 (Assert-VgtReleaseSidecarBinding)'
        notListedInArtifactsBecause = 'the sidecar embeds this provenance file SHA-256; a two-way binding would be circular and would go stale on every provenance regeneration'
    }
    vcs = $vcs
    limitations = @(
        'Unsigned provenance: no code-signing key is used and no RFC3161 timestamp exists; identity/authenticity must be anchored out-of-band.',
        'No public CA, CRL/OCSP revocation or durable externally anchored anti-rollback channel is available in this delivery (external blockers).',
        'No CI service/attestation: the build is reproducible locally, not remotely attested.',
        'The measured Go version may differ from the pinned release toolchain on non-release hosts; the gate enforces the minimum patched release.'
    )
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $ReleaseDirectory ('GeDefense-Provenance-v{0}.json' -f $version) }
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [IO.Path]::GetDirectoryName($outputFull)
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null }
Write-VgtDeterministicJson -Object $document -Path $outputFull

[pscustomobject][ordered]@{
    Status = 'PASS'
    Version = $version
    SourceTreeDigest = $sourceTree.Digest
    SourceTreeFiles = $sourceTree.FileCount
    SourceManifestState = $manifestInfo.state
    Artifacts = $artifacts.Count
    VcsState = $vcs.state
    OutputPath = $outputFull
}
