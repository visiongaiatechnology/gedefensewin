# STATUS: DIAMANT VGT SUPREME
# Verifier for the offline build-provenance artifact (SC-FIND-005).
#
# Recomputes the source-tree digest from the real working tree, re-reads the
# toolchain pin, checks the recorded build recipe and re-hashes every recorded
# artifact. Fails closed on any tampering, stale source tree or unverifiable
# claim. Artifact paths are hardened: no `..` traversal, absolute paths only
# inside the project root or the provenance file's own directory, duplicates and
# unknown artifact kinds are rejected, and the JSON release sidecar must never
# be bound back (it embeds the provenance hash; a two-way binding would be
# circular and stale). It never claims authenticity: the artifact is unsigned by
# design and the public-CA/timestamp/revocation/anti-rollback gaps are external
# blockers.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ProjectRoot = '',
    [switch]$RequireSourceManifest,
    [switch]$AllowMissingArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$Path = [IO.Path]::GetFullPath($Path)
Import-Module -Name (Join-Path $PSScriptRoot 'VgtSupplyChain.psm1') -Force

$checks = [Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Provenance validation failed: {0} ({1})' -f $Name,$Detail)) }
}

function Get-VgtJsonProperty {
    param($Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Provenance artifact is missing: {0}' -f $Path)) }
$document = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
$version = Read-VgtVersion -ProjectRoot $ProjectRoot
$toolchain = Get-VgtToolchain -ProjectRoot $ProjectRoot

Add-Check -Name 'schema' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'schema') -eq 'vgt-build-provenance/1')
Add-Check -Name 'version-matches' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'version') -eq $version) -Detail ('artifact={0} VERSION={1}' -f (Get-VgtJsonProperty -Object $document -Name 'version'),$version)
$signatureNode = Get-VgtJsonProperty -Object $document -Name 'signature'
Add-Check -Name 'signature-explicitly-unsigned' -Passed ([string](Get-VgtJsonProperty -Object $signatureNode -Name 'type') -eq 'none')
$limitations = @(Get-VgtJsonProperty -Object $document -Name 'limitations')
Add-Check -Name 'limitations-present' -Passed ($limitations.Count -ge 3)
$limitationText = ($limitations -join ' ')
Add-Check -Name 'limitation-external-trust-anchor' -Passed ($limitationText -match 'CA|timestamp|revocation|anti-rollback')

$sourceTree = Get-VgtJsonProperty -Object $document -Name 'sourceTree'
$recordedDigest = [string](Get-VgtJsonProperty -Object $sourceTree -Name 'sha256')
$recordedFiles = [int](Get-VgtJsonProperty -Object $sourceTree -Name 'fileCount')
$actualTree = Get-VgtSourceTreeDigest -ProjectRoot $ProjectRoot
Add-Check -Name 'source-digest-matches-working-tree' -Passed ($recordedDigest -eq $actualTree.Digest) -Detail ('recorded={0} actual={1}' -f $recordedDigest,$actualTree.Digest)
Add-Check -Name 'source-file-count-matches' -Passed ($recordedFiles -eq $actualTree.FileCount) -Detail ('recorded={0} actual={1}' -f $recordedFiles,$actualTree.FileCount)

$manifestNode = Get-VgtJsonProperty -Object $document -Name 'sourceManifest'
$manifestState = [string](Get-VgtJsonProperty -Object $manifestNode -Name 'state')
Add-Check -Name 'source-manifest-state-known' -Passed ($manifestState -in @('verified','stale','absent')) -Detail $manifestState
if ($RequireSourceManifest) {
    Add-Check -Name 'source-manifest-verified' -Passed ($manifestState -eq 'verified')
    $manifestPath = Join-Path $ProjectRoot 'SOURCE-MANIFEST.sha256'
    Add-Check -Name 'source-manifest-present' -Passed (Test-Path -LiteralPath $manifestPath -PathType Leaf)
    $recordedManifestHash = [string](Get-VgtJsonProperty -Object $manifestNode -Name 'sha256')
    $actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Check -Name 'source-manifest-hash-matches' -Passed ($recordedManifestHash -eq $actualManifestHash)
}

$toolchainNode = Get-VgtJsonProperty -Object $document -Name 'toolchain'
$pinnedGo = [string](Get-VgtJsonProperty -Object $toolchainNode -Name 'pinnedGo')
Add-Check -Name 'pinned-go-matches-lock' -Passed ($pinnedGo -eq [string]$toolchain['go']) -Detail ('artifact={0} lock={1}' -f $pinnedGo,$toolchain['go'])
$pinnedZip = [string](Get-VgtJsonProperty -Object $toolchainNode -Name 'goWindowsAmd64ZipSha256')
$expectedZip = ''
if ($toolchain.ContainsKey('go_windows_amd64_zip_sha256')) { $expectedZip = ([string]$toolchain['go_windows_amd64_zip_sha256']).ToLowerInvariant() }
Add-Check -Name 'go-toolchain-archive-pinned' -Passed ($pinnedZip -match '^[0-9a-f]{64}$' -and $pinnedZip -eq $expectedZip)
Add-Check -Name 'toolchain-lock-hash-present' -Passed ([string](Get-VgtJsonProperty -Object $toolchainNode -Name 'toolchainLockSha256') -match '^[0-9a-f]{64}$')
$lockHash = (Get-FileHash -LiteralPath (Join-Path $ProjectRoot 'TOOLCHAINS.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
Add-Check -Name 'toolchain-lock-hash-matches' -Passed ([string](Get-VgtJsonProperty -Object $toolchainNode -Name 'toolchainLockSha256') -eq $lockHash)
Add-Check -Name 'zero-go-dependencies' -Passed ([string](Get-VgtJsonProperty -Object $toolchainNode -Name 'goSumBytes') -eq '0')

$recipeNode = Get-VgtJsonProperty -Object $document -Name 'buildRecipe'
$flagsNode = Get-VgtJsonProperty -Object $recipeNode -Name 'flags'
Add-Check -Name 'recipe-trimpath' -Passed ([string](Get-VgtJsonProperty -Object $flagsNode -Name 'trimpath') -eq 'True')
Add-Check -Name 'recipe-windows-amd64' -Passed ([string](Get-VgtJsonProperty -Object $flagsNode -Name 'goos') -eq 'windows' -and [string](Get-VgtJsonProperty -Object $flagsNode -Name 'goarch') -eq 'amd64')
Add-Check -Name 'recipe-ldflags' -Passed ([string](Get-VgtJsonProperty -Object $flagsNode -Name 'ldflags') -eq '-s -w')
$recipeCommands = @(Get-VgtJsonProperty -Object $recipeNode -Name 'commands')
Add-Check -Name 'recipe-commands-present' -Passed ($recipeCommands.Count -ge 3)
$scriptEntries = @(Get-VgtJsonProperty -Object $recipeNode -Name 'scripts')
Add-Check -Name 'recipe-script-hashes-present' -Passed ($scriptEntries.Count -ge 5)
foreach ($scriptEntry in $scriptEntries) {
    $relative = [string](Get-VgtJsonProperty -Object $scriptEntry -Name 'path')
    $recordedHash = [string](Get-VgtJsonProperty -Object $scriptEntry -Name 'sha256')
    $full = Join-Path $ProjectRoot ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar))
    Add-Check -Name ('recipe-script-present-' + $relative) -Passed (Test-Path -LiteralPath $full -PathType Leaf)
    $actualHash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Check -Name ('recipe-script-hash-matches-' + $relative) -Passed ($actualHash -eq $recordedHash)
}

$artifacts = @(Get-VgtJsonProperty -Object $document -Name 'artifacts')
# A dry-run generation (gate self-test before any artifact exists) may contain no
# artifacts; an official release verification always requires at least one.
Add-Check -Name 'artifacts-recorded' -Passed ($artifacts.Count -ge 1 -or $AllowMissingArtifacts) -Detail ('count={0}' -f $artifacts.Count)
$allowedArtifactKinds = @('standalone-installer','sbom','source-archive')
$artifactAllowedRoots = @($ProjectRoot,[IO.Path]::GetDirectoryName($Path))
$seenArtifactTargets = @{}
foreach ($artifact in $artifacts) {
    $artifactPath = [string](Get-VgtJsonProperty -Object $artifact -Name 'path')
    $artifactKind = [string](Get-VgtJsonProperty -Object $artifact -Name 'kind')
    $artifactName = [string](Get-VgtJsonProperty -Object $artifact -Name 'name')
    $recordedHash = ([string](Get-VgtJsonProperty -Object $artifact -Name 'sha256')).ToLowerInvariant()
    Add-Check -Name ('artifact-path-present-' + $recordedHash) -Passed (-not [string]::IsNullOrWhiteSpace($artifactPath))
    Add-Check -Name ('artifact-kind-known-' + $artifactPath) -Passed ($allowedArtifactKinds -contains $artifactKind) -Detail $artifactKind
    Add-Check -Name ('artifact-name-present-' + $artifactPath) -Passed (-not [string]::IsNullOrWhiteSpace($artifactName))
    Add-Check -Name ('artifact-hash-format-' + $artifactPath) -Passed ($recordedHash -match '^[0-9a-f]{64}$')
    $normalizedArtifactPath = $artifactPath.Replace('\','/')
    Add-Check -Name ('artifact-path-no-traversal-' + $normalizedArtifactPath) -Passed (-not (@($normalizedArtifactPath -split '/') -contains '..')) -Detail 'A provenance artifact must not escape its allowed root via ..'
    if ([IO.Path]::IsPathRooted($artifactPath)) {
        $full = [IO.Path]::GetFullPath($artifactPath)
        $insideAllowedRoot = $false
        foreach ($allowedRoot in $artifactAllowedRoots) {
            if ([string]::IsNullOrWhiteSpace($allowedRoot)) { continue }
            $allowedFull = [IO.Path]::GetFullPath($allowedRoot).TrimEnd('\') + '\'
            if ($full.StartsWith($allowedFull,[StringComparison]::OrdinalIgnoreCase)) { $insideAllowedRoot = $true; break }
        }
        Add-Check -Name ('artifact-absolute-path-inside-root-' + $normalizedArtifactPath) -Passed $insideAllowedRoot -Detail ('absolute artifact path outside the project/provenance directory: {0}' -f $full)
    } else {
        $full = [IO.Path]::GetFullPath((Join-Path $ProjectRoot ($artifactPath.Replace('/',[IO.Path]::DirectorySeparatorChar))))
        $projectFull = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\') + '\'
        Add-Check -Name ('artifact-relative-path-inside-root-' + $normalizedArtifactPath) -Passed ($full.StartsWith($projectFull,[StringComparison]::OrdinalIgnoreCase)) -Detail $full
    }
    if ($seenArtifactTargets.ContainsKey($full.ToLowerInvariant())) { throw [InvalidOperationException]::new(('Provenance lists the same artifact more than once: {0}' -f $artifactPath)) }
    $seenArtifactTargets[$full.ToLowerInvariant()] = $true
    $artifactLeaf = [IO.Path]::GetFileName($full)
    Add-Check -Name ('artifact-not-release-sidecar-' + $normalizedArtifactPath) -Passed (-not ($artifactLeaf -match '^GeDefense-Setup-x64-v[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[1-9][0-9]*)?\.json$')) -Detail 'The JSON release sidecar embeds the provenance hash; provenance must not bind it back (circular/stale binding).'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        if (-not $AllowMissingArtifacts) { throw [IO.FileNotFoundException]::new(('Provenance artifact references a missing file: {0}' -f $artifactPath)) }
        continue
    }
    $actualHash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Check -Name ('artifact-hash-matches-' + $artifactPath) -Passed ($actualHash -eq $recordedHash)
    $recordedBytes = [long](Get-VgtJsonProperty -Object $artifact -Name 'bytes')
    $actualBytes = [long](Get-Item -LiteralPath $full).Length
    Add-Check -Name ('artifact-bytes-match-' + $artifactPath) -Passed ($recordedBytes -eq $actualBytes)
}

$vcsNode = Get-VgtJsonProperty -Object $document -Name 'vcs'
Add-Check -Name 'vcs-state-recorded' -Passed ([string](Get-VgtJsonProperty -Object $vcsNode -Name 'state') -in @('present','absent','unreadable','git-unavailable'))

[pscustomobject][ordered]@{
    Status = 'PASS'
    Path = $Path
    Version = $version
    SourceTreeDigest = $actualTree.Digest
    SourceTreeFiles = $actualTree.FileCount
    SourceManifestState = $manifestState
    Artifacts = $artifacts.Count
    Checks = $checks.Count
    Signature = 'unsigned-local-provenance'
    ExternalTrustAnchor = 'EXTERNAL-BLOCKER'
}
