# STATUS: DIAMANT VGT SUPREME
# Regression gate for build/Publish-GitHubRelease.ps1 (SC-FIND-009).
#
# Two layers:
#   1. static proof that the publisher contains no hardcoded signature claims,
#      generates measured metadata, verifies hashes/signatures/tag, publishes
#      only after digest re-verification and keeps -VerifyOnly token-free,
#   2. functional tests of the fail-closed verification helpers on disposable
#      fixtures (tampered file/sidecar, missing sidecar, non-git tree).
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$publishPath = Join-Path $projectRoot 'build\Publish-GitHubRelease.ps1'
$modulePath = Join-Path $projectRoot 'build\PublishVerification.psm1'
$checks = [Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Publish gate check failed: {0} ({1})' -f $Name,$Detail)) }
}

foreach ($requiredFile in @($publishPath,$modulePath)) {
    Add-Check -Name ('file-present-' + [IO.Path]::GetFileName($requiredFile)) -Passed (Test-Path -LiteralPath $requiredFile -PathType Leaf)
}
$publish = Get-Content -LiteralPath $publishPath -Raw -Encoding UTF8
$publishModule = Get-Content -LiteralPath $modulePath -Raw -Encoding UTF8
Import-Module -Name $modulePath -Force
Import-Module -Name (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Force

# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------
Add-Check -Name 'no-hardcoded-signer-thumbprint' -Passed (-not [Regex]::IsMatch($publish,'\b[0-9A-Fa-f]{40}\b')) -Detail 'A literal thumbprint makes the release metadata unverifiable.'
Add-Check -Name 'no-hardcoded-valid-claim' -Passed (-not [Regex]::IsMatch($publish,'(?i)\|\s*Valid\s*\(Authenticode')) -Detail 'Signature status must be measured, not asserted.'
foreach ($requiredCall in @('Assert-VgtAssetHash','Assert-VgtPublisherSignature','Assert-VgtJsonManifestMatchesAsset','Assert-VgtCleanTag','Write-VgtSha256Sums','Test-VgtSbom.ps1','Test-VgtProvenance.ps1','-RequireSourceManifest')) {
    Add-Check -Name ('publisher-uses-' + $requiredCall.TrimStart('-')) -Passed ($publish.Contains($requiredCall))
}
Add-Check -Name 'measured-values-in-body' -Passed ($publish.Contains('$measured.signatureStatus') -and $publish.Contains('$measured.signerThumbprint') -and $publish.Contains('$measured.exeSha256'))
Add-Check -Name 'verify-only-mode-present' -Passed ($publish.Contains('-VerifyOnly'))
Add-Check -Name 'draft-first' -Passed ($publish.Contains('draft = $true'))
$draftFalseMatches = [Regex]::Matches($publish,'draft = \$false').Count
Add-Check -Name 'single-explicit-publish-step' -Passed ($draftFalseMatches -eq 1) -Detail ('draft-false-count={0}' -f $draftFalseMatches)
$verifyOnlyIndex = $publish.IndexOf('if ($VerifyOnly)',[StringComparison]::Ordinal)
$tokenIndex = $publish.IndexOf('$token = $env:VGT_GITHUB_TOKEN',[StringComparison]::Ordinal)
Add-Check -Name 'verify-only-needs-no-token' -Passed ($verifyOnlyIndex -ge 0 -and $tokenIndex -gt $verifyOnlyIndex) -Detail ('verifyOnly={0} token={1}' -f $verifyOnlyIndex,$tokenIndex)
$digestIndex = $publish.IndexOf('Uploaded digests re-verified',[StringComparison]::Ordinal)
$publishIndex = $publish.IndexOf('if ($PublishImmediately)',[StringComparison]::Ordinal)
Add-Check -Name 'publish-only-after-digest-reverification' -Passed ($digestIndex -ge 0 -and $publishIndex -gt $digestIndex) -Detail ('digestVerify={0} publish={1}' -f $digestIndex,$publishIndex)
Add-Check -Name 'refuses-to-mutate-published-release' -Passed ($publish.Contains('refusing to mutate it'))
Add-Check -Name 'verify-only-path-returns-before-network' -Passed ($publish.Contains('return $summaryObject'))
Add-Check -Name 'external-blockers-stated' -Passed ($publish.Contains('External blockers') -and $publish.Contains('RFC3161') -and $publish.Contains('anti-rollback'))
foreach ($requiredBindingCall in @('Assert-VgtReleaseSidecarBinding','Assert-VgtSha256SumsCoverage','Unexpected file in the release directory')) {
    Add-Check -Name ('publisher-uses-' + ($requiredBindingCall -replace '[^A-Za-z0-9-]','')) -Passed ($publish.Contains($requiredBindingCall))
}
Add-Check -Name 'publisher-cannot-silently-ship-stale-sidecar' -Passed ($publish.Contains('Release sidecar') -and $publish.Contains('does not match the measured'))

# ---------------------------------------------------------------------------
# Build/release ordering (SC-FIND-005): the standalone assembly writes the JSON
# sidecar LAST from measured values; the stage markers are the testable order
# contract. The release gate must enforce channel hygiene, sidecar binding and
# source-archive freshness.
# ---------------------------------------------------------------------------
$standalonePath = Join-Path $projectRoot 'build\Build-GeDefenseStandalone.ps1'
$releaseGatePath = Join-Path $projectRoot 'build\Test-GeDefenseRelease.ps1'
foreach ($requiredFile in @($standalonePath,$releaseGatePath)) {
    Add-Check -Name ('file-present-' + [IO.Path]::GetFileName($requiredFile)) -Passed (Test-Path -LiteralPath $requiredFile -PathType Leaf)
}
$standalone = Get-Content -LiteralPath $standalonePath -Raw -Encoding UTF8
$releaseGate = Get-Content -LiteralPath $releaseGatePath -Raw -Encoding UTF8
$stageMarkers = @('VGT-STAGE: payload-built','VGT-STAGE: sbom-artifact','VGT-STAGE: installer-signed','VGT-STAGE: provenance','VGT-STAGE: hash-sidecar','VGT-STAGE: release-sidecar','VGT-STAGE: sha256sums')
$previousStageIndex = -1
foreach ($stageMarker in $stageMarkers) {
    $stageIndex = $standalone.IndexOf($stageMarker,[StringComparison]::Ordinal)
    Add-Check -Name ('standalone-stage-' + ($stageMarker -replace '[^A-Za-z0-9-]','')) -Passed ($stageIndex -gt $previousStageIndex) -Detail ('index={0}' -f $stageIndex)
    $previousStageIndex = $stageIndex
}
Add-Check -Name 'standalone-provenance-after-signing' -Passed ($standalone.IndexOf('VGT-STAGE: provenance',[StringComparison]::Ordinal) -gt $standalone.IndexOf('VGT-STAGE: installer-signed',[StringComparison]::Ordinal))
Add-Check -Name 'standalone-sidecar-last-metadata-stage' -Passed ($standalone.IndexOf('VGT-STAGE: release-sidecar',[StringComparison]::Ordinal) -gt $standalone.IndexOf('VGT-STAGE: provenance',[StringComparison]::Ordinal))
Add-Check -Name 'standalone-no-hardcoded-64hex' -Passed (-not [Regex]::IsMatch($standalone,'\b[0-9a-fA-F]{64}\b')) -Detail 'Release sidecar/provenance/sums values must be measured, never literal.'
Add-Check -Name 'standalone-sidecar-binding-verified' -Passed ($standalone.Contains('Assert-VgtReleaseSidecarBinding') -and $standalone.Contains('Get-VgtFileSha256Lower'))
Add-Check -Name 'standalone-sums-generated-and-verified' -Passed ($standalone.Contains('Write-VgtSha256Sums') -and $standalone.Contains('Assert-VgtSha256SumsCoverage'))
Add-Check -Name 'release-gate-release-channel-hygiene' -Passed ($releaseGate.Contains('Assert-VgtReleaseChannelHygiene'))
Add-Check -Name 'release-gate-sidecar-binding' -Passed ($releaseGate.Contains('Assert-VgtReleaseSidecarBinding'))
Add-Check -Name 'release-gate-source-archive-freshness' -Passed ($releaseGate.Contains('Assert-VgtSourceArchiveFreshness'))
Add-Check -Name 'publish-module-sidecar-binding-helper' -Passed ($publishModule.Contains('function Assert-VgtReleaseSidecarBinding'))
Add-Check -Name 'supply-chain-sums-coverage-helper' -Passed ((Get-Content -LiteralPath (Join-Path $projectRoot 'tools\VgtSupplyChain.psm1') -Raw -Encoding UTF8).Contains('function Assert-VgtSha256SumsCoverage'))

# ---------------------------------------------------------------------------
# Functional checks (fail-closed helpers on disposable fixtures)
# ---------------------------------------------------------------------------
$sandbox = Join-Path $env:TEMP ('vgt-publish-gates-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $sandbox -ItemType Directory -Force | Out-Null
try {
    $assetPath = Join-Path $sandbox 'release-asset.bin'
    [IO.File]::WriteAllBytes($assetPath,[Text.Encoding]::UTF8.GetBytes('vgt release asset fixture'))
    $realHash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sidecarPath = Join-Path $sandbox 'release-asset.bin.sha256'
    [IO.File]::WriteAllText($sidecarPath,($realHash + '  release-asset.bin' + "`n"),[Text.UTF8Encoding]::new($false))

    Add-Check -Name 'hash-verification-accepts-valid-sidecar' -Passed ((Assert-VgtAssetHash -Path $assetPath -SidecarPath $sidecarPath) -eq $realHash)
    $tamperedSidecar = Join-Path $sandbox 'tampered-sidecar.sha256'
    [IO.File]::WriteAllText($tamperedSidecar,((('0' * 64)) + '  release-asset.bin' + "`n"),[Text.UTF8Encoding]::new($false))
    $sidecarRejected = $false
    try { Assert-VgtAssetHash -Path $assetPath -SidecarPath $tamperedSidecar | Out-Null } catch { $sidecarRejected = $true }
    Add-Check -Name 'hash-verification-rejects-tampered-sidecar' -Passed $sidecarRejected
    $missingSidecarRejected = $false
    try { Assert-VgtAssetHash -Path $assetPath -SidecarPath (Join-Path $sandbox 'missing.sha256') | Out-Null } catch { $missingSidecarRejected = $true }
    Add-Check -Name 'hash-verification-rejects-missing-sidecar' -Passed $missingSidecarRejected

    $manifestPath = Join-Path $sandbox 'release.json'
    $manifest = [ordered]@{
        product = 'VGT GeDefense Titan'
        version = '5.1.3'
        bytes = (Get-Item -LiteralPath $assetPath).Length
        sha256 = $realHash.ToUpperInvariant()
        signerThumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        signature = 'Valid'
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestCheck = Assert-VgtJsonManifestMatchesAsset -ManifestPath $manifestPath -AssetPath $assetPath -ExpectedVersion '5.1.3'
    Add-Check -Name 'json-manifest-matches-asset' -Passed ([string]$manifestCheck.version -eq '5.1.3')
    $manifest.version = '5.1.2'
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $versionRejected = $false
    try { Assert-VgtJsonManifestMatchesAsset -ManifestPath $manifestPath -AssetPath $assetPath -ExpectedVersion '5.1.3' | Out-Null } catch { $versionRejected = $true }
    Add-Check -Name 'json-manifest-version-mismatch-rejected' -Passed $versionRejected
    $manifest.version = '5.1.3'
    $manifest.sha256 = ('F' * 64)
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $hashRejected = $false
    try { Assert-VgtJsonManifestMatchesAsset -ManifestPath $manifestPath -AssetPath $assetPath -ExpectedVersion '5.1.3' | Out-Null } catch { $hashRejected = $true }
    Add-Check -Name 'json-manifest-hash-mismatch-rejected' -Passed $hashRejected

    $sumsPath = Join-Path $sandbox 'SHA256SUMS.txt'
    $sums = Write-VgtSha256Sums -Assets @([pscustomobject]@{ Name = 'release-asset.bin'; Path = $assetPath }) -OutputPath $sumsPath
    Add-Check -Name 'sums-file-generated' -Passed ($sums.Lines -eq 1 -and (Get-Content -LiteralPath $sumsPath -Raw) -match ('(?m)^' + $realHash + '  release-asset\.bin$'))

    # No .git repository: clean tagged revision cannot be proven, so the helper
    # must fail closed unless the explicit override is used.
    $noGitRejected = $false
    try { Assert-VgtCleanTag -ProjectRoot $sandbox -Tag 'v5.1.3' | Out-Null } catch { $noGitRejected = $true }
    Add-Check -Name 'clean-tag-fails-without-vcs' -Passed $noGitRejected
    $override = Assert-VgtCleanTag -ProjectRoot $sandbox -Tag 'v5.1.3' -AllowMissingVcs
    Add-Check -Name 'vcs-override-is-explicit-and-flagged' -Passed ([string]$override.State -eq 'unavailable-override' -and -not [bool]$override.TreeClean)

    # -------------------------------------------------------------------
    # Release-channel hygiene + SHA256SUMS coverage (SC-FIND-003)
    # -------------------------------------------------------------------
    $channelVersion = '5.1.4'
    $channelRoot = Join-Path $sandbox 'channel'
    $channelRelease = Join-Path $channelRoot 'release'
    function New-VgtChannelAsset {
        param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Name,[string]$Content = 'fixture')
        $path = Join-Path $Directory $Name
        [IO.File]::WriteAllText($path,($Content + "`n"),[Text.UTF8Encoding]::new($false))
        return $path
    }
    function New-VgtChannelSidecar {
        param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$AssetName)
        $assetPath = Join-Path $Directory $AssetName
        $hash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText(($assetPath + '.sha256'),($hash + '  ' + $AssetName + "`n"),[Text.UTF8Encoding]::new($false))
    }
    function Write-VgtChannelSums {
        param([Parameter(Mandatory)][string]$Directory)
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($file in @(Get-ChildItem -LiteralPath $Directory -File -Force | Sort-Object Name)) {
            if ($file.Name -eq 'SHA256SUMS.txt') { continue }
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $lines.Add(($hash + '  ' + $file.Name))
        }
        [IO.File]::WriteAllText((Join-Path $Directory 'SHA256SUMS.txt'),(($lines -join "`n") + "`n"),[Text.UTF8Encoding]::new($false))
    }
    function New-VgtFakeInstallerSet {
        param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Version,[switch]$WithoutSidecar)
        $manifestContent = '{"version":"' + $Version + '"}'
        $provenanceContent = '{"sourceTree":{"sha256":"' + ('a' * 64) + '"}}'
        [void](New-VgtChannelAsset -Directory $Directory -Name ('GeDefense-Setup-x64-v{0}.exe' -f $Version) -Content 'exe-fixture')
        [void](New-VgtChannelAsset -Directory $Directory -Name ('GeDefense-Setup-x64-v{0}.json' -f $Version) -Content $manifestContent)
        [void](New-VgtChannelAsset -Directory $Directory -Name ('GeDefense-SBOM-v{0}.cdx.json' -f $Version) -Content '{"components":[]}')
        [void](New-VgtChannelAsset -Directory $Directory -Name ('GeDefense-Provenance-v{0}.json' -f $Version) -Content $provenanceContent)
        if (-not $WithoutSidecar) { New-VgtChannelSidecar -Directory $Directory -AssetName ('GeDefense-Setup-x64-v{0}.exe' -f $Version) }
    }
    function New-VgtFakeSourceArchive {
        param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Version)
        [void](New-VgtChannelAsset -Directory $Directory -Name ('VGT_GeDefense_Windows_{0}_Source.zip' -f $Version) -Content 'zip-fixture')
        New-VgtChannelSidecar -Directory $Directory -AssetName ('VGT_GeDefense_Windows_{0}_Source.zip' -f $Version)
    }
    function Reset-VgtChannelDirectory {
        if (Test-Path -LiteralPath $channelRelease) { Remove-Item -LiteralPath $channelRelease -Recurse -Force }
        New-Item -Path $channelRelease -ItemType Directory -Force | Out-Null
    }

    Reset-VgtChannelDirectory
    New-VgtFakeInstallerSet -Directory $channelRelease -Version '4.1.1'
    $foreignVersionRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $foreignVersionRejected = $true }
    Add-Check -Name 'release-channel-rejects-foreign-version-assets' -Passed $foreignVersionRejected

    Reset-VgtChannelDirectory
    [void](New-VgtChannelAsset -Directory $channelRelease -Name 'notes.txt' -Content 'unknown')
    $unknownAssetRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $unknownAssetRejected = $true }
    Add-Check -Name 'release-channel-rejects-unknown-assets' -Passed $unknownAssetRejected

    Reset-VgtChannelDirectory
    New-VgtFakeInstallerSet -Directory $channelRelease -Version $channelVersion -WithoutSidecar
    $missingSidecarRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $missingSidecarRejected = $true }
    Add-Check -Name 'release-channel-rejects-missing-asset-sidecar' -Passed $missingSidecarRejected

    Reset-VgtChannelDirectory
    New-VgtFakeInstallerSet -Directory $channelRelease -Version $channelVersion
    $partialChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion
    Add-Check -Name 'release-channel-accepts-consistent-partial-build' -Passed ([string]$partialChannel.State -eq 'PARTIAL' -and [string]$partialChannel.SumsState -eq 'pending-build' -and [bool]$partialChannel.HasInstaller -and -not [bool]$partialChannel.HasSourceArchive)

    New-VgtFakeSourceArchive -Directory $channelRelease -Version $channelVersion
    $missingSumsRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $missingSumsRejected = $true }
    Add-Check -Name 'release-channel-rejects-complete-set-without-sums' -Passed $missingSumsRejected

    Write-VgtChannelSums -Directory $channelRelease
    $verifiedChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion
    Add-Check -Name 'release-channel-accepts-complete-verified-set' -Passed ([string]$verifiedChannel.State -eq 'VERIFIED' -and [string]$verifiedChannel.SumsState -eq 'verified' -and [int]$verifiedChannel.SumsEntries -eq (([int]$verifiedChannel.Assets) - 1))

    $sumsFilePath = Join-Path $channelRelease 'SHA256SUMS.txt'
    $validSumsText = Get-Content -LiteralPath $sumsFilePath -Raw -Encoding UTF8
    [IO.File]::WriteAllText($sumsFilePath,($validSumsText -replace '(?m)^[0-9a-f]{64}',('0' * 64)),[Text.UTF8Encoding]::new($false))
    $tamperedSumsRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $tamperedSumsRejected = $true }
    Add-Check -Name 'release-channel-rejects-tampered-sums-hash' -Passed $tamperedSumsRejected
    [IO.File]::WriteAllText($sumsFilePath,$validSumsText,[Text.UTF8Encoding]::new($false))

    [IO.File]::WriteAllText($sumsFilePath,($validSumsText + (('f' * 64) + '  stale-asset.bin' + "`n")),[Text.UTF8Encoding]::new($false))
    $staleSumsRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $staleSumsRejected = $true }
    Add-Check -Name 'release-channel-rejects-stale-sums-entry' -Passed $staleSumsRejected
    [IO.File]::WriteAllText($sumsFilePath,$validSumsText,[Text.UTF8Encoding]::new($false))

    $duplicateSumsRejected = $false
    $validLines = @($validSumsText.Trim() -split "`n")
    [IO.File]::WriteAllText($sumsFilePath,(($validLines -join "`n") + "`n" + $validLines[0] + "`n"),[Text.UTF8Encoding]::new($false))
    try { Assert-VgtSha256SumsCoverage -ReleaseDirectory $channelRelease | Out-Null } catch { $duplicateSumsRejected = $true }
    Add-Check -Name 'sums-coverage-rejects-duplicate-entry' -Passed $duplicateSumsRejected
    [IO.File]::WriteAllText($sumsFilePath,$validSumsText,[Text.UTF8Encoding]::new($false))

    # -------------------------------------------------------------------
    # Release-sidecar binding: measured SBOM/provenance hashes (SC-FIND-005)
    # -------------------------------------------------------------------
    $bindingRoot = Join-Path $sandbox 'binding'
    $bindingRelease = Join-Path $bindingRoot 'release'
    New-Item -Path $bindingRelease -ItemType Directory -Force | Out-Null
    $bindingComponents = @()
    for ($componentIndex = 1; $componentIndex -le 30; $componentIndex++) { $bindingComponents += [ordered]@{ 'bom-ref' = ('pkg:fixture/component-{0}' -f $componentIndex); type = 'library'; name = ('component-{0}' -f $componentIndex); version = '1.0.0' } }
    $bindingSbomPath = Join-Path $bindingRelease 'GeDefense-SBOM-v5.1.4.cdx.json'
    [IO.File]::WriteAllText($bindingSbomPath,(([ordered]@{ components = $bindingComponents }) | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    $bindingSourceTreeDigest = ('b' * 64)
    $bindingProvenancePath = Join-Path $bindingRelease 'GeDefense-Provenance-v5.1.4.json'
    [IO.File]::WriteAllText($bindingProvenancePath,(([ordered]@{ sourceTree = [ordered]@{ sha256 = $bindingSourceTreeDigest } }) | ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
    $bindingSidecarPath = Join-Path $bindingRelease 'GeDefense-Setup-x64-v5.1.4.json'
    $bindingSidecar = [ordered]@{
        schema = 'vgt-release-sidecar/1'
        version = '5.1.4'
        sbom = [ordered]@{ name = [IO.Path]::GetFileName($bindingSbomPath); sha256 = (Get-VgtFileSha256Lower -Path $bindingSbomPath); components = 30 }
        provenance = [ordered]@{ name = [IO.Path]::GetFileName($bindingProvenancePath); sha256 = (Get-VgtFileSha256Lower -Path $bindingProvenancePath); sourceTreeDigest = $bindingSourceTreeDigest }
    }
    function Write-VgtBindingSidecar {
        param([Parameter(Mandatory)]$Sidecar,[Parameter(Mandatory)][string]$Path)
        [IO.File]::WriteAllText($Path,($Sidecar | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    }
    Write-VgtBindingSidecar -Sidecar $bindingSidecar -Path $bindingSidecarPath
    $bindingCheck = Assert-VgtReleaseSidecarBinding -SidecarPath $bindingSidecarPath -ReleaseDirectory $bindingRelease -ExpectedVersion '5.1.4'
    Add-Check -Name 'sidecar-binding-accepts-measured-values' -Passed ([int]$bindingCheck.SbomComponents -eq 30 -and [string]$bindingCheck.SourceTreeDigest -eq $bindingSourceTreeDigest -and [string]$bindingCheck.SbomSha256 -eq (Get-VgtFileSha256Lower -Path $bindingSbomPath))

    $tamperedBinding = ($bindingSidecar | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    $tamperedBinding.sbom.sha256 = ('c' * 64)
    Write-VgtBindingSidecar -Sidecar $tamperedBinding -Path $bindingSidecarPath
    $tamperedBindingRejected = $false
    try { Assert-VgtReleaseSidecarBinding -SidecarPath $bindingSidecarPath -ReleaseDirectory $bindingRelease -ExpectedVersion '5.1.4' | Out-Null } catch { $tamperedBindingRejected = $true }
    Add-Check -Name 'sidecar-binding-rejects-stale-sbom-hash' -Passed $tamperedBindingRejected

    $missingProvenanceBinding = ($bindingSidecar | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    $missingProvenanceBinding.PSObject.Properties.Remove('provenance')
    Write-VgtBindingSidecar -Sidecar $missingProvenanceBinding -Path $bindingSidecarPath
    $missingProvenanceRejected = $false
    try { Assert-VgtReleaseSidecarBinding -SidecarPath $bindingSidecarPath -ReleaseDirectory $bindingRelease -ExpectedVersion '5.1.4' | Out-Null } catch { $missingProvenanceRejected = $true }
    Add-Check -Name 'sidecar-binding-rejects-missing-provenance-binding' -Passed $missingProvenanceRejected

    $digestMismatchBinding = ($bindingSidecar | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    $digestMismatchBinding.provenance.sourceTreeDigest = ('d' * 64)
    Write-VgtBindingSidecar -Sidecar $digestMismatchBinding -Path $bindingSidecarPath
    $digestMismatchRejected = $false
    try { Assert-VgtReleaseSidecarBinding -SidecarPath $bindingSidecarPath -ReleaseDirectory $bindingRelease -ExpectedVersion '5.1.4' | Out-Null } catch { $digestMismatchRejected = $true }
    Add-Check -Name 'sidecar-binding-rejects-source-tree-mismatch' -Passed $digestMismatchRejected

    $componentMismatchBinding = ($bindingSidecar | ConvertTo-Json -Depth 6 | ConvertFrom-Json)
    $componentMismatchBinding.sbom.components = 29
    Write-VgtBindingSidecar -Sidecar $componentMismatchBinding -Path $bindingSidecarPath
    $componentMismatchRejected = $false
    try { Assert-VgtReleaseSidecarBinding -SidecarPath $bindingSidecarPath -ReleaseDirectory $bindingRelease -ExpectedVersion '5.1.4' | Out-Null } catch { $componentMismatchRejected = $true }
    Add-Check -Name 'sidecar-binding-rejects-component-count-mismatch' -Passed $componentMismatchRejected
    Write-VgtBindingSidecar -Sidecar $bindingSidecar -Path $bindingSidecarPath

    # -------------------------------------------------------------------
    # Source-archive freshness against the authoritative source manifest
    # -------------------------------------------------------------------
    $archiveRoot = Join-Path $sandbox 'archive-root'
    $archiveRelease = Join-Path $archiveRoot 'release'
    New-Item -Path $archiveRelease -ItemType Directory -Force | Out-Null
    $archiveManifestPath = Join-Path $archiveRoot 'SOURCE-MANIFEST.sha256'
    $archiveManifestText = (('e' * 64) + '  VERSION' + "`n")
    [IO.File]::WriteAllText($archiveManifestPath,$archiveManifestText,[Text.UTF8Encoding]::new($false))
    $archiveStaging = Join-Path $sandbox 'archive-staging\GeDefense-Windows-5.1.4'
    New-Item -Path $archiveStaging -ItemType Directory -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $archiveStaging 'SOURCE-MANIFEST.sha256'),$archiveManifestText,[Text.UTF8Encoding]::new($false))
    $fakeArchivePath = Join-Path $archiveRelease 'VGT_GeDefense_Windows_5.1.4_Source.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $sandbox 'archive-staging'),$fakeArchivePath,[IO.Compression.CompressionLevel]::NoCompression,$false)
    $freshness = Assert-VgtSourceArchiveFreshness -ProjectRoot $archiveRoot -ArchivePath $fakeArchivePath -Version '5.1.4'
    Add-Check -Name 'source-archive-freshness-accepts-matching-manifest' -Passed ([string]$freshness.Status -eq 'PASS' -and [string]$freshness.ManifestSha256 -eq (Get-FileHash -LiteralPath $archiveManifestPath -Algorithm SHA256).Hash.ToLowerInvariant())
    [IO.File]::WriteAllText($archiveManifestPath,($archiveManifestText + (('f' * 64) + '  extra.txt' + "`n")),[Text.UTF8Encoding]::new($false))
    $staleArchiveRejected = $false
    try { Assert-VgtSourceArchiveFreshness -ProjectRoot $archiveRoot -ArchivePath $fakeArchivePath -Version '5.1.4' | Out-Null } catch { $staleArchiveRejected = $true }
    Add-Check -Name 'source-archive-freshness-rejects-stale-archive' -Passed $staleArchiveRejected
    $wrongVersionArchiveRejected = $false
    try { Assert-VgtSourceArchiveFreshness -ProjectRoot $archiveRoot -ArchivePath $fakeArchivePath -Version '5.1.3' | Out-Null } catch { $wrongVersionArchiveRejected = $true }
    Add-Check -Name 'source-archive-freshness-rejects-wrong-version-entry' -Passed $wrongVersionArchiveRejected
} finally {
    if (Test-Path -LiteralPath $sandbox) { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
}

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = 'static+functional'
    Checks = $checks.Count
    Results = $checks.ToArray()
}
