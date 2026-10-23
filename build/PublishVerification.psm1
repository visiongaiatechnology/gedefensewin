# STATUS: DIAMANT VGT SUPREME
# Fail-closed verification helpers for build/Publish-GitHubRelease.ps1
# (SC-FIND-009). Imported only by the publish tooling; never shipped in the
# product payload.
#
# Every helper throws on a failed verification. There is no "assume Valid"
# branch: release metadata is always derived from measured values.
Set-StrictMode -Version Latest

function Get-VgtFileSha256Lower {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Asset is missing: {0}' -f $Path)) }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-VgtSha256Sidecar {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('SHA-256 sidecar is missing: {0}' -f $Path)) }
    $text = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8).Trim()
    if ($text -notmatch '^(?<hash>[0-9a-fA-F]{64})(?:\s+\*?(?<name>\S+))?$') { throw [IO.InvalidDataException]::new(('SHA-256 sidecar has an invalid format: {0}' -f $Path)) }
    return [pscustomobject][ordered]@{ Sha256 = $Matches['hash'].ToLowerInvariant(); FileName = $(if ($Matches['name']) { $Matches['name'].Trim() } else { '' }) }
}

function Assert-VgtAssetHash {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SidecarPath
    )
    $sidecar = Read-VgtSha256Sidecar -Path $SidecarPath
    $measured = Get-VgtFileSha256Lower -Path $Path
    if ($sidecar.Sha256 -ne $measured) { throw [Security.SecurityException]::new(('SHA-256 sidecar mismatch for {0}: sidecar={1} measured={2}' -f $Path,$sidecar.Sha256,$measured)) }
    if ($sidecar.FileName) {
        $expectedName = [IO.Path]::GetFileName($Path)
        if ($sidecar.FileName -ne $expectedName -and $sidecar.FileName -ne ('*' + $expectedName)) { throw [Security.SecurityException]::new(('SHA-256 sidecar names a different file: {0} vs {1}' -f $sidecar.FileName,$expectedName)) }
    }
    return $measured
}

function Assert-VgtPublisherSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedThumbprint
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Signed asset is missing: {0}' -f $Path)) }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { throw [Security.SecurityException]::new(('Authenticode signature is not valid: status={0} message={1}' -f $signature.Status,$signature.StatusMessage)) }
    if (-not $signature.SignerCertificate) { throw [Security.SecurityException]::new('Authenticode signature has no signer certificate.') }
    if ([string]$signature.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) { throw [Security.SecurityException]::new(('Signer thumbprint mismatch: measured={0} expected={1}' -f $signature.SignerCertificate.Thumbprint,$ExpectedThumbprint)) }
    return [pscustomobject][ordered]@{
        Status = [string]$signature.Status
        Thumbprint = [string]$signature.SignerCertificate.Thumbprint
        Subject = [string]$signature.SignerCertificate.Subject
        TimeStamperPresent = ($null -ne $signature.TimeStamperCertificate)
    }
}

function Assert-VgtJsonManifestMatchesAsset {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$AssetPath,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Release manifest is missing: {0}' -f $ManifestPath)) }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$manifest.version -ne $ExpectedVersion) { throw [IO.InvalidDataException]::new(('Release manifest version mismatch: {0} vs {1}' -f $manifest.version,$ExpectedVersion)) }
    $assetBytes = [long](Get-Item -LiteralPath $AssetPath).Length
    if ([long]$manifest.bytes -ne $assetBytes) { throw [Security.SecurityException]::new(('Release manifest byte count mismatch: {0} vs {1}' -f $manifest.bytes,$assetBytes)) }
    $measuredHash = (Get-VgtFileSha256Lower -Path $AssetPath).ToUpperInvariant()
    if (([string]$manifest.sha256).ToUpperInvariant() -ne $measuredHash) { throw [Security.SecurityException]::new(('Release manifest SHA-256 mismatch: {0} vs measured {1}' -f $manifest.sha256,$measuredHash)) }
    return $manifest
}

function Assert-VgtCleanTag {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$Tag,
        [switch]$AllowMissingVcs
    )
    $gitDirectory = Join-Path $ProjectRoot '.git'
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container) -or $null -eq $git) {
        if (-not $AllowMissingVcs) { throw [Security.SecurityException]::new('No .git repository is available: a clean, tagged revision cannot be proven. Publishing is refused (use -AllowMissingVcs only for non-official dry runs).') }
        return [pscustomobject][ordered]@{ State = 'unavailable-override'; Commit = ''; Tag = ''; TreeClean = $false }
    }
    $statusOutput = (& git -C $ProjectRoot status --porcelain 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { throw [Security.SecurityException]::new('git status failed; the working tree state cannot be proven.') }
    if (-not [string]::IsNullOrWhiteSpace($statusOutput.Trim())) { throw [Security.SecurityException]::new('Working tree is dirty; a release must be built from a clean tagged revision.') }
    $commit = (& git -C $ProjectRoot rev-parse HEAD 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40,64}$') { throw [Security.SecurityException]::new('git HEAD could not be resolved.') }
    $exactTag = (& git -C $ProjectRoot describe --tags --exact-match HEAD 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $exactTag -ne $Tag) { throw [Security.SecurityException]::new(('HEAD is not tagged with {0} (measured: {1}).' -f $Tag,$exactTag)) }
    $tagObjectType = (& git -C $ProjectRoot for-each-ref ("refs/tags/{0}" -f $Tag) --format='%(objecttype)' 2>$null | Out-String).Trim()
    if ($tagObjectType -ne 'tag') { throw [Security.SecurityException]::new(('Release tag {0} is not an annotated tag (objecttype={1}).' -f $Tag,$tagObjectType)) }
    $tagSignatureState = 'unsigned-or-unverifiable'
    $verifyTag = (& git -C $ProjectRoot verify-tag $Tag 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) { $tagSignatureState = 'verified' } elseif ($verifyTag -match 'gpg|no public key|not signed|cannot') { $tagSignatureState = 'not-verified' } else { $tagSignatureState = 'not-verified' }
    return [pscustomobject][ordered]@{ State = 'verified'; Commit = $commit; Tag = $Tag; TreeClean = $true; TagObjectType = $tagObjectType; TagSignature = $tagSignatureState }
}

function Write-VgtSha256Sums {
    param(
        [Parameter(Mandatory)][object[]]$Assets,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $lines = [Collections.Generic.List[string]]::new()
    $ordered = @($Assets | Sort-Object { [string]$_.Name })
    foreach ($asset in $ordered) {
        $hash = Get-VgtFileSha256Lower -Path $asset.Path
        $lines.Add(('{0}  {1}' -f $hash,[string]$asset.Name))
    }
    $payload = ($lines -join "`n") + "`n"
    [IO.File]::WriteAllText($OutputPath,$payload,[Text.UTF8Encoding]::new($false))
    return [pscustomobject][ordered]@{ Path = $OutputPath; Lines = $lines.Count; Entries = $lines.ToArray() }
}

function Get-VgtSidecarNodeValue {
    param($Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-VgtReleaseSidecarBinding {
    # SC-FIND-005/SC-FIND-003: the release sidecar (GeDefense-Setup-x64-v<v>.json)
    # is written last and must embed the measured hashes of the FINAL SBOM and
    # provenance artifacts. Re-measures both files and compares the embedded
    # values, their asset names, the SBOM component count and the provenance
    # source-tree digest with the referenced documents. Fail-closed: a missing
    # field, a stale hash or a name mismatch aborts the release.
    param(
        [Parameter(Mandatory)][string]$SidecarPath,
        [Parameter(Mandatory)][string]$ReleaseDirectory,
        [Parameter(Mandatory)][string]$ExpectedVersion,
        [string]$SbomPath = '',
        [string]$ProvenancePath = ''
    )
    if (-not (Test-Path -LiteralPath $SidecarPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Release sidecar manifest is missing: {0}' -f $SidecarPath)) }
    $sidecar = Get-Content -LiteralPath $SidecarPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $sidecar) { throw [IO.InvalidDataException]::new(('Release sidecar manifest is empty or invalid: {0}' -f $SidecarPath)) }
    $sidecarVersion = [string](Get-VgtSidecarNodeValue -Object $sidecar -Name 'version')
    if ($sidecarVersion -ne $ExpectedVersion) { throw [IO.InvalidDataException]::new(('Release sidecar version mismatch: {0} vs {1}' -f $sidecarVersion,$ExpectedVersion)) }
    $releaseFull = [IO.Path]::GetFullPath($ReleaseDirectory)
    if ([string]::IsNullOrWhiteSpace($SbomPath)) { $SbomPath = Join-Path $releaseFull ('GeDefense-SBOM-v{0}.cdx.json' -f $ExpectedVersion) } else { $SbomPath = [IO.Path]::GetFullPath($SbomPath) }
    if ([string]::IsNullOrWhiteSpace($ProvenancePath)) { $ProvenancePath = Join-Path $releaseFull ('GeDefense-Provenance-v{0}.json' -f $ExpectedVersion) } else { $ProvenancePath = [IO.Path]::GetFullPath($ProvenancePath) }

    $sbomNode = Get-VgtSidecarNodeValue -Object $sidecar -Name 'sbom'
    if ($null -eq $sbomNode) { throw [Security.SecurityException]::new('Release sidecar does not embed the SBOM binding (sidecar/sbom.sha256).') }
    $sbomName = [string](Get-VgtSidecarNodeValue -Object $sbomNode -Name 'name')
    $sbomHash = ([string](Get-VgtSidecarNodeValue -Object $sbomNode -Name 'sha256')).ToLowerInvariant()
    $sbomComponents = [long](Get-VgtSidecarNodeValue -Object $sbomNode -Name 'components')
    $measuredSbomHash = Get-VgtFileSha256Lower -Path $SbomPath
    $expectedSbomName = [IO.Path]::GetFileName($SbomPath)
    if ($sbomName -ne $expectedSbomName) { throw [Security.SecurityException]::new(('Release sidecar SBOM binding names a different file: {0} vs {1}' -f $sbomName,$expectedSbomName)) }
    if ($sbomHash -notmatch '^[0-9a-f]{64}$') { throw [IO.InvalidDataException]::new('Release sidecar SBOM binding has an invalid SHA-256 value.') }
    if ($sbomHash -ne $measuredSbomHash) { throw [Security.SecurityException]::new(('Release sidecar SBOM SHA-256 does not match the measured SBOM: sidecar={0} measured={1}' -f $sbomHash,$measuredSbomHash)) }
    $sbomDocument = Get-Content -LiteralPath $SbomPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $sbomDocumentComponents = @((Get-VgtSidecarNodeValue -Object $sbomDocument -Name 'components')).Count
    if ($sbomComponents -ne $sbomDocumentComponents) { throw [Security.SecurityException]::new(('Release sidecar SBOM component count does not match the SBOM: sidecar={0} sbom={1}' -f $sbomComponents,$sbomDocumentComponents)) }
    if ($sbomComponents -lt 30) { throw [Security.SecurityException]::new(('Release sidecar SBOM component count is too small: {0}' -f $sbomComponents)) }

    $provenanceNode = Get-VgtSidecarNodeValue -Object $sidecar -Name 'provenance'
    if ($null -eq $provenanceNode) { throw [Security.SecurityException]::new('Release sidecar does not embed the provenance binding (sidecar/provenance.sha256).') }
    $provenanceName = [string](Get-VgtSidecarNodeValue -Object $provenanceNode -Name 'name')
    $provenanceHash = ([string](Get-VgtSidecarNodeValue -Object $provenanceNode -Name 'sha256')).ToLowerInvariant()
    $sidecarSourceTreeDigest = ([string](Get-VgtSidecarNodeValue -Object $provenanceNode -Name 'sourceTreeDigest')).ToLowerInvariant()
    $measuredProvenanceHash = Get-VgtFileSha256Lower -Path $ProvenancePath
    $expectedProvenanceName = [IO.Path]::GetFileName($ProvenancePath)
    if ($provenanceName -ne $expectedProvenanceName) { throw [Security.SecurityException]::new(('Release sidecar provenance binding names a different file: {0} vs {1}' -f $provenanceName,$expectedProvenanceName)) }
    if ($provenanceHash -notmatch '^[0-9a-f]{64}$') { throw [IO.InvalidDataException]::new('Release sidecar provenance binding has an invalid SHA-256 value.') }
    if ($provenanceHash -ne $measuredProvenanceHash) { throw [Security.SecurityException]::new(('Release sidecar provenance SHA-256 does not match the measured provenance: sidecar={0} measured={1}' -f $provenanceHash,$measuredProvenanceHash)) }
    $provenanceDocument = Get-Content -LiteralPath $ProvenancePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $provenanceSourceTree = Get-VgtSidecarNodeValue -Object $provenanceDocument -Name 'sourceTree'
    $measuredSourceTreeDigest = ([string](Get-VgtSidecarNodeValue -Object $provenanceSourceTree -Name 'sha256')).ToLowerInvariant()
    if ($measuredSourceTreeDigest -notmatch '^[0-9a-f]{64}$') { throw [IO.InvalidDataException]::new('Provenance artifact has no valid source-tree digest.') }
    if ($sidecarSourceTreeDigest -ne $measuredSourceTreeDigest) { throw [Security.SecurityException]::new(('Release sidecar provenance source-tree digest does not match the provenance: sidecar={0} provenance={1}' -f $sidecarSourceTreeDigest,$measuredSourceTreeDigest)) }

    return [pscustomobject][ordered]@{
        Status = 'PASS'
        SbomName = $sbomName
        SbomSha256 = $measuredSbomHash
        SbomComponents = $sbomComponents
        ProvenanceName = $provenanceName
        ProvenanceSha256 = $measuredProvenanceHash
        SourceTreeDigest = $measuredSourceTreeDigest
    }
}

Export-ModuleMember -Function Get-VgtFileSha256Lower,Read-VgtSha256Sidecar,Assert-VgtAssetHash,Assert-VgtPublisherSignature,Assert-VgtJsonManifestMatchesAsset,Assert-VgtCleanTag,Write-VgtSha256Sums,Assert-VgtReleaseSidecarBinding
