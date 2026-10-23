# STATUS: DIAMANT VGT SUPREME
# Deterministic CycloneDX 1.5 SBOM generator for VGT GeDefense Windows.
#
# The previous SBOM was an empty stub enforced by the release gate. This
# generator derives real components from the working tree:
#   - the application component and its first-party PowerShell/asset files,
#   - the vendored jsVectorMap world-geometry data (MIT),
#   - the optional bundled GeoIP/ASN dataset (DB-IP Lite CC BY 4.0 / PDDL),
#   - the pinned Go toolchain and the Windows PowerShell 5.1 runtime,
#   - the three Windows build artifacts.
#
# Every hash is measured from real bytes. Optional inputs that are absent from
# the public tree are reported as absent instead of being invented. External
# trust anchors (public CA certificate, RFC3161 timestamp, revocation and an
# externally anchored anti-rollback channel) are documented limitations, not
# SBOM claims.
#
# Determinism: components are sorted ordinal by bom-ref, the timestamp derives
# from the SOURCE_DATE_EPOCH metadata file (legacy changelog fallback) and the
# serial number derives from the component graph. Running twice on identical
# inputs produces identical output.
[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [string]$OutputPath = '',
    [switch]$ArtifactMode,
    [string]$PayloadRoot = '',
    [long]$SourceDateEpoch = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
Import-Module -Name (Join-Path $PSScriptRoot 'VgtSupplyChain.psm1') -Force

$version = Read-VgtVersion -ProjectRoot $ProjectRoot
$toolchain = Get-VgtToolchain -ProjectRoot $ProjectRoot
if ($SourceDateEpoch -le 0) {
    $epochInfo = Get-VgtSourceDateEpoch -ProjectRoot $ProjectRoot
    $SourceDateEpoch = $epochInfo.Epoch
    $epochSource = $epochInfo.Source
    $epochDate = $epochInfo.Date
} else {
    $epochSource = 'explicit-parameter'
    $epochDate = ([DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch)).UtcDateTime.ToString('yyyy-MM-dd')
}
$timestamp = ([DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')

function New-VgtLicenseEntry {
    param([string]$Id = '',[string]$Name = '')
    if ($Id) { return [ordered]@{ license = [ordered]@{ id = $Id } } }
    return [ordered]@{ license = [ordered]@{ name = $Name } }
}

$agplLicense = @((New-VgtLicenseEntry -Id 'AGPL-3.0-only'))
$mitLicense = @((New-VgtLicenseEntry -Id 'MIT'))
$trademarkLicense = @((New-VgtLicenseEntry -Name 'LicenseRef-VGT-Trademark-Restricted'))

function New-VgtComponent {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$BomRef,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Version,
        [string]$Group = '',
        [string]$Supplier = '',
        [object[]]$Licenses = @(),
        [string]$Sha256 = '',
        [object[]]$Properties = @()
    )
    $component = [ordered]@{
        type = $Type
        'bom-ref' = $BomRef
        name = $Name
        version = $Version
    }
    if ($Group) { $component.group = $Group }
    if ($Supplier) { $component.supplier = [ordered]@{ name = $Supplier } }
    if ($Licenses.Count -gt 0) { $component.licenses = $Licenses }
    if ($Sha256) { $component.hashes = @([ordered]@{ alg = 'SHA-256'; content = $Sha256 }) }
    if ($Properties.Count -gt 0) { $component.properties = @($Properties) }
    return $component
}

function New-VgtProperty {
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return [ordered]@{ name = $Name; value = $Value }
}

$componentsByRef = @{}
function Add-VgtComponent {
    param([Parameter(Mandatory)]$Component)
    $ref = [string]$Component['bom-ref']
    if ($componentsByRef.ContainsKey($ref)) { throw [IO.InvalidDataException]::new(('Duplicate SBOM component reference: {0}' -f $ref)) }
    $componentsByRef[$ref] = $Component
}

$appRef = 'pkg:github/visiongaiatechnology/gedefensewin@{0}' -f $version
$projectFiles = @(Get-VgtSourceSnapshot -ProjectRoot $ProjectRoot)
$fileByRelative = @{}
foreach ($file in $projectFiles) { $fileByRelative[$file.Relative] = $file }

# Resolve the output path early: the SBOM file itself is a source-release input,
# so it must be excluded from the SBOM's own source-tree digest. Otherwise the
# digest would be self-referential and every regeneration would produce a
# different document.
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $ProjectRoot 'sbom\gedefense-windows.cdx.json' }
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$sbomOutputRelative = ''
try { $sbomOutputRelative = Get-VgtRelativePath -FullName $outputFull -ProjectRoot $ProjectRoot } catch { $sbomOutputRelative = '' }

function Get-VgtMeasuredSourceHash {
    param([Parameter(Mandatory)][string]$RelativePath)
    if (-not $fileByRelative.ContainsKey($RelativePath)) { return '' }
    return [string]$fileByRelative[$RelativePath].Sha256
}

# ---------------------------------------------------------------------------
# Payload inventory (artifact mode only)
# ---------------------------------------------------------------------------
# NOTE: do not initialise a variable named $payloadRoot here; PowerShell
# variable names are case-insensitive and it would clobber the -PayloadRoot
# parameter before it is read.
$payloadFiles = @{}
if ($ArtifactMode) {
    if ([string]::IsNullOrWhiteSpace($PayloadRoot)) { $PayloadRoot = Join-Path $ProjectRoot 'payload\VGT\GeDefense' }
    $resolvedPayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
    $payloadManifestPath = Join-Path $resolvedPayloadRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $payloadManifestPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Payload manifest is missing: {0}' -f $payloadManifestPath)) }
    $payloadVersionPath = Join-Path $resolvedPayloadRoot 'VERSION'
    if (-not (Test-Path -LiteralPath $payloadVersionPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Payload VERSION metadata is missing.') }
    $payloadVersion = (Get-Content -LiteralPath $payloadVersionPath -Raw -Encoding UTF8).Trim()
    if ($payloadVersion -ne $version) { throw [IO.InvalidDataException]::new(('Payload version {0} does not match VERSION {1}.' -f $payloadVersion,$version)) }
    foreach ($payloadFile in @(Get-ChildItem -LiteralPath $resolvedPayloadRoot -Recurse -File -Force)) {
        $relative = Get-VgtRelativePath -FullName $payloadFile.FullName -ProjectRoot $resolvedPayloadRoot
        $payloadFiles[$relative] = [pscustomobject][ordered]@{
            Relative = $relative
            FullName = $payloadFile.FullName
            Sha256 = (Get-FileHash -LiteralPath $payloadFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            Length = [long]$payloadFile.Length
        }
    }
}

function Get-VgtPayloadHash {
    param([Parameter(Mandatory)][string]$RelativePath)
    if (-not $payloadFiles.ContainsKey($RelativePath)) { return $null }
    return $payloadFiles[$RelativePath]
}

function New-VgtPayloadProperties {
    param([Parameter(Mandatory)][string]$RelativePath)
    $payloadFile = Get-VgtPayloadHash -RelativePath $RelativePath
    if ($null -eq $payloadFile) { return @() }
    return @(
        (New-VgtProperty -Name 'vgt:payload-path' -Value $payloadFile.Relative),
        (New-VgtProperty -Name 'vgt:payload-sha256' -Value $payloadFile.Sha256),
        (New-VgtProperty -Name 'vgt:payload-bytes' -Value ([string]$payloadFile.Length))
    )
}

# ---------------------------------------------------------------------------
# Third-party components (real versions, licenses and measured hashes)
# ---------------------------------------------------------------------------
$worldMercRelative = 'src/GeDefense/windows/internal/server/web/world-merc.js'
$worldMercHash = Get-VgtMeasuredSourceHash -RelativePath $worldMercRelative
if (-not $worldMercHash) { throw [IO.FileNotFoundException]::new('Vendored jsVectorMap world-merc.js geometry is missing.') }
Add-VgtComponent -Component (New-VgtComponent -Type 'data' -BomRef ('pkg:generic/jsvectormap-world-merc-geometry@vendored-snapshot') -Name 'jsVectorMap world-merc map geometry' -Version 'vendored-snapshot' -Supplier 'jsVectorMap / Mustafa Omar' -Licenses $mitLicense -Sha256 $worldMercHash -Properties @(
    (New-VgtProperty -Name 'vgt:component-class' -Value 'third-party-library'),
    (New-VgtProperty -Name 'vgt:source-path' -Value $worldMercRelative),
    (New-VgtProperty -Name 'vgt:provenance' -Value 'Vendored data literal from jsVectorMap maps/src/world-merc.js; only the ES-module wrapper was adapted locally.'),
    (New-VgtProperty -Name 'vgt:version-note' -Value 'The vendored file does not record an exact upstream release; the content hash is the authoritative identity.')
))

$geoipRelative = 'data/geoip.csv'
$geoipHash = Get-VgtMeasuredSourceHash -RelativePath $geoipRelative
$geoipSidecarHash = Get-VgtMeasuredSourceHash -RelativePath 'data/geoip.csv.sha256'
$geoipPayloadHash = if ($ArtifactMode) { Get-VgtPayloadHash -RelativePath 'bin/geoip.csv' } else { $null }
$geoipVersion = 'unversioned-snapshot'
if ($geoipHash) { $geoipVersion = 'snapshot-' + $geoipHash.Substring(0,12) }
elseif ($null -ne $geoipPayloadHash) { $geoipVersion = 'snapshot-' + $geoipPayloadHash.Sha256.Substring(0,12) }
$geoipProperties = [Collections.Generic.List[object]]::new()
$geoipProperties.Add((New-VgtProperty -Name 'vgt:component-class' -Value 'third-party-dataset'))
$geoipProperties.Add((New-VgtProperty -Name 'vgt:provenance' -Value 'DB-IP Lite geolocation combined with sapics/ip-location-db ASN data; exact upstream snapshot date is not independently proven (see GEOIP_LICENSE_AND_DEPLOYMENT.md).'))
if ($geoipHash) {
    $geoipProperties.Add((New-VgtProperty -Name 'vgt:source-path' -Value $geoipRelative))
    $geoipProperties.Add((New-VgtProperty -Name 'vgt:bundle-state' -Value 'present-in-working-tree'))
    if ($geoipSidecarHash) { $geoipProperties.Add((New-VgtProperty -Name 'vgt:ships-sidecar' -Value $true.ToString().ToLowerInvariant())) }
} elseif ($null -ne $geoipPayloadHash) {
    $geoipProperties.Add((New-VgtProperty -Name 'vgt:bundle-state' -Value 'present-in-built-payload'))
} else {
    $geoipProperties.Add((New-VgtProperty -Name 'vgt:bundle-state' -Value 'optional-not-present-in-this-tree'))
}
$geoipSha = if ($geoipHash) { $geoipHash } elseif ($null -ne $geoipPayloadHash) { $geoipPayloadHash.Sha256 } else { '' }
Add-VgtComponent -Component (New-VgtComponent -Type 'data' -BomRef ('pkg:generic/gedefense-geoip-asn-dataset@{0}' -f $geoipVersion) -Name 'GeDefense bundled GeoIP/ASN dataset (DB-IP Lite + sapics ip-location-db)' -Version $geoipVersion -Supplier 'DB-IP (geolocation) / sapics ip-location-db (ASN)' -Licenses @((New-VgtLicenseEntry -Id 'CC-BY-4.0'),(New-VgtLicenseEntry -Id 'PDDL-1.0')) -Sha256 $geoipSha -Properties @($geoipProperties.ToArray()))
if ($ArtifactMode) {
    $geoipPayloadProps = @(New-VgtPayloadProperties -RelativePath 'bin/geoip.csv')
    if ($geoipPayloadProps.Count -gt 0) {
        $datasetComponent = $componentsByRef[('pkg:generic/gedefense-geoip-asn-dataset@{0}' -f $geoipVersion)]
        $datasetComponent.properties = @($datasetComponent.properties) + @($geoipPayloadProps)
    }
}

$goVersion = [string]$toolchain['go']
$goZipHash = ''
if ($toolchain.ContainsKey('go_windows_amd64_zip_sha256')) { $goZipHash = ([string]$toolchain['go_windows_amd64_zip_sha256']).Trim().ToLowerInvariant() }
if ($goZipHash -and $goZipHash -notmatch '^[0-9a-f]{64}$') { throw [IO.InvalidDataException]::new('TOOLCHAINS.lock Go archive hash is not a SHA-256 value.') }
$goProperties = @(
    (New-VgtProperty -Name 'vgt:component-class' -Value 'toolchain'),
    (New-VgtProperty -Name 'vgt:pin-source' -Value 'TOOLCHAINS.lock'),
    (New-VgtProperty -Name 'vgt:artifact' -Value ('go{0}.windows-amd64.zip' -f $goVersion)),
    (New-VgtProperty -Name 'vgt:hash-source' -Value 'TOOLCHAINS.lock pin; the archive is not re-downloaded by this offline generator'),
    (New-VgtProperty -Name 'vgt:redistributed' -Value 'false')
)
Add-VgtComponent -Component (New-VgtComponent -Type 'application' -BomRef ('pkg:generic/go-toolchain@{0}?os=windows&arch=amd64' -f $goVersion) -Name 'Go toolchain (standard library only)' -Version $goVersion -Supplier 'Go Authors / Google LLC' -Licenses @((New-VgtLicenseEntry -Id 'BSD-3-Clause')) -Sha256 $goZipHash -Properties $goProperties)

$powershellVersion = '5.1'
if ($toolchain.ContainsKey('powershell')) { $powershellVersion = [string]$toolchain['powershell'] }
Add-VgtComponent -Component (New-VgtComponent -Type 'application' -BomRef ('pkg:generic/windows-powershell@{0}?os=windows' -f $powershellVersion) -Name 'Windows PowerShell' -Version $powershellVersion -Supplier 'Microsoft Corporation' -Licenses @((New-VgtLicenseEntry -Name 'Microsoft-EULA (operating-system component, not redistributed)')) -Properties @(
    (New-VgtProperty -Name 'vgt:component-class' -Value 'runtime'),
    (New-VgtProperty -Name 'vgt:pin-source' -Value 'TOOLCHAINS.lock'),
    (New-VgtProperty -Name 'vgt:hash-state' -Value 'platform-provided; no redistributable artifact hash exists'),
    (New-VgtProperty -Name 'vgt:redistributed' -Value 'false')
))

# ---------------------------------------------------------------------------
# First-party source assets
# ---------------------------------------------------------------------------
$firstPartyPatterns = @(
    'engine/',
    'audit/',
    'xdr/',
    'branding/',
    'LICENSES/'
)
$firstPartyRootFiles = @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','GEOIP_LICENSE_AND_DEPLOYMENT.md','VERSION','DEPENDENCIES.md','LICENSE-MATRIX.md')
$firstPartyInstallers = @('installer/Install-GeDefense.ps1','installer/Uninstall-GeDefense.ps1','installer/Bootstrap-GeDefense.ps1','installer/InstallerSafety.psm1')

$firstPartyRelatives = [Collections.Generic.List[string]]::new()
foreach ($relative in $fileByRelative.Keys) {
    $matched = $false
    foreach ($prefix in $firstPartyPatterns) {
        if ($relative.StartsWith($prefix,[StringComparison]::Ordinal)) { $matched = $true; break }
    }
    if ($matched) { $firstPartyRelatives.Add($relative) }
}
foreach ($relative in $firstPartyRootFiles) {
    if ($fileByRelative.ContainsKey($relative)) { $firstPartyRelatives.Add($relative) }
}
foreach ($relative in $firstPartyInstallers) {
    if ($fileByRelative.ContainsKey($relative)) { $firstPartyRelatives.Add($relative) }
}

foreach ($relative in ($firstPartyRelatives | Sort-Object)) {
    $hash = Get-VgtMeasuredSourceHash -RelativePath $relative
    if (-not $hash) { continue }
    $componentClass = 'first-party-source'
    if ($relative.StartsWith('LICENSES/',[StringComparison]::Ordinal)) { $componentClass = 'license-text' }
    if ($relative.StartsWith('branding/',[StringComparison]::Ordinal)) { $componentClass = 'branding-asset' }
    $licenses = $agplLicense
    if ($componentClass -eq 'branding-asset') { $licenses = $trademarkLicense }
    $properties = [Collections.Generic.List[object]]::new()
    $properties.Add((New-VgtProperty -Name 'vgt:component-class' -Value $componentClass))
    $properties.Add((New-VgtProperty -Name 'vgt:source-path' -Value $relative))
    $properties.Add((New-VgtProperty -Name 'vgt:supplier-role' -Value 'first-party'))
    if ($ArtifactMode) {
        $payloadProps = @(New-VgtPayloadProperties -RelativePath $relative)
        foreach ($property in $payloadProps) { $properties.Add($property) }
    }
    Add-VgtComponent -Component (New-VgtComponent -Type 'file' -BomRef ('file:vgt-gedefense/{0}' -f $relative) -Name $relative -Version $version -Group 'VisionGaiaTechnology' -Supplier 'VisionGaia Technology' -Licenses $licenses -Sha256 $hash -Properties @($properties.ToArray()))
}

# ---------------------------------------------------------------------------
# Windows build artifacts (hashes only once the payload has been built)
# ---------------------------------------------------------------------------
$binaryTargets = @(
    @{ Relative = 'bin/gedefense-windows.exe'; Target = './cmd/gedefense-windows'; Name = 'GeDefense Windows service'; Gui = $false },
    @{ Relative = 'bin/GeDefenseCenter.exe'; Target = './cmd/gedefense-center'; Name = 'GeDefense Security Center'; Gui = $true },
    @{ Relative = 'bin/GeDefenseTray.exe'; Target = './cmd/gedefense-tray'; Name = 'GeDefense Tray'; Gui = $true }
)
foreach ($binary in $binaryTargets) {
    $payloadHash = if ($ArtifactMode) { Get-VgtPayloadHash -RelativePath $binary.Relative } else { $null }
    $properties = [Collections.Generic.List[object]]::new()
    $properties.Add((New-VgtProperty -Name 'vgt:component-class' -Value 'first-party-binary'))
    $properties.Add((New-VgtProperty -Name 'vgt:build-target' -Value $binary.Target))
    $binaryFlags = '-trimpath -ldflags "-s -w"'
    if ($binary.Gui) { $binaryFlags += ' -H=windowsgui' }
    $properties.Add((New-VgtProperty -Name 'vgt:build-flags' -Value $binaryFlags))
    if ($null -ne $payloadHash) {
        $properties.Add((New-VgtProperty -Name 'vgt:build-state' -Value 'payload-built'))
        $properties.Add((New-VgtProperty -Name 'vgt:payload-path' -Value $payloadHash.Relative))
        $properties.Add((New-VgtProperty -Name 'vgt:payload-sha256' -Value $payloadHash.Sha256))
        $sha = $payloadHash.Sha256
    } else {
        $properties.Add((New-VgtProperty -Name 'vgt:build-state' -Value 'pending-build'))
        $properties.Add((New-VgtProperty -Name 'vgt:hash-state' -Value 'artifact hash is filled when the signed payload is built'))
        $sha = ''
    }
    Add-VgtComponent -Component (New-VgtComponent -Type 'application' -BomRef ('pkg:generic/vgt-gedefense/{0}@{1}' -f $binary.Relative,$version) -Name ('VGT GeDefense Windows artifact: {0}' -f $binary.Relative) -Version $version -Group 'VisionGaiaTechnology' -Supplier 'VisionGaia Technology' -Licenses $agplLicense -Sha256 $sha -Properties @($properties.ToArray()))
}

# Payload metadata artifacts exist only in a built payload.
if ($ArtifactMode) {
    $payloadMetadata = @(
        @{ Relative = 'manifest.json'; Name = 'Signed payload manifest'; Description = 'sha256/bytes manifest generated by Build-VgtPayload.ps1'; Optional = $false },
        @{ Relative = 'vgt-payload.cat'; Name = 'Signed payload catalog'; Description = 'Authenticode-signed catalog of the release payload'; Optional = $false },
        @{ Relative = 'vgt-release.cer'; Name = 'VGT release signing certificate (public)'; Description = 'Public self-signed release certificate distributed with the payload; trust anchoring is an external blocker'; Optional = $false },
        @{ Relative = 'bin/geoip.csv.sha256'; Name = 'Bundled GeoIP dataset SHA-256 sidecar'; Description = 'SHA-256 sidecar for the optional GeoIP/ASN dataset'; Optional = $true }
    )
    foreach ($artifact in $payloadMetadata) {
        $payloadHash = Get-VgtPayloadHash -RelativePath $artifact.Relative
        if ($null -eq $payloadHash) {
            if ($artifact.Optional) { continue }
            throw [IO.FileNotFoundException]::new(('Payload metadata artifact is missing: {0}' -f $artifact.Relative))
        }
        Add-VgtComponent -Component (New-VgtComponent -Type 'file' -BomRef ('file:vgt-gedefense/payload/{0}' -f $artifact.Relative) -Name $artifact.Name -Version $version -Group 'VisionGaiaTechnology' -Supplier 'VisionGaia Technology' -Licenses $agplLicense -Sha256 $payloadHash.Sha256 -Properties @(
            (New-VgtProperty -Name 'vgt:component-class' -Value 'payload-metadata'),
            (New-VgtProperty -Name 'vgt:payload-path' -Value $artifact.Relative),
            (New-VgtProperty -Name 'vgt:payload-sha256' -Value $payloadHash.Sha256),
            (New-VgtProperty -Name 'vgt:payload-bytes' -Value ([string]$payloadHash.Length)),
            (New-VgtProperty -Name 'vgt:description' -Value $artifact.Description)
        ))
    }
    # Defensive completeness: any payload file without a mapped component is
    # still represented, but the validator flags it as unmapped.
    $mappedPayloadPaths = @{}
    foreach ($component in $componentsByRef.Values) {
        foreach ($property in @($component.properties)) {
            if ($property.name -eq 'vgt:payload-path') { $mappedPayloadPaths[[string]$property.value] = $true }
        }
    }
    $keys = [string[]]@($payloadFiles.Keys)
    [Array]::Sort($keys,[StringComparer]::Ordinal)
    foreach ($relative in $keys) {
        if ($mappedPayloadPaths.ContainsKey($relative)) { continue }
        $payloadHash = $payloadFiles[$relative]
        Add-VgtComponent -Component (New-VgtComponent -Type 'file' -BomRef ('file:vgt-gedefense/payload/{0}' -f $relative) -Name ('payload file: {0}' -f $relative) -Version $version -Group 'VisionGaiaTechnology' -Supplier 'VisionGaia Technology' -Licenses $agplLicense -Sha256 $payloadHash.Sha256 -Properties @(
            (New-VgtProperty -Name 'vgt:component-class' -Value 'payload-artifact'),
            (New-VgtProperty -Name 'vgt:payload-path' -Value $relative),
            (New-VgtProperty -Name 'vgt:payload-sha256' -Value $payloadHash.Sha256),
            (New-VgtProperty -Name 'vgt:payload-unmapped' -Value 'true')
        ))
    }
}

# ---------------------------------------------------------------------------
# Deterministic graph, serial number and document
# ---------------------------------------------------------------------------
$componentRefs = [Collections.Generic.List[string]]::new()
foreach ($ref in $componentsByRef.Keys) { $componentRefs.Add([string]$ref) }
$componentRefs.Sort([StringComparer]::Ordinal)
$components = [Collections.Generic.List[object]]::new()
foreach ($ref in $componentRefs) { $components.Add($componentsByRef[$ref]) }

# Source-tree digest excluding the SBOM output file itself (see above). The
# canonical checked-in path is always excluded, independent of OutputPath, so
# generating to a temporary file yields byte-identical content.
$canonicalSbomRelative = 'sbom/gedefense-windows.cdx.json'
$digestLines = [Collections.Generic.List[string]]::new()
$digestFileCount = 0
foreach ($file in $projectFiles) {
    if ($file.Relative -eq $canonicalSbomRelative) { continue }
    if ($sbomOutputRelative -and $file.Relative -eq $sbomOutputRelative) { continue }
    $digestLines.Add(('{0}  {1}' -f $file.Sha256,$file.Relative))
    $digestFileCount++
}
$digestPayload = ($digestLines -join "`n") + "`n"
$digestSha = [Security.Cryptography.SHA256]::Create()
try { $digestBytes = $digestSha.ComputeHash([Text.Encoding]::UTF8.GetBytes($digestPayload)) } finally { $digestSha.Dispose() }
$sourceTree = [pscustomobject][ordered]@{
    Digest = ([BitConverter]::ToString($digestBytes)).Replace('-','').ToLowerInvariant()
    FileCount = $digestFileCount
}
$serialSeed = ('{0}|{1}|{2}' -f $version,$sourceTree.Digest,($componentRefs -join ','))
$serialNumber = 'urn:uuid:' + (Get-VgtStableUuid -Seed $serialSeed)

$appProperties = [Collections.Generic.List[object]]::new()
$appProperties.Add((New-VgtProperty -Name 'vgt:scope' -Value 'Windows application, first-party PowerShell automation, bundled third-party data, toolchain/runtime inputs and payload artifacts.'))
$appProperties.Add((New-VgtProperty -Name 'vgt:source-tree-digest' -Value $sourceTree.Digest))
$appProperties.Add((New-VgtProperty -Name 'vgt:source-tree-files' -Value ([string]$sourceTree.FileCount)))
$appProperties.Add((New-VgtProperty -Name 'vgt:source-date-epoch' -Value ([string]$SourceDateEpoch)))
$appProperties.Add((New-VgtProperty -Name 'vgt:timestamp-source' -Value ('{0} ({1})' -f $epochSource,$epochDate)))
$appProperties.Add((New-VgtProperty -Name 'vgt:generator' -Value 'tools/New-VgtSbom.ps1'))
$appProperties.Add((New-VgtProperty -Name 'vgt:mode' -Value $(if ($ArtifactMode) { 'artifact' } else { 'source' })))
$appProperties.Add((New-VgtProperty -Name 'vgt:external-blockers' -Value 'Publicly trusted code-signing CA, RFC3161 timestamp, revocation (CRL/OCSP) and an externally anchored anti-rollback channel are unavailable in this delivery; they are tracked as external blockers, not silently omitted.'))
$appProperties.Add((New-VgtProperty -Name 'vgt:not-a-vulnerability-scan' -Value 'SBOM inventory only; govulncheck -mode=binary is the vulnerability gate.'))

$appComponent = [ordered]@{
    type = 'application'
    'bom-ref' = $appRef
    group = 'VisionGaiaTechnology'
    name = 'GeDefense-Windows'
    version = $version
    licenses = $agplLicense
    purl = $appRef
    properties = @($appProperties.ToArray())
}

$dependencies = [Collections.Generic.List[object]]::new()
$dependencies.Add([ordered]@{ ref = $appRef; dependsOn = @($componentRefs.ToArray()) })
foreach ($ref in $componentRefs) { $dependencies.Add([ordered]@{ ref = $ref; dependsOn = @() }) }

$generatorPath = Join-Path $PSScriptRoot 'New-VgtSbom.ps1'
$document = [ordered]@{
    bomFormat = 'CycloneDX'
    specVersion = '1.5'
    serialNumber = $serialNumber
    version = 1
    metadata = [ordered]@{
        timestamp = $timestamp
        tools = [ordered]@{
            components = @(
                [ordered]@{
                    type = 'application'
                    name = 'VGT-VgtSbomGenerator'
                    version = '1.0.0'
                    supplier = [ordered]@{ name = 'VisionGaia Technology' }
                    hashes = @([ordered]@{ alg = 'SHA-256'; content = (Get-VgtSha256 -Path $generatorPath) })
                }
            )
        }
        component = $appComponent
    }
    components = @($components.ToArray())
    dependencies = @($dependencies.ToArray())
}

$outputDirectory = [IO.Path]::GetDirectoryName($outputFull)
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null }
Write-VgtDeterministicJson -Object $document -Path $outputFull

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = $(if ($ArtifactMode) { 'artifact' } else { 'source' })
    Version = $version
    Components = $components.Count
    PayloadFiles = $payloadFiles.Count
    SourceTreeFiles = $sourceTree.FileCount
    SourceTreeDigest = $sourceTree.Digest
    SerialNumber = $serialNumber
    OutputPath = $outputFull
    Timestamp = $timestamp
}
