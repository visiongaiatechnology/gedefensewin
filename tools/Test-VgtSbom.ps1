# STATUS: DIAMANT VGT SUPREME
# Validator for sbom/gedefense-windows.cdx.json (SC-FIND-004).
#
# Fails closed when the SBOM is empty, structurally invalid, missing required
# component classes (application, third-party library/dataset, toolchain,
# runtime, first-party assets/binaries) or when any recorded SHA-256 no longer
# matches the working tree / built payload. This is the regression gate against
# the former "components: []" stub.
[CmdletBinding()]
param(
    [string]$Path = '',
    [string]$ProjectRoot = '',
    [switch]$ArtifactMode,
    [string]$PayloadRoot = '',
    [switch]$SkipSourceHashVerification
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Join-Path $ProjectRoot 'sbom\gedefense-windows.cdx.json' }
$Path = [IO.Path]::GetFullPath($Path)
Import-Module -Name (Join-Path $PSScriptRoot 'VgtSupplyChain.psm1') -Force

$checks = [Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('SBOM validation failed: {0} ({1})' -f $Name,$Detail)) }
}

function Get-VgtJsonProperty {
    param($Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-VgtJsonPropertyArray {
    param($Object,[Parameter(Mandatory)][string]$Name)
    $value = Get-VgtJsonProperty -Object $Object -Name $Name
    if ($null -eq $value) { return @() }
    return @($value)
}

function Get-VgtComponentPropertyValue {
    param($Component,[Parameter(Mandatory)][string]$Name)
    foreach ($property in (Get-VgtJsonPropertyArray -Object $Component -Name 'properties')) {
        if ([string](Get-VgtJsonProperty -Object $property -Name 'name') -eq $Name) { return [string](Get-VgtJsonProperty -Object $property -Name 'value') }
    }
    return $null
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('SBOM is missing: {0}' -f $Path)) }
$raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
$document = $raw | ConvertFrom-Json
$version = Read-VgtVersion -ProjectRoot $ProjectRoot

Add-Check -Name 'bom-format-cyclonedx' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'bomFormat') -eq 'CycloneDX')
Add-Check -Name 'spec-version-1.5' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'specVersion') -eq '1.5')
Add-Check -Name 'serial-number-uuid' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'serialNumber') -match '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
Add-Check -Name 'document-version' -Passed ([string](Get-VgtJsonProperty -Object $document -Name 'version') -eq '1')
$metadata = Get-VgtJsonProperty -Object $document -Name 'metadata'
Add-Check -Name 'metadata-timestamp' -Passed ([string](Get-VgtJsonProperty -Object $metadata -Name 'timestamp') -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
$tools = Get-VgtJsonProperty -Object $metadata -Name 'tools'
Add-Check -Name 'metadata-tools-present' -Passed (@(Get-VgtJsonPropertyArray -Object $tools -Name 'components').Count -ge 1)
$appComponent = Get-VgtJsonProperty -Object $metadata -Name 'component'
Add-Check -Name 'application-component-present' -Passed ($null -ne $appComponent -and [string](Get-VgtJsonProperty -Object $appComponent -Name 'type') -eq 'application')
$appVersion = [string](Get-VgtJsonProperty -Object $appComponent -Name 'version')
Add-Check -Name 'application-version-matches' -Passed ($appVersion -eq $version) -Detail ('sbom={0} VERSION={1}' -f $appVersion,$version)
$appRef = [string](Get-VgtJsonProperty -Object $appComponent -Name 'bom-ref')
Add-Check -Name 'application-bom-ref' -Passed ($appRef.StartsWith('pkg:github/visiongaiatechnology/gedefensewin@',[StringComparison]::Ordinal))

# SC-FIND-005: the SBOM binds the source tree it was generated from. Recompute
# the same digest the generator writes (canonical SBOM file and the output file
# itself excluded) so a generated or checked-in SBOM that no longer matches the
# working tree fails closed instead of silently describing stale sources.
$recordedSourceTreeDigest = ([string](Get-VgtComponentPropertyValue -Component $appComponent -Name 'vgt:source-tree-digest')).ToLowerInvariant()
$recordedSourceTreeFiles = [string](Get-VgtComponentPropertyValue -Component $appComponent -Name 'vgt:source-tree-files')
Add-Check -Name 'source-tree-digest-recorded' -Passed ($recordedSourceTreeDigest -match '^[0-9a-f]{64}$') -Detail $recordedSourceTreeDigest
Add-Check -Name 'source-tree-file-count-recorded' -Passed ($recordedSourceTreeFiles -match '^[0-9]+$') -Detail $recordedSourceTreeFiles
$canonicalSbomRelative = 'sbom/gedefense-windows.cdx.json'
$outputRelative = ''
try { $outputRelative = Get-VgtRelativePath -FullName $Path -ProjectRoot $ProjectRoot } catch { $outputRelative = '' }
$expectedDigestLines = [Collections.Generic.List[string]]::new()
$expectedDigestFileCount = 0
foreach ($sourceFile in @(Get-VgtSourceSnapshot -ProjectRoot $ProjectRoot)) {
    if ($sourceFile.Relative -eq $canonicalSbomRelative) { continue }
    if ($outputRelative -and $sourceFile.Relative -eq $outputRelative) { continue }
    $expectedDigestLines.Add(('{0}  {1}' -f $sourceFile.Sha256,$sourceFile.Relative))
    $expectedDigestFileCount++
}
$expectedDigestPayload = ($expectedDigestLines -join "`n") + "`n"
$expectedDigestSha = [Security.Cryptography.SHA256]::Create()
try { $expectedDigestBytes = $expectedDigestSha.ComputeHash([Text.Encoding]::UTF8.GetBytes($expectedDigestPayload)) } finally { $expectedDigestSha.Dispose() }
$expectedSourceTreeDigest = ([BitConverter]::ToString($expectedDigestBytes)).Replace('-','').ToLowerInvariant()
Add-Check -Name 'source-tree-digest-matches-working-tree' -Passed ($recordedSourceTreeDigest -eq $expectedSourceTreeDigest) -Detail ('recorded={0} actual={1}' -f $recordedSourceTreeDigest,$expectedSourceTreeDigest)
Add-Check -Name 'source-tree-file-count-matches' -Passed ([int]$recordedSourceTreeFiles -eq $expectedDigestFileCount) -Detail ('recorded={0} actual={1}' -f $recordedSourceTreeFiles,$expectedDigestFileCount)
$externalBlockerStatement = [string](Get-VgtComponentPropertyValue -Component $appComponent -Name 'vgt:external-blockers')
Add-Check -Name 'external-blockers-documented' -Passed ($externalBlockerStatement -match '(?i)CA' -and $externalBlockerStatement -match '(?i)timestamp' -and $externalBlockerStatement -match '(?i)revocation' -and $externalBlockerStatement -match '(?i)anti-rollback') -Detail 'The SBOM must state the external trust-anchor blockers instead of implying completeness.'

$components = Get-VgtJsonPropertyArray -Object $document -Name 'components'
Add-Check -Name 'components-not-empty' -Passed ($components.Count -ge 30) -Detail ('count={0} (expected >= 30 real components)' -f $components.Count)

$allowedTypes = @('application','library','framework','file','data','operating-system','device','container','firmware','platform')
$refs = @{}
$classCounts = @{}
$sourcePathHashes = 0
foreach ($component in $components) {
    $ref = [string](Get-VgtJsonProperty -Object $component -Name 'bom-ref')
    $componentName = [string](Get-VgtJsonProperty -Object $component -Name 'name')
    Add-Check -Name ('component-ref-present-' + $componentName) -Passed (-not [string]::IsNullOrWhiteSpace($ref))
    if ($refs.ContainsKey($ref)) { throw [InvalidOperationException]::new(('Duplicate component bom-ref: {0}' -f $ref)) }
    $refs[$ref] = $true
    $componentType = [string](Get-VgtJsonProperty -Object $component -Name 'type')
    Add-Check -Name ('component-type-' + $ref) -Passed ($allowedTypes -contains $componentType) -Detail $componentType
    Add-Check -Name ('component-name-' + $ref) -Passed (-not [string]::IsNullOrWhiteSpace($componentName))
    $componentVersion = [string](Get-VgtJsonProperty -Object $component -Name 'version')
    Add-Check -Name ('component-version-' + $ref) -Passed (-not [string]::IsNullOrWhiteSpace($componentVersion))
    $classValue = [string](Get-VgtComponentPropertyValue -Component $component -Name 'vgt:component-class')
    Add-Check -Name ('component-class-' + $ref) -Passed (-not [string]::IsNullOrWhiteSpace($classValue))
    if (-not $classCounts.ContainsKey($classValue)) { $classCounts[$classValue] = 0 }
    $classCounts[$classValue] = [int]$classCounts[$classValue] + 1

    Add-Check -Name ('component-license-' + $ref) -Passed (@(Get-VgtJsonPropertyArray -Object $component -Name 'licenses').Count -ge 1)
    $recordedHashes = Get-VgtJsonPropertyArray -Object $component -Name 'hashes'
    foreach ($hash in $recordedHashes) {
        Add-Check -Name ('component-hash-alg-' + $ref) -Passed ([string](Get-VgtJsonProperty -Object $hash -Name 'alg') -eq 'SHA-256') -Detail ([string](Get-VgtJsonProperty -Object $hash -Name 'alg'))
        Add-Check -Name ('component-hash-value-' + $ref) -Passed ([string](Get-VgtJsonProperty -Object $hash -Name 'content') -match '^[0-9a-f]{64}$') -Detail ([string](Get-VgtJsonProperty -Object $hash -Name 'content'))
    }

    # Verify recorded working-tree hashes for components bound to a source file.
    $sourceRelative = Get-VgtComponentPropertyValue -Component $component -Name 'vgt:source-path'
    if ($sourceRelative) {
        if (-not $SkipSourceHashVerification) {
            $sourcePath = Join-Path $ProjectRoot ($sourceRelative.Replace('/',[IO.Path]::DirectorySeparatorChar))
            Add-Check -Name ('source-present-' + $sourceRelative) -Passed (Test-Path -LiteralPath $sourcePath -PathType Leaf)
            $recordedHash = ''
            foreach ($hash in $recordedHashes) { $recordedHash = ([string](Get-VgtJsonProperty -Object $hash -Name 'content')).ToLowerInvariant(); break }
            Add-Check -Name ('source-hash-present-' + $sourceRelative) -Passed ($recordedHash -match '^[0-9a-f]{64}$')
            $actualHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
            Add-Check -Name ('source-hash-match-' + $sourceRelative) -Passed ($actualHash -eq $recordedHash) -Detail ('recorded={0} actual={1}' -f $recordedHash,$actualHash)
        }
        $sourcePathHashes++
    }
}

$requiredClasses = @('third-party-library','third-party-dataset','toolchain','runtime','first-party-source','first-party-binary','license-text','branding-asset')
foreach ($requiredClass in $requiredClasses) {
    $countValue = 0
    if ($classCounts.ContainsKey($requiredClass)) { $countValue = [int]$classCounts[$requiredClass] }
    Add-Check -Name ('required-class-' + $requiredClass) -Passed ($countValue -ge 1) -Detail ('count={0}' -f $countValue)
}

$dependencies = Get-VgtJsonPropertyArray -Object $document -Name 'dependencies'
Add-Check -Name 'dependencies-present' -Passed ($dependencies.Count -ge 2)
$appDependency = $null
foreach ($dependency in $dependencies) {
    $dependencyRef = [string](Get-VgtJsonProperty -Object $dependency -Name 'ref')
    Add-Check -Name ('dependency-target-' + $dependencyRef) -Passed (($null -ne $dependencyRef) -and $dependencyRef.Length -gt 0)
    if ($dependencyRef -eq $appRef) { $appDependency = $dependency }
}
Add-Check -Name 'application-dependency-node' -Passed ($null -ne $appDependency)
$dependsOn = Get-VgtJsonPropertyArray -Object $appDependency -Name 'dependsOn'
Add-Check -Name 'application-depends-on-all' -Passed ($dependsOn.Count -eq $components.Count) -Detail ('dependsOn={0} components={1}' -f $dependsOn.Count,$components.Count)
foreach ($depRef in $dependsOn) {
    Add-Check -Name ('dependency-resolves-' + [string]$depRef) -Passed ($refs.ContainsKey([string]$depRef))
}

# Artifact mode: every payload file must be mapped and hash-verified.
$payloadFileCount = 0
if ($ArtifactMode) {
    if ([string]::IsNullOrWhiteSpace($PayloadRoot)) { $PayloadRoot = Join-Path $ProjectRoot 'payload\VGT\GeDefense' }
    $payloadRootFull = [IO.Path]::GetFullPath($PayloadRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $payloadRootFull 'manifest.json') -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Payload manifest is missing for artifact SBOM validation.') }
    $payloadVersion = (Get-Content -LiteralPath (Join-Path $payloadRootFull 'VERSION') -Raw -Encoding UTF8).Trim()
    Add-Check -Name 'payload-version-matches' -Passed ($payloadVersion -eq $version) -Detail ('payload={0} VERSION={1}' -f $payloadVersion,$version)
    $payloadFiles = @{}
    foreach ($payloadFile in @(Get-ChildItem -LiteralPath $payloadRootFull -Recurse -File -Force)) {
        $relative = Get-VgtRelativePath -FullName $payloadFile.FullName -ProjectRoot $payloadRootFull
        $payloadFiles[$relative] = (Get-FileHash -LiteralPath $payloadFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $payloadFileCount = $payloadFiles.Count
    $mapped = @{}
    foreach ($component in $components) {
        $componentPayloadPath = [string](Get-VgtComponentPropertyValue -Component $component -Name 'vgt:payload-path')
        $componentPayloadHash = ([string](Get-VgtComponentPropertyValue -Component $component -Name 'vgt:payload-sha256')).ToLowerInvariant()
        $unmappedFlag = Get-VgtComponentPropertyValue -Component $component -Name 'vgt:payload-unmapped'
        if ($unmappedFlag) { throw [InvalidOperationException]::new(('Payload file has no explicit component mapping in the artifact SBOM: {0}' -f [string](Get-VgtJsonProperty -Object $component -Name 'name'))) }
        if ([string]::IsNullOrWhiteSpace($componentPayloadPath)) { continue }
        Add-Check -Name ('payload-file-mapped-' + $componentPayloadPath) -Passed ($payloadFiles.ContainsKey($componentPayloadPath))
        Add-Check -Name ('payload-hash-recorded-' + $componentPayloadPath) -Passed ($componentPayloadHash -match '^[0-9a-f]{64}$')
        $actualPayloadHash = [string]$payloadFiles[$componentPayloadPath]
        Add-Check -Name ('payload-hash-match-' + $componentPayloadPath) -Passed ($actualPayloadHash -eq $componentPayloadHash)
        $mapped[$componentPayloadPath] = $true
    }
    foreach ($payloadRelative in $payloadFiles.Keys) {
        Add-Check -Name ('payload-covered-' + $payloadRelative) -Passed ($mapped.ContainsKey([string]$payloadRelative))
    }
    Add-Check -Name 'payload-inventory-non-empty' -Passed ($payloadFileCount -ge 30) -Detail ('files={0}' -f $payloadFileCount)
}

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = $(if ($ArtifactMode) { 'artifact' } else { 'source' })
    Path = $Path
    Version = $version
    Components = $components.Count
    SourceHashChecks = $sourcePathHashes
    PayloadFiles = $payloadFileCount
    Checks = $checks.Count
    SourceTreeDigest = $expectedSourceTreeDigest
    ExternalBlockers = 'documented'
    ClassCounts = $classCounts
}
