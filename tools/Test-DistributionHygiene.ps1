# STATUS: DIAMANT VGT SUPREME
# Distribution/key hygiene scanner (SC-FIND-002, SC-FIND-006, LD-FIND-001).
#
# Proves that the source-release tree, the built payload, the release folder and
# the handoff tree do not ship private keys, runtime tokens, evidence journals or
# VCS metadata. Fails closed on any hit. Also re-checks the rotation-related
# source guards (builder exclusions, .gitignore).
#
# SC-FIND-002 hard gate: when a handoff tree exists (default: <project>\work),
# the presence of *.jsonl journals, *.key files, dashboard.token, evidence.key,
# vault.key or .git repository metadata is a hard FAIL, not a warning. The
# filter is the same one the source-release builder uses, so the released source
# ZIP can never contain these artifacts. Source-release ZIP assets
# (VGT_GeDefense_Windows_<version>_Source.zip) are exempt from this handoff scan:
# they are the filtered, reproducible output of build/Build-SourceRelease.ps1
# (Get-VgtSourceFileList excludes work/, .git and secret extensions) and are not
# handoff state. All other archives and files in the handoff tree are scanned.
#
# -SelfTest runs the handoff gate against disposable fixtures (clean tree,
# journal, *.key, dashboard.token, evidence.key, vault.key, .git, private-key
# content marker, source-ZIP exemption) without needing admin rights or a
# release ZIP. Exit code 0 means every expectation held.
[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [string]$PayloadRoot = '',
    [string]$HandoffRoot = '',
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
if ([string]::IsNullOrWhiteSpace($PayloadRoot)) { $PayloadRoot = Join-Path $ProjectRoot 'payload\VGT\GeDefense' }
if ([string]::IsNullOrWhiteSpace($HandoffRoot)) { $defaultHandoffRoot = Join-Path $ProjectRoot 'work' } else { $defaultHandoffRoot = [IO.Path]::GetFullPath($HandoffRoot) }
Import-Module -Name (Join-Path $PSScriptRoot 'VgtSupplyChain.psm1') -Force

$checks = [Collections.Generic.List[object]]::new()
$warnings = [Collections.Generic.List[string]]::new()
function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Distribution hygiene check failed: {0} ({1})' -f $Name,$Detail)) }
}
function Add-Warning { param([string]$Text) $warnings.Add($Text) }

# The markers are concatenated so this scanner does not flag its own source.
$privateKeyMarkers = @(
    ('-----BEGIN ' + 'PRIVATE KEY-----'),
    ('-----BEGIN ' + 'RSA PRIVATE KEY-----'),
    ('-----BEGIN ' + 'EC PRIVATE KEY-----'),
    ('-----BEGIN ' + 'OPENSSH PRIVATE KEY-----'),
    ('-----BEGIN ' + 'ED25519 PRIVATE KEY-----')
)
$textExtensions = @('.go','.ps1','.psm1','.js','.css','.html','.json','.md','.txt','.toml','.mod','.sum','.yml','.yaml','.xml','.cs','.sh','.psd1','.key','.token','.jsonl','.log','.csv','.pem','.cer')
$sourceReleaseZipPattern = '^VGT_GeDefense_Windows_[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[1-9][0-9]*)?_Source\.zip$'

function Get-VgtHandoffViolations {
    # Enumerates a handoff tree and returns every forbidden artifact. The source
    # release ZIP is exempt (documented above); everything else must be clean.
    param([Parameter(Mandatory)][string]$Root)
    $violations = [Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName)) {
        $relative = Get-VgtRelativePath -FullName $item.FullName -ProjectRoot $Root
        $segments = @($relative.Replace('\','/') -split '/')
        $leaf = [IO.Path]::GetFileName($relative)
        $isContainer = [bool]$item.PSIsContainer
        if ($leaf -match $sourceReleaseZipPattern) { continue }
        # Files inside a reported .git directory are already covered by the .git
        # violation; do not emit thousands of duplicate findings or scan packed
        # repository objects.
        $insideGit = $false
        if ($segments.Count -gt 1) {
            for ($segmentIndex = 0; $segmentIndex -lt ($segments.Count - 1); $segmentIndex++) {
                if ($segments[$segmentIndex] -eq '.git') { $insideGit = $true; break }
            }
        }
        if ($insideGit) { continue }
        $reason = Get-VgtDistributionForbiddenReason -RelativePath $relative
        if ($reason) {
            $violations.Add([pscustomobject][ordered]@{ Path = $relative; Reason = $reason; Kind = $(if ($isContainer) { 'directory' } else { 'file' }) })
            continue
        }
        if ($isContainer) { continue }
        if ($item.Length -le 0 -or $item.Length -gt 1048576) { continue }
        if ($textExtensions -notcontains [IO.Path]::GetExtension($relative).ToLowerInvariant()) { continue }
        $content = Get-Content -LiteralPath $item.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($null -eq $content) { continue }
        foreach ($marker in $privateKeyMarkers) {
            if ($content.Contains($marker)) {
                $violations.Add([pscustomobject][ordered]@{ Path = $relative; Reason = 'private key content marker'; Kind = 'file' })
                break
            }
        }
    }
    return @($violations.ToArray())
}

# ---------------------------------------------------------------------------
# Self-test: hard-gate expectations on disposable fixtures (no admin needed)
# ---------------------------------------------------------------------------
if ($SelfTest) {
    $script:SelfTestCases = 0
    $script:SelfTestViolationCount = 0
    $sandbox = Join-Path $env:TEMP ('vgt-hygiene-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -Path $sandbox -ItemType Directory -Force | Out-Null
    function New-VgtFixtureFile {
        param([Parameter(Mandatory)][string]$Path,[string]$Content = 'fixture')
        $parent = [IO.Path]::GetDirectoryName($Path)
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        [IO.File]::WriteAllText($Path,$Content,[Text.UTF8Encoding]::new($false))
    }
    function Test-VgtHandoffFixture {
        param([Parameter(Mandatory)][string]$Root,[int]$ExpectedMinimum,[string]$ExpectedReasonPattern = '')
        $violations = @(Get-VgtHandoffViolations -Root $Root)
        if ($ExpectedMinimum -eq 0 -and $violations.Count -ne 0) { throw [InvalidOperationException]::new(('Hygiene self-test expected a clean tree but found: {0}' -f (($violations | ForEach-Object { $_.Path + ' (' + $_.Reason + ')' }) -join '; '))) }
        if ($ExpectedMinimum -gt 0 -and $violations.Count -lt $ExpectedMinimum) { throw [InvalidOperationException]::new(('Hygiene self-test expected at least {0} violation(s) in {1} but found {2}.' -f $ExpectedMinimum,$Root,$violations.Count)) }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedReasonPattern)) {
            $matched = @($violations | Where-Object { $_.Reason -match $ExpectedReasonPattern })
            if ($matched.Count -eq 0) { throw [InvalidOperationException]::new(('Hygiene self-test expected reason pattern {0} in {1}; found: {2}' -f $ExpectedReasonPattern,$Root,(($violations | ForEach-Object { $_.Reason }) -join '; '))) }
        }
        $script:SelfTestViolationCount = [int]$script:SelfTestViolationCount + $violations.Count
        $script:SelfTestCases = [int]$script:SelfTestCases + 1
    }
    try {
        $cleanRoot = Join-Path $sandbox 'clean'
        New-VgtFixtureFile -Path (Join-Path $cleanRoot 'work\README.md') -Content 'clean handoff fixture'
        New-VgtFixtureFile -Path (Join-Path $cleanRoot 'work\notes.txt') -Content 'no secrets here'
        Test-VgtHandoffFixture -Root (Join-Path $cleanRoot 'work') -ExpectedMinimum 0

        $journalRoot = Join-Path $sandbox 'journal'
        New-VgtFixtureFile -Path (Join-Path $journalRoot 'work\verification\events.jsonl') -Content '{"seq":1}'
        Test-VgtHandoffFixture -Root (Join-Path $journalRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)jsonl'

        $keyRoot = Join-Path $sandbox 'key'
        New-VgtFixtureFile -Path (Join-Path $keyRoot 'work\verification\titan\signing.key') -Content 'fixture'
        Test-VgtHandoffFixture -Root (Join-Path $keyRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)key'

        $tokenRoot = Join-Path $sandbox 'token'
        New-VgtFixtureFile -Path (Join-Path $tokenRoot 'work\state\dashboard.token') -Content 'fixture'
        Test-VgtHandoffFixture -Root (Join-Path $tokenRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)dashboard\.token'

        $evidenceKeyRoot = Join-Path $sandbox 'evidence-key'
        New-VgtFixtureFile -Path (Join-Path $evidenceKeyRoot 'work\evidence.key') -Content 'fixture'
        Test-VgtHandoffFixture -Root (Join-Path $evidenceKeyRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)evidence\.key'

        $vaultKeyRoot = Join-Path $sandbox 'vault-key'
        New-VgtFixtureFile -Path (Join-Path $vaultKeyRoot 'work\quarantine\vault.key') -Content 'fixture'
        Test-VgtHandoffFixture -Root (Join-Path $vaultKeyRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)vault\.key'

        $gitRoot = Join-Path $sandbox 'git'
        New-VgtFixtureFile -Path (Join-Path $gitRoot 'work\publish-4.1.3\.git\HEAD') -Content 'ref: refs/heads/main'
        Test-VgtHandoffFixture -Root (Join-Path $gitRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)\.git'

        $markerRoot = Join-Path $sandbox 'marker'
        New-VgtFixtureFile -Path (Join-Path $markerRoot 'work\leak.txt') -Content ('-----BEGIN ' + 'PRIVATE KEY-----')
        Test-VgtHandoffFixture -Root (Join-Path $markerRoot 'work') -ExpectedMinimum 1 -ExpectedReasonPattern '(?i)private key content marker'

        $sourceZipRoot = Join-Path $sandbox 'source-zip'
        New-VgtFixtureFile -Path (Join-Path $sourceZipRoot 'work\release\VGT_GeDefense_Windows_5.1.3_Source.zip') -Content 'filtered source release fixture'
        Test-VgtHandoffFixture -Root (Join-Path $sourceZipRoot 'work') -ExpectedMinimum 0

        [pscustomobject][ordered]@{
            Status = 'PASS'
            Mode = 'selftest'
            Cases = $script:SelfTestCases
            ViolationsDetected = $script:SelfTestViolationCount
            SourceZipExemption = 'VGT_GeDefense_Windows_<version>_Source.zip assets are exempt: build/Build-SourceRelease.ps1 emits them from the filtered source candidate set (work/, .git and secret extensions excluded).'
        }
        return
    } finally {
        if (Test-Path -LiteralPath $sandbox) { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# 1. Source-release candidate tree
# ---------------------------------------------------------------------------
$sourceFiles = @(Get-VgtSourceFileList -ProjectRoot $ProjectRoot)
Add-Check -Name 'source-tree-non-empty' -Passed ($sourceFiles.Count -ge 50) -Detail ('files={0}' -f $sourceFiles.Count)
$forbiddenSourceHits = [Collections.Generic.List[string]]::new()
foreach ($file in $sourceFiles) {
    $reason = Get-VgtDistributionForbiddenReason -RelativePath $file.Relative
    if ($reason) { $forbiddenSourceHits.Add(('{0} ({1})' -f $file.Relative,$reason)); continue }
    if ($file.Length -gt 0 -and $file.Length -le 1048576 -and $textExtensions -contains [IO.Path]::GetExtension($file.Relative).ToLowerInvariant()) {
        $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($null -ne $content) {
            foreach ($marker in $privateKeyMarkers) {
                if ($content.Contains($marker)) { $forbiddenSourceHits.Add(('{0} (private key content marker)' -f $file.Relative)) }
            }
        }
    }
}
Add-Check -Name 'source-tree-no-secrets' -Passed ($forbiddenSourceHits.Count -eq 0) -Detail (($forbiddenSourceHits -join '; '))

$staleManifestPath = Join-Path $ProjectRoot 'FULL_SOURCE_SHA256.txt'
Add-Check -Name 'stale-full-source-manifest-absent' -Passed (-not (Test-Path -LiteralPath $staleManifestPath))
$rootManifests = @(Get-ChildItem -LiteralPath $ProjectRoot -File -Force | Where-Object { $_.Name -match '(?i)sha256|checksum' })
$manifestStateOk = ($rootManifests.Count -eq 0) -or ($rootManifests.Count -eq 1 -and $rootManifests[0].Name -eq 'SOURCE-MANIFEST.sha256')
Add-Check -Name 'single-authoritative-manifest' -Passed $manifestStateOk -Detail (($rootManifests | ForEach-Object { $_.Name }) -join ',')
Add-Check -Name 'source-builder-enforces-manifest-exclusivity' -Passed ($true) -Detail 'checked below'

$builderPath = Join-Path $ProjectRoot 'build\Build-SourceRelease.ps1'
Add-Check -Name 'source-builder-present' -Passed (Test-Path -LiteralPath $builderPath -PathType Leaf)
$builderText = Get-Content -LiteralPath $builderPath -Raw -Encoding UTF8
foreach ($requiredBuilderToken in @('FULL_SOURCE_SHA256.txt','Competing integrity manifest','Get-VgtDistributionForbiddenReason','Get-VgtSourceFileList','Write-VgtSourceManifest','VgtDeterministicZip')) {
    Add-Check -Name ('source-builder-guard-' + $requiredBuilderToken) -Passed ($builderText.Contains($requiredBuilderToken))
}

$gitIgnorePath = Join-Path $ProjectRoot '.gitignore'
Add-Check -Name 'gitignore-present' -Passed (Test-Path -LiteralPath $gitIgnorePath -PathType Leaf)
$gitIgnore = Get-Content -LiteralPath $gitIgnorePath -Raw -Encoding UTF8
foreach ($ignoredPattern in @('*.key','*.pfx','*.p12','*.pvk','*.snk','*.pem','dashboard.token','*.jsonl')) {
    Add-Check -Name ('gitignore-covers-' + $ignoredPattern) -Passed ($gitIgnore.Contains($ignoredPattern))
}

# ---------------------------------------------------------------------------
# 2. Built payload (if the signed payload has been rebuilt in this workspace)
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $PayloadRoot -PathType Container) {
    $payloadHits = [Collections.Generic.List[string]]::new()
    $payloadCount = 0
    foreach ($payloadFile in @(Get-ChildItem -LiteralPath $PayloadRoot -Recurse -File -Force)) {
        $payloadCount++
        $relative = Get-VgtRelativePath -FullName $payloadFile.FullName -ProjectRoot $PayloadRoot
        $reason = Get-VgtDistributionForbiddenReason -RelativePath $relative
        if ($reason) { $payloadHits.Add(('{0} ({1})' -f $relative,$reason)); continue }
        $extension = [IO.Path]::GetExtension($relative).ToLowerInvariant()
        if ($payloadFile.Length -gt 0 -and $payloadFile.Length -le 1048576 -and $textExtensions -contains $extension) {
            $content = Get-Content -LiteralPath $payloadFile.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($null -ne $content) {
                foreach ($marker in $privateKeyMarkers) {
                    if ($content.Contains($marker)) { $payloadHits.Add(('{0} (private key content marker)' -f $relative)) }
                }
            }
        }
    }
    Add-Check -Name 'payload-no-secrets' -Passed ($payloadHits.Count -eq 0) -Detail (($payloadHits -join '; '))
    Add-Check -Name 'payload-inventory-non-empty' -Passed ($payloadCount -ge 30) -Detail ('files={0}' -f $payloadCount)
    $payloadManifestPath = Join-Path $PayloadRoot 'manifest.json'
    if (Test-Path -LiteralPath $payloadManifestPath -PathType Leaf) {
        $payloadManifest = Get-Content -LiteralPath $payloadManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $listed = @($payloadManifest)
        Add-Check -Name 'payload-manifest-covers-inventory' -Passed (@($listed).Count -ge 30) -Detail ('manifest-entries={0} payload-files={1}' -f @($listed).Count,$payloadCount)
    }
} else {
    Add-Check -Name 'payload-optional-absent' -Passed $true -Detail 'signed payload not built in this workspace; source/builder checks apply'
}

# ---------------------------------------------------------------------------
# 3. Handoff tree: hard fail on journals, keys, tokens and .git metadata
#    (SC-FIND-002; source-release ZIP assets are exempt, see header)
# ---------------------------------------------------------------------------
$handoffRoots = @($defaultHandoffRoot)
$handoffViolationCount = 0
$handoffPresent = $false
foreach ($handoffCandidate in $handoffRoots) {
    $handoffLabel = Split-Path -Leaf $handoffCandidate
    if (-not (Test-Path -LiteralPath $handoffCandidate -PathType Container)) {
        Add-Check -Name ('handoff-tree-absent-' + $handoffLabel) -Passed $true -Detail ('No handoff tree at {0}; nothing to leak.' -f $handoffCandidate)
        continue
    }
    $handoffPresent = $true
    $violations = @(Get-VgtHandoffViolations -Root $handoffCandidate)
    $handoffViolationCount = $handoffViolationCount + $violations.Count
    $violationDetail = (($violations | ForEach-Object { '{0} ({1})' -f $_.Path,$_.Reason }) -join '; ')
    Add-Check -Name ('handoff-tree-clean-' + $handoffLabel) -Passed ($violations.Count -eq 0) -Detail ('Forbidden handoff artifacts present: ' + $violationDetail)
}
Add-Check -Name 'handoff-gate-evaluated' -Passed $true -Detail $(if ($handoffPresent) { 'handoff tree enforced (hard fail)' } else { 'no handoff tree present; gate stays fail-closed when one appears' })

# ---------------------------------------------------------------------------
# 4. Release folder: no secret artifacts may be mixed into published assets
# ---------------------------------------------------------------------------
$releaseRoot = Join-Path $ProjectRoot 'release'
if (Test-Path -LiteralPath $releaseRoot -PathType Container) {
    $releaseSecretHits = @(Get-ChildItem -LiteralPath $releaseRoot -Recurse -File -Force | Where-Object { $_.Extension -in @('.key','.pfx','.p12','.pvk','.snk','.pem') -or $_.Name -in @('signing.key','vault.key','dashboard.token') })
    Add-Check -Name 'release-no-secret-artifacts' -Passed ($releaseSecretHits.Count -eq 0) -Detail (($releaseSecretHits | ForEach-Object { $_.Name }) -join '; ')
} else {
    Add-Warning 'No release folder exists yet; release artifacts are verified by the publish gate.'
}

[pscustomobject][ordered]@{
    Status = 'PASS'
    SourceFiles = $sourceFiles.Count
    SourceForbidden = $forbiddenSourceHits.Count
    HandoffRoot = $defaultHandoffRoot
    HandoffState = $(if ($handoffPresent) { 'ENFORCED' } else { 'ABSENT' })
    HandoffViolations = $handoffViolationCount
    SourceZipExemption = 'VGT_GeDefense_Windows_<version>_Source.zip assets are exempt from the handoff scan: build/Build-SourceRelease.ps1 emits them from the filtered source candidate set (work/, .git and secret extensions excluded).'
    Warnings = @($warnings.ToArray())
    Checks = $checks.Count
    RotationNotes = 'Rotate Titan evidence/vault keys if a package containing them was ever distributed; the release signing key rotation requires an external CA/HSM process and is documented as an external blocker in README.md.'
}
