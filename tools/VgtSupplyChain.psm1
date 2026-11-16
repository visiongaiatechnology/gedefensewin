# STATUS: DIAMANT VGT SUPREME
# Shared deterministic supply-chain helpers used by the SBOM, provenance,
# source-release builder and the local release gate.
#
# All helpers are intentionally free of network access, signatures and secrets.
# They enumerate the working tree with ordinal ordering and SHA-256 hashing so
# that repeated runs on identical inputs produce identical output.
Set-StrictMode -Version Latest

$script:ForbiddenSourceDirectories = @('.git','release','payload','work','output','dist','certificates')
$script:ForbiddenSourceExtensions = @('.exe','.dll','.sys','.msi','.msix','.zip','.7z','.iso','.wim','.esd','.syso','.pdb','.log','.pfx','.p12','.pvk','.snk','.key','.pem')

# FIND-WIN-022: AI-agent handoff notes are canonical working-tree artifacts (the
# agent workflow writes Next.md and friends), so their mere presence is NOT a
# repository-hygiene violation. They are working state, never distribution
# content: this central exclusion is applied while the source ship set is
# enumerated, which means SOURCE-MANIFEST.sha256, SOURCE-MANIFEST-bound SBOMs,
# the deterministic source ZIP and the provenance source-tree digest can never
# contain them. Keep this list in sync with .gitignore ("Handoff / AI-agent
# artifacts") and with build/Test-GeDefenseRelease.ps1, which asserts that the
# generated source archive is note-free.
$script:ExcludedDistributionNoteNames = @(
    'Next.md',
    'CURRENT_TASK.md',
    'HANDOFF.md',
    'SESSION_NOTES.md',
    'DEVELOPER_NOTES.md',
    'AGENT_NOTES.md',
    'WORKLOG.md',
    'GITHUB-UPLOAD.md',
    'RELEASE-NOTES.md',
    'MERGE_REPORT.json'
)
$script:ExcludedDistributionNotePatterns = @('START_HERE_*.md')

function Get-VgtProjectRoot {
    param([string]$ToolsRoot = '')
    if ([string]::IsNullOrWhiteSpace($ToolsRoot)) { $ToolsRoot = $PSScriptRoot }
    $resolved = [IO.Path]::GetFullPath($ToolsRoot)
    return [IO.Path]::GetFullPath((Join-Path $resolved '..'))
}

function Read-VgtVersion {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path = Join-Path $ProjectRoot 'VERSION'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VERSION is missing.') }
    $value = (Get-Content -LiteralPath $path -Raw -Encoding UTF8).Trim()
    if ($value -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$') { throw [IO.InvalidDataException]::new('VERSION has an invalid format.') }
    return $value
}

function Get-VgtRelativePath {
    param(
        [Parameter(Mandatory)][string]$FullName,
        [Parameter(Mandatory)][string]$ProjectRoot
    )
    $full = [IO.Path]::GetFullPath($FullName)
    $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\') + '\'
    if (-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new(('Path escaped the project root: {0}' -f $FullName))
    }
    return $full.Substring($root.Length).Replace('\','/')
}

function Get-VgtPublishedSourceExclusionReason {
    # Returns a human-readable reason when a working-tree path is agent/handoff
    # state that must never enter any distribution artifact (source manifest,
    # source ZIP, SBOM, provenance), or '' when the path is ordinary content.
    # Unknown files deliberately fall through: this function only removes known
    # agent notes, it never removes arbitrary content.
    param([Parameter(Mandatory)][string]$RelativePath)
    $relative = $RelativePath.Replace('\','/')
    if ([string]::IsNullOrWhiteSpace($relative)) { return '' }
    $leaf = [IO.Path]::GetFileName($relative)
    if ([string]::IsNullOrWhiteSpace($leaf)) { return '' }
    foreach ($excludedName in $script:ExcludedDistributionNoteNames) {
        if ([string]::Equals($leaf,$excludedName,[StringComparison]::OrdinalIgnoreCase)) { return ('AI-agent handoff note: {0}' -f $leaf) }
    }
    foreach ($excludedPattern in $script:ExcludedDistributionNotePatterns) {
        if ($leaf -like $excludedPattern) { return ('AI-agent handoff note pattern {0}: {1}' -f $excludedPattern,$leaf) }
    }
    return ''
}

function Test-VgtSourceCandidate {
    param([Parameter(Mandatory)][string]$RelativePath)
    $relative = $RelativePath.Replace('\','/')
    if ([string]::IsNullOrWhiteSpace($relative)) { return $false }
    # FIND-WIN-022: agent handoff notes may live in the working tree but are
    # never part of the distribution ship set.
    if (Get-VgtPublishedSourceExclusionReason -RelativePath $relative) { return $false }
    $parts = @($relative -split '/')
    if ($parts[0] -in $script:ForbiddenSourceDirectories) { return $false }
    foreach ($forbiddenPart in @('__pycache__','.pytest_cache','node_modules')) {
        if ($parts -contains $forbiddenPart) { return $false }
    }
    $leaf = [IO.Path]::GetFileName($relative)
    if ($leaf -in @('.DS_Store','Thumbs.db')) { return $false }
    if ($relative.StartsWith('src/GeDefense/windows/work/',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($relative.StartsWith('src/GeDefense/windows/cmd/gedefense-installer/bundle/',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($relative -eq 'SOURCE-MANIFEST.sha256') { return $false }
    if ($relative -eq 'FULL_SOURCE_SHA256.txt') { return $false }
    if ($leaf -eq 'release-thumbprint.txt') { return $false }
    $extension = [IO.Path]::GetExtension($relative).ToLowerInvariant()
    if ($script:ForbiddenSourceExtensions -contains $extension) { return $false }
    return $true
}

function Get-VgtSourceFileList {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $root = [IO.Path]::GetFullPath($ProjectRoot)
    $entries = @{}
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Force) {
        $relative = Get-VgtRelativePath -FullName $file.FullName -ProjectRoot $root
        if (Test-VgtSourceCandidate -RelativePath $relative) {
            $entries[$relative] = $file
        }
    }
    # FIND-WIN-022 fail-closed assertion: the central exclusion above must have
    # removed every agent/handoff note. If a future change to the candidate
    # filter lets one through, the ship set aborts instead of leaking notes.
    foreach ($relative in @($entries.Keys)) {
        $exclusionReason = Get-VgtPublishedSourceExclusionReason -RelativePath $relative
        if ($exclusionReason) {
            throw [Security.SecurityException]::new(('Excluded agent/handoff note entered the source distribution set (fail-closed): {0} ({1})' -f $relative,$exclusionReason))
        }
    }
    $keys = [string[]]@($entries.Keys)
    [Array]::Sort($keys,[StringComparer]::Ordinal)
    $result = [Collections.Generic.List[object]]::new()
    foreach ($key in $keys) {
        $file = $entries[$key]
        $result.Add([pscustomobject][ordered]@{
            Relative = $key
            FullName = $file.FullName
            Length = [long]$file.Length
        })
    }
    return @($result.ToArray())
}

function Get-VgtSourceSnapshot {
    # Enumerate and hash the source-release candidate set. Retries a bounded
    # number of times when a concurrently edited file disappears mid-scan so
    # that build-time tooling fails on real errors, not on editor churn.
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $lastError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $files = @(Get-VgtSourceFileList -ProjectRoot $ProjectRoot)
            if ($files.Count -lt 1) { throw [IO.InvalidDataException]::new('Source tree enumeration returned no files.') }
            $result = [Collections.Generic.List[object]]::new()
            foreach ($file in $files) {
                $hash = Get-VgtSha256 -Path $file.FullName
                $result.Add([pscustomobject][ordered]@{
                    Relative = $file.Relative
                    FullName = $file.FullName
                    Length = $file.Length
                    Sha256 = $hash
                })
            }
            return @($result.ToArray())
        } catch [IO.FileNotFoundException] {
            $lastError = $_.Exception
            if ($attempt -lt 3) { Start-Sleep -Milliseconds 250; continue }
            throw
        }
    }
    throw $lastError
}

function Get-VgtSha256 {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('File is missing: {0}' -f $Path)) }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VgtSourceTreeDigest {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $files = @(Get-VgtSourceSnapshot -ProjectRoot $ProjectRoot)
    if ($files.Count -lt 1) { throw [IO.InvalidDataException]::new('Source tree enumeration returned no files.') }
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $lines.Add(('{0}  {1}' -f $file.Sha256,$file.Relative))
    }
    $payload = ($lines -join "`n") + "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digestBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload))
    } finally {
        $sha.Dispose()
    }
    $digest = ([BitConverter]::ToString($digestBytes)).Replace('-','').ToLowerInvariant()
    return [pscustomobject][ordered]@{
        Digest = $digest
        FileCount = $files.Count
        Lines = @($lines.ToArray())
    }
}

function Get-VgtToolchain {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path = Join-Path $ProjectRoot 'TOOLCHAINS.lock'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw [IO.FileNotFoundException]::new('TOOLCHAINS.lock is missing.') }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $parts = $trimmed.Split('=',2)
        if ($parts.Count -ne 2) { throw [IO.InvalidDataException]::new('TOOLCHAINS.lock contains an invalid entry.') }
        $values[$parts[0].Trim()] = $parts[1].Trim()
    }
    if (-not $values.ContainsKey('go')) { throw [IO.InvalidDataException]::new('TOOLCHAINS.lock does not pin the Go toolchain.') }
    return $values
}

function Get-VgtSourceDateEpoch {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $null = Read-VgtVersion -ProjectRoot $ProjectRoot
    # The clean-source repository carries the release timestamp as small,
    # reviewable metadata instead of a historical changelog file. The value is
    # a Unix epoch (UTC midnight of the release day) and is also honoured by
    # SBOM and provenance generation.
    $epochPath = Join-Path $ProjectRoot 'SOURCE_DATE_EPOCH'
    if (Test-Path -LiteralPath $epochPath -PathType Leaf) {
        $raw = (Get-Content -LiteralPath $epochPath -Raw -Encoding UTF8).Trim()
        if ($raw -notmatch '^[0-9]{9,11}$') { throw [IO.InvalidDataException]::new('SOURCE_DATE_EPOCH must contain a Unix epoch in seconds.') }
        $epoch = [long]$raw
        $stamp = [DateTimeOffset]::FromUnixTimeSeconds($epoch)
        return [pscustomobject][ordered]@{
            Epoch = $epoch
            Date = $stamp.ToUniversalTime().ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
            Source = 'metadata-file'
        }
    }
    $changelogPath = Join-Path $ProjectRoot 'CHANGELOG.md'
    if (-not (Test-Path -LiteralPath $changelogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('SOURCE_DATE_EPOCH is missing (and no legacy CHANGELOG.md fallback exists).') }
    $changelog = Get-Content -LiteralPath $changelogPath -Raw -Encoding UTF8
    $version = Read-VgtVersion -ProjectRoot $ProjectRoot
    $escapedVersion = [Regex]::Escape($version)
    $match = [Regex]::Match($changelog,('(?m)^## \[{0}\] - (?<date>\d{{4}}-\d{{2}}-\d{{2}})$' -f $escapedVersion))
    $source = 'changelog-version'
    if (-not $match.Success) {
        $match = [Regex]::Match($changelog,'(?m)^## \[[0-9]+\.[0-9]+\.[0-9]+[^\]]*\] - (?<date>\d{4}-\d{2}-\d{2})$')
        $source = 'changelog-latest-fallback'
        if (-not $match.Success) { throw [IO.InvalidDataException]::new('Release date could not be derived from SOURCE_DATE_EPOCH or CHANGELOG.md.') }
    }
    $dateText = $match.Groups['date'].Value
    $releaseDate = [DateTime]::ParseExact($dateText,'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
    $epoch = [DateTimeOffset]::new($releaseDate).ToUnixTimeSeconds()
    return [pscustomobject][ordered]@{
        Epoch = [long]$epoch
        Date = $dateText
        Source = $source
    }
}

function Get-VgtStableUuid {
    param([Parameter(Mandatory)][string]$Seed)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed))
    } finally {
        $sha.Dispose()
    }
    $uuidBytes = New-Object byte[] 16
    [Array]::Copy($bytes,$uuidBytes,16)
    $uuidBytes[6] = [byte](($uuidBytes[6] -band 0x0F) -bor 0x50)
    $uuidBytes[8] = [byte](($uuidBytes[8] -band 0x3F) -bor 0x80)
    return ([Guid]::new($uuidBytes)).ToString('D')
}

function Write-VgtDeterministicJson {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Path
    )
    $json = ($Object | ConvertTo-Json -Depth 20)
    [IO.File]::WriteAllText($Path,($json + "`n"),[Text.UTF8Encoding]::new($false))
}

function Write-VgtSourceManifest {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $root = [IO.Path]::GetFullPath($ProjectRoot)
    $files = @(Get-VgtSourceSnapshot -ProjectRoot $root)
    if ($files.Count -lt 50 -or $files.Count -gt 2000) { throw [IO.InvalidDataException]::new(('Source release file count violated the expected boundary: {0}' -f $files.Count)) }
    # FIND-WIN-022 fail-closed assertion: the authoritative manifest must never
    # list agent/handoff notes, even if a caller supplies a hand-crafted file
    # list in the future.
    foreach ($file in $files) {
        $exclusionReason = Get-VgtPublishedSourceExclusionReason -RelativePath $file.Relative
        if ($exclusionReason) { throw [Security.SecurityException]::new(('Excluded agent/handoff note entered SOURCE-MANIFEST.sha256 (fail-closed): {0} ({1})' -f $file.Relative,$exclusionReason)) }
    }
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $lines.Add(('{0}  {1}' -f $file.Sha256,$file.Relative))
    }
    $payload = ($lines -join "`n") + "`n"
    $manifestPath = Join-Path $root 'SOURCE-MANIFEST.sha256'
    [IO.File]::WriteAllText($manifestPath,$payload,[Text.UTF8Encoding]::new($false))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digestBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)) } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        Path = $manifestPath
        FileCount = $files.Count
        Digest = ([BitConverter]::ToString($digestBytes)).Replace('-','').ToLowerInvariant()
        Lines = @($lines.ToArray())
    }
}

function Get-VgtDistributionForbiddenReason {
    param([Parameter(Mandatory)][string]$RelativePath)
    $relative = $RelativePath.Replace('\','/')
    foreach ($part in ($relative -split '/')) {
        if ($part -eq '.git') { return 'repository metadata (.git)' }
    }
    $leaf = [IO.Path]::GetFileName($relative).ToLowerInvariant()
    $extension = [IO.Path]::GetExtension($relative).ToLowerInvariant()
    if ($leaf -in @('signing.key','vault.key','evidence.key','evidence-signing.key','feed-policy.key','protected-policy.key','dashboard.token','evidence.jsonl','checkpoints.jsonl')) { return ('private key/runtime state artifact: {0}' -f $leaf) }
    if ($extension -in @('.key','.jsonl','.snk','.pfx','.p12','.pvk','.pem')) { return ('forbidden secret/evidence extension: {0}' -f $extension) }
    return ''
}

# ---------------------------------------------------------------------------
# Release-channel hygiene (SC-FIND-003)
# ---------------------------------------------------------------------------
$script:VgtReleaseVersionPattern = '[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[1-9][0-9]*)?'

function Get-VgtReleaseAssetVersion {
    # Returns the version encoded in a recognised GeDefense release asset name,
    # or '' when the file is not a version-bearing release asset. Unknown files
    # deliberately fall through so the channel gate can fail closed on them.
    # FIND-WIN-022: the Inno beta-onboarding installer is a first-class release
    # asset: GeDefense-Setup-Inno-x64-v<ver>.exe, .exe.sha256 and .exe.json.
    param([Parameter(Mandatory)][string]$FileName)
    $name = [IO.Path]::GetFileName($FileName)
    $pattern = '^(?:GeDefense-Setup-x64-v(?<v1>' + $script:VgtReleaseVersionPattern + ')\.(?:exe(?:\.sha256)?|json)|GeDefense-Setup-Inno-x64-v(?<v5>' + $script:VgtReleaseVersionPattern + ')\.exe(?:\.sha256|\.json)?|GeDefense-SBOM-v(?<v2>' + $script:VgtReleaseVersionPattern + ')\.cdx\.json|GeDefense-Provenance-v(?<v3>' + $script:VgtReleaseVersionPattern + ')\.json|VGT_GeDefense_Windows_(?<v4>' + $script:VgtReleaseVersionPattern + ')_Source\.zip(?:\.sha256)?)$'
    $match = [Regex]::Match($name, $pattern)
    if (-not $match.Success) { return '' }
    foreach ($groupName in @('v1','v5','v2','v3','v4')) {
        $group = $match.Groups[$groupName]
        if ($group.Success -and -not [string]::IsNullOrWhiteSpace($group.Value)) { return $group.Value }
    }
    return ''
}

function Assert-VgtReleaseSidecarHash {
    # Verifies one <asset>.sha256 sidecar against the measured asset bytes.
    param(
        [Parameter(Mandatory)][string]$AssetPath,
        [Parameter(Mandatory)][string]$SidecarPath
    )
    if (-not (Test-Path -LiteralPath $AssetPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Release asset is missing: {0}' -f $AssetPath)) }
    if (-not (Test-Path -LiteralPath $SidecarPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Release asset SHA-256 sidecar is missing: {0}' -f $SidecarPath)) }
    $text = (Get-Content -LiteralPath $SidecarPath -Raw -Encoding UTF8).Trim()
    $match = [Regex]::Match($text, '^(?<hash>[0-9a-fA-F]{64})(?:\s+\*?(?<name>[^\\/]+))?$')
    if (-not $match.Success) { throw [IO.InvalidDataException]::new(('Release asset SHA-256 sidecar has an invalid format: {0}' -f $SidecarPath)) }
    $measured = Get-VgtSha256 -Path $AssetPath
    if ($match.Groups['hash'].Value.ToLowerInvariant() -ne $measured) { throw [Security.SecurityException]::new(('Release asset SHA-256 sidecar mismatch: {0}' -f [IO.Path]::GetFileName($AssetPath))) }
    if ($match.Groups['name'].Success) {
        $expectedName = [IO.Path]::GetFileName($AssetPath)
        if ($match.Groups['name'].Value -ne $expectedName) { throw [Security.SecurityException]::new(('Release asset sidecar names a different file: {0} vs {1}' -f $match.Groups['name'].Value,$expectedName)) }
    }
    return $measured
}

function Assert-VgtSha256SumsCoverage {
    # Proves that SHA256SUMS.txt names every release asset exactly once with the
    # measured SHA-256 (no missing, stale or mismatched entries). The sums file
    # itself is never an asset.
    param(
        [Parameter(Mandatory)][string]$ReleaseDirectory,
        [string]$SumsPath = '',
        [string[]]$ExpectedAssets = @()
    )
    $releaseFull = [IO.Path]::GetFullPath($ReleaseDirectory)
    if (-not (Test-Path -LiteralPath $releaseFull -PathType Container)) { throw [IO.DirectoryNotFoundException]::new(('Release directory is missing: {0}' -f $releaseFull)) }
    if ([string]::IsNullOrWhiteSpace($SumsPath)) { $SumsPath = Join-Path $releaseFull 'SHA256SUMS.txt' }
    $sumsFull = [IO.Path]::GetFullPath($SumsPath)
    if (-not (Test-Path -LiteralPath $sumsFull -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('SHA256SUMS.txt is missing: {0}' -f $sumsFull)) }

    $assetNames = [Collections.Generic.List[string]]::new()
    if (@($ExpectedAssets).Count -gt 0) {
        foreach ($expectedAsset in @($ExpectedAssets)) {
            if ([string]::IsNullOrWhiteSpace($expectedAsset)) { throw [IO.InvalidDataException]::new('SHA256SUMS expectation contains an empty asset name.') }
            if ($expectedAsset -match '[\\/]' -or $expectedAsset -eq 'SHA256SUMS.txt') { throw [IO.InvalidDataException]::new(('SHA256SUMS expectations must be flat asset file names: {0}' -f $expectedAsset)) }
            if ($assetNames.Contains($expectedAsset)) { throw [IO.InvalidDataException]::new(('Duplicate expected release asset: {0}' -f $expectedAsset)) }
            $assetNames.Add($expectedAsset)
        }
    } else {
        foreach ($file in @(Get-ChildItem -LiteralPath $releaseFull -Recurse -File -Force | Sort-Object FullName)) {
            $relative = Get-VgtRelativePath -FullName $file.FullName -ProjectRoot $releaseFull
            if ($relative -eq 'SHA256SUMS.txt') { continue }
            $assetNames.Add($relative)
        }
    }

    $entries = [Collections.Specialized.OrderedDictionary]::new()
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $sumsFull -Encoding UTF8) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { throw [IO.InvalidDataException]::new(('SHA256SUMS.txt contains an empty line at line {0}.' -f $lineNumber)) }
        $match = [Regex]::Match($line, '^(?<hash>[0-9a-fA-F]{64})  (?<name>[A-Za-z0-9._-]+)$')
        if (-not $match.Success) { throw [IO.InvalidDataException]::new(('SHA256SUMS.txt has an invalid line {0} (expected "<sha256>  <flat-name>").' -f $lineNumber)) }
        $name = $match.Groups['name'].Value
        if ($name -eq 'SHA256SUMS.txt') { throw [IO.InvalidDataException]::new('SHA256SUMS.txt must not list itself.') }
        if ($entries.Contains($name)) { throw [IO.InvalidDataException]::new(('SHA256SUMS.txt lists an asset more than once: {0}' -f $name)) }
        $entries[$name] = $match.Groups['hash'].Value.ToLowerInvariant()
    }
    if ($entries.Count -eq 0) { throw [IO.InvalidDataException]::new('SHA256SUMS.txt is empty.') }

    $missing = [Collections.Generic.List[string]]::new()
    $stale = [Collections.Generic.List[string]]::new()
    $mismatched = [Collections.Generic.List[string]]::new()
    $checked = 0
    foreach ($assetName in @($assetNames.ToArray())) {
        if (-not $entries.Contains($assetName)) { $missing.Add($assetName); continue }
        $assetPath = Join-Path $releaseFull ($assetName.Replace('/',[IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Expected release asset is missing: {0}' -f $assetPath)) }
        $measured = Get-VgtSha256 -Path $assetPath
        if ($measured -ne [string]$entries[$assetName]) { $mismatched.Add($assetName) }
        $checked++
    }
    foreach ($sumsName in @($entries.Keys)) {
        if (-not $assetNames.Contains([string]$sumsName)) { $stale.Add([string]$sumsName) }
    }
    if ($missing.Count -gt 0 -or $stale.Count -gt 0 -or $mismatched.Count -gt 0) {
        $detail = ('missing=[{0}] stale=[{1}] mismatched=[{2}]' -f ($missing -join ', '),($stale -join ', '),($mismatched -join ', '))
        throw [Security.SecurityException]::new(('SHA256SUMS.txt does not exactly cover the release directory: {0}' -f $detail))
    }
    return [pscustomobject][ordered]@{
        Status = 'PASS'
        SumsPath = $sumsFull
        Entries = $entries.Count
        Assets = $assetNames.Count
        CheckedHashes = $checked
    }
}

function Assert-VgtReleaseChannelHygiene {
    # SC-FIND-003: a release directory may only contain assets of the current
    # VERSION. Foreign-version EXEs/source archives are a hard failure, unknown
    # assets fail closed, every binary/archive needs a matching .sha256 sidecar,
    # an installer requires its manifest/SBOM/provenance siblings and - when the
    # channel is publishable - SHA256SUMS.txt must cover every asset exactly.
    # FIND-WIN-022: the Inno beta-onboarding installer is registered as a normal
    # asset and is held to the same sidecar/hash rules as the standalone build
    # (an optional Inno .exe.json is additionally bound to version, bytes, hash).
    # A missing release directory is reported as State=ABSENT (nothing to
    # verify); a partial build is reported as State=PARTIAL and is not a fail
    # until a complete set (installer + source archive) exists without sums.
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$ReleaseDirectory = '',
        [string]$Version = ''
    )
    $rootFull = [IO.Path]::GetFullPath($ProjectRoot)
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = Read-VgtVersion -ProjectRoot $rootFull }
    if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) { $ReleaseDirectory = Join-Path $rootFull 'release' }
    $releaseFull = [IO.Path]::GetFullPath($ReleaseDirectory)
    $result = [ordered]@{
        Status = 'PASS'
        State = 'ABSENT'
        Version = $Version
        ReleaseDirectory = $releaseFull
        Assets = 0
        CurrentAssets = @()
        ForeignAssets = @()
        UnknownAssets = @()
        HasInstaller = $false
        HasInnoInstaller = $false
        HasSourceArchive = $false
        InnoJsonState = 'absent'
        SumsState = 'absent'
        SumsEntries = 0
        SidecarsVerified = 0
    }
    if (-not (Test-Path -LiteralPath $releaseFull -PathType Container)) { return [pscustomobject]$result }

    $current = [Collections.Generic.List[string]]::new()
    $foreign = [Collections.Generic.List[string]]::new()
    $unknown = [Collections.Generic.List[string]]::new()
    $files = @(Get-ChildItem -LiteralPath $releaseFull -Recurse -File -Force | Sort-Object FullName)
    foreach ($file in $files) {
        $relative = Get-VgtRelativePath -FullName $file.FullName -ProjectRoot $releaseFull
        if ($relative -eq 'SHA256SUMS.txt') { continue }
        if ($relative -match '[\\/]') { $unknown.Add(('{0} (nested release path)' -f $relative)); continue }
        $assetVersion = Get-VgtReleaseAssetVersion -FileName $relative
        if ([string]::IsNullOrWhiteSpace($assetVersion)) { $unknown.Add(('{0} (unrecognised release asset)' -f $relative)); continue }
        if ($assetVersion -ne $Version) { $foreign.Add(('{0} (version {1})' -f $relative,$assetVersion)); continue }
        $current.Add($relative)
    }
    $result.Assets = $files.Count
    $result.CurrentAssets = @($current.ToArray())
    $result.ForeignAssets = @($foreign.ToArray())
    $result.UnknownAssets = @($unknown.ToArray())
    if ($foreign.Count -gt 0) { throw [Security.SecurityException]::new(('Release channel contains foreign-version artifacts for VERSION {0}: {1}' -f $Version,($foreign -join '; '))) }
    if ($unknown.Count -gt 0) { throw [Security.SecurityException]::new(('Release channel contains unrecognised artifacts (fail-closed): {0}' -f ($unknown -join '; '))) }
    if ($current.Count -eq 0) {
        $emptySumsPath = Join-Path $releaseFull 'SHA256SUMS.txt'
        if (Test-Path -LiteralPath $emptySumsPath -PathType Leaf) { [void](Assert-VgtSha256SumsCoverage -ReleaseDirectory $releaseFull) }
        $result.State = 'EMPTY'
        return [pscustomobject]$result
    }

    foreach ($currentName in @($current.ToArray())) {
        if ($currentName -match '\.exe$' -or $currentName -match '_Source\.zip$') {
            $sidecarName = $currentName + '.sha256'
            if (-not $current.Contains($sidecarName)) { throw [Security.SecurityException]::new(('Release asset has no SHA-256 sidecar: {0}' -f $currentName)) }
            [void](Assert-VgtReleaseSidecarHash -AssetPath (Join-Path $releaseFull $currentName) -SidecarPath (Join-Path $releaseFull $sidecarName))
            $result.SidecarsVerified = [int]$result.SidecarsVerified + 1
        }
    }

    $installerName = 'GeDefense-Setup-x64-v{0}.exe' -f $Version
    $innoInstallerName = 'GeDefense-Setup-Inno-x64-v{0}.exe' -f $Version
    $innoSidecarName = $innoInstallerName + '.sha256'
    $innoJsonName = $innoInstallerName + '.json'
    $sourceArchiveName = 'VGT_GeDefense_Windows_{0}_Source.zip' -f $Version
    $result.HasInstaller = $current.Contains($installerName)
    $result.HasInnoInstaller = $current.Contains($innoInstallerName)
    $result.HasSourceArchive = $current.Contains($sourceArchiveName)
    if ($result.HasInstaller) {
        foreach ($requiredAsset in @(('GeDefense-Setup-x64-v{0}.json' -f $Version),('GeDefense-SBOM-v{0}.cdx.json' -f $Version),('GeDefense-Provenance-v{0}.json' -f $Version))) {
            if (-not $current.Contains($requiredAsset)) { throw [Security.SecurityException]::new(('Release channel has installer {0} but is missing the required supply-chain asset {1}.' -f $installerName,$requiredAsset)) }
        }
    }
    # FIND-WIN-022: the Inno installer is optional (only present once the beta
    # onboarding path was built) but never half-registered. The generic sidecar
    # loop above already proved the .exe has a measured, matching .sha256.
    if ($result.HasInnoInstaller) {
        if ($current.Contains($innoJsonName)) {
            $innoInstallerPath = Join-Path $releaseFull $innoInstallerName
            $innoJsonPath = Join-Path $releaseFull $innoJsonName
            try {
                $innoJson = Get-Content -LiteralPath $innoJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                throw [IO.InvalidDataException]::new(('Inno installer sidecar is not valid JSON: {0}' -f $innoJsonName))
            }
            if ($null -eq $innoJson) { throw [IO.InvalidDataException]::new(('Inno installer sidecar is empty: {0}' -f $innoJsonName)) }
            if ([string]$innoJson.version -ne $Version) { throw [Security.SecurityException]::new(('Inno installer sidecar version mismatch: {0} vs {1}' -f $innoJson.version,$Version)) }
            $innoMeasuredHash = Get-VgtSha256 -Path $innoInstallerPath
            if (([string]$innoJson.sha256).ToLowerInvariant() -ne $innoMeasuredHash) { throw [Security.SecurityException]::new(('Inno installer sidecar SHA-256 does not match the measured installer: {0}' -f $innoJsonName)) }
            $innoInstallerBytes = [long](Get-Item -LiteralPath $innoInstallerPath).Length
            if ([long]$innoJson.bytes -ne $innoInstallerBytes) { throw [Security.SecurityException]::new(('Inno installer sidecar byte count does not match the measured installer: {0}' -f $innoJsonName)) }
            $result.InnoJsonState = 'verified'
        }
    } elseif ($current.Contains($innoSidecarName) -or $current.Contains($innoJsonName)) {
        throw [Security.SecurityException]::new('Release channel contains Inno sidecar assets without the Inno installer (fail-closed).')
    }

    $sumsPath = Join-Path $releaseFull 'SHA256SUMS.txt'
    if (Test-Path -LiteralPath $sumsPath -PathType Leaf) {
        $coverage = Assert-VgtSha256SumsCoverage -ReleaseDirectory $releaseFull
        $result.SumsState = 'verified'
        $result.SumsEntries = [int]$coverage.Entries
        $result.State = $(if ($result.HasInstaller -and $result.HasSourceArchive) { 'VERIFIED' } else { 'SUMS_VERIFIED_PARTIAL' })
    } elseif ($result.HasInstaller -and $result.HasSourceArchive) {
        throw [Security.SecurityException]::new(('Complete release set (installer + source archive) exists but SHA256SUMS.txt is missing: {0}. Publish-GitHubRelease.ps1 -VerifyOnly generates the final checksum manifest.' -f $sumsPath))
    } else {
        $result.SumsState = 'pending-build'
        $result.State = 'PARTIAL'
    }
    return [pscustomobject]$result
}

function Get-VgtZipEntryNames {
    # Bounded, read-only enumeration of ZIP entry names. Both the entry count and
    # the individual name length are capped so a hostile or corrupt archive can
    # never make a release gate allocate or loop without bound.
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [int]$MaximumEntries = 4096,
        [int]$MaximumNameLength = 1024
    )
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Archive is missing: {0}' -f $ArchivePath)) }
    if ($MaximumEntries -lt 1) { throw [IO.InvalidDataException]::new('ZIP entry bound must be positive.') }
    if ($MaximumNameLength -lt 1) { throw [IO.InvalidDataException]::new('ZIP entry name bound must be positive.') }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = [IO.Compression.ZipFile]::OpenRead([IO.Path]::GetFullPath($ArchivePath))
    try {
        if ($archive.Entries.Count -gt $MaximumEntries) { throw [IO.InvalidDataException]::new(('Archive exceeds the bounded entry count: {0} entries (max {1}).' -f $archive.Entries.Count,$MaximumEntries)) }
        $names = [Collections.Generic.List[string]]::new()
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if ($name.Length -gt $MaximumNameLength) { throw [IO.InvalidDataException]::new(('Archive entry name exceeds the bounded length: {0} characters (max {1}).' -f $name.Length,$MaximumNameLength)) }
            $names.Add($name)
        }
        return @($names.ToArray())
    } finally {
        $archive.Dispose()
    }
}

function Assert-VgtSourceArchiveExcludesAgentNotes {
    # FIND-WIN-022: agent/handoff notes (Next.md, START_HERE_*.md, ...) are
    # allowed in the working tree but must never ship. This gate inspects the
    # generated deterministic source archive (bounded read) and fails closed when
    # any excluded note is present, so Test-GeDefenseRelease.ps1 checks the
    # distribution instead of forbidding the working file.
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [string]$Version = ''
    )
    $archiveFull = [IO.Path]::GetFullPath($ArchivePath)
    if (-not (Test-Path -LiteralPath $archiveFull -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Source archive is missing: {0}' -f $archiveFull)) }
    $prefix = ''
    if (-not [string]::IsNullOrWhiteSpace($Version)) { $prefix = ('GeDefense-Windows-{0}/' -f $Version) }
    $names = @(Get-VgtZipEntryNames -ArchivePath $archiveFull -MaximumEntries 4096 -MaximumNameLength 1024)
    $violations = [Collections.Generic.List[string]]::new()
    foreach ($name in $names) {
        $relative = $name.Replace('\','/')
        if ($prefix -and $relative.StartsWith($prefix,[StringComparison]::Ordinal)) { $relative = $relative.Substring($prefix.Length) }
        if ([string]::IsNullOrWhiteSpace($relative)) { continue }
        $exclusionReason = Get-VgtPublishedSourceExclusionReason -RelativePath $relative
        if ($exclusionReason) { $violations.Add(('{0} ({1})' -f $name,$exclusionReason)) }
    }
    if ($violations.Count -gt 0) {
        throw [Security.SecurityException]::new(('Source archive contains AI-agent handoff notes (fail-closed): {0}' -f ($violations -join '; ')))
    }
    return [pscustomobject][ordered]@{
        Status = 'PASS'
        Archive = $archiveFull
        Entries = $names.Count
        ExcludedNotes = 0
    }
}

function Get-VgtZipEntryBytes {
    # Reads one ZIP entry into memory with a hard size bound. Used to compare
    # the SOURCE-MANIFEST.sha256 shipped inside the deterministic source archive
    # with the manifest of the current working tree.
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$EntryName,
        [int]$MaximumBytes = 1048576
    )
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Archive is missing: {0}' -f $ArchivePath)) }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = [IO.Compression.ZipFile]::OpenRead([IO.Path]::GetFullPath($ArchivePath))
    try {
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry -and $EntryName.Contains('/')) {
            # The VGT deterministic writer uses forward slashes; tolerate archives
            # produced by tools that stored Windows-style separators.
            $entry = $archive.GetEntry($EntryName.Replace('/','\'))
        }
        if ($null -eq $entry) { return $null }
        if ($entry.Length -lt 0 -or $entry.Length -gt $MaximumBytes) { throw [IO.InvalidDataException]::new(('Archive entry exceeds the bounded size: {0} ({1} bytes).' -f $EntryName,$entry.Length)) }
        $stream = $entry.Open()
        try {
            $buffer = New-Object byte[] ([int]$entry.Length)
            $offset = 0
            while ($offset -lt $buffer.Length) {
                $read = $stream.Read($buffer,$offset,$buffer.Length - $offset)
                if ($read -le 0) { break }
                $offset += $read
            }
            if ($offset -ne $buffer.Length) { throw [IO.InvalidDataException]::new(('Archive entry is truncated: {0}' -f $EntryName)) }
            return $buffer
        } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
}

function Assert-VgtSourceArchiveFreshness {
    # SC-FIND-003/SC-FIND-005: proves that the source-release ZIP in release/
    # was built from the current tree by comparing the SOURCE-MANIFEST.sha256
    # shipped inside the archive with the authoritative manifest on disk. A
    # stale archive must be rebuilt before the installer/provenance/sidecar are
    # assembled, otherwise the release would bind an outdated source snapshot.
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$ArchivePath,
        [string]$Version = ''
    )
    $rootFull = [IO.Path]::GetFullPath($ProjectRoot)
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = Read-VgtVersion -ProjectRoot $rootFull }
    $archiveFull = [IO.Path]::GetFullPath($ArchivePath)
    if (-not (Test-Path -LiteralPath $archiveFull -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Source archive is missing: {0}' -f $archiveFull)) }
    $manifestPath = Join-Path $rootFull 'SOURCE-MANIFEST.sha256'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('SOURCE-MANIFEST.sha256 is missing; the source archive freshness cannot be proven.') }
    $entryName = ('GeDefense-Windows-{0}/SOURCE-MANIFEST.sha256' -f $Version)
    $entryBytes = Get-VgtZipEntryBytes -ArchivePath $archiveFull -EntryName $entryName -MaximumBytes 1048576
    if ($null -eq $entryBytes) { throw [IO.InvalidDataException]::new(('Source archive does not contain {0}; it was not produced by build/Build-SourceRelease.ps1 for VERSION {1}.' -f $entryName,$Version)) }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $archiveManifestHash = ([BitConverter]::ToString($sha.ComputeHash($entryBytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $currentManifestHash = Get-VgtSha256 -Path $manifestPath
    if ($archiveManifestHash -ne $currentManifestHash) {
        throw [Security.SecurityException]::new(('Source archive is stale: it ships SOURCE-MANIFEST.sha256 {0} but the working tree manifest is {1}. Run build/Build-SourceRelease.ps1 before assembling the release.' -f $archiveManifestHash,$currentManifestHash))
    }
    return [pscustomobject][ordered]@{
        Status = 'PASS'
        Archive = $archiveFull
        Version = $Version
        ManifestSha256 = $currentManifestHash
        Entry = $entryName
    }
}

Export-ModuleMember -Function Get-VgtProjectRoot,Read-VgtVersion,Get-VgtRelativePath,Get-VgtPublishedSourceExclusionReason,Test-VgtSourceCandidate,Get-VgtSourceFileList,Get-VgtSourceSnapshot,Get-VgtSha256,Get-VgtSourceTreeDigest,Write-VgtSourceManifest,Get-VgtToolchain,Get-VgtSourceDateEpoch,Get-VgtStableUuid,Write-VgtDeterministicJson,Get-VgtDistributionForbiddenReason,Get-VgtReleaseAssetVersion,Assert-VgtSha256SumsCoverage,Assert-VgtReleaseChannelHygiene,Assert-VgtSourceArchiveFreshness,Get-VgtZipEntryNames,Assert-VgtSourceArchiveExcludesAgentNotes
