# STATUS: DIAMANT VGT SUPREME
# FIND-WIN-022 regression suite: release-asset registration, agent-note
# distribution exclusion and prerelease-aware downgrade comparison.
#
# The suite is fully offline and needs neither admin rights, Inno Setup, a Go
# toolchain nor a signed installer. It uses disposable fixtures under %TEMP% and
# proves fail-closed behaviour for every negative case:
#   1. every PowerShell file under the tooling roots parses,
#   2. Get-VgtReleaseAssetVersion recognises the standalone, Inno, SBOM,
#      provenance and source-archive asset names (and returns '' for unknown
#      names, including the legacy bare Inno sidecar),
#   3. agent/handoff notes may exist in the working tree but are centrally
#      excluded from Get-VgtSourceFileList, Write-VgtSourceManifest and the
#      source ZIP gate (Assert-VgtSourceArchiveExcludesAgentNotes),
#   4. Assert-VgtReleaseChannelHygiene accepts a complete current-version channel
#      including the Inno triple and fails closed for foreign versions, unknown
#      assets, missing/invalid Inno sidecars and SHA256SUMS coverage gaps,
#   5. Test-GeDefenseRelease.ps1 no longer forbids Next.md in the tree but
#      asserts the generated source archive is note-free,
#   6. the FIND-WIN-022 prerelease downgrade guard in installer/Install-
#      GeDefense.ps1 is verified (it was fixed by a separate change; this suite
#      only proves the ordering, it does not modify the installer).
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $PSScriptRoot 'VgtSupplyChain.psm1'
$checks = [Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Release-channel hygiene check failed: {0} ({1})' -f $Name,$Detail)) }
}

function Get-VgtParsedAst {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('File is missing: {0}' -f $Path)) }
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) {
        throw [IO.InvalidDataException]::new(('PowerShell parse failure in {0}: {1}' -f $Path,(@($errors | ForEach-Object { $_.Message }) -join '; ')))
    }
    return $ast
}

function Get-VgtFunctionBody {
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][string]$FunctionName)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw [IO.InvalidDataException]::new(('PowerShell parse failure while analysing {0}' -f $FunctionName)) }
    $functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },$true))
    $match = @($functions | Where-Object { $_.Name -eq $FunctionName })
    if ($match.Count -ne 1) { throw [IO.InvalidDataException]::new(('Expected exactly one function {0}, found {1}.' -f $FunctionName,$match.Count)) }
    return $match[0].Body.Extent.Text
}

function New-FixtureFile {
    param([Parameter(Mandatory)][string]$Path,[AllowEmptyString()][string]$Content = 'fixture')
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    [IO.File]::WriteAllText($Path,($Content + "`n"),[Text.UTF8Encoding]::new($false))
}

function Get-FixtureHash {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-FixtureSidecar {
    param([Parameter(Mandatory)][string]$Path)
    $name = [IO.Path]::GetFileName($Path)
    [IO.File]::WriteAllText(($Path + '.sha256'),((Get-FixtureHash -Path $Path) + '  ' + $name + "`n"),[Text.UTF8Encoding]::new($false))
}

function Write-FixtureSums {
    param([Parameter(Mandatory)][string]$Directory,[string[]]$ExcludeNames = @())
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -File -Force | Sort-Object Name)) {
        if ($file.Name -eq 'SHA256SUMS.txt') { continue }
        if ($ExcludeNames -contains $file.Name) { continue }
        $lines.Add(((Get-FixtureHash -Path $file.FullName) + '  ' + $file.Name))
    }
    [IO.File]::WriteAllText((Join-Path $Directory 'SHA256SUMS.txt'),(($lines -join "`n") + "`n"),[Text.UTF8Encoding]::new($false))
}

function New-FixtureStandaloneSet {
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Version)
    $exePath = Join-Path $Directory ('GeDefense-Setup-x64-v{0}.exe' -f $Version)
    New-FixtureFile -Path $exePath -Content 'standalone-exe-fixture'
    New-FixtureSidecar -Path $exePath
    $manifest = ('{{"version":"{0}","bytes":{1},"sha256":"{2}"}}' -f $Version,(Get-Item -LiteralPath $exePath).Length,(Get-FixtureHash -Path $exePath))
    New-FixtureFile -Path (Join-Path $Directory ('GeDefense-Setup-x64-v{0}.json' -f $Version)) -Content $manifest
    New-FixtureFile -Path (Join-Path $Directory ('GeDefense-SBOM-v{0}.cdx.json' -f $Version)) -Content '{"components":[]}'
    New-FixtureFile -Path (Join-Path $Directory ('GeDefense-Provenance-v{0}.json' -f $Version)) -Content ('{"sourceTree":{"sha256":"' + ('a' * 64) + '"}}')
}

function New-FixtureSourceArchiveSet {
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Version)
    $archivePath = Join-Path $Directory ('VGT_GeDefense_Windows_{0}_Source.zip' -f $Version)
    New-FixtureFile -Path $archivePath -Content 'source-archive-fixture'
    New-FixtureSidecar -Path $archivePath
}

function New-FixtureInnoSet {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Version,
        [switch]$WithoutSidecar,
        [switch]$TamperedHash,
        [switch]$WrongVersionJson,
        [switch]$InvalidJson
    )
    $exePath = Join-Path $Directory ('GeDefense-Setup-Inno-x64-v{0}.exe' -f $Version)
    New-FixtureFile -Path $exePath -Content 'inno-exe-fixture'
    $bytes = [long](Get-Item -LiteralPath $exePath).Length
    $hash = Get-FixtureHash -Path $exePath
    if (-not $WithoutSidecar) {
        $sidecarHash = if ($TamperedHash) { '0' * 64 } else { $hash }
        [IO.File]::WriteAllText(($exePath + '.sha256'),($sidecarHash + '  ' + [IO.Path]::GetFileName($exePath) + "`n"),[Text.UTF8Encoding]::new($false))
    }
    if ($InvalidJson) {
        New-FixtureFile -Path ($exePath + '.json') -Content '{this is not valid json'
    } else {
        $jsonVersion = if ($WrongVersionJson) { '5.2.9' } else { $Version }
        New-FixtureFile -Path ($exePath + '.json') -Content ('{{"version":"{0}","bytes":{1},"sha256":"{2}"}}' -f $jsonVersion,$bytes,$hash)
    }
}

function New-FixtureZip {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string[]]$EntryRelativePaths
    )
    $stagingRoot = Join-Path $env:TEMP ('vgt-zip-staging-' + [Guid]::NewGuid().ToString('N'))
    $versionRoot = Join-Path $stagingRoot ('GeDefense-Windows-' + $Version)
    New-Item -Path $versionRoot -ItemType Directory -Force | Out-Null
    foreach ($relative in $EntryRelativePaths) {
        New-FixtureFile -Path (Join-Path $versionRoot ($relative.Replace('/','\'))) -Content ('fixture-entry: ' + $relative)
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [IO.Compression.ZipFile]::CreateFromDirectory($stagingRoot,$Path,[IO.Compression.CompressionLevel]::NoCompression,$true)
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Import-Module -Name $modulePath -Force
$moduleText = Get-Content -LiteralPath $modulePath -Raw -Encoding UTF8

$sandbox = Join-Path $env:TEMP ('vgt-release-channel-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $sandbox -ItemType Directory -Force | Out-Null
try {
    # -------------------------------------------------------------------
    # 1. Parser gate for every PowerShell file of the release toolchain
    # -------------------------------------------------------------------
    $parserFiles = [Collections.Generic.List[string]]::new()
    foreach ($toolingRoot in @('tools','build','installer','engine','xdr','audit')) {
        $rootPath = Join-Path $projectRoot $toolingRoot
        if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) { continue }
        foreach ($scriptFile in @(Get-ChildItem -LiteralPath $rootPath -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1' })) {
            $null = Get-VgtParsedAst -Path $scriptFile.FullName
            $parserFiles.Add($scriptFile.FullName)
        }
    }
    Add-Check -Name 'ps-parser-all-ok' -Passed ($parserFiles.Count -ge 10) -Detail ('parsed={0}' -f $parserFiles.Count)

    # -------------------------------------------------------------------
    # 2. Get-VgtReleaseAssetVersion matrix (FIND-WIN-022)
    # -------------------------------------------------------------------
    $assetMatrix = @(
        @{ Name = 'GeDefense-Setup-x64-v5.3.0.exe'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-x64-v5.3.0.exe.sha256'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-x64-v5.3.0.json'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.0.exe'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.0.exe.sha256'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.0.exe.json'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.1-beta.2.exe'; Expected = '5.3.1-beta.2' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.1-beta.2.exe.sha256'; Expected = '5.3.1-beta.2' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.1-beta.2.exe.json'; Expected = '5.3.1-beta.2' },
        @{ Name = 'GeDefense-SBOM-v5.3.0.cdx.json'; Expected = '5.3.0' },
        @{ Name = 'GeDefense-Provenance-v5.3.0.json'; Expected = '5.3.0' },
        @{ Name = 'VGT_GeDefense_Windows_5.3.0_Source.zip'; Expected = '5.3.0' },
        @{ Name = 'VGT_GeDefense_Windows_5.3.0_Source.zip.sha256'; Expected = '5.3.0' },
        @{ Name = 'notes.txt'; Expected = '' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.0.json'; Expected = '' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.0.exe.backup'; Expected = '' },
        @{ Name = 'GeDefense-Setup-x64-v5.3.0.exe.sig'; Expected = '' },
        @{ Name = 'GeDefense-Setup-Inno-x64-5.3.0.exe'; Expected = '' },
        @{ Name = 'GeDefense-Setup-Inno-x64-v5.3.exe'; Expected = '' }
    )
    foreach ($case in $assetMatrix) {
        $checkName = 'asset-version-' + ($case.Name -replace '[^A-Za-z0-9]+','-')
        $actual = Get-VgtReleaseAssetVersion -FileName $case.Name
        Add-Check -Name $checkName -Passed ($actual -eq $case.Expected) -Detail ('expected=[{0}] actual=[{1}]' -f $case.Expected,$actual)
    }
    Add-Check -Name 'asset-version-ignores-directory-prefix' -Passed ((Get-VgtReleaseAssetVersion -FileName 'X:\release\GeDefense-Setup-Inno-x64-v5.3.0.exe') -eq '5.3.0')

    # -------------------------------------------------------------------
    # 3. Agent/handoff note distribution exclusion (FIND-WIN-022)
    # -------------------------------------------------------------------
    $excludedNotes = @('Next.md','GITHUB-UPLOAD.md','RELEASE-NOTES.md','MERGE_REPORT.json','START_HERE_FULL_MERGED_SOURCE.md')
    foreach ($noteName in $excludedNotes) {
        Add-Check -Name ('note-exclusion-reason-' + ($noteName -replace '[^A-Za-z0-9]+','-')) -Passed (-not [string]::IsNullOrWhiteSpace((Get-VgtPublishedSourceExclusionReason -RelativePath $noteName)))
        Add-Check -Name ('note-excluded-candidate-' + ($noteName -replace '[^A-Za-z0-9]+','-')) -Passed (-not (Test-VgtSourceCandidate -RelativePath $noteName))
    }
    Add-Check -Name 'note-exclusion-reason-nested' -Passed (-not [string]::IsNullOrWhiteSpace((Get-VgtPublishedSourceExclusionReason -RelativePath 'docs/START_HERE_RELEASE.md')))
    Add-Check -Name 'note-exclusion-reason-backslash' -Passed (-not [string]::IsNullOrWhiteSpace((Get-VgtPublishedSourceExclusionReason -RelativePath 'work\Next.md')))
    foreach ($ordinaryPath in @('README.md','CHANGELOG.md','docs/guide.md','src/GeDefense/windows/go.mod','.gitignore')) {
        Add-Check -Name ('ordinary-file-kept-' + ($ordinaryPath -replace '[^A-Za-z0-9]+','-')) -Passed ([string]::IsNullOrWhiteSpace((Get-VgtPublishedSourceExclusionReason -RelativePath $ordinaryPath)))
        Add-Check -Name ('ordinary-candidate-kept-' + ($ordinaryPath -replace '[^A-Za-z0-9]+','-')) -Passed (Test-VgtSourceCandidate -RelativePath $ordinaryPath)
    }

    $sourceFixture = Join-Path $sandbox 'source-fixture'
    New-FixtureFile -Path (Join-Path $sourceFixture 'VERSION') -Content '5.3.0'
    New-FixtureFile -Path (Join-Path $sourceFixture 'README.md') -Content 'readme'
    New-FixtureFile -Path (Join-Path $sourceFixture 'CHANGELOG.md') -Content 'changelog'
    New-FixtureFile -Path (Join-Path $sourceFixture 'docs\guide.md') -Content 'guide'
    New-FixtureFile -Path (Join-Path $sourceFixture 'src\main.ps1') -Content 'Write-Host fixture'
    foreach ($noteName in $excludedNotes) { New-FixtureFile -Path (Join-Path $sourceFixture $noteName) -Content 'agent note' }
    for ($noteIndex = 1; $noteIndex -le 60; $noteIndex++) {
        New-FixtureFile -Path (Join-Path $sourceFixture ('docs\reference-{0:D2}.md' -f $noteIndex)) -Content ('reference body {0}' -f $noteIndex)
    }
    $sourceList = @(Get-VgtSourceFileList -ProjectRoot $sourceFixture)
    $shippedNoteNames = @($sourceList | Where-Object { -not [string]::IsNullOrWhiteSpace((Get-VgtPublishedSourceExclusionReason -RelativePath $_.Relative)) })
    Add-Check -Name 'source-list-excludes-agent-notes' -Passed ($shippedNoteNames.Count -eq 0) -Detail (($shippedNoteNames | ForEach-Object { $_.Relative }) -join ', ')
    $sourceRelatives = @($sourceList | ForEach-Object { $_.Relative })
    Add-Check -Name 'source-list-keeps-ordinary-markdown' -Passed (($sourceRelatives -contains 'README.md') -and ($sourceRelatives -contains 'CHANGELOG.md') -and ($sourceRelatives -contains 'docs/guide.md')) -Detail ($sourceRelatives -join ', ')
    Add-Check -Name 'source-list-keeps-ordinary-script' -Passed ($sourceRelatives -contains 'src/main.ps1')

    $manifestInfo = Write-VgtSourceManifest -ProjectRoot $sourceFixture
    $manifestNoteLines = @($manifestInfo.Lines | Where-Object { $_ -match '  (?:Next\.md|GITHUB-UPLOAD\.md|RELEASE-NOTES\.md|MERGE_REPORT\.json|START_HERE_[^/]*\.md)$' })
    Add-Check -Name 'source-manifest-excludes-agent-notes' -Passed ($manifestNoteLines.Count -eq 0) -Detail (($manifestNoteLines) -join '; ')
    $manifestFileText = Get-Content -LiteralPath (Join-Path $sourceFixture 'SOURCE-MANIFEST.sha256') -Raw -Encoding UTF8
    Add-Check -Name 'source-manifest-file-excludes-next-md' -Passed (-not [Regex]::IsMatch($manifestFileText,'(?m)^[0-9a-f]{64}  Next\.md$'))
    Add-Check -Name 'source-manifest-keeps-ordinary-markdown' -Passed ([Regex]::IsMatch($manifestFileText,'(?m)^[0-9a-f]{64}  docs/guide\.md$'))

    # Structural fail-closed assertions: both the enumeration and the manifest
    # writer must actively reject an excluded path that reaches the ship set.
    $fileListBody = Get-VgtFunctionBody -Text $moduleText -FunctionName 'Get-VgtSourceFileList'
    Add-Check -Name 'file-list-has-fail-closed-note-assertion' -Passed ($fileListBody.Contains('Get-VgtPublishedSourceExclusionReason') -and $fileListBody.Contains('throw'))
    $manifestBody = Get-VgtFunctionBody -Text $moduleText -FunctionName 'Write-VgtSourceManifest'
    Add-Check -Name 'manifest-writer-has-fail-closed-note-assertion' -Passed ($manifestBody.Contains('Get-VgtPublishedSourceExclusionReason') -and $manifestBody.Contains('throw'))

    # -------------------------------------------------------------------
    # 4. Source-ZIP rule used by build/Test-GeDefenseRelease.ps1
    # -------------------------------------------------------------------
    $cleanZip = Join-Path $sandbox 'source-clean.zip'
    New-FixtureZip -Path $cleanZip -Version '5.3.0' -EntryRelativePaths @('README.md','VERSION','docs/guide.md')
    $cleanZipResult = Assert-VgtSourceArchiveExcludesAgentNotes -ArchivePath $cleanZip -Version '5.3.0'
    Add-Check -Name 'zip-rule-accepts-note-free-archive' -Passed ([string]$cleanZipResult.Status -eq 'PASS' -and [int]$cleanZipResult.Entries -eq 3) -Detail ('entries={0}' -f $cleanZipResult.Entries)

    $nextZip = Join-Path $sandbox 'source-next.zip'
    New-FixtureZip -Path $nextZip -Version '5.3.0' -EntryRelativePaths @('README.md','Next.md')
    $nextZipRejected = $false
    try { Assert-VgtSourceArchiveExcludesAgentNotes -ArchivePath $nextZip -Version '5.3.0' | Out-Null } catch { $nextZipRejected = $true }
    Add-Check -Name 'zip-rule-rejects-next-md' -Passed $nextZipRejected

    $nestedZip = Join-Path $sandbox 'source-nested-note.zip'
    New-FixtureZip -Path $nestedZip -Version '5.3.0' -EntryRelativePaths @('README.md','docs/START_HERE_RELEASE.md')
    $nestedZipRejected = $false
    try { Assert-VgtSourceArchiveExcludesAgentNotes -ArchivePath $nestedZip -Version '5.3.0' | Out-Null } catch { $nestedZipRejected = $true }
    Add-Check -Name 'zip-rule-rejects-start-here-note' -Passed $nestedZipRejected

    Add-Check -Name 'zip-rule-bounded-entry-count' -Passed ((Get-VgtZipEntryNames -ArchivePath $cleanZip -MaximumEntries 3).Count -eq 3)
    $boundedRejected = $false
    try { Get-VgtZipEntryNames -ArchivePath $cleanZip -MaximumEntries 2 | Out-Null } catch { $boundedRejected = $true }
    Add-Check -Name 'zip-rule-enforces-entry-bound' -Passed $boundedRejected

    # -------------------------------------------------------------------
    # 5. Assert-VgtReleaseChannelHygiene with the registered Inno asset
    # -------------------------------------------------------------------
    $channelVersion = '5.3.0'
    $channelRoot = Join-Path $sandbox 'channel'
    $channelRelease = Join-Path $channelRoot 'release'
    function Reset-FixtureChannel {
        if (Test-Path -LiteralPath $channelRelease) { Remove-Item -LiteralPath $channelRelease -Recurse -Force }
        New-Item -Path $channelRelease -ItemType Directory -Force | Out-Null
    }
    function Complete-FixtureChannel {
        param([string]$Version = $channelVersion)
        Reset-FixtureChannel
        New-FixtureStandaloneSet -Directory $channelRelease -Version $Version
        New-FixtureSourceArchiveSet -Directory $channelRelease -Version $Version
        New-FixtureInnoSet -Directory $channelRelease -Version $Version
        Write-FixtureSums -Directory $channelRelease
    }

    Complete-FixtureChannel
    $verifiedChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion
    Add-Check -Name 'channel-accepts-registered-inno-asset' -Passed ([string]$verifiedChannel.State -eq 'VERIFIED' -and [bool]$verifiedChannel.HasInnoInstaller -and [string]$verifiedChannel.InnoJsonState -eq 'verified') -Detail ('state={0} inno={1} json={2}' -f $verifiedChannel.State,$verifiedChannel.HasInnoInstaller,$verifiedChannel.InnoJsonState)
    Add-Check -Name 'channel-sums-cover-inno-assets' -Passed ((Get-Content -LiteralPath (Join-Path $channelRelease 'SHA256SUMS.txt') -Raw -Encoding UTF8) -match '(?m)^[0-9a-f]{64}  GeDefense-Setup-Inno-x64-v5\.3\.0\.exe\.json$')
    Add-Check -Name 'channel-sums-entry-count-matches-assets' -Passed (([int]$verifiedChannel.SumsEntries) -eq (([int]$verifiedChannel.Assets) - 1))

    Complete-FixtureChannel
    New-FixtureFile -Path (Join-Path $channelRelease 'GeDefense-Setup-Inno-x64-v5.2.9.exe') -Content 'foreign-inno'
    $foreignRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $foreignRejected = $true }
    Add-Check -Name 'channel-rejects-foreign-inno-version' -Passed $foreignRejected

    Complete-FixtureChannel
    New-FixtureFile -Path (Join-Path $channelRelease 'notes.txt') -Content 'unknown-asset'
    $unknownRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $unknownRejected = $true }
    Add-Check -Name 'channel-rejects-unknown-asset' -Passed $unknownRejected

    Complete-FixtureChannel
    New-FixtureFile -Path (Join-Path $channelRelease 'GeDefense-Setup-Inno-x64-v5.3.0.json') -Content '{"version":"5.3.0"}'
    $legacyRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $legacyRejected = $true }
    Add-Check -Name 'channel-rejects-legacy-bare-inno-sidecar' -Passed $legacyRejected

    Reset-FixtureChannel
    New-FixtureStandaloneSet -Directory $channelRelease -Version $channelVersion
    New-FixtureSourceArchiveSet -Directory $channelRelease -Version $channelVersion
    New-FixtureInnoSet -Directory $channelRelease -Version $channelVersion -WithoutSidecar
    Write-FixtureSums -Directory $channelRelease
    $missingInnoSidecarRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $missingInnoSidecarRejected = $true }
    Add-Check -Name 'channel-rejects-inno-without-sidecar' -Passed $missingInnoSidecarRejected

    Reset-FixtureChannel
    New-FixtureStandaloneSet -Directory $channelRelease -Version $channelVersion
    New-FixtureSourceArchiveSet -Directory $channelRelease -Version $channelVersion
    New-FixtureInnoSet -Directory $channelRelease -Version $channelVersion -TamperedHash
    Write-FixtureSums -Directory $channelRelease
    $tamperedInnoRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $tamperedInnoRejected = $true }
    Add-Check -Name 'channel-rejects-inno-wrong-hash' -Passed $tamperedInnoRejected

    Reset-FixtureChannel
    New-FixtureStandaloneSet -Directory $channelRelease -Version $channelVersion
    New-FixtureSourceArchiveSet -Directory $channelRelease -Version $channelVersion
    New-FixtureInnoSet -Directory $channelRelease -Version $channelVersion -WrongVersionJson
    Write-FixtureSums -Directory $channelRelease
    $wrongInnoJsonRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $wrongInnoJsonRejected = $true }
    Add-Check -Name 'channel-rejects-inno-sidecar-version-mismatch' -Passed $wrongInnoJsonRejected

    Reset-FixtureChannel
    New-FixtureStandaloneSet -Directory $channelRelease -Version $channelVersion
    New-FixtureSourceArchiveSet -Directory $channelRelease -Version $channelVersion
    New-FixtureInnoSet -Directory $channelRelease -Version $channelVersion
    Write-FixtureSums -Directory $channelRelease -ExcludeNames @(
        'GeDefense-Setup-Inno-x64-v5.3.0.exe',
        'GeDefense-Setup-Inno-x64-v5.3.0.exe.sha256',
        'GeDefense-Setup-Inno-x64-v5.3.0.exe.json'
    )
    $uncoveredInnoRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $uncoveredInnoRejected = $true }
    Add-Check -Name 'channel-rejects-sums-missing-inno' -Passed $uncoveredInnoRejected

    Complete-FixtureChannel
    Remove-Item -LiteralPath (Join-Path $channelRelease 'GeDefense-Setup-Inno-x64-v5.3.0.exe') -Force
    Write-FixtureSums -Directory $channelRelease
    $orphanInnoRejected = $false
    try { Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion | Out-Null } catch { $orphanInnoRejected = $true }
    Add-Check -Name 'channel-rejects-orphan-inno-sidecars' -Passed $orphanInnoRejected

    # The standalone-only channel (no Inno built yet) keeps working unchanged.
    Reset-FixtureChannel
    New-FixtureStandaloneSet -Directory $channelRelease -Version $channelVersion
    New-FixtureSourceArchiveSet -Directory $channelRelease -Version $channelVersion
    Write-FixtureSums -Directory $channelRelease
    $withoutInnoChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory $channelRelease -Version $channelVersion
    Add-Check -Name 'channel-accepts-standalone-only-release' -Passed ([string]$withoutInnoChannel.State -eq 'VERIFIED' -and -not [bool]$withoutInnoChannel.HasInnoInstaller)

    # Existing unknown/local file behaviour is unchanged: no directory -> ABSENT.
    $absentChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $channelRoot -ReleaseDirectory (Join-Path $channelRoot 'missing-release') -Version $channelVersion
    Add-Check -Name 'channel-absent-directory-is-not-a-fail' -Passed ([string]$absentChannel.State -eq 'ABSENT')

    # -------------------------------------------------------------------
    # 6. Static tooling contract (builder / gate / publisher)
    # -------------------------------------------------------------------
    $buildInnoText = Get-Content -LiteralPath (Join-Path $projectRoot 'build\Build-InnoInstaller.ps1') -Raw -Encoding UTF8
    Add-Check -Name 'inno-builder-uses-registered-sidecar-name' -Passed ($buildInnoText.Contains('$sidecarPath = "$installerPath.json"'))
    Add-Check -Name 'inno-builder-drops-changeextension-sidecar' -Passed (-not $buildInnoText.Contains('[IO.Path]::ChangeExtension($installerPath'))
    Add-Check -Name 'inno-builder-verifies-registered-asset-names' -Passed ($buildInnoText.Contains('Get-VgtReleaseAssetVersion'))
    Add-Check -Name 'inno-builder-rejects-stale-legacy-sidecar' -Passed ($buildInnoText.Contains('Stale legacy Inno sidecar'))

    $buildSourceText = Get-Content -LiteralPath (Join-Path $projectRoot 'build\Build-SourceRelease.ps1') -Raw -Encoding UTF8
    Add-Check -Name 'source-builder-excludes-agent-notes' -Passed ($buildSourceText.Contains('Get-VgtPublishedSourceExclusionReason') -and $buildSourceText.Contains('entered the source ZIP ship set'))

    $releaseGateText = Get-Content -LiteralPath (Join-Path $projectRoot 'build\Test-GeDefenseRelease.ps1') -Raw -Encoding UTF8
    Add-Check -Name 'release-gate-no-longer-forbids-next-md' -Passed (-not $releaseGateText.Contains("'Next.md'"))
    Add-Check -Name 'release-gate-checks-source-archive-notes' -Passed ($releaseGateText.Contains('Assert-VgtSourceArchiveExcludesAgentNotes'))

    $publishText = Get-Content -LiteralPath (Join-Path $projectRoot 'build\Publish-GitHubRelease.ps1') -Raw -Encoding UTF8
    Add-Check -Name 'publisher-registers-inno-name' -Passed ($publishText.Contains('$innoExeName') -and $publishText.Contains('GeDefense-Setup-Inno-x64-'))
    Add-Check -Name 'publisher-inno-assets-are-conditional' -Passed ($publishText.Contains('if ($hasInnoInstaller)') -and $publishText.Contains('$sumsAssets +=') -and $publishText.Contains('$assetsToUpload +='))
    Add-Check -Name 'publisher-verifies-inno-asset-hash' -Passed ($publishText.Contains('Assert-VgtAssetHash -Path $innoExePath'))
    Add-Check -Name 'publisher-has-no-force-bypass' -Passed (-not [Regex]::IsMatch($publishText,'(?i)\[switch\]\$Force'))

    $channelBody = Get-VgtFunctionBody -Text $moduleText -FunctionName 'Assert-VgtReleaseChannelHygiene'
    Add-Check -Name 'channel-gate-requires-inno-sidecar' -Passed ($channelBody.Contains('GeDefense-Setup-Inno-x64-v'))
    Add-Check -Name 'channel-gate-rejects-foreign-and-unknown' -Passed ($channelBody.Contains('foreign-version artifacts') -and $channelBody.Contains('unrecognised artifacts'))

    # -------------------------------------------------------------------
    # 7. FIND-WIN-022 prerelease downgrade guard (verify, do not modify)
    # -------------------------------------------------------------------
    $installerPath = Join-Path $projectRoot 'installer\Install-GeDefense.ps1'
    $installerText = Get-Content -LiteralPath $installerPath -Raw -Encoding UTF8
    Add-Check -Name 'installer-uses-prerelease-compare' -Passed ($installerText.Contains('Compare-VgtVersionParts -Left $newParts -Right $oldParts') -and $installerText.Contains('Prerelease'))
    $versionFunctions = @('ConvertTo-VgtVersionParts','Compare-VgtVersionParts')
    $versionAst = Get-VgtParsedAst -Path $installerPath
    $versionNodes = @($versionAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $versionFunctions -contains $node.Name },$true))
    Add-Check -Name 'installer-downgrade-functions-present' -Passed ($versionNodes.Count -eq 2)
    foreach ($functionNode in $versionNodes) { . ([scriptblock]::Create($functionNode.Extent.Text)) }
    $downgradeCases = @(
        @('5.3.1-beta.2','5.3.1',1),
        @('5.3.1','5.3.1-beta.2',-1),
        @('5.3.2','5.3.1',-1),
        @('5.3.1','5.3.2',1),
        @('5.3.0-beta.2','5.3.0',1),
        @('5.3.1-beta.2','5.3.1-beta.10',1),
        @('5.3.1-beta.10','5.3.1-beta.2',-1),
        @('5.3.0','5.3.0',0),
        @('5.2.9','5.3.0-beta.2',1)
    )
    foreach ($case in $downgradeCases) {
        $oldParts = ConvertTo-VgtVersionParts -Value $case[0]
        $newParts = ConvertTo-VgtVersionParts -Value $case[1]
        $sign = if ($null -eq $oldParts -or $null -eq $newParts) { -99 } else { [Math]::Sign((Compare-VgtVersionParts -Left $newParts -Right $oldParts)) }
        Add-Check -Name ('downgrade-' + $case[0] + '-vs-' + $case[1]) -Passed ($sign -eq [int]$case[2]) -Detail ('expected={0} actual={1}' -f $case[2],$sign)
    }

    [pscustomobject][ordered]@{
        Status = 'PASS'
        Mode = 'functional+static'
        Checks = $checks.Count
        ParserFiles = $parserFiles.Count
        AssetMatrixCases = $assetMatrix.Count
        ChannelScenarios = 12
        VersionGuard = 'verified (FIND-WIN-022 fix already present; installer not modified by this suite)'
        Results = $checks.ToArray()
    }
} finally {
    if (Test-Path -LiteralPath $sandbox) { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
}
