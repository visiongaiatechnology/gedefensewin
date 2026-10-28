# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$versionPath = Join-Path $projectRoot 'VERSION'
$toolsRoot = Join-Path $projectRoot 'tools'
Import-Module -Name (Join-Path $toolsRoot 'VgtSupplyChain.psm1') -Force
Import-Module -Name (Join-Path $projectRoot 'build\PublishVerification.psm1') -Force

function Assert-Vgt {
    param([Parameter(Mandatory)][bool]$Condition,[Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw [InvalidOperationException]::new($Message) }
}

function Read-VgtText {
    param([Parameter(Mandatory)][string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ($null -eq $text) { return '' }
    return $text
}

$version = (Read-VgtText $versionPath).Trim()
Assert-Vgt ($version -match '^5\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$') 'VERSION is not a valid GeDefense V5 version.'

$toolchainPath = Join-Path $projectRoot 'TOOLCHAINS.lock'
$toolchain = @{}
foreach ($line in Get-Content -LiteralPath $toolchainPath -Encoding UTF8) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $parts = $trimmed.Split('=',2)
    if ($parts.Count -ne 2) { throw [IO.InvalidDataException]::new('TOOLCHAINS.lock contains an invalid entry.') }
    $toolchain[$parts[0].Trim()] = $parts[1].Trim()
}
Assert-Vgt ($toolchain.ContainsKey('go')) 'Pinned Go release toolchain is missing.'
Assert-Vgt ($toolchain.ContainsKey('powershell')) 'Pinned PowerShell release toolchain is missing.'
Assert-Vgt (([string]$toolchain['go_windows_amd64_zip_sha256']) -match '^[0-9a-fA-F]{64}$') 'Pinned Go toolchain archive hash is missing or invalid.'
$goVersion = (& go env GOVERSION).Trim()
Assert-Vgt ($LASTEXITCODE -eq 0) 'Unable to read the Go toolchain version.'
$requiredGo = $toolchain['go'].TrimStart('g','o')
$actualGo = $goVersion.TrimStart('g','o')
try {
    Assert-Vgt ([version]$actualGo -ge [version]$requiredGo) ("Official release requires Go >= {0}; detected {1}." -f $requiredGo,$goVersion)
} catch {
    throw [InvalidOperationException]::new(("Unable to compare Go toolchain versions: pinned={0}, detected={1}." -f $requiredGo,$goVersion))
}
Assert-Vgt ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Official release requires Windows PowerShell 5.1.'
Assert-Vgt ([Environment]::Is64BitProcess) 'Official release gate requires a 64-bit Windows PowerShell process.'

$goModPath = Join-Path $sourceRoot 'go.mod'
$goSumPath = Join-Path $sourceRoot 'go.sum'
$goMod = Read-VgtText $goModPath
Assert-Vgt (-not [Regex]::IsMatch($goMod,'(?m)^\s*require(?:\s|\()')) 'External Go module dependency detected in go.mod.'
Assert-Vgt ((Get-Item -LiteralPath $goSumPath).Length -eq 0) 'go.sum must remain empty for the zero-Go-dependency release.'
Assert-Vgt (-not (Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'cmd') -Recurse -File | Where-Object { $_.Extension -in '.rc','.syso' })) 'Legacy Windows resource compiler artifacts detected.'

$productVersionFile = Join-Path $sourceRoot 'internal\product\version.go'
$productVersionSource = Read-VgtText $productVersionFile
Assert-Vgt ($productVersionSource.Contains('const Version = "' + $version + '"')) 'Go product version does not match VERSION.'

# Clean-source repository contract: generated build output and AI-agent handoff
# artifacts are gitignored and must never be part of the delivered source tree.
# CHANGELOG.md is intentionally public documentation as of 5.3.0.
$forbiddenRepositoryFiles = @(
    'Next.md',
    'MERGE_REPORT.json',
    'START_HERE_FULL_MERGED_SOURCE.md',
    'GITHUB-UPLOAD.md',
    'RELEASE-NOTES.md'
)
foreach ($forbiddenFile in $forbiddenRepositoryFiles) {
    Assert-Vgt (-not (Test-Path -LiteralPath (Join-Path $projectRoot $forbiddenFile))) ("Repository hygiene violation: {0} must not be part of the source tree." -f $forbiddenFile)
}
foreach ($forbiddenPattern in @('docs\VERIFICATION-*.md','docs\AUDIT-REMEDIATION-*.md','docs\SUPPLY-CHAIN-*.md','docs\TRUST-*.md')) {
    $hits = @(Get-ChildItem -Path (Join-Path $projectRoot $forbiddenPattern) -File -ErrorAction SilentlyContinue)
    Assert-Vgt ($hits.Count -eq 0) ("Repository hygiene violation: legacy report artifacts present ({0})." -f $forbiddenPattern)
}
Assert-Vgt (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'docs\patch-history'))) 'Repository hygiene violation: docs/patch-history must not be part of the source tree.'
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'SOURCE-MANIFEST.sha256'))) {
    $null = Write-VgtSourceManifest -ProjectRoot $projectRoot
}
$payloadBuilderSource = Read-VgtText (Join-Path $projectRoot 'build\Build-VgtPayload.ps1')
Assert-Vgt ($payloadBuilderSource.Contains("'VERSION'")) 'Payload builder does not include VERSION metadata.'
Assert-Vgt ($payloadBuilderSource.Contains('function Get-VgtSigningCertificate')) 'Payload builder signing-certificate gate is missing.'
Assert-Vgt ($payloadBuilderSource.Contains('function Copy-VgtTree')) 'Payload builder tree-copy gate is missing.'
Assert-Vgt ($payloadBuilderSource.Contains('$publicCertificate')) 'Payload builder public-certificate export is missing.'
$installerSource = Read-VgtText (Join-Path $projectRoot 'installer\Install-GeDefense.ps1')
Assert-Vgt ($installerSource.Contains('$releaseVersion')) 'Installer does not consume verified release version metadata.'
Assert-Vgt (-not $installerSource.Contains('Cert:\LocalMachine\Root')) 'Installer must never self-root an embedded release certificate.'
$goInstallerSource = Read-VgtText (Join-Path $sourceRoot 'cmd\gedefense-installer\main.go')
Assert-Vgt (-not $goInstallerSource.Contains('"Bypass"')) 'Installer bootstrap must never execute PowerShell with ExecutionPolicy Bypass.'
Assert-Vgt ($goInstallerSource.Contains('"AllSigned"')) 'Installer bootstrap must require ExecutionPolicy AllSigned.'
$mhxEngineSource = Read-VgtText (Join-Path $sourceRoot 'internal\mhx\engine.go')
Assert-Vgt ($mhxEngineSource.Contains('protectionHealth')) 'Protection-health state is missing from MHX.'
Assert-Vgt ($mhxEngineSource.Contains('policyGate')) 'Global policy mutation gate is missing from MHX.'
$watcherSource = Read-VgtText (Join-Path $sourceRoot 'internal\mhx\watcher_windows.go')
Assert-Vgt (-not $watcherSource.Contains('exec.LookPath')) 'Privileged MHX telemetry must not resolve PowerShell through PATH.'
$winexecSource = Read-VgtText (Join-Path $sourceRoot 'internal\winexec\powershell.go')
Assert-Vgt ($winexecSource.Contains('System32')) 'Validated system PowerShell resolver is missing.'
$bootstrapSource = Read-VgtText (Join-Path $projectRoot 'installer\Bootstrap-GeDefense.ps1')
Assert-Vgt ($bootstrapSource.Contains('Get-AuthenticodeSignature -LiteralPath $resolvedInstaller')) 'Bootstrap does not anchor trust in the outer installer signature.'
Assert-Vgt (-not $bootstrapSource.Contains('Cert:\CurrentUser\Root')) 'Bootstrap must never self-root an embedded release certificate.'

$forbiddenDependencies = @(
    ('fyne.io/' + 'systray'),
    ('github.com/jchv/' + 'go-webview2'),
    ('golang.org/x/' + 'sys'),
    ('github.com/godbus/' + 'dbus'),
    ('github.com/jchv/' + 'go-winloader'),
    ('Web' + 'View2')
)
$scanExtensions = @('.go','.js','.css','.html','.md','.ps1','.psm1','.json','.mod','.sum')
$scanRoots = @(
    $sourceRoot,
    (Join-Path $projectRoot 'engine'),
    (Join-Path $projectRoot 'xdr'),
    (Join-Path $projectRoot 'installer'),
    (Join-Path $projectRoot 'build')
)
$scanFiles = @(Get-ChildItem -LiteralPath $scanRoots -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/](?:work|release|payload|certificates)[\\/]' -and $scanExtensions -contains $_.Extension
})
foreach ($file in $scanFiles) {
    $content = Read-VgtText $file.FullName
    foreach ($forbidden in $forbiddenDependencies) {
        Assert-Vgt (-not $content.Contains($forbidden)) ("Forbidden legacy dependency reference '{0}' in {1}." -f $forbidden,$file.FullName)
    }
}

$webRoot = Join-Path $sourceRoot 'internal\server\web'
$webFiles = @(Get-ChildItem -LiteralPath $webRoot -Recurse -File -Include *.js,*.css,*.html)
foreach ($file in $webFiles) {
    $content = Read-VgtText $file.FullName
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?i)https?://')) ("External web resource reference in {0}." -f $file.FullName)
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?i)\beval\s*\(')) ("eval() is forbidden in {0}." -f $file.FullName)
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?i)\bnew\s+Function\s*\(')) ("Dynamic Function construction is forbidden in {0}." -f $file.FullName)
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?i)\b(?:localStorage|sessionStorage)\b')) ("Persistent browser storage is forbidden in {0}." -f $file.FullName)
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?i)\b(?:console\.log|debugger)\b')) ("Debug frontend code detected in {0}." -f $file.FullName)
}

$productRoots = @(
    $sourceRoot,
    (Join-Path $projectRoot 'xdr'),
    (Join-Path $projectRoot 'engine'),
    (Join-Path $projectRoot 'audit'),
    (Join-Path $projectRoot 'installer')
)
$productFiles = @(Get-ChildItem -LiteralPath $productRoots -Recurse -File -ErrorAction Stop | Where-Object { $_.Extension -in '.go','.ps1','.psm1','.js' })
foreach ($file in $productFiles) {
    $content = Read-VgtText $file.FullName
    Assert-Vgt (-not [Regex]::IsMatch($content,'(?im)^\s*(?://|#).*\b(?:TODO|FIXME)\b')) ("TODO/FIXME detected in production source: {0}." -f $file.FullName)
}

# SC-FIND-004: the SBOM must be a real, current component inventory. The former
# "components == 0" contract is replaced by generation + validation + a
# freshness comparison against the checked-in release SBOM.
$sbomGenerator = Join-Path $toolsRoot 'New-VgtSbom.ps1'
$sbomValidator = Join-Path $toolsRoot 'Test-VgtSbom.ps1'
Assert-Vgt (Test-Path -LiteralPath $sbomGenerator -PathType Leaf) 'SBOM generator tools/New-VgtSbom.ps1 is missing.'
Assert-Vgt (Test-Path -LiteralPath $sbomValidator -PathType Leaf) 'SBOM validator tools/Test-VgtSbom.ps1 is missing.'
$sbomTempDirectory = Join-Path $env:TEMP ('vgt-release-sbom-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $sbomTempDirectory -ItemType Directory -Force | Out-Null
try {
    $sbomTempPath = Join-Path $sbomTempDirectory 'gedefense-windows.cdx.json'
    & $sbomGenerator -OutputPath $sbomTempPath | Out-Null
    $sbomValidation = & $sbomValidator -Path $sbomTempPath
    Assert-Vgt ([int]$sbomValidation.Components -ge 30) 'Generated SBOM contains too few real components.'
    Assert-Vgt ($sbomValidation.Version -eq $version) 'Generated SBOM version mismatch.'
} finally {
    if (Test-Path -LiteralPath $sbomTempDirectory) { Remove-Item -LiteralPath $sbomTempDirectory -Recurse -Force }
}

# SC-FIND-005: reproducible offline provenance must be generatable, verifiable
# and tamper-evident on the very tree that is being released.
$provenanceGenerator = Join-Path $toolsRoot 'New-VgtProvenance.ps1'
$provenanceValidator = Join-Path $toolsRoot 'Test-VgtProvenance.ps1'
Assert-Vgt (Test-Path -LiteralPath $provenanceGenerator -PathType Leaf) 'Provenance generator tools/New-VgtProvenance.ps1 is missing.'
Assert-Vgt (Test-Path -LiteralPath $provenanceValidator -PathType Leaf) 'Provenance verifier tools/Test-VgtProvenance.ps1 is missing.'
$provenanceTempDirectory = Join-Path $env:TEMP ('vgt-release-provenance-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $provenanceTempDirectory -ItemType Directory -Force | Out-Null
try {
    $provenanceTempPath = Join-Path $provenanceTempDirectory ('GeDefense-Provenance-v{0}.json' -f $version)
    & $provenanceGenerator -OutputPath $provenanceTempPath | Out-Null
    $provenanceValidation = & $provenanceValidator -Path $provenanceTempPath -AllowMissingArtifacts
    Assert-Vgt ([string]$provenanceValidation.Signature -eq 'unsigned-local-provenance') 'Provenance artifact must state that it is unsigned.'
    Assert-Vgt ([string]$provenanceValidation.ExternalTrustAnchor -eq 'EXTERNAL-BLOCKER') 'Provenance artifact must record the external trust-anchor blocker.'
    $provenanceDocument = Get-Content -LiteralPath $provenanceTempPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $tamperedProvenancePath = Join-Path $provenanceTempDirectory 'tampered-provenance.json'
    $provenanceDocument.sourceTree.sha256 = ('0' * 64)
    $provenanceDocument | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tamperedProvenancePath -Encoding UTF8
    $tamperRejected = $false
    try { & $provenanceValidator -Path $tamperedProvenancePath -AllowMissingArtifacts | Out-Null } catch { $tamperRejected = $true }
    Assert-Vgt $tamperRejected 'Provenance verifier accepted a tampered source-tree digest.'
} finally {
    if (Test-Path -LiteralPath $provenanceTempDirectory) { Remove-Item -LiteralPath $provenanceTempDirectory -Recurse -Force }
}

# SC-FIND-002 / SC-FIND-006: distribution/key hygiene, one authoritative
# manifest, no stale FULL_SOURCE_SHA256.txt in the packaging path.
$hygieneScript = Join-Path $toolsRoot 'Test-DistributionHygiene.ps1'
Assert-Vgt (Test-Path -LiteralPath $hygieneScript -PathType Leaf) 'Distribution hygiene scanner is missing.'
$hygiene = & $hygieneScript -ProjectRoot $projectRoot
Assert-Vgt ([string]$hygiene.Status -eq 'PASS') 'Distribution hygiene scan did not pass.'
Assert-Vgt (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'FULL_SOURCE_SHA256.txt'))) 'Stale FULL_SOURCE_SHA256.txt is present; only SOURCE-MANIFEST.sha256 is authoritative.'
$manifestWords = @(Get-ChildItem -LiteralPath $projectRoot -File -Force | Where-Object { $_.Name -match '(?i)sha256|checksum' })
Assert-Vgt ($manifestWords.Count -le 1) 'At most one integrity manifest may exist at the repository root.'
if ($manifestWords.Count -eq 1) { Assert-Vgt ($manifestWords[0].Name -eq 'SOURCE-MANIFEST.sha256') 'The only repository manifest must be SOURCE-MANIFEST.sha256.' }

# SC-FIND-003: one release channel for exactly the current VERSION. Foreign
# version EXEs/source archives and unknown assets are a hard failure, current
# binaries/archives need matching .sha256 sidecars and a publishable channel
# needs a complete SHA256SUMS.txt (including the SBOM and provenance assets).
# A missing release directory is ABSENT (this gate also runs before the
# artifact build); an intermediate build is PARTIAL, not a PASS.
try {
    $releaseChannel = Assert-VgtReleaseChannelHygiene -ProjectRoot $projectRoot -Version $version
} catch {
    $recoveryHint = ' Recovery: build the source archive with build/Build-SourceRelease.ps1 BEFORE build/Build-GeDefenseStandalone.ps1; remove a stale release/SHA256SUMS.txt before rebuilding so the checksum manifest is regenerated for the final asset set.'
    throw [InvalidOperationException]::new(($_.Exception.Message + $recoveryHint))
}
$releaseSidecarState = 'not-applicable'
if ($releaseChannel.HasInstaller) {
    $releaseSidecarPath = Join-Path ([string]$releaseChannel.ReleaseDirectory) ('GeDefense-Setup-x64-v{0}.json' -f $version)
    $releaseExecutablePath = Join-Path ([string]$releaseChannel.ReleaseDirectory) ('GeDefense-Setup-x64-v{0}.exe' -f $version)
    $releaseSidecarBinding = Assert-VgtReleaseSidecarBinding -SidecarPath $releaseSidecarPath -ReleaseDirectory ([string]$releaseChannel.ReleaseDirectory) -ExpectedVersion $version
    [void](Assert-VgtJsonManifestMatchesAsset -ManifestPath $releaseSidecarPath -AssetPath $releaseExecutablePath -ExpectedVersion $version)
    $releaseSidecarState = 'verified'
}
$sourceArchiveState = 'not-present'
if ($releaseChannel.HasSourceArchive) {
    $sourceArchivePath = Join-Path ([string]$releaseChannel.ReleaseDirectory) ('VGT_GeDefense_Windows_{0}_Source.zip' -f $version)
    $sourceArchiveFreshness = Assert-VgtSourceArchiveFreshness -ProjectRoot $projectRoot -ArchivePath $sourceArchivePath -Version $version
    $sourceArchiveState = 'verified'
}

# SC-FIND-008 / SC-FIND-011: installer reparse-point primitives and the static
# hardening sequence (journal deletion is never counted as a live install test).
& (Join-Path $toolsRoot 'Test-InstallerSafety.ps1') | Out-Null
& (Join-Path $toolsRoot 'Test-InstallerHardening.ps1') | Out-Null

# SC-FIND-009: publish path is fail-closed and contains no hardcoded claims.
& (Join-Path $toolsRoot 'Test-PublishGates.ps1') | Out-Null

Push-Location $sourceRoot
try {
    $modules = @(& go list -m all)
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('go list -m all failed.') }
    Assert-Vgt ($modules.Count -eq 1) 'External Go modules detected by go list -m all.'

    $goFiles = @(Get-ChildItem -LiteralPath '.\cmd','.\internal' -Recurse -File -Filter '*.go' | Sort-Object FullName | ForEach-Object FullName)
    $unformatted = @()
    for ($offset = 0; $offset -lt $goFiles.Count; $offset += 40) {
        $batch = @($goFiles[$offset..([Math]::Min($offset + 39,$goFiles.Count - 1))])
        $unformatted += @(& gofmt -l @batch)
        if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('gofmt validation failed.') }
    }
    Assert-Vgt ($unformatted.Count -eq 0) ('Unformatted Go files: ' + ($unformatted -join ', '))

    & go test -race ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Go race tests failed.') }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('go vet failed.') }

    $buildRoot = Join-Path $env:TEMP ('vgt-gedefense-releasecheck-' + [Guid]::NewGuid().ToString('N'))
    New-Item -Path $buildRoot -ItemType Directory -Force | Out-Null
    try {
        $govulncheck = Get-Command govulncheck -ErrorAction SilentlyContinue
        Assert-Vgt ($null -ne $govulncheck) 'Official release requires govulncheck for binary vulnerability scanning.'
        $targets = @(
            @{Name='service';Package='./cmd/gedefense-windows';Gui=$false},
            @{Name='center';Package='./cmd/gedefense-center';Gui=$true},
            @{Name='tray';Package='./cmd/gedefense-tray';Gui=$true},
            @{Name='installer';Package='./cmd/gedefense-installer';Gui=$true}
        )
        foreach ($target in $targets) {
            $output = Join-Path $buildRoot ($target.Name + '.exe')
            $ldflags = '-s -w'
            if ($target.Gui) { $ldflags += ' -H=windowsgui' }
            & go build -trimpath -ldflags $ldflags -o $output $target.Package
            if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new("Build failed for $($target.Name).") }
            Assert-Vgt ((Get-Item -LiteralPath $output).Length -gt 0) ("Empty binary produced for {0}." -f $target.Name)
            & $govulncheck.Source -mode=binary $output | Out-Host
            if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new("govulncheck reported a reachable vulnerability in $($target.Name).") }
        }
    } finally {
        if (Test-Path -LiteralPath $buildRoot) { Remove-Item -LiteralPath $buildRoot -Recurse -Force }
    }
} finally {
    Pop-Location
}

$scripts = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'audit'),(Join-Path $projectRoot 'engine'),(Join-Path $projectRoot 'xdr'),(Join-Path $projectRoot 'installer'),(Join-Path $projectRoot 'build'),(Join-Path $projectRoot 'tools') -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1' })
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$errors)
    Assert-Vgt (@($errors).Count -eq 0) ("PowerShell parse failure in {0}: {1}" -f $script.FullName,($errors | Out-String))
}

[pscustomobject]@{
    Status = 'PASS'
    Version = $version
    GoModules = 0
    GoRace = 'PASS'
    GoVet = 'PASS'
    Govulncheck = 'PASS'
    WindowsBuilds = 4
    PowerShell = 'PASS'
    FrontendSecurity = 'PASS'
    Sbom = 'PASS'
    Provenance = 'PASS'
    DistributionHygiene = 'PASS'
    ReleaseChannel = [string]$releaseChannel.State
    ReleaseChannelAssets = [int]$releaseChannel.Assets
    ReleaseChannelForeignAssets = @($releaseChannel.ForeignAssets).Count
    Sha256Sums = [string]$releaseChannel.SumsState
    ReleaseSidecar = $releaseSidecarState
    SourceArchive = $sourceArchiveState
    InstallerSafety = 'PASS'
    PublishGates = 'PASS'
    ExternalTrustAnchor = 'EXTERNAL-BLOCKER (public CA/RFC3161/revocation/anti-rollback unavailable)'
}
