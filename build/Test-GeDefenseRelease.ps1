# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$versionPath = Join-Path $projectRoot 'VERSION'

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
Assert-Vgt ($version -match '^4\.0\.0-beta\.[1-9][0-9]*$') 'VERSION is not a valid GeDefense V4 beta version.'

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
$goVersion = (& go env GOVERSION).Trim()
Assert-Vgt ($LASTEXITCODE -eq 0) 'Unable to read the Go toolchain version.'
Assert-Vgt ($goVersion -eq ('go' + $toolchain['go'])) ("Official release requires Go {0}; detected {1}." -f $toolchain['go'],$goVersion)
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

$sbom = Read-VgtText (Join-Path $projectRoot 'sbom\gedefense-windows.cdx.json') | ConvertFrom-Json
Assert-Vgt ($sbom.metadata.component.version -eq $version) 'SBOM version mismatch.'
Assert-Vgt (@($sbom.components).Count -eq 0) 'SBOM contains third-party code components despite zero-Go-dependency contract.'

Push-Location $sourceRoot
try {
    $modules = @(& go list -m all)
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('go list -m all failed.') }
    Assert-Vgt ($modules.Count -eq 1) 'External Go modules detected by go list -m all.'

    $goFiles = @(Get-ChildItem -LiteralPath '.\cmd','.\internal' -Recurse -File -Filter '*.go' | Sort-Object FullName | ForEach-Object FullName)
    $unformatted = @(& gofmt -l @goFiles)
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('gofmt validation failed.') }
    Assert-Vgt ($unformatted.Count -eq 0) ('Unformatted Go files: ' + ($unformatted -join ', '))

    & go test -race ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Go race tests failed.') }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('go vet failed.') }

    $buildRoot = Join-Path $env:TEMP ('vgt-gedefense-releasecheck-' + [Guid]::NewGuid().ToString('N'))
    New-Item -Path $buildRoot -ItemType Directory -Force | Out-Null
    try {
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
    WindowsBuilds = 4
    PowerShell = 'PASS'
    FrontendSecurity = 'PASS'
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDE7iczYvzks8Sx
# XSxYYUk0kQdJB+WUQml/ZO5/IvznJ6CCBCwwggQoMIICkKADAgECAhBc5F62BB+R
# m08OD57tPeOLMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEg
# VGVjaG5vbG9neSBWR1QgUmVsZWFzZTAeFw0yNjA4MjExMzUyNDFaFw0zNjA4MjEx
# MjAyNDBaMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEgVGVjaG5vbG9neSBWR1QgUmVs
# ZWFzZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAL5pFqzqfhSchgN3
# OSKoeRbHXQIUtVwI7Q5go/7UvOFVMV0d/Au5Q5yPFOr351VqQyZlLWehwPG88Wdh
# TEPxfzYXDeJFgG6MwdjVaA10WklxDzSu8XQQzQKvoSOtf6b76xYswPdR8WaUOvYL
# NVYHG38cZCE/Vmt8W29/+8bT0SFoMv8S++3YUL3BaTTVBj5wcunaQYu7bcBUFz8M
# wCWGaqZUwWi/7sZPb5Ix0KKnMarxxAAM/y1GaRnWDQavGSuFZ18LmMh+Agd6znFZ
# 6pH1USuu0NreFUOWNg2ANEmGAO4XTnst3ILT4Eab/Jsjmw4nRm8rckRaWVKJxcRc
# P7ukJJi3cV11JegdsYSBGKvZ8TUNiSRuVI0MGg1IJl4ga/dir1crp0DnqezcC/6y
# 9mxsnxuJLpW8I1nLdRLjE1ow5VshhvEMFjPoYbcowpcI0EUFj/clBpA+rHjPjkYF
# jw8oow+tYqnEK/GkrYkzGwGxpApKcECh5GGHgQ5iSgKuNTPueQIDAQABo0YwRDAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFDBP
# H8Z9qi6vrLw8FPD3k/kz+c1gMA0GCSqGSIb3DQEBCwUAA4IBgQBIQe+HN5spItMd
# 884eV6JR3H8xGr8DeNpgjuhQnRnQqWB60Et6ehQwQFDg5Ft8iU4sGzdEQB4U+q79
# 9oReJ6G1CuV6yXXqDe/Ljr5DGfGr+Wah4RuRi/QGhUUeIyyn8h5kXwOgGWz4VA5I
# 9CmN+onZHRLnv3Lu9mKyUqo7ll5WaWEd/r3hvBqe30Rg0IanD8qpWXEbshlayTux
# 8WMgjW3nA7tEWXmToCJpRk8DsaGU5m6rNxVa6zSS7qF2JiMWnZZBsr76cQsMYvTk
# ZgshPz+OTsl84mR7i/BalTIyuI74TWd+8LdcBB+FpmhXvYmKAPQKQg25dHGWbVlB
# E7kK29X38hvaQBO6lVT7mtTOPx2auMTmas6LLU+1XGFNm4zvwuydpf/4ltPSYlNp
# K8Ij5vkp2DjXOaJF02BoqBkZt6w4wQPuCdu3OOTH3A3hymQrVD0tP408qNkLuzd5
# xI+m7oTQCw6SYCxeEUEOooR7XMWuxE1R/KyLlPRCI1zi9DjhLawxggJyMIICbgIB
# ATBAMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEgVGVjaG5vbG9neSBWR1QgUmVsZWFz
# ZQIQXORetgQfkZtPDg+e7T3jizANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDpj5R4kFYv
# bfR03YbIUTDLU12YzMVkbrDMmGQMrO3mEzANBgkqhkiG9w0BAQEFAASCAYAPV2zz
# RVxsGygmCnjhx2qLCdWXxMzEdsPcbFY9cVIcV3hq+FT5mJtc5Nrt5aUEe2RM7wZ5
# eyVKWizFu5AdTNGSKnC3d2Pt8NxuUkS/UmA11qXfyeBXE575qqZbIYN3c0TiN6Lt
# 2mwMIwY3Ku65wbYe7zxb7LgYh6H4UrSbwje1IUnrfTUuY4NItdjEsgDiJm3SMA0T
# xLass9k6I0TGfKs1R3hIt1BQSqaq55Lp8NHoqwnKORmf3WmWoP7bB/JzeFpvdxUq
# c6soxdoKM90AwHA4y0Se3quLzVVG6q9W/ViLTNs956oNfyxEFWo1yKMaZVfCMOII
# cFmZQQSriGKnMWulM6xGmWXLq0zkkynjpUcjf90Zc2rsvUL2PERKIlLfhNpdRpqe
# /s7C9J58z2CYLJcTCJFPTBXok1nwTo4TBQfl6vQsQ28XfGvunMKbvAoZn5IpnJgl
# X4jKUUuMktG+9iX3rS6Mj21n67/4/D4ygTYb4NOi6nV/YhBUJUgotBz7XXg=
# SIG # End signature block
