# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [switch]$TrustDevelopmentCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$payloadRoot = Join-Path $projectRoot 'payload\VGT\GeDefense'
$bundleRoot = Join-Path $projectRoot 'work\standalone-bundle'
$bundlePayload = Join-Path $bundleRoot 'payload'
$embeddedBundleDirectory = Join-Path $sourceRoot 'cmd\gedefense-installer\bundle'
$embeddedBundle = Join-Path $embeddedBundleDirectory 'payload.zip'
$releaseRoot = Join-Path $projectRoot 'release'
$releaseExecutable = Join-Path $releaseRoot 'GeDefense-Setup-x64-v2.3.2.exe'
$releaseManifest = Join-Path $releaseRoot 'GeDefense-Setup-x64-v2.3.2.json'
$thumbprintFile = Join-Path $projectRoot 'certificates\release-thumbprint.txt'

function Assert-VgtChildPath {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Parent)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolvedPath.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Standalone build path escaped the VGT workspace.') }
}

Assert-VgtChildPath -Path $bundleRoot -Parent $projectRoot
Assert-VgtChildPath -Path $embeddedBundle -Parent $projectRoot
Assert-VgtChildPath -Path $releaseExecutable -Parent $projectRoot
& (Join-Path $PSScriptRoot 'Build-VgtPayload.ps1') -TrustDevelopmentCertificate:$TrustDevelopmentCertificate
if (-not (Test-Path -LiteralPath $payloadRoot -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Signed GeDefense payload was not produced.') }

if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }
New-Item -Path $bundleRoot,$embeddedBundleDirectory,$releaseRoot -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath $payloadRoot -Destination $bundlePayload -Recurse -Force
if (Test-Path -LiteralPath $embeddedBundle) { Remove-Item -LiteralPath $embeddedBundle -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($bundleRoot,$embeddedBundle,[IO.Compression.CompressionLevel]::Optimal,$false)
if ((Get-Item -LiteralPath $embeddedBundle).Length -gt 134217728) { throw [IO.InvalidDataException]::new('Embedded installer payload exceeds the 128 MiB release boundary.') }

Push-Location $sourceRoot
try {
    & gofmt -w '.\cmd\gedefense-installer\main.go' '.\cmd\gedefense-center\main.go' '.\cmd\gedefense-tray\main.go' '.\internal\app\app.go' '.\internal\audit\engine.go' '.\internal\launcher\launcher_windows.go' '.\internal\scriptengine\engine.go' '.\internal\server\server.go' '.\internal\server\server_test.go' '.\internal\winexec\powershell.go' '.\internal\xdr\engine.go'
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Go formatting failed.') }
    & go test -race -tags vgt_bundle ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone GeDefense tests failed.') }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone GeDefense static analysis failed.') }
    if (Test-Path -LiteralPath $releaseExecutable) { Remove-Item -LiteralPath $releaseExecutable -Force }
    & go build -tags vgt_bundle -trimpath -ldflags '-s -w -H=windowsgui' -o $releaseExecutable ./cmd/gedefense-installer
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Standalone installer compilation failed.') }
} finally { Pop-Location }

$thumbprint = (Get-Content -LiteralPath $thumbprintFile -Raw -Encoding UTF8).Trim()
if ($thumbprint -notmatch '^[A-F0-9]{40}$') { throw [Security.SecurityException]::new('Release certificate thumbprint is invalid.') }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
Set-AuthenticodeSignature -LiteralPath $releaseExecutable -Certificate $certificate -HashAlgorithm SHA256 | Out-Null
$verifiedSignature = Get-AuthenticodeSignature -LiteralPath $releaseExecutable
$acceptedStatuses = if ($TrustDevelopmentCertificate) { @('Valid') } else { @('Valid','NotTrusted','UnknownError') }
if (-not $verifiedSignature.SignerCertificate -or $verifiedSignature.SignerCertificate.Thumbprint -ne $thumbprint -or [string]$verifiedSignature.Status -notin $acceptedStatuses) { throw [Security.SecurityException]::new('Standalone installer signature verification failed.') }

$release = [ordered]@{
    product = 'VGT GeDefense Security Center'
    version = '2.3.2-vgt.win17'
    architecture = 'x64'
    bytes = (Get-Item -LiteralPath $releaseExecutable).Length
    sha256 = (Get-FileHash -LiteralPath $releaseExecutable -Algorithm SHA256).Hash
    signerThumbprint = $thumbprint
    signature = [string]$verifiedSignature.Status
    builtUtc = [DateTime]::UtcNow.ToString('o')
}
$release | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $releaseManifest -Encoding UTF8
$release
