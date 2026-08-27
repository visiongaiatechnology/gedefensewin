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
$certificateDirectory = Join-Path $projectRoot 'certificates'
$thumbprintFile = Join-Path $certificateDirectory 'release-thumbprint.txt'
$iconPath = Join-Path $projectRoot 'branding\gedefense.ico'

$resolvedPayloadParent = [IO.Path]::GetFullPath((Join-Path $projectRoot 'payload')).TrimEnd('\') + '\'
$resolvedPayloadRoot = [IO.Path]::GetFullPath($payloadRoot)
if (-not $resolvedPayloadRoot.StartsWith($resolvedPayloadParent,[StringComparison]::OrdinalIgnoreCase)) {
    throw [Security.SecurityException]::new('Payload staging path escaped the VGT workspace.')
}
if (Test-Path -LiteralPath $payloadRoot) { Remove-Item -LiteralPath $payloadRoot -Recurse -Force }
New-Item -Path $payloadRoot -ItemType Directory -Force | Out-Null

function Get-VgtSigningCertificate {
    New-Item -Path $certificateDirectory -ItemType Directory -Force | Out-Null
    if (Test-Path -LiteralPath $thumbprintFile -PathType Leaf) {
        $storedThumbprint = (Get-Content -LiteralPath $thumbprintFile -Raw -Encoding UTF8).Trim()
        if ($storedThumbprint -match '^[A-F0-9]{40}$') {
            $existing = Get-Item -LiteralPath "Cert:\CurrentUser\My\$storedThumbprint" -ErrorAction SilentlyContinue
            if ($existing -and $existing.HasPrivateKey -and $existing.NotAfter -gt [DateTime]::UtcNow.AddYears(1)) { return $existing }
        }
    }
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=VisionGaia Technology VGT Release' -FriendlyName 'VGT Win11E+ Release Signing' -HashAlgorithm SHA256 -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddYears(10)) -CertStoreLocation 'Cert:\CurrentUser\My'
    Set-Content -LiteralPath $thumbprintFile -Value $certificate.Thumbprint -Encoding ASCII
    return $certificate
}

function Copy-VgtTree {
    param([Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$Destination)
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Assert-VgtAuthenticodeSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedThumbprint,
        [switch]$AllowUntrusted
    )
    $verified = Get-AuthenticodeSignature -LiteralPath $Path
    if (-not $verified.SignerCertificate -or $verified.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) {
        throw [Security.SecurityException]::new('Artifact signer identity verification failed.')
    }
    $acceptedStatuses = if ($AllowUntrusted) { @('Valid','NotTrusted','UnknownError') } else { @('Valid') }
    if ([string]$verified.Status -notin $acceptedStatuses) {
        throw [Security.SecurityException]::new("Artifact signature verification failed with status $($verified.Status).")
    }
    return $verified
}

$certificate = Get-VgtSigningCertificate
$publicCertificate = Join-Path $certificateDirectory 'vgt-release.cer'
Export-Certificate -Cert $certificate -FilePath $publicCertificate -Type CERT -Force | Out-Null
if ($TrustDevelopmentCertificate) {
    Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
}

if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense application icon is missing.') }
$windres = (Get-Command 'windres.exe' -ErrorAction Stop).Source
$resourceTargets = @(
    [pscustomobject]@{ Directory = Join-Path $sourceRoot 'cmd\gedefense-center'; Resource = 'gedefense-center.rc' },
    [pscustomobject]@{ Directory = Join-Path $sourceRoot 'cmd\gedefense-tray'; Resource = 'gedefense-tray.rc' },
    [pscustomobject]@{ Directory = Join-Path $sourceRoot 'cmd\gedefense-installer'; Resource = 'gedefense-installer.rc' }
)
foreach ($target in $resourceTargets) {
    Copy-Item -LiteralPath $iconPath -Destination (Join-Path $target.Directory 'gedefense.ico') -Force
    Push-Location $target.Directory
    try {
        & $windres -i $target.Resource -o 'resource_windows_amd64.syso' -O coff
        if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new("Windows icon resource compilation failed: $($target.Resource)") }
    } finally { Pop-Location }
}

Push-Location $sourceRoot
try {
    & go test -race ./internal/... ./cmd/gedefense-windows ./cmd/gedefense-center ./cmd/gedefense-tray
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Windows tests failed.') }
    New-Item -Path (Join-Path $payloadRoot 'bin') -ItemType Directory -Force | Out-Null
    & go build -trimpath -ldflags '-s -w' -o (Join-Path $payloadRoot 'bin\gedefense-windows.exe') ./cmd/gedefense-windows
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Windows build failed.') }
    & go build -trimpath -ldflags '-s -w -H=windowsgui' -o (Join-Path $payloadRoot 'bin\GeDefenseCenter.exe') ./cmd/gedefense-center
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Center build failed.') }
    & go build -trimpath -ldflags '-s -w -H=windowsgui' -o (Join-Path $payloadRoot 'bin\GeDefenseTray.exe') ./cmd/gedefense-tray
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Tray build failed.') }
} finally { Pop-Location }

Copy-VgtTree -Source (Join-Path $projectRoot 'engine') -Destination (Join-Path $payloadRoot 'engine')
Copy-VgtTree -Source (Join-Path $projectRoot 'audit') -Destination (Join-Path $payloadRoot 'audit')
Copy-VgtTree -Source (Join-Path $projectRoot 'xdr') -Destination (Join-Path $payloadRoot 'xdr')
Copy-VgtTree -Source (Join-Path $projectRoot 'branding') -Destination (Join-Path $payloadRoot 'branding')
New-Item -Path (Join-Path $payloadRoot 'installer') -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'installer\Install-GeDefense.ps1') -Destination (Join-Path $payloadRoot 'installer\Install-GeDefense.ps1') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'installer\Uninstall-GeDefense.ps1') -Destination (Join-Path $payloadRoot 'installer\Uninstall-GeDefense.ps1') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'installer\Bootstrap-GeDefense.ps1') -Destination (Join-Path $payloadRoot 'installer\Bootstrap-GeDefense.ps1') -Force
Copy-Item -LiteralPath $publicCertificate -Destination (Join-Path $payloadRoot 'vgt-release.cer') -Force

$signable = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Where-Object Extension -in '.ps1','.psm1','.exe')
foreach ($file in $signable) {
    Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256 | Out-Null
    Assert-VgtAuthenticodeSignature -Path $file.FullName -ExpectedThumbprint $certificate.Thumbprint -AllowUntrusted:(-not $TrustDevelopmentCertificate) | Out-Null
}
$manifest = foreach ($file in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Sort-Object FullName) {
    [ordered]@{
        path = $file.FullName.Substring($payloadRoot.Length + 1).Replace('\','/')
        bytes = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifestPath = Join-Path $payloadRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$catalogPath = Join-Path $payloadRoot 'vgt-payload.cat'
New-FileCatalog -Path $payloadRoot -CatalogFilePath $catalogPath -CatalogVersion 2.0 | Out-Null
Set-AuthenticodeSignature -LiteralPath $catalogPath -Certificate $certificate -HashAlgorithm SHA256 | Out-Null
Assert-VgtAuthenticodeSignature -Path $catalogPath -ExpectedThumbprint $certificate.Thumbprint -AllowUntrusted:(-not $TrustDevelopmentCertificate) | Out-Null
Write-Output "VGT payload built: $payloadRoot"
