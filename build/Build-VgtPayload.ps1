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
$payloadParent = Join-Path $projectRoot 'payload'
$certificateDirectory = Join-Path $projectRoot 'certificates'
$thumbprintFile = Join-Path $certificateDirectory 'release-thumbprint.txt'
$publicCertificate = Join-Path $certificateDirectory 'vgt-release.cer'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'

function Assert-VgtChildPath {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Parent)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolvedPath.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('Build path escaped the VGT workspace.')
    }
}

function Assert-VgtCodeSigningCertificate {
    param([Parameter(Mandatory)]$Certificate)
    if (-not $Certificate.HasPrivateKey) { throw [Security.SecurityException]::new('Release certificate has no private key.') }
    $now = [DateTime]::UtcNow
    if ($Certificate.NotBefore.ToUniversalTime() -gt $now -or $Certificate.NotAfter.ToUniversalTime() -le $now.AddDays(30)) {
        throw [Security.SecurityException]::new('Release certificate validity window is insufficient.')
    }
    $ekuExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $ekuExtension) { throw [Security.SecurityException]::new('Release certificate has no enhanced key usage extension.') }
    $decodedEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuExtension,$ekuExtension.Critical)
    $eku = @($decodedEku.EnhancedKeyUsages | ForEach-Object { $_.Value })
    if ($codeSigningOid -notin $eku) { throw [Security.SecurityException]::new('Release certificate is not valid for code signing.') }
}

function Get-VgtSigningCertificate {
    New-Item -Path $certificateDirectory -ItemType Directory -Force | Out-Null
    if (Test-Path -LiteralPath $thumbprintFile -PathType Leaf) {
        $storedThumbprint = (Get-Content -LiteralPath $thumbprintFile -Raw -Encoding UTF8).Trim().ToUpperInvariant()
        if ($storedThumbprint -notmatch '^[A-F0-9]{40}$') { throw [Security.SecurityException]::new('Release certificate thumbprint metadata is invalid.') }
        $existing = Get-Item -LiteralPath "Cert:\CurrentUser\My\$storedThumbprint" -ErrorAction SilentlyContinue
        if ($existing) {
            Assert-VgtCodeSigningCertificate -Certificate $existing
            return $existing
        }
        if (-not $TrustDevelopmentCertificate) { throw [Security.SecurityException]::new('Provisioned release signing certificate is unavailable.') }
    } elseif (-not $TrustDevelopmentCertificate) {
        throw [Security.SecurityException]::new('Official builds require a provisioned release signing certificate and release-thumbprint.txt.')
    }

    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=VisionGaia Technology VGT Development Signing' -FriendlyName 'VGT GeDefense Development Signing' -HashAlgorithm SHA256 -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddYears(2)) -CertStoreLocation 'Cert:\CurrentUser\My'
    Assert-VgtCodeSigningCertificate -Certificate $certificate
    Set-Content -LiteralPath $thumbprintFile -Value $certificate.Thumbprint.ToUpperInvariant() -Encoding ASCII
    return $certificate
}

function Copy-VgtTree {
    param([Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$Destination)
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { throw [IO.DirectoryNotFoundException]::new("Required source tree is missing: $Source") }
    Assert-VgtChildPath -Path $Destination -Parent $payloadParent
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Assert-VgtAuthenticodeSignature {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$ExpectedThumbprint)
    $verified = Get-AuthenticodeSignature -LiteralPath $Path
    if ($verified.Status -ne 'Valid' -or -not $verified.SignerCertificate -or $verified.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) {
        throw [Security.SecurityException]::new("Artifact signature verification failed: $Path")
    }
}

Assert-VgtChildPath -Path $payloadRoot -Parent $payloadParent
if (Test-Path -LiteralPath $payloadRoot) { Remove-Item -LiteralPath $payloadRoot -Recurse -Force }
New-Item -Path $payloadRoot -ItemType Directory -Force | Out-Null

$certificate = Get-VgtSigningCertificate
Export-Certificate -Cert $certificate -FilePath $publicCertificate -Type CERT -Force | Out-Null
if ($TrustDevelopmentCertificate) {
    # Development-only: trust is established on the build machine so signatures can
    # be validated. Target systems must establish this development trust themselves.
    Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
}
Push-Location $sourceRoot
try {
    & go test -race ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Windows tests failed.') }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('GeDefense Windows vet failed.') }
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
Copy-VgtTree -Source (Join-Path $projectRoot 'LICENSES') -Destination (Join-Path $payloadRoot 'LICENSES')
foreach ($noticeName in @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','GEOIP_LICENSE_AND_DEPLOYMENT.md')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $noticeName) -Destination (Join-Path $payloadRoot $noticeName) -Force
}
if (Test-Path -LiteralPath (Join-Path $projectRoot 'data\geoip.csv')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot 'data\geoip.csv') -Destination (Join-Path $payloadRoot 'bin\geoip.csv') -Force
    if (Test-Path -LiteralPath (Join-Path $projectRoot 'data\geoip.csv.sha256')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot 'data\geoip.csv.sha256') -Destination (Join-Path $payloadRoot 'bin\geoip.csv.sha256') -Force
    }
}
$installerPayloadRoot = Join-Path $payloadRoot 'installer'
New-Item -Path $installerPayloadRoot -ItemType Directory -Force | Out-Null
foreach ($installerFile in @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'installer') -File | Where-Object { $_.Extension -in @('.ps1','.psm1') })) {
    Copy-Item -LiteralPath $installerFile.FullName -Destination (Join-Path $installerPayloadRoot $installerFile.Name) -Force
}
foreach ($requiredInstallerFile in @('Install-GeDefense.ps1','Uninstall-GeDefense.ps1','Bootstrap-GeDefense.ps1','InstallerSafety.psm1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $installerPayloadRoot $requiredInstallerFile) -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Required installer payload file is missing: {0}' -f $requiredInstallerFile)) }
}
Copy-Item -LiteralPath $publicCertificate -Destination (Join-Path $payloadRoot 'vgt-release.cer') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'VERSION') -Destination (Join-Path $payloadRoot 'VERSION') -Force

$signable = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1','.exe' })
foreach ($file in $signable) {
    if ($file.Extension -in '.ps1','.psm1') {
        # PowerShell's signing cmdlet can drop the last code line when a script
        # already contains an Authenticode banner. Strip any stale banner from
        # the copied source first, then sign the clean script.
        $text = [IO.File]::ReadAllText($file.FullName)
        $marker = '# SIG # Begin signature block'
        $markerIndex = $text.IndexOf($marker, [StringComparison]::Ordinal)
        if ($markerIndex -ge 0) {
            $clean = $text.Substring(0, $markerIndex)
            if (-not $clean.EndsWith("`n")) { $clean += "`n" }
            [IO.File]::WriteAllText($file.FullName, $clean, [Text.UTF8Encoding]::new($false))
        }
    }
    $signed = Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256
    if (-not $signed.SignerCertificate -or $signed.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new("Artifact signing failed: $($file.FullName)") }
    Assert-VgtAuthenticodeSignature -Path $file.FullName -ExpectedThumbprint $certificate.Thumbprint
    if ($file.Extension -in '.ps1','.psm1') {
        $parseErrors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) { throw [IO.InvalidDataException]::new(("Signed payload script is not parseable: {0} ({1})" -f $file.FullName, $parseErrors[0].Message)) }
    }
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
$signedCatalog = Set-AuthenticodeSignature -LiteralPath $catalogPath -Certificate $certificate -HashAlgorithm SHA256
if (-not $signedCatalog.SignerCertificate -or $signedCatalog.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Payload catalog signing failed.') }
Assert-VgtAuthenticodeSignature -Path $catalogPath -ExpectedThumbprint $certificate.Thumbprint
Write-Output "VGT payload built: $payloadRoot"
