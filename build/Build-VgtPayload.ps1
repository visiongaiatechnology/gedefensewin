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
New-Item -Path (Join-Path $payloadRoot 'installer') -ItemType Directory -Force | Out-Null
foreach ($scriptName in @('Install-GeDefense.ps1','Uninstall-GeDefense.ps1','Bootstrap-GeDefense.ps1')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot "installer\$scriptName") -Destination (Join-Path $payloadRoot "installer\$scriptName") -Force
}
Copy-Item -LiteralPath $publicCertificate -Destination (Join-Path $payloadRoot 'vgt-release.cer') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'VERSION') -Destination (Join-Path $payloadRoot 'VERSION') -Force

$signable = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1','.exe' })
foreach ($file in $signable) {
    $signed = Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256
    if (-not $signed.SignerCertificate -or $signed.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new("Artifact signing failed: $($file.FullName)") }
    Assert-VgtAuthenticodeSignature -Path $file.FullName -ExpectedThumbprint $certificate.Thumbprint
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

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAV8h03W+J6ZFFk
# iExnUdGIdnpBaShAF6cIJO8HI5RZA6CCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDEkyZCKB5h
# oEn/gU56e1vWG8Z40dQwbiOC2b/PxOtvlTANBgkqhkiG9w0BAQEFAASCAYAKn619
# lFdG2p7fUxklHgTphkxj46KpBp+YWtbMesoFHHUzVreD9pudAsnvtdiJLjMbyUYg
# kVPti4SPQDTtsWs2YSDlirnn4gNWYERVAADuTAJce6PdA8PoXsKHxOU6TXZxaqp5
# Ly/bKo2Pt76myqqrbkxaq9uBdZFbGDErSOXbA+YH7ZjSetr5xWXwM5K/1EtUeSPl
# kEeiBFaZHGTAO1lCz6NyfcBW/VpF/BcfH60R6u7pFUfX21OYIbI54yypG3zueXNm
# 3K9y6pQpmTWtVxxpO0FR6pMRLYhN9f3cwAY9DiTpOd8zxFZGoUHQ26Y922uM8xeI
# 4p1hckyL4cBXt5qonmImcdxshT4zUwhJNjHqE2+jslHPLYKmHuRm+w8WhETEKrAm
# zMtNfwV5NpNS5hFkk9sERWL7oWgVlRwF3kXnczhnyYQoKmDIdt3RvG90h4VBhMxg
# B6X+hA7U33LOPykB3EMCFDGiDlH0k5gnGGkqZJnIOQLM0ZnoiyEYPT6Mmec=
# SIG # End signature block
