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
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'VERSION') -Raw -Encoding UTF8).Trim()
if ($version -notmatch '^4\.0\.0-beta\.[1-9][0-9]*$') { throw [IO.InvalidDataException]::new('Release VERSION is invalid.') }
$releaseExecutable = Join-Path $releaseRoot ("GeDefense-Setup-x64-v{0}.exe" -f $version)
$releaseManifest = Join-Path $releaseRoot ("GeDefense-Setup-x64-v{0}.json" -f $version)
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
& (Join-Path $PSScriptRoot 'Test-GeDefenseRelease.ps1')
& (Join-Path $PSScriptRoot 'Build-VgtPayload.ps1') -TrustDevelopmentCertificate:$TrustDevelopmentCertificate
if (-not (Test-Path -LiteralPath $payloadRoot -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Signed GeDefense payload was not produced.') }

if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }
New-Item -Path $bundlePayload,$embeddedBundleDirectory,$releaseRoot -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $payloadRoot '*') -Destination $bundlePayload -Recurse -Force
if (Test-Path -LiteralPath $embeddedBundle) { Remove-Item -LiteralPath $embeddedBundle -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($bundleRoot,$embeddedBundle,[IO.Compression.CompressionLevel]::Optimal,$false)
if ((Get-Item -LiteralPath $embeddedBundle).Length -gt 134217728) { throw [IO.InvalidDataException]::new('Embedded installer payload exceeds the 128 MiB release boundary.') }

Push-Location $sourceRoot
try {
    $goFiles = @(Get-ChildItem -LiteralPath '.\cmd','.\internal' -Recurse -File -Filter '*.go' | Sort-Object FullName | ForEach-Object FullName)
    $unformatted = @(& gofmt -l @goFiles)
    if ($LASTEXITCODE -ne 0 -or $unformatted.Count -gt 0) { throw [InvalidOperationException]::new('Go formatting gate failed.') }
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
if ($verifiedSignature.Status -ne 'Valid' -or -not $verifiedSignature.SignerCertificate -or $verifiedSignature.SignerCertificate.Thumbprint -ne $thumbprint) { throw [Security.SecurityException]::new('Standalone installer signature verification failed.') }

$release = [ordered]@{
    product = 'VGT GeDefense Security Center'
    version = $version
    architecture = 'x64'
    bytes = (Get-Item -LiteralPath $releaseExecutable).Length
    sha256 = (Get-FileHash -LiteralPath $releaseExecutable -Algorithm SHA256).Hash
    signerThumbprint = $thumbprint
    signature = [string]$verifiedSignature.Status
    builtUtc = [DateTime]::UtcNow.ToString('o')
}
$release | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $releaseManifest -Encoding UTF8
if (Test-Path -LiteralPath $embeddedBundle) { Remove-Item -LiteralPath $embeddedBundle -Force }
if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }
$release

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA322D7oopLeIuG
# k9sY0r15kYuD3tvieEstMp5i+U4lC6CCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAIng16VwYo
# F/nS3ZpXyrabsedic7Xf8bORgW+dnNS/4zANBgkqhkiG9w0BAQEFAASCAYBsgPiL
# 7FCblVP4Avjhy8g77omzsqofvKxkWoYl6AygN9l2uWU+n6C09+O+Eb0GvJt1tI1B
# lI4fapltpe8BEZRXICSRW1AAaDmFeK4sxCbhKMF2jPdMUdVrffD7Ef98pOUrxAFl
# ruppfkqsXAVQQCbLQJWapQQ0b68EbTHuZB/3n9wC9+JWxK6TfkN8Z3TA0aWnMxbE
# cBpzDVuSAkPIM0wi3gDgEKIDdQ5BVhc/HBoHLIGBmIuK2DEWClHn2z519UAaRF+5
# whoBc6kKNQ6PllyUwGTwjLSYpjj+w7urvxVlAEP940riY0GDawg/6HlzLZtdTsnr
# kvQPteAEnqLYLMQT02Y/88Lc+nMvjFTu/anq2Ty6GaNbP3qCDnBJy91l7d+54UU3
# Anqa7yeMWu6Kr3B1+y+pWUEAq690d1fSTSzjzLYlByMpv6u2a8VnMe2EByG6AHh2
# 9cWn+pJkZiGBm2xlMrrkvLJ0Ya7iPrjleYq3rCIs65yLLpMLrmtzJibDAAU=
# SIG # End signature block
