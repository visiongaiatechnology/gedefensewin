# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [long]$SourceDateEpoch = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'VERSION') -Raw -Encoding UTF8).Trim()
if ($version -notmatch '^4\.0\.0-beta\.[1-9][0-9]*$') { throw [IO.InvalidDataException]::new('Release VERSION is invalid.') }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $projectRoot 'release' }
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$projectPath = [IO.Path]::GetFullPath($projectRoot)
$projectFull = $projectPath.TrimEnd('\') + '\'
$releasePath = [IO.Path]::GetFullPath((Join-Path $projectRoot 'release'))
$releaseFull = $releasePath.TrimEnd('\') + '\'
if ($outputRoot -eq $projectPath -or ($outputRoot.StartsWith($projectFull,[StringComparison]::OrdinalIgnoreCase) -and -not $outputRoot.StartsWith($releaseFull,[StringComparison]::OrdinalIgnoreCase) -and $outputRoot -ne $releasePath)) {
    throw [Security.SecurityException]::new('Source release output must not overwrite project source paths.')
}

function Test-VgtSourceFile {
    param([Parameter(Mandatory)][string]$FullName)
    $relative = $FullName.Substring($projectRoot.Length).TrimStart('\').Replace('\','/')
    if ($relative -eq '') { return $false }
    $parts = @($relative -split '/')
    $first = $parts[0]
    if ($first -in @('.git','release','payload','work','output','dist','certificates')) { return $false }
    if ($parts -contains '__pycache__' -or $parts -contains '.pytest_cache' -or $parts -contains 'node_modules') { return $false }
    if ([IO.Path]::GetFileName($relative) -in @('.DS_Store','Thumbs.db')) { return $false }
    if ($relative.StartsWith('src/GeDefense/windows/work/',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($relative.StartsWith('src/GeDefense/windows/cmd/gedefense-installer/bundle/',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($relative -eq 'SOURCE-MANIFEST.sha256') { return $false }
    if ([IO.Path]::GetExtension($relative).ToLowerInvariant() -in @('.exe','.dll','.sys','.msi','.msix','.zip','.7z','.iso','.wim','.esd','.syso','.pdb','.log','.pfx','.p12','.pvk','.snk','.key','.pem')) { return $false }
    if ([IO.Path]::GetFileName($relative) -eq 'release-thumbprint.txt') { return $false }
    return $true
}

if ($SourceDateEpoch -le 0) {
    $changelog = Get-Content -LiteralPath (Join-Path $projectRoot 'CHANGELOG.md') -Raw -Encoding UTF8
    $escapedVersion = [Regex]::Escape($version)
    $match = [Regex]::Match($changelog,"(?m)^## \[$escapedVersion\] - (?<date>\d{4}-\d{2}-\d{2})$")
    if (-not $match.Success) { throw [IO.InvalidDataException]::new('Release date could not be derived from CHANGELOG.md.') }
    $releaseDate = [DateTime]::ParseExact($match.Groups['date'].Value,'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
    $SourceDateEpoch = [DateTimeOffset]::new($releaseDate).ToUnixTimeSeconds()
}
if ($SourceDateEpoch -lt 315532800) { throw [IO.InvalidDataException]::new('SOURCE_DATE_EPOCH predates the ZIP timestamp boundary.') }
$fixedTimestamp = [DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch)

$files = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File -Force | Where-Object { Test-VgtSourceFile $_.FullName } | Sort-Object { $_.FullName.Substring($projectRoot.Length).Replace('\','/') })
if ($files.Count -lt 50 -or $files.Count -gt 2000) { throw [IO.InvalidDataException]::new('Source release file count violated the expected boundary.') }
$reparse = @($files | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
if ($reparse.Count -ne 0) { throw [Security.SecurityException]::new('Source release contains a reparse-point file.') }

$manifestLines = [Collections.Generic.List[string]]::new()
foreach ($file in $files) {
    $relative = $file.FullName.Substring($projectRoot.Length).TrimStart('\').Replace('\','/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines.Add("$hash  $relative")
}
$manifestPath = Join-Path $projectRoot 'SOURCE-MANIFEST.sha256'
[IO.File]::WriteAllText($manifestPath,($manifestLines -join "`n") + "`n",[Text.UTF8Encoding]::new($false))

# Re-enumerate so the freshly generated manifest is shipped, while intentionally
# excluding it from self-hashing.
$files = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File -Force | Where-Object {
    $relative = $_.FullName.Substring($projectRoot.Length).TrimStart('\').Replace('\','/')
    if ($relative -eq 'SOURCE-MANIFEST.sha256') { return $true }
    Test-VgtSourceFile $_.FullName
} | Sort-Object { $_.FullName.Substring($projectRoot.Length).Replace('\','/') })

New-Item -Path $outputRoot -ItemType Directory -Force | Out-Null
$archivePath = Join-Path $outputRoot ("VGT_GeDefense_Windows_{0}_Source.zip" -f $version)
$checksumPath = "$archivePath.sha256"
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
if (Test-Path -LiteralPath $checksumPath) { Remove-Item -LiteralPath $checksumPath -Force }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [IO.File]::Open($archivePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$false,[Text.Encoding]::UTF8)
    try {
        $prefix = "GeDefense-Windows-$version/"
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($projectRoot.Length).TrimStart('\').Replace('\','/')
            $entry = $archive.CreateEntry($prefix + $relative,[IO.Compression.CompressionLevel]::NoCompression)
            $entry.LastWriteTime = $fixedTimestamp
            $entryStream = $entry.Open()
            try {
                $input = [IO.File]::OpenRead($file.FullName)
                try { $input.CopyTo($entryStream) } finally { $input.Dispose() }
            } finally { $entryStream.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $stream.Dispose() }

$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($checksumPath,"$archiveHash  $([IO.Path]::GetFileName($archivePath))`n",[Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    Status = 'PASS'
    Version = $version
    Files = $files.Count
    SourceDateEpoch = $SourceDateEpoch
    Archive = $archivePath
    SHA256 = $archiveHash
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0+OgIbbg98795
# Q/ZYHaUaTRedmiDVLRThswJPdY1Q8KCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCuF4cJZlx2
# ykx+p0wdGglXwS4JY7toifbWJDfuvmeNEzANBgkqhkiG9w0BAQEFAASCAYCg4di2
# P4uLyqpzA7jDBVsKIhmbI5prAIlaYCVQEQDs4vB8U1/Z1KCG7y7YT2+KVN+fQSGP
# 5wdc9t5tYfQNTlhFDRrMeZtSqTHbzEMLnHTM4kQ9UJoRNwv/NzDqU0SjkKWJu9/G
# Ff8HDFuBBFiOKHWtjHNhwBuInx9nLw4D9UPGXLdvju84N90jqbSm2tFttWFccHOQ
# OOp+hqnARNjabP/tnx0xBhjgbCCQYi88FLSHOoa4rV2AiLWwL4Zl8Ncjw/EltDvy
# +1Sc/ivTEIbMCTiv9sGmCIkCyxmScfzbVIDhkGof2YvuBFJzeRNM8nS5b0hIXmOO
# ISXoJnoh0839jCDJJeuyGjdh3oeLQBorp7whVseTjQIURb7BOuuADdhhvbWho1U9
# dDShwLj8vVC0lGPt2Ut8as1+0CIqtO/q0wonWUqw+9tIm6KtPwGqYcYBe/Zli1rp
# UilwUVkmlDE4UXeY/H4S9Zyu9X2qnEQbvY2XmM9XqlBOn0ZQZPVY2WifSIQ=
# SIG # End signature block
