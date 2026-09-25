# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$token = ((cmd.exe /c "echo protocol=https&echo host=github.com&echo." | & "C:\Program Files\Git\mingw64\bin\git-credential-manager.exe" get) | Select-String "^password=").ToString().Substring(9).Trim()
$headers = @{
    Authorization = "Bearer $token"
    "User-Agent" = "VGT-Release-Bot"
    Accept = "application/vnd.github+json"
}

$version = (Get-Content (Join-Path $PSScriptRoot "..\VERSION") -Raw).Trim()
$tag = "v$version"

$releaseDir = Resolve-Path (Join-Path $PSScriptRoot "..\release")
$exePath = (Resolve-Path (Join-Path $releaseDir "GeDefense-Setup-x64-$tag.exe")).Path
$exeName = [System.IO.Path]::GetFileName($exePath)
$exeBytes = [System.IO.File]::ReadAllBytes($exePath)
$sha256 = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToUpperInvariant()
$formattedSize = "{0:N0} Bytes" -f $exeBytes.Length

$jsonPath = (Resolve-Path (Join-Path $releaseDir "GeDefense-Setup-x64-$tag.json")).Path
$jsonName = [System.IO.Path]::GetFileName($jsonPath)
$jsonBytes = [System.IO.File]::ReadAllBytes($jsonPath)

$release = try {
    Invoke-RestMethod -Uri "https://api.github.com/repos/visiongaiatechnology/gedefensewin/releases/tags/$tag" -Headers $headers -Method Get
} catch {
    $null
}

if (-not $release) {
    $body = @"
# VGT GeDefense Windows $version

Offizielles Standalone-Release für **VGT GeDefense Windows 4 (Version $version)** von VisionGaia Technology.

Für Security Researcher und System-Architekten ist die vollständige technische Systemspezifikation in der [**ARCHITECTURE.md**](https://github.com/visiongaiatechnology/gedefensewin/blob/main/ARCHITECTURE.md) hinterlegt.

---

## Highlights der Version $version

- **Dediziertes Anwendungsfenster**: Eigenständiges, tab- und adressleistenfreies Anwendungsfenster für das GeDefense Security Center via Chromium App Mode (`--app`) mit nativer Dark-Theme-Farbkopplung (`<meta name="theme-color" content="#050b14">`).
- **Resiliente Policy-Synchronisation**: Graceful Tolerance bei der Bereinigung entfernter Windows App Control (WDAC) Policies (`0x80070002`) und neuer API-Endpoint `POST /api/v1/mhx/policy/reconcile` mit synchronen Dashboard-Buttons für sofortige Wiederherstellung des Schutzstatus.
- **Glassmorphism Setup Wizard**: Vollständig modernisierter Installer mit Ice-Blue Glassmorphism UI, Blur-Effekten und transaktionaler Elevations-Überwachung.
- **Zero External Go Dependencies**: Vollständige Entfernung externer Go-Module (`go.sum` hat exakt 0 Bytes). Direkte native Win32-Syscalls (`kernel32.dll`, `advapi32.dll`, `user32.dll`, `iphlpapi.dll`).
- **Loopback-Only Control Plane**: Bindet strikt an `127.0.0.1:17831` mit Token-basierter Authentifizierung (`dashboard.token`), Host-/Origin-Prüfung und kurzlebigen, signierten Session-Cookies.
- **Anti-PID-Reuse EDR Response**: Prozessterminierung validiert zwingend das Tripel `(PID, CreationTime, ExecutablePath)` vor Ausführung.
- **Native Netzwerk-zu-Prozess-Korrelation**: Echtzeit-TCP-Extended-Table (`iphlpapi.dll`) mit atomarer Owning-PID-Zuordnung und Attack-Story-Verknüpfung.
- **MHX Heuristik & EncodedCommand Unpacker**: Dekodierung von Base64/UTF-16LE PowerShell-Payloads mit Hash-basierter Evidenz.
- **HMAC-SHA-256 Evidence Ledger**: Manipulationssicheres, sequenziell verkettetes Audit-Protokoll (`evidence.jsonl`).
- **Autarker Standalone-Installer**: Eingebetteter, kryptografisch katalogisierter Payload (`vgt-payload.cat`) unter strikter `ExecutionPolicy AllSigned`.

---

## Verifikationsdaten & Checksummen

| Eigenschaft | Wert |
| :--- | :--- |
| **Datei** | ``$exeName`` |
| **Architektur** | Windows 11 x64 |
| **Dateigröße** | $formattedSize |
| **SHA-256** | ``$sha256`` |
| **Signatur-Status** | Valid (Authenticode SHA-256) |
| **Signer Thumbprint** | ``1E7B1641FC2E8EB82735216829C13721E3B9D895`` |
| **Signer Subject** | ``CN=VisionGaia Technology VGT Release`` |

---

## Installation & Upgrade

1. Lade die Datei ``$exeName`` herunter.
2. Starte die Datei mit Administratorrechten ("Als Administrator ausführen").
3. Der Installer ersetzt frühere Versionen, installiert die V4-Binaries nach ``C:\Program Files\VGT\GeDefense``, registriert den Dienst ``VGTGeDefense`` mit Startmodus ``Automatic`` (**startet direkt bei jedem Windows-Boot**) und richtet den Autostart für das System-Tray ein.
"@

    $releasePayload = @{
        tag_name = $tag
        target_commitish = "main"
        name = "VGT GeDefense Windows $version"
        body = $body
        draft = $false
        prerelease = $false
    } | ConvertTo-Json -Depth 4

    Write-Host "Creating GitHub release for $tag..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/visiongaiatechnology/gedefensewin/releases" -Headers $headers -Method Post -Body $releasePayload -ContentType "application/json; charset=utf-8"
}

Write-Host "Using release ID: $($release.id)"

$uploadUrlBase = [string]$release.upload_url -replace '\{\?name,label\}', ''

# Delete old assets if they exist
$existingAssets = Invoke-RestMethod -Uri "https://api.github.com/repos/visiongaiatechnology/gedefensewin/releases/$($release.id)/assets" -Headers $headers -Method Get
foreach ($asset in $existingAssets) {
    Write-Host "Removing existing asset $($asset.name)..."
    Invoke-RestMethod -Uri $asset.url -Headers $headers -Method Delete | Out-Null
}

# Upload .exe
$exeUploadUrl = "$($uploadUrlBase)?name=$($exeName)"
Write-Host "Uploading $($exeName) ($($exeBytes.Length) bytes)..."
$uploadExeHeaders = @{
    Authorization = "Bearer $token"
    "User-Agent" = "VGT-Release-Bot"
    "Content-Type" = "application/octet-stream"
}
$exeAsset = Invoke-RestMethod -Uri $exeUploadUrl -Headers $uploadExeHeaders -Method Post -Body $exeBytes
Write-Host "Uploaded $($exeName) -> $($exeAsset.browser_download_url)"

# Upload .json manifest
$jsonUploadUrl = "$($uploadUrlBase)?name=$($jsonName)"
Write-Host "Uploading $($jsonName) ($($jsonBytes.Length) bytes)..."
$uploadJsonHeaders = @{
    Authorization = "Bearer $token"
    "User-Agent" = "VGT-Release-Bot"
    "Content-Type" = "application/json"
}
$jsonAsset = Invoke-RestMethod -Uri $jsonUploadUrl -Headers $uploadJsonHeaders -Method Post -Body $jsonBytes
Write-Host "Uploaded $($jsonName) -> $($jsonAsset.browser_download_url)"

Write-Host "SUCCESS: Release published at $($release.html_url)"
# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnw/0UdC12ia1p
# RmBzkiAl+GW0fdUh0jwSBJeqhjqyfqCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAJMMDBjuZ0
# pPD92D17/3jS+4G06fcFV8HCgwxbRWUQdzANBgkqhkiG9w0BAQEFAASCAYCcOEpL
# 4PCEKVdrwvyKosYCC/WrI7EHcF05DTS0tj/z2ZafR1Q5yy0d4bjd8ZbIRiyMRcNw
# 3ROLzs7Xeva6z7FTlPLON4c0vuozDs8THSBoEl3P8WF0cTk/6+5YCNYvhSTfOzSB
# qbpIAREpN5e8c2RUVsIA5tg2M45Vhx10/4ARmtnX0kGULIFiPxv+wNC1LST95Vfq
# ngxsx1HACP5ClZ5j2uZgZGgyd+r2EANtMxFBw6XN6gOGWHZ/0zsO/GQzNV30Ikmk
# Vl1dIO8Uqk0fNWCaYqvQRefouQcUGNtsbSRVO7yuJ9Bwa/mZpX6EFYMuL3W3D3lc
# JetYmIc8dD64MUMbVNfPbJbUq+2l+0lCYCdZKWsFTABwc5qTG8bc5Et1HbX19ms0
# ko2cLEWciyCJVdleRNojh65MQD7HcmL0sN7Hi6vFFy16JYPPNCyXO51HuNdVCT6T
# gra0GdivJ3iqi9GM/dFWvS38rXeSWHwwg5jlpd5kgTbFygjbHxZS1Yyf5bY=
# SIG # End signature block
