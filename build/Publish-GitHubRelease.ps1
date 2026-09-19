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

$tag = "v4.1.0-beta.1"
$release = try {
    Invoke-RestMethod -Uri "https://api.github.com/repos/visiongaiatechnology/gedefensewin/releases/tags/$tag" -Headers $headers -Method Get
} catch {
    $null
}

if (-not $release) {
    $body = @"
# VGT GeDefense Windows 4.1.0-beta.1

Offizielles Standalone-Release für **VGT GeDefense Windows 4 (Version 4.1.0-beta.1)** von VisionGaia Technology.

Für Security Researcher und System-Architekten ist die vollständige technische Systemspezifikation in der [**ARCHITECTURE.md**](https://github.com/visiongaiatechnology/gedefensewin/blob/main/ARCHITECTURE.md) hinterlegt.

---

## Highlights der Generation 4

- **Zero External Go Dependencies**: Vollständige Entfernung externer Go-Module (`go.sum` hat exakt 0 Bytes). Direkte native Win32-Syscalls (`kernel32.dll`, `advapi32.dll`, `user32.dll`, `iphlpapi.dll`).
- **Loopback-Only Control Plane**: Bindet strikt an `127.0.0.1:17831` mit Token-basierter Authentifizierung (`dashboard.token`), Host-/Origin-Prüfung und kurzlebigen, signierten Session-Cookies.
- **Anti-PID-Reuse EDR Response**: Prozessterminierung validiert zwingend das Tripel `(PID, CreationTime, ExecutablePath)` vor Ausführung. Keine unautorisierten Host-Kills durch reine Netzwerk-IOCs.
- **Native Netzwerk-zu-Prozess-Korrelation**: Echtzeit-TCP-Extended-Table (`iphlpapi.dll`) mit atomarer Owning-PID-Zuordnung und Attack-Story-Verknüpfung.
- **MHX Heuristik & EncodedCommand Unpacker**: Dekodierung von Base64/UTF-16LE PowerShell-Payloads mit Hash-basierter Evidenz.
- **Sovereign Application Control**: Windows App Control (WDAC / CiTool) Kernel-Richtlinien mit atomaren Transaktionen.
- **HMAC-SHA-256 Evidence Ledger**: Manipulationssicheres, sequenziell verkettetes Audit-Protokoll (`evidence.jsonl`).
- **Autarker Standalone-Installer**: Eingebetteter, kryptografisch katalogisierter Payload (`vgt-payload.cat`) unter strikter `ExecutionPolicy AllSigned`.

---

## Verifikationsdaten & Checksummen

| Eigenschaft | Wert |
| :--- | :--- |
| **Datei** | ``GeDefense-Setup-x64-v4.1.0-beta.1.exe`` |
| **Architektur** | Windows 11 x64 |
| **Dateigröße** | 15.140.152 Bytes |
| **SHA-256** | ``A1F33DC3994559B2B41292F5A43BF0624C7F8FD1FACC33B709E89B2F7FFDC16D`` |
| **Signatur-Status** | Valid (Authenticode SHA-256) |
| **Signer Thumbprint** | ``1E7B1641FC2E8EB82735216829C13721E3B9D895`` |
| **Signer Subject** | ``CN=VisionGaia Technology VGT Release`` |

---

## Installation & Upgrade

1. Lade die Datei ``GeDefense-Setup-x64-v4.1.0-beta.1.exe`` herunter.
2. Starte die Datei mit Administratorrechten ("Als Administrator ausführen").
3. Der Installer ersetzt frühere Versionen (z. B. 2.3.2), installiert die V4-Binaries nach ``C:\Program Files\VGT\GeDefense``, registriert den Dienst ``VGTGeDefense`` mit Startmodus ``Automatic`` (**startet direkt bei jedem Windows-Boot**) und richtet den Autostart für das System-Tray ein.
"@

    $releasePayload = @{
        tag_name = $tag
        target_commitish = "main"
        name = "VGT GeDefense Windows 4.1.0-beta.1"
        body = $body
        draft = $false
        prerelease = $true
    } | ConvertTo-Json -Depth 4

    Write-Host "Creating GitHub release..."
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
$exePath = (Resolve-Path ".\release\GeDefense-Setup-x64-v4.1.0-beta.1.exe").Path
$exeName = [System.IO.Path]::GetFileName($exePath)
$exeBytes = [System.IO.File]::ReadAllBytes($exePath)
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
$jsonPath = (Resolve-Path ".\release\GeDefense-Setup-x64-v4.1.0-beta.1.json").Path
$jsonName = [System.IO.Path]::GetFileName($jsonPath)
$jsonBytes = [System.IO.File]::ReadAllBytes($jsonPath)
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDXqdGAEP4WrbkS
# yIyl7DAB9LqWqMJ77imiuhHFuzUFSKCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAAhncIb70u
# LZv4wtaGKiVCtPOUj7WahtwnSSvotZ6aNDANBgkqhkiG9w0BAQEFAASCAYB65JFy
# p6uATDR4USeDNloItzd8HhkaNgiQ4qjQxd8IcAmyveZlO/FqTPSMap5NGVJobjUr
# AQ7EZXQK/izJDa2ilcfxD5/YFVItEFAHrF6tnNLCmuPvrW1zr2RBptO1WN7DdQ4/
# pgh3WySgJwIG+ZWXQuYJCIx5gWJX2hmGYGJtkgpIwznfI1FgTs1vnzh6nbEbLIdH
# qkkzJHX+4SNnEhcuR22kS+o2HnTQe3YQCK2VlXIaXx9948Z/1bk4sXnjtetVqQRr
# u0mJGCFXOZDRtr65WU57hmLnC2k+f8XhJIa2C4xX+lBEOqHYnQ/g6WkS39A+V209
# i71zHpm9bHto7nS9HyAoz2cWo5ov0qQv+U5xkF27XPULqVflVro33uyKzhqgif7I
# 2bnXlO5jnD8AK9f5u3GXpBXPlv7W6FdGhiGOvM4+X7tOB5Me+0uN9IJ7Pi7Po7z/
# D9eTTBrbqLsztHl0LajtxldMJqzmS/tZ2Jrgjd+7ooCYYGPcYN7gC8/VEzo=
# SIG # End signature block
