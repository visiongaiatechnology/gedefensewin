# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Add','Remove','List','Verify')][string]$Action,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$ApplicationPath,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense\mhx'
$allowFile = Join-Path $dataRoot 'application-allows.json'
$ruleGroup = 'VGT GeDefense Sovereign Allows'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative allow transaction required.') }
}

function Read-Entries {
    if (-not (Test-Path -LiteralPath $allowFile -PathType Leaf)) { return @() }
    $item = Get-Item -LiteralPath $allowFile -Force
    if ($item.Length -le 0 -or $item.Length -gt 1MB -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw [Security.SecurityException]::new('Allow database boundary validation failed.') }
    return @((Get-Content -LiteralPath $allowFile -Raw -Encoding UTF8 | ConvertFrom-Json).entries)
}

function Write-Entries([array]$Entries) {
    [IO.Directory]::CreateDirectory($dataRoot) | Out-Null
    $temporary = "$allowFile.$PID.tmp"
    [ordered]@{ version=1; updatedUtc=[DateTime]::UtcNow.ToString('o'); entries=@($Entries) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $allowFile -Force
}

function Resolve-Application {
    if ([string]::IsNullOrWhiteSpace($ApplicationPath)) { throw [Security.SecurityException]::new('Application path is required.') }
    $resolved = (Resolve-Path -LiteralPath $ApplicationPath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -and $item.Extension -eq '.exe' -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $resolved }
    throw [Security.SecurityException]::new('Application file validation failed.')
}

function New-VerifiedEntry([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw [Security.SecurityException]::new('Only valid Authenticode applications can receive sovereign network access.') }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{ path=$Path; sha256=$hash; signer=[string]$signature.SignerCertificate.Subject; addedUtc=[DateTime]::UtcNow.ToString('o'); rule="VGT Sovereign Allow $($hash.Substring(0,16))" }
}

function Sync-Rules([array]$Entries) {
    Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $verified = @()
    foreach ($entry in $Entries) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { continue }
        $hash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = Get-AuthenticodeSignature -LiteralPath $entry.path
        if ($hash -ne [string]$entry.sha256 -or $signature.Status -ne 'Valid' -or [string]$signature.SignerCertificate.Subject -ne [string]$entry.signer) { continue }
        New-NetFirewallRule -DisplayName ([string]$entry.rule) -Group $ruleGroup -Direction Outbound -Action Allow -Program ([string]$entry.path) -Protocol Any | Out-Null
        $verified += $entry
    }
    return @($verified)
}

try {
    Assert-Administrator
    $entries = @(Read-Entries)
    if ($Action -eq 'Add') {
        $resolved = Resolve-Application
        $entry = New-VerifiedEntry -Path $resolved
        $entries = @($entries | Where-Object { -not ([string]$_.path).Equals($resolved,[StringComparison]::OrdinalIgnoreCase) }) + @($entry)
    } elseif ($Action -eq 'Remove') {
        $resolvedCandidate = [IO.Path]::GetFullPath($ApplicationPath)
        $entries = @($entries | Where-Object { -not ([string]$_.path).Equals($resolvedCandidate,[StringComparison]::OrdinalIgnoreCase) })
    }
    if ($Action -ne 'List') { $entries = @(Sync-Rules -Entries $entries); Write-Entries -Entries $entries }
    $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); Entries=@($entries); Count=$entries.Count }
    $json = $result | ConvertTo-Json -Depth 5
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"; Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8; Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    Write-Error 'Sovereign application allow transaction was rejected.'
    exit 10
} catch {
    Write-Error 'Sovereign application allow transaction failed.'
    exit 20
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAw5gtzVCQXnfAL
# ilm3Nrky55cUqopMnAcg0jbngjR2IKCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCRbPbyzyDX
# rqFel8g5Fr0G3leA/btWKMBwdys4tgF5ezANBgkqhkiG9w0BAQEFAASCAYCIgDmy
# jdsxsoiDhTDFajsHceEZKU8bZy+7/y9HnUr4NrmoOWX14pU5dUvaW0pJfdLy8GQZ
# CRnOL4XFzy48eT7QiD838SYZokbOJu07+DqhKmwF1HRGcYkGBuxBgpEB3+Aw3oIU
# oAmzDcBrJMSaxHxMH4QHDFEz+dF+L3V2NgIBUdjGNGFtroIU1tQ8ZxM9xXS0d4G2
# vfjWsERu9xr3eVX+xplfWcFl/HL7q1G5EY/C+CoywR51NB9b/Y0iSrX92LbyvOZo
# Gx4oOJwtJS1EHxTOy3kkXVnz5McnMpc43OtRNkyq9L7KQHn32FS75zDITnmfOg1N
# wSPed2kJYszyx84rZC5OWm+4n+VxDwDZFwpQoCga+wgXI9J+VUyve+45fS5Hvo2W
# m3Kl1V78nrlFJ9vIn7LvqnPtxOMixm4Wm5sfRur7CIG+aS7KifYx91PuEBNbir4p
# rjoy0xpen1ZAay6lwVnDCbJZZnNXRmIUT6pyWLYsWJqjNSYwZAy+G5LfUHs=
# SIG # End signature block
