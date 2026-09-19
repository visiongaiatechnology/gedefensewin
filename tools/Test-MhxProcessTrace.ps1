# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot 'work\mhx-process-trace-diagnostic.json'
$sourceId = 'VGT_MHX_ProcessTrace_Diagnostic'
$probe = $null

try {
    Register-CimIndicationEvent -Namespace 'root/cimv2' -ClassName 'Win32_ProcessStartTrace' -SourceIdentifier $sourceId | Out-Null
    $probe = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 8') -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    $matched = $null
    $observed = 0
    while ([DateTime]::UtcNow -lt $deadline -and $null -eq $matched) {
        $event = Wait-Event -SourceIdentifier $sourceId -Timeout 1
        if ($null -eq $event) { continue }
        try {
            $observed++
            $trace = $event.SourceEventArgs.NewEvent
            if ([uint32]$trace.ProcessID -eq [uint32]$probe.Id) {
                $matched = [ordered]@{
                    processId = [uint32]$trace.ProcessID
                    parentProcessId = [uint32]$trace.ParentProcessID
                    processName = [string]$trace.ProcessName
                    sessionId = [uint32]$trace.SessionID
                }
            }
        } finally {
            Remove-Event -EventIdentifier $event.EventIdentifier -ErrorAction SilentlyContinue
        }
    }
    if ($matched) {
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$probe.Id) -ErrorAction Stop
        $parent = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$process.ParentProcessId) -ErrorAction SilentlyContinue
        $signature = if ($process.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $process.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
        $parentSignature = if ($parent -and $parent.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $parent.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
        $sha = if ($process.ExecutablePath) { (Get-FileHash -LiteralPath $process.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
        $parentSha = if ($parent -and $parent.ExecutablePath) { (Get-FileHash -LiteralPath $parent.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
        $result = [ordered]@{
            timestampUtc=[DateTime]::UtcNow.ToString('o'); state='ENRICHED'; observed=$observed; probeId=$probe.Id; match=$matched
            process=[ordered]@{ image=[string]$process.Name; path=[string]$process.ExecutablePath; commandLine=[string]$process.CommandLine; signerStatus=if($signature){[string]$signature.Status}else{'Unknown'}; signer=if($signature -and $signature.SignerCertificate){[string]$signature.SignerCertificate.Subject}else{''}; sha256=[string]$sha }
            parent=[ordered]@{ image=if($parent){[string]$parent.Name}else{''}; path=if($parent){[string]$parent.ExecutablePath}else{''}; signerStatus=if($parentSignature){[string]$parentSignature.Status}else{'Unknown'}; signer=if($parentSignature -and $parentSignature.SignerCertificate){[string]$parentSignature.SignerCertificate.Subject}else{''}; sha256=[string]$parentSha }
        }
    } else {
        $result = [ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); state='NOT_MATCHED'; observed=$observed; probeId=$probe.Id; match=$null }
    }
} catch {
    $result = [ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); state='FAILED'; exceptionType=$_.Exception.GetType().FullName; message=$_.Exception.Message; line=$_.InvocationInfo.ScriptLineNumber }
} finally {
    if ($probe -and -not $probe.HasExited) { Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue }
    Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputPath -Encoding UTF8
if ($result.state -ne 'ENRICHED') { exit 1 }
exit 0

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCD7q9XhQnBXBf0
# wqtnP0G8cTIZwInLwbsy41TjMEArpaCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDPvnHQQqOW
# /rXOxZyC/iXP7slcsnR56tPYBBIRr30j/DANBgkqhkiG9w0BAQEFAASCAYB16XmV
# sLo5ASQplnOkbQHVIS2wiOyPbM1uUn9UA9kzDlTT/K6Kc9eZ60XKEmwDqC+PmBP4
# LiD/wy7Bq3dLzrVA+beAtlVzxhB/robPmJQSZumTIaq5nLiX6muXg9j+2zZzULkO
# Oe9lx8FHc4/cO5DacwN0KxMxzqcUBCHY+VgTBTMg6i4/x2AvoiVqS9FWMOoQvDo3
# wCQRhyvwREBTRG7ZuW6ur77Ib986kdYP1QXZg6PgSYL39rS7ejik+eQcUDIX+4ha
# V+Tyh5pXPwOo6ZGD0eyjxMOyIICcZijFXH8qTFwqal/rK3MKHCHtBxIPlarR7+km
# YtNiVxfJH6BFA4cWdaO5M7oXXFVLqOZYsL/Swi4R3v3J9QYLJ5NMHPJSa7u0Wvuq
# ixIT2RLk9V+3ggm7aybTXKw/CqINaW/pW+Y7qJsxi3y6saAXVafWp1PGCJlOPtNy
# h66vfJCjFVJrUalhCF4YXb1jUf3fux5wJiQh5f811GmqolHFTHJC3lZRT7U=
# SIG # End signature block
