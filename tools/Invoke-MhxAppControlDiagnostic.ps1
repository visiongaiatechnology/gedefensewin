# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative diagnostic execution required.')
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'xdr\Set-VgtMhxAppControl.ps1'
$protectedDiagnostic = Join-Path $env:ProgramData 'VGT\GeDefense\mhx\appcontrol\diagnostics.jsonl'
$exportPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.jsonl'
$statusPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic-status.json'
$stdoutPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.stdout.log'
$stderrPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.stderr.log'

if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('MHX App Control module is unavailable.')
}

try {
    $child = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $modulePath), '-Action', 'Audit'
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -Wait -PassThru -WindowStyle Hidden

    if (Test-Path -LiteralPath $protectedDiagnostic -PathType Leaf) {
        Copy-Item -LiteralPath $protectedDiagnostic -Destination $exportPath -Force
    }
    $status = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        state = if ($child.ExitCode -eq 0) { 'SUCCEEDED' } else { 'CHILD_FAILED' }
        childExitCode = $child.ExitCode
        protectedDiagnosticExists = Test-Path -LiteralPath $protectedDiagnostic -PathType Leaf
        stdoutBytes = if (Test-Path -LiteralPath $stdoutPath) { (Get-Item -LiteralPath $stdoutPath).Length } else { 0 }
        stderrBytes = if (Test-Path -LiteralPath $stderrPath) { (Get-Item -LiteralPath $stderrPath).Length } else { 0 }
    }
    $status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    exit $child.ExitCode
} catch {
    $status = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        state = 'WRAPPER_FAILED'
        exceptionType = $_.Exception.GetType().FullName
        message = $_.Exception.Message
        scriptLine = $_.InvocationInfo.ScriptLineNumber
    }
    $status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    exit 90
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCw43dXEdUG8ja2
# kltXljm/hRxJRk67iQqLX+qoE2lG3aCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA3zVRUy3iQ
# YLtDRW+Weob8ASfqUy44U2prp5quZprpuzANBgkqhkiG9w0BAQEFAASCAYC3de1A
# bcc8TbX4S/qwJdjJA5moT44Zl0m/7ZYLz2wPbdfAfgFLKa7mi8QE+BHrkFY0tPm8
# SaPhkD4E8wOW04LGQ3fnZNZF+nmSvocPM0QI09hSYnXidp9riLtt5gUIBdPvHzTY
# BjNQHRKTpQ8GnzmtpjKelft/6pcED9Bjhq0rVS3GR3BEhDoc2nq1Hm4JODSBk9Sy
# eQDnC2eEEcNRsqhK4/NSJ4pE7gVVTPlv6yMB1KUT2VPePqDrqyqUOT7s+zgX7H1A
# LSVnIob/BImNCTVXPuRO8a7NepEPLYtPuwntNPZDholZgNlVKDmgd/56Kla7h4rY
# AM5mv79V90E6+PAGBZG541V1qYpD7+PAnp9sB6Gnn8PVDqtWZ8R9YnfdK3t96CLd
# wIDmE34pK75HZPJOBVlTtudPk0zMXVYErJ7diEdpbEuZXXam3OiqzeY8FJXpUpr+
# Kak8HR1nlD/561w+EPi/k4pWuOBOMPFarNlD0AXZjUtVKjBNhsiMSSTL5Rg=
# SIG # End signature block
