# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$go = Join-Path $env:ProgramFiles 'Go\bin\go.exe'
$stdout = Join-Path $projectRoot 'work\mhx-watcher-integration.stdout.log'
$stderr = Join-Path $projectRoot 'work\mhx-watcher-integration.stderr.log'
$status = Join-Path $projectRoot 'work\mhx-watcher-integration.status.json'
if (-not (Test-Path -LiteralPath $go -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Go runtime unavailable.') }
$env:VGT_MHX_INTEGRATION = '1'
$process = Start-Process -FilePath $go -WorkingDirectory $sourceRoot -ArgumentList @('test','-run','TestProcessWatcherReceivesEncodedCommand','-count=1','-v','./internal/mhx') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru -WindowStyle Hidden
[ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); exitCode=$process.ExitCode } | ConvertTo-Json | Set-Content -LiteralPath $status -Encoding UTF8
exit $process.ExitCode

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXWPcbwyHYV6G2
# 2vpHcGFszBb0a9FIFczBxkNN+34fzaCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAwWjK2GNB3
# Q/ZaF2g0ejIpVVIw8Hly8pF/pH58z4g6PDANBgkqhkiG9w0BAQEFAASCAYBHN52b
# 13D6GvY8Ikbu3i/OTYcS0rRX9zSNbZYLizJOaBCp7yO1/9kTO/gOl48EGT6ctFIo
# TkAOxiIWrIDy6Uzyggpo1YEq3tFZlcy2+Zmeb8n4dMCyJ+wtX0s8z9qPxuTdx+PR
# EP9gySSCdIsAFcOiPTzY+NUVC7WJJyVmU7xzoiKmfxIFU67eCvXae6JZtD07j9Lh
# MXHIN5OIeMAORSAL/jDyqS4Y0Ggt6hmCyOZEZKBj6w6DIljuNLvx8fot5whwRJK2
# BuulKeuXZcZY7f2POCj0UOkggsqmi3LLUJzrLp+rC1Bv2zOT4Sgvqm+mlO4DMdZO
# JyFvE9KUN3a0hwxAt4D5Z0bZXn5P1ZgkCf7OoZoiaeqUUBcaOZTWsVGZDTDdodbn
# iNmQWd62nvGWgEzq5JyOLMZKKRrpWQsCFTWJD1aoPNs04gGUmLPJC10puimb+8Pp
# zGrHABi362NS9ne6xSRIt729gRwl53TtP31sQdSwwmrlL8PNbb98gFLwpwk=
# SIG # End signature block
