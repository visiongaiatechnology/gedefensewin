# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-VgtDefenderBaseline {
    param([Parameter(Mandatory)][pscustomobject]$Profile)
    $status = Get-MpComputerStatus
    if (-not $status.AntivirusEnabled) { throw [InvalidOperationException]::new('Microsoft Defender Antivirus is not active.') }

    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -CloudBlockLevel $Profile.cloudBlockLevel
    Set-MpPreference -EnableControlledFolderAccess $Profile.controlledFolderAccess

    $ids = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5',
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        '3b576869-a4ec-4529-8536-b80a7769e899',
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        'd3e037e1-3eb8-44c8-a917-57927947596d',
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
        'c1db55ab-c21a-4637-bb3f-a12568109d35',
        '33ddedf1-c6e0-47cb-833e-de6133960387'
    )
    $actions = @($ids | ForEach-Object { $Profile.asrMode })
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions
}

Export-ModuleMember -Function Set-VgtDefenderBaseline

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7Rs0PTvAjYmtY
# 5IFkW8yqVjVbuPiG6seG0I1zeaB5YaCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBn3dcJi3eS
# 93k+Gw9sp5lxkwG3JhQ1VsJZ21pU8J4zlDANBgkqhkiG9w0BAQEFAASCAYAGkPpP
# l5kZEEsGZ7oberCqmSPFxa0SRLuYfedMpJUGFdc5efnHJsY7ukFT/ZLgAhGcoWwj
# I18bUv3ECN+xt1XWZ2urowK2Dj4LRIdr39oosa0IzpSGm6Cb7hf0BjmQCeouXf35
# nzyf3M9A82Y2XYC0Fc3IEtb0z/zN+rr3OrQeSvgBun0jLYMcRPI+/eWbzjuRHzsn
# EecZfPgUGTXghOkNHvHgvsN4egmSxK3b+FeftefZxnMswCRl9f0BzavhzB8Eijfk
# rnzriTjgCzy2Pp17iItM4RgSgMhWhwi25ExLwsBigHm6EPzriPCMK0sx1fo+qjt3
# 1ATCbQ0NaK1AfqkPDefHjoMoAuQcSa9KW9ALw4X9COvKlmzKoVt/nmvLOjDwm/zF
# yaUFWy8dX5E9VtqX0FBHms7GbjecotHBZgz27orUELNYjPFYATGyOQEurXNumxMq
# +jPxwxdzx5my0ln0/CoA3q9tr6CWewgAqED4LmvTJv/TX5jcZL8+8n7ZBgM=
# SIG # End signature block
