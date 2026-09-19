# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-VgtNetworkBaseline {
    param([Parameter(Mandatory)][pscustomobject]$Profile)
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction $Profile.defaultOutboundAction -NotifyOnListen True -AllowUnicastResponseToMulticast False
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' 0
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    if ($Profile.disableRemoteDesktop) {
        Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    }
    if ($Profile.disableUsbStorage) {
        Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start' 4
    }
}

Export-ModuleMember -Function Set-VgtNetworkBaseline

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5oF3NKdGzo+iO
# X+zTZwtIm8itjY2fQlxzUI8vApI+x6CCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBsFpKDhwfo
# /tWL2SvaL3uHbjvdMjHzno+LbVjMlrI20TANBgkqhkiG9w0BAQEFAASCAYA05F1E
# 2zjtal3p9e3CUeocySWwnOJRTLp4zgZ5HlCOJegG2gMxfmsyLW6gJLOKDjX1wqxL
# F7fVexov8GaVN/2YL2TJjj+qXFoslu6YCBEAIx0/zX38fKJLtRlf/7Tp4Oh+ngi7
# 4kgL7vRPNSqPbQ6DyEJtW4ZH++PUta5WU79NygWPquQ7fKDa+9SafwKAsDfJrM31
# BkWLEeYDpWGqJksogtiJnkzzajUrn8IF4HTa+kqE/IBL+V9HEnjBVXPnZPzByjAk
# gee61NjsdqJb1mJTWUejkJEvOcUQnRreGmS6KFq7mIkZIxFtCvSvlw8P1be0S56y
# Ao51p6Cuh6hunBI+rep4Myo63GSUwhyLBg8HFgXpxfTvs59Trr2geDum3NVMHRRf
# z41BkTBdlJAouSZ5sFBPnsTz68GXcQS4u3WLpoMfIs8U9RAsL9zIaGzUJaRQyM7M
# uvQtDMCARNQ+tXuCbXypJ/oEIYS5IZZj1i61PAYUJrTgdX5p/mLpJw9ev2Q=
# SIG # End signature block
