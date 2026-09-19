# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$PayloadRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative token required.') }
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
$certificatePath = Join-Path $resolvedPayload 'vgt-release.cer'
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or -not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Signed uninstall payload is incomplete.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$signature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Uninstaller signature validation failed.') }
$catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
if ($catalogSignature.Status -ne 'Valid' -or -not $catalogSignature.SignerCertificate -or $catalogSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Uninstall catalog signer validation failed.') }
$catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('Uninstall payload catalog validation failed.') }

foreach ($processName in @('GeDefenseTray','GeDefenseCenter')) {
    foreach ($process in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
        $expectedPath = Join-Path $installRoot ("bin\{0}.exe" -f $processName)
        $actualPath = try { [IO.Path]::GetFullPath($process.Path) } catch { '' }
        if ($actualPath -and $actualPath.Equals([IO.Path]::GetFullPath($expectedPath),[StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
    }
}

$protectionScript = Join-Path $installRoot 'xdr\Set-VgtMhxProtection.ps1'
if (Test-Path -LiteralPath $protectionScript -PathType Leaf) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File $protectionScript -Mode Restore | Out-Null
}
$appControlScript = Join-Path $installRoot 'xdr\Set-VgtMhxAppControl.ps1'
if (Test-Path -LiteralPath $appControlScript -PathType Leaf) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File $appControlScript -Action Remove | Out-Null
}
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like 'VGT GeDefense Threat Intelligence *' -or $_.Group -in @('VGT GeDefense Sovereign','VGT GeDefense Sovereign Allows') } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & "$env:SystemRoot\System32\sc.exe" delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Service removal failed.') }
}
Get-ScheduledTask -TaskName 'VGT GeDefense*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $startMenu) { Remove-Item -LiteralPath $startMenu -Recurse -Force }
if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Force }
if (Test-Path -LiteralPath $runKey) { Remove-ItemProperty -LiteralPath $runKey -Name 'VGTGeDefenseTray' -ErrorAction SilentlyContinue }
if (Get-LocalGroup -Name 'VGT GeDefense Operators' -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name 'VGT GeDefense Operators' }
if (Test-Path -LiteralPath $installRoot) {
    Get-ChildItem -LiteralPath $installRoot -Force | Where-Object Name -ne 'GeDefense-Setup.exe' | Remove-Item -Recurse -Force
    $installedSetup = Join-Path $installRoot 'GeDefense-Setup.exe'
    if (Test-Path -LiteralPath $installedSetup -PathType Leaf) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VgtPendingDelete {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existingName, string newName, int flags);
    public static bool Schedule(string path) { return MoveFileEx(path, null, 4); }
}
'@
        if (-not [VgtPendingDelete]::Schedule($installedSetup)) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    }
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAPwZi+ldf8V0e9
# gor4bokR6hyHgu6K1iEe0z0TINqWWKCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA68fJr7OHT
# bS6c3cdJzZ7rFNBvAZs+GfJEYi0Bslp9KjANBgkqhkiG9w0BAQEFAASCAYBqM4lC
# ajg1XraHwDY2+Sel3Z4SM9ePywdLdLojphcbBSs/Zmj6OMM0wTmFJ8e8FkZ1cisL
# CzHe+d7rOhM4oXa4eaQ/OhqCo4V1D0wEjpj5u3UxcWlEP3qEcRn/QAx//dBjU6tv
# uekxHoTewlXva+HMC3+iaEdF6PbjpQl0NKPlz6IzAIa1YGC1/FIP0Vof7XSC1T31
# phTvvtOeJvGHcU/9x/p2ficsT0ntdhvwy/rX8iEujElZlOsnqI3a5iuyZfnmGf07
# G84W8TFo1J2kPfOr2PIjONIYnxAJzLfMKC8xI+nuSIHvF5YMqIC2x11sLJcoedqk
# wejBZU1jRNrD6upmWX+8RKNfMeloSY1rx5nxX+khDUqtpCJQ4uMVmO4balaFRhl9
# jQ9bt3tkeg5HbT0zgXYg/F94QfQTB4fJpG+vnpnjNjg4m6YjT1RKu8waE1KbJ15m
# 91g6wUi02yKAHVxVJirq/HBZ2ZQNG0gFiGSPVVq0cI69Sz0dUfH1FXIDpFo=
# SIG # End signature block
