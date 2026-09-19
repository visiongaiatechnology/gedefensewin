# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [Parameter(Mandatory)][ValidateSet('Install','Uninstall')][string]$Operation,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
$resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
$certificatePath = Join-Path $resolvedPayload 'vgt-release.cer'
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or -not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('VGT trust payload is incomplete.')
}

$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$now = [DateTime]::UtcNow
if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now.AddDays(30)) {
    throw [Security.SecurityException]::new('VGT release certificate validity window was rejected.')
}

# The outer executable is the trust anchor. The bootstrap never self-roots an
# embedded certificate. Development certificates therefore must be explicitly
# trusted on the target test machine before installation.
$installerSignature = Get-AuthenticodeSignature -LiteralPath $resolvedInstaller
if ($installerSignature.Status -ne 'Valid' -or -not $installerSignature.SignerCertificate -or $installerSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('Standalone installer signature validation failed.')
}
$bootstrapSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($bootstrapSignature.Status -ne 'Valid' -or -not $bootstrapSignature.SignerCertificate -or $bootstrapSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('Bootstrap signature validation failed.')
}

$currentUserPublisher = "Cert:\CurrentUser\TrustedPublisher\$($certificate.Thumbprint)"
$removePublisherAfterValidation = -not (Test-Path -LiteralPath $currentUserPublisher)
if ($removePublisherAfterValidation) {
    Import-Certificate -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
}

try {
    $catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
    if ($catalogSignature.Status -ne 'Valid' -or -not $catalogSignature.SignerCertificate -or $catalogSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw [Security.SecurityException]::new('Bootstrap catalog signer validation failed.')
    }
    $catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
    if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('Bootstrap payload catalog validation failed.') }

    $scriptName = if ($Operation -eq 'Install') { 'Install-GeDefense.ps1' } else { 'Uninstall-GeDefense.ps1' }
    $targetScript = Join-Path $resolvedPayload "installer\$scriptName"
    if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Elevated transaction script is missing.') }
    $targetSignature = Get-AuthenticodeSignature -LiteralPath $targetScript
    if ($targetSignature.Status -ne 'Valid' -or -not $targetSignature.SignerCertificate -or $targetSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw [Security.SecurityException]::new('Elevated transaction signer validation failed.')
    }

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows PowerShell 5.1 is unavailable.') }
    $diagnosticRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VGT\InstallerDiagnostics'
    New-Item -Path $diagnosticRoot -ItemType Directory -Force | Out-Null
    $diagnosticLog = Join-Path $diagnosticRoot 'latest-transaction.log'
    if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf) { Remove-Item -LiteralPath $diagnosticLog -Force }

    $arguments = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',('"{0}"' -f $targetScript),'-PayloadRoot',('"{0}"' -f $resolvedPayload),'-DiagnosticLogPath',('"{0}"' -f $diagnosticLog))
    if ($Operation -eq 'Install') { $arguments += @('-InstallerPath',('"{0}"' -f $resolvedInstaller)) }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $start = @{
        FilePath = $powershell
        ArgumentList = $arguments
        Wait = $true
        PassThru = $true
    }
    if (-not $isAdministrator) { 
        $start.Verb = 'RunAs' 
    } else {
        $start.WindowStyle = 'Hidden'
    }
    $process = Start-Process @start
    if ($process.ExitCode -ne 0) {
        $diagnostic = try {
            if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf -ErrorAction Stop) {
                @(Get-Content -LiteralPath $diagnosticLog -Tail 16 -ErrorAction Stop) -join '; '
            } else {
                'No elevated diagnostic log was produced.'
            }
        } catch {
            'Elevated diagnostic log could not be read.'
        }
        throw [InvalidOperationException]::new("Elevated transaction failed with exit code $($process.ExitCode). Diagnostic: $diagnostic")
    }

    # Never spawn the tray elevated. A normally launched installer bootstrap is
    # non-elevated and can start the per-user tray after the elevated child exits.
    if ($Operation -eq 'Install' -and -not $isAdministrator) {
        $installedTray = Join-Path $env:ProgramFiles 'VGT\GeDefense\bin\GeDefenseTray.exe'
        if (-not (Test-Path -LiteralPath $installedTray -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Installed GeDefense Tray executable is missing.') }
        Start-Process -FilePath $installedTray -ArgumentList '--tray'
    }
} finally {
    if ($removePublisherAfterValidation -and (Test-Path -LiteralPath $currentUserPublisher)) {
        Remove-Item -LiteralPath $currentUserPublisher -Force
    }
}

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA7P+PY4vhpYX4S
# ecbbPLSARwdQj5kbZ3lX2hQhSPzwXKCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC4jNdzjyPH
# EKu8C/1uE4/XEMpJy7G2DkOTinev8U6ldjANBgkqhkiG9w0BAQEFAASCAYAeCoJ+
# mlQpWPriqKarI4lxHTw9hr0PkbXussteINwPSXdG53yTEPiIcNQJSYVo60s2n1Kd
# pUqLIvX/m4zNr/+HCdGVmY2VX7BVIyB5vf7fb7aP55IrRLeDk9Z/7aCovfpNsCem
# Y4vhnP90dd8zJt4lxshsyaEs3JwxViN6pN4EdBkxzdJ95Ubg+3S2JVW0gCZ22V7R
# UXywdnHqSOsoL5aKcsoqlSkGBAMVV8itXuA2XtBZrlUk9MlXhmoEc5k9P70MGjCi
# wYmVQ3SAMDaV3tXeGIuk6vInXG6vsO/oSICe9Xv0N1LpoGyN1bVM85idhGmXvE6F
# l888PccaxQQY2//gyBaF5WFXuDak5dDgblCqxPteaD0kH8p6knmQ1DhIFFw73kXC
# 6ij3nQ73UGdah33ncal7wq/IT3rf7PNH8y8C/TyrURWn5JCKT3rr7DlOR0M/2Ata
# 9GHVCuEn60dA8onfvyl8/SehnukGnCbmTm1SNo92Ak9m13vvC8dBYSfrvQM=
# SIG # End signature block
