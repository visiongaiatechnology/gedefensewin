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
# MIIHIwYJKoZIhvcNAQcCoIIHFDCCBxACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuw9SjRyvtBewMMYom99q2x6N
# RF2gggQsMIIEKDCCApCgAwIBAgIQXORetgQfkZtPDg+e7T3jizANBgkqhkiG9w0B
# AQsFADAsMSowKAYDVQQDDCFWaXNpb25HYWlhIFRlY2hub2xvZ3kgVkdUIFJlbGVh
# c2UwHhcNMjYwODIxMTM1MjQxWhcNMzYwODIxMTIwMjQwWjAsMSowKAYDVQQDDCFW
# aXNpb25HYWlhIFRlY2hub2xvZ3kgVkdUIFJlbGVhc2UwggGiMA0GCSqGSIb3DQEB
# AQUAA4IBjwAwggGKAoIBgQC+aRas6n4UnIYDdzkiqHkWx10CFLVcCO0OYKP+1Lzh
# VTFdHfwLuUOcjxTq9+dVakMmZS1nocDxvPFnYUxD8X82Fw3iRYBujMHY1WgNdFpJ
# cQ80rvF0EM0Cr6EjrX+m++sWLMD3UfFmlDr2CzVWBxt/HGQhP1ZrfFtvf/vG09Eh
# aDL/Evvt2FC9wWk01QY+cHLp2kGLu23AVBc/DMAlhmqmVMFov+7GT2+SMdCipzGq
# 8cQADP8tRmkZ1g0GrxkrhWdfC5jIfgIHes5xWeqR9VErrtDa3hVDljYNgDRJhgDu
# F057LdyC0+BGm/ybI5sOJ0ZvK3JEWllSicXEXD+7pCSYt3FddSXoHbGEgRir2fE1
# DYkkblSNDBoNSCZeIGv3Yq9XK6dA56ns3Av+svZsbJ8biS6VvCNZy3US4xNaMOVb
# IYbxDBYz6GG3KMKXCNBFBY/3JQaQPqx4z45GBY8PKKMPrWKpxCvxpK2JMxsBsaQK
# SnBAoeRhh4EOYkoCrjUz7nkCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQwTx/Gfaour6y8PBTw95P5M/nNYDAN
# BgkqhkiG9w0BAQsFAAOCAYEASEHvhzebKSLTHfPOHleiUdx/MRq/A3jaYI7oUJ0Z
# 0KlgetBLenoUMEBQ4ORbfIlOLBs3REAeFPqu/faEXiehtQrlesl16g3vy46+Qxnx
# q/lmoeEbkYv0BoVFHiMsp/IeZF8DoBls+FQOSPQpjfqJ2R0S579y7vZislKqO5Ze
# VmlhHf694bwant9EYNCGpw/KqVlxG7IZWsk7sfFjII1t5wO7RFl5k6AiaUZPA7Gh
# lOZuqzcVWus0ku6hdiYjFp2WQbK++nELDGL05GYLIT8/jk7JfOJke4vwWpUyMriO
# +E1nfvC3XAQfhaZoV72JigD0CkINuXRxlm1ZQRO5CtvV9/Ib2kATupVU+5rUzj8d
# mrjE5mrOiy1PtVxhTZuM78LsnaX/+JbT0mJTaSvCI+b5Kdg41zmiRdNgaKgZGbes
# OMED7gnbtzjkx9wN4cpkK1Q9LT+NPKjZC7s3ecSPpu6E0AsOkmAsXhFBDqKEe1zF
# rsRNUfysi5T0QiNc4vQ44S2sMYICYTCCAl0CAQEwQDAsMSowKAYDVQQDDCFWaXNp
# b25HYWlhIFRlY2hub2xvZ3kgVkdUIFJlbGVhc2UCEFzkXrYEH5GbTw4Pnu0944sw
# CQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# IwYJKoZIhvcNAQkEMRYEFPJf7zPNFAOefHUaDeCdwJvn2wYLMA0GCSqGSIb3DQEB
# AQUABIIBgFBvmqwUJdROvIGfJ76sQW9gH+sqvH5a+bYDQ0c6eJMF5mj9/ERCPHb3
# rYC97EJD8Fs9Vq48bk9ylxHeKJFdljyv02DKs4BTeg6Azn56heFPyapFkvGXbOIo
# 3hL8YTbmU7qBkRfdIQ6xpDw4zHa8Zk9zgKEVJS1GFFIjowgChc3L9afdUWq6I41S
# 8+wSJpxpq5/s8FEZYefrPRmF3kXpg7SJsLI7lG7R7mAhNzEr9YAOXF5nfmVaXgpq
# XDES1QQBErx9KwktJoIlazmBwR0EAgkqz7RKZQOzXPE7m2ed5jPexAHX0Mzt4I4E
# EUe0S+KoVodZRNOW3P2vsTmhwQAmHa94/huxH6i9T+U96X4HxUkpp/jFoNoEJg0H
# DWHTD3WCnqCUDjMi+b2ijy/K6B1B1VM1B/Z2bvpRvGQZtGBzCGfbdZhuWc40umJ8
# LtmMuM0mASh9CCOFm/vdY0adRHWRN+AU8LSvlF0hm3yQZESmEaetl3C0ODMsPLb/
# F/ab5frdHg==
# SIG # End signature block
