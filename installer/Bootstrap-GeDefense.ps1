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
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or -not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT trust payload is incomplete.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$bootstrapSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if (-not $bootstrapSignature.SignerCertificate -or $bootstrapSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Bootstrap signature validation failed.') }
$currentUserRoot = "Cert:\CurrentUser\Root\$($certificate.Thumbprint)"
$currentUserPublisher = "Cert:\CurrentUser\TrustedPublisher\$($certificate.Thumbprint)"
$removeRootAfterValidation = -not (Test-Path -LiteralPath $currentUserRoot)
$removePublisherAfterValidation = -not (Test-Path -LiteralPath $currentUserPublisher)
if ($removeRootAfterValidation) { Import-Certificate -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null }
if ($removePublisherAfterValidation) { Import-Certificate -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null }

try {
    $catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
    if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('Bootstrap payload catalog validation failed.') }
    $scriptName = if($Operation -eq 'Install'){'Install-GeDefense.ps1'}else{'Uninstall-GeDefense.ps1'}
    $targetScript = Join-Path $resolvedPayload "installer\$scriptName"
    if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Elevated transaction script is missing.') }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $diagnosticRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VGT\InstallerDiagnostics'
    New-Item -Path $diagnosticRoot -ItemType Directory -Force | Out-Null
    $diagnosticLog = Join-Path $diagnosticRoot 'latest-transaction.log'
    if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf) { Remove-Item -LiteralPath $diagnosticLog -Force }
    $arguments = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $targetScript),'-PayloadRoot',('"{0}"' -f $resolvedPayload),'-DiagnosticLogPath',('"{0}"' -f $diagnosticLog))
    if($Operation -eq 'Install') { $arguments += @('-InstallerPath',('"{0}"' -f $resolvedInstaller)) }
    $process = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru -WindowStyle Hidden
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
    if ($Operation -eq 'Install') {
        $installedTray = Join-Path $env:ProgramFiles 'VGT\GeDefense\bin\GeDefenseTray.exe'
        if (-not (Test-Path -LiteralPath $installedTray -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Installed GeDefense Tray executable is missing.') }
        Start-Process -FilePath $installedTray -ArgumentList '--tray'
    }
} finally {
    if ($removePublisherAfterValidation -and (Test-Path -LiteralPath $currentUserPublisher)) { Remove-Item -LiteralPath $currentUserPublisher -Force }
    if ($removeRootAfterValidation -and (Test-Path -LiteralPath $currentUserRoot)) { Remove-Item -LiteralPath $currentUserRoot -Force }
}
