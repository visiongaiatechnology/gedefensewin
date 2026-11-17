# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [Parameter(Mandatory)][ValidateSet('Install','Uninstall')][string]$Operation,
    # Optional: only the standalone (embedded payload) installer passes the outer
    # setup executable. The Inno Setup transaction does not need a persistent
    # copy of its own setup executable in {app} (FIND-WIN-014).
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$diagnosticRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VGT\InstallerDiagnostics'
$diagnosticLog = Join-Path $diagnosticRoot 'latest-transaction.log'
$removePublisherAfterValidation = $false
$currentUserPublisher = ''

function Write-BootstrapFailureLog {
    param([Parameter(Mandatory)][string]$Message)
    $sanitized = ($Message -replace '[\r\n|]+', ' ').Trim()
    if (-not $sanitized) { $sanitized = 'Unknown bootstrap error.' }
    $line = '{0:o}|Bootstrap|FAILED|{1}' -f [DateTime]::UtcNow, $sanitized
    try {
        if (-not (Test-Path -LiteralPath $diagnosticRoot -PathType Container)) {
            New-Item -Path $diagnosticRoot -ItemType Directory -Force | Out-Null
        }
        $existingTail = ''
        if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf) {
            $existingTail = @(Get-Content -LiteralPath $diagnosticLog -Tail 4 -ErrorAction SilentlyContinue) -join "`n"
        }
        if ($existingTail -notmatch '\|FAILED\|') {
            Add-Content -LiteralPath $diagnosticLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {
        # Best-effort diagnostic persistence; original exception stays primary.
    }
    try {
        $programDataLog = Join-Path $env:ProgramData 'VGT\InstallerLogs\install.log'
        $programDataLogDir = Split-Path -Parent $programDataLog
        if (Test-Path -LiteralPath $programDataLogDir -PathType Container) {
            Add-Content -LiteralPath $programDataLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {
        # Non-elevated callers cannot write into InstallerLogs; localappdata still receives the trace.
    }
}

try {
    if ($Operation -eq 'Install' -and (Test-Path -LiteralPath $diagnosticLog -PathType Leaf)) {
        Remove-Item -LiteralPath $diagnosticLog -Force -ErrorAction SilentlyContinue
    }
    $resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
    $resolvedInstaller = ''
    if ($InstallerPath) {
        $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
    }
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
    if ($resolvedInstaller) {
        $installerSignature = Get-AuthenticodeSignature -LiteralPath $resolvedInstaller
        if ($installerSignature.Status -ne 'Valid' -or -not $installerSignature.SignerCertificate -or $installerSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
            throw [Security.SecurityException]::new("Standalone installer signature validation failed: $($installerSignature.Status) $($installerSignature.StatusMessage)")
        }
    }
    $bootstrapSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
    if ($bootstrapSignature.Status -ne 'Valid' -or -not $bootstrapSignature.SignerCertificate -or $bootstrapSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw [Security.SecurityException]::new("Bootstrap signature validation failed: $($bootstrapSignature.Status) $($bootstrapSignature.StatusMessage)")
    }

    $currentUserPublisher = "Cert:\CurrentUser\TrustedPublisher\$($certificate.Thumbprint)"
    $removePublisherAfterValidation = -not (Test-Path -LiteralPath $currentUserPublisher)
    if ($removePublisherAfterValidation) {
        # .NET store API: Import-Certificate may request an interactive confirmation
        # that is unavailable in the silent setup path.
        $publisherStore = [Security.Cryptography.X509Certificates.X509Store]::new(
            [Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        try {
            $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $publisherStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath))
        } finally {
            $publisherStore.Close()
        }
    }

    $catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
    if ($catalogSignature.Status -ne 'Valid' -or -not $catalogSignature.SignerCertificate -or $catalogSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw [Security.SecurityException]::new("Bootstrap catalog signer validation failed: $($catalogSignature.Status) $($catalogSignature.StatusMessage)")
    }
    $catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
    if ($catalog.Status -ne 'Valid') {
        $detail = if ($catalog.CatalogItems) {
            $mismatches = [Collections.Generic.List[string]]::new()
            foreach ($k in ($catalog.CatalogItems.Keys | Sort-Object)) {
                if ($catalog.PathItems[$k] -ne $catalog.CatalogItems[$k]) { [void]$mismatches.Add($k) }
            }
            $sample = if ($mismatches.Count -gt 0) { ' sample=' + (($mismatches | Select-Object -First 5) -join ',') } else { '' }
            "status=$($catalog.Status) hashAlgo=$($catalog.HashAlgorithm) cat=$($catalog.CatalogItems.Count) path=$($catalog.PathItems.Count)$sample"
        } else {
            "status=$($catalog.Status)"
        }
        throw [Security.SecurityException]::new("Bootstrap payload catalog validation failed ($detail).")
    }

    $scriptName = if ($Operation -eq 'Install') { 'Install-GeDefense.ps1' } else { 'Uninstall-GeDefense.ps1' }
    $targetScript = Join-Path $resolvedPayload "installer\$scriptName"
    if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Elevated transaction script is missing.') }
    $targetSignature = Get-AuthenticodeSignature -LiteralPath $targetScript
    if ($targetSignature.Status -ne 'Valid' -or -not $targetSignature.SignerCertificate -or $targetSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw [Security.SecurityException]::new("Elevated transaction signer validation failed: $($targetSignature.Status) $($targetSignature.StatusMessage)")
    }

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows PowerShell 5.1 is unavailable.') }
    New-Item -Path $diagnosticRoot -ItemType Directory -Force | Out-Null
    if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf) { Remove-Item -LiteralPath $diagnosticLog -Force }

    $arguments = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','AllSigned','-File',('"{0}"' -f $targetScript),'-PayloadRoot',('"{0}"' -f $resolvedPayload),'-DiagnosticLogPath',('"{0}"' -f $diagnosticLog))
    if ($Operation -eq 'Install' -and $resolvedInstaller) { $arguments += @('-InstallerPath',('"{0}"' -f $resolvedInstaller)) }

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
} catch {
    $errMsg = "{0} (line {1})" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
    Write-BootstrapFailureLog -Message $errMsg
    throw
} finally {
    if ($removePublisherAfterValidation -and $currentUserPublisher -and (Test-Path -LiteralPath $currentUserPublisher)) {
        Remove-Item -LiteralPath $currentUserPublisher -Force -ErrorAction SilentlyContinue
    }
}

