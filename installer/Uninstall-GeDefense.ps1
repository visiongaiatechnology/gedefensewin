# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$PayloadRoot,
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.log$')][string]$DiagnosticLogPath = '',
    [switch]$PurgeData,
    [switch]$KeepPublisherTrust,
    [switch]$KeepOperatorGroup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense'
$brandingRoot = Join-Path $env:ProgramData 'VGT\Branding'
$installerLogRoot = Join-Path $env:ProgramData 'VGT\InstallerLogs'
$installerLog = Join-Path $installerLogRoot 'uninstall.log'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$stateKey = 'HKLM:\SOFTWARE\VGT\GeDefense'
$operatorGroup = 'VGT GeDefense Operators'
$resolvedDiagnosticLog = ''
$script:uninstallLogReady = $false
$script:uninstallLogBuffer = [Collections.Generic.List[string]]::new()
$safetyModule = Join-Path $PSScriptRoot 'InstallerSafety.psm1'
if (-not (Test-Path -LiteralPath $safetyModule -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Installer safety module is missing.') }
Import-Module -Name $safetyModule -Force

function Write-VgtLogLine {
    param([Parameter(Mandatory)][string]$Line)
    if ($resolvedDiagnosticLog) {
        try {
            Add-Content -LiteralPath $resolvedDiagnosticLog -Value $Line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 50
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
    }
    try {
        Add-Content -LiteralPath $installerLog -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

function Write-VgtUninstallPhase {
    param([Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$State,[AllowEmptyString()][string]$Detail = '')
    $safeDetail = if ($Detail) { $Detail.Replace("`r",' ').Replace("`n",' ') } else { '' }
    $line = '{0}|{1}|{2}|{3}' -f [DateTime]::UtcNow.ToString('o'),$Phase,$State,$safeDetail
    if (-not $script:uninstallLogReady) {
        [void]$script:uninstallLogBuffer.Add($line)
        return
    }
    Write-VgtLogLine -Line $line
}

function Remove-VgtTreeSafely {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [IO.Directory]::Exists($Path)) { return }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Never recurse through a junction/reparse point: remove the link only.
            [IO.Directory]::Delete($child.FullName,$false)
        } elseif ($child.PSIsContainer) {
            Remove-VgtTreeSafely -Path $child.FullName
        } else {
            Remove-Item -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

function Remove-VgtSecretFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 0 -and $length -le 1048576) {
            $random = New-Object byte[] ([int]$length)
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($random) } finally { $rng.Dispose() }
            [IO.File]::WriteAllBytes($Path,$random)
        }
    } catch {}
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return -not (Test-Path -LiteralPath $Path)
}

function Initialize-VgtUninstallLogging {
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $localAppDataRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('LocalApplicationData'))
    if ([string]::IsNullOrWhiteSpace($programDataRoot) -or [string]::IsNullOrWhiteSpace($localAppDataRoot)) { throw [IO.InvalidDataException]::new('ProgramData/LocalAppData environment is unavailable.') }
    Assert-VgtNoReparseTraversal -Path $installRoot -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramFiles))
    Assert-VgtNoReparseTraversal -Path $dataRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $brandingRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $installerLogRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $startMenu -AllowedRoot $programDataRoot
    if ($DiagnosticLogPath) {
        $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path $localAppDataRoot 'VGT\InstallerDiagnostics')).TrimEnd('\') + '\'
        $candidateDiagnosticLog = [IO.Path]::GetFullPath($DiagnosticLogPath)
        if (-not $candidateDiagnosticLog.StartsWith($diagnosticRoot,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Diagnostic log path escaped the user diagnostic jail.') }
        Assert-VgtNoReparseTraversal -Path $candidateDiagnosticLog -AllowedRoot $localAppDataRoot
        New-VgtSafeDirectory -Path ([IO.Path]::GetDirectoryName($candidateDiagnosticLog)) -AllowedRoot $localAppDataRoot | Out-Null
        $script:resolvedDiagnosticLog = $candidateDiagnosticLog
    }
    New-VgtSafeDirectory -Path $installerLogRoot -AllowedRoot $programDataRoot | Out-Null
    $nativeOutput = (& "$env:SystemRoot\System32\icacls.exe" $installerLogRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw [Security.SecurityException]::new(('Uninstall log ACL hardening failed: {0}' -f $nativeOutput)) }
    Assert-VgtSafeFileTarget -Path $installerLog -AllowedRoot $installerLogRoot | Out-Null
    $script:uninstallLogReady = $true
    foreach ($bufferedLine in $script:uninstallLogBuffer) { Write-VgtLogLine -Line $bufferedLine }
    $script:uninstallLogBuffer.Clear()
    Write-VgtUninstallPhase -Phase 'Logging' -State 'OK' -Detail ('persistent log: {0}' -f $installerLog)
}

trap {
    try {
        $msg = if ($_.Exception) { $_.Exception.Message } else { 'Unknown uninstaller exception' }
        if ($script:uninstallLogReady) {
            Write-VgtUninstallPhase -Phase 'Uninstaller' -State 'FAILED' -Detail $msg
        } elseif ($resolvedDiagnosticLog) {
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value ('{0}|Uninstaller|FAILED|{1}' -f [DateTime]::UtcNow.ToString('o'),$msg.Replace("`r",' ').Replace("`n",' ')) -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
    exit 90
}

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

# Paths are validated (and the restricted uninstall log is created) before the
# first persistent write or removal.
Initialize-VgtUninstallLogging
Write-VgtUninstallPhase -Phase 'Elevation' -State 'OK' -Detail $identity.Name
Write-VgtUninstallPhase -Phase 'PayloadTrust' -State 'OK' -Detail $certificate.Thumbprint

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
    Write-VgtUninstallPhase -Phase 'Service' -State 'OK' -Detail 'removed'
}
Get-ScheduledTask -TaskName 'VGT GeDefense*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $startMenu) { Remove-Item -LiteralPath $startMenu -Recurse -Force }
if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Force }
if (Test-Path -LiteralPath $runKey) { Remove-ItemProperty -LiteralPath $runKey -Name 'VGTGeDefenseTray' -ErrorAction SilentlyContinue }
Write-VgtUninstallPhase -Phase 'Registration' -State 'OK' -Detail 'shortcuts, run key and uninstall key removed'

# Only remove local group members/groups that this product provably created.
$state = $null
if (Test-Path -LiteralPath $stateKey) {
    try { $state = Get-ItemProperty -LiteralPath $stateKey -ErrorAction Stop } catch { $state = $null }
}
if (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue) {
    if ($KeepOperatorGroup) {
        Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'KEPT' -Detail 'explicitly retained'
    } elseif ($null -eq $state -or -not (@($state.PSObject.Properties.Name) -contains 'OperatorGroupCreated')) {
        # Older installations did not record product ownership: never delete a
        # group that might have existed before GeDefense was installed.
        Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'RETAINED' -Detail 'no product ownership marker (pre-5.1.3 install)'
    } else {
        $recordedMembers = @()
        if (@($state.PSObject.Properties.Name) -contains 'InstallerAddedMembers' -and $state.InstallerAddedMembers) {
            $recordedMembers = @([string]$state.InstallerAddedMembers -split ';' | Where-Object { $_ -match '^S-1-(?:\d+-)+\d+$' })
        }
        foreach ($memberSid in $recordedMembers) {
            try {
                $match = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction Stop | Where-Object { [string]$_.SID.Value -eq $memberSid })
                foreach ($entry in $match) { Remove-LocalGroupMember -Group $operatorGroup -Member $entry -ErrorAction Stop }
            } catch {
                Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'WARN' -Detail ('could not remove recorded member {0}' -f $memberSid)
            }
        }
        $remaining = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction SilentlyContinue)
        $createdByProduct = ([int]$state.OperatorGroupCreated -eq 1)
        if ($createdByProduct -and $remaining.Count -eq 0) {
            try {
                Remove-LocalGroup -Name $operatorGroup -ErrorAction Stop
                Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'OK' -Detail 'product-created group removed'
            } catch {
                Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'WARN' -Detail 'product-created group removal failed'
            }
        } else {
            Write-VgtUninstallPhase -Phase 'OperatorGroup' -State 'RETAINED' -Detail ('remaining members: {0}' -f $remaining.Count)
        }
    }
}

if (Test-Path -LiteralPath $installRoot) {
    $installedSetup = Join-Path $installRoot 'GeDefense-Setup.exe'
    Get-ChildItem -LiteralPath $installRoot -Force | Where-Object Name -ne 'GeDefense-Setup.exe' | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            [IO.Directory]::Delete($_.FullName,$false)
        } elseif ($_.PSIsContainer) {
            Remove-VgtTreeSafely -Path $_.FullName
        } else {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
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
    Write-VgtUninstallPhase -Phase 'ProgramFiles' -State 'OK' -Detail $installRoot
}

# Remove only the publisher trust anchor that matches the signed payload
# certificate. /Root is never touched (the installer never self-roots).
$publisherStorePath = "Cert:\LocalMachine\TrustedPublisher\$($certificate.Thumbprint)"
if ($KeepPublisherTrust) {
    Write-VgtUninstallPhase -Phase 'PublisherTrust' -State 'KEPT' -Detail 'explicitly retained'
} elseif (Test-Path -LiteralPath $publisherStorePath) {
    $stored = Get-Item -LiteralPath $publisherStorePath -ErrorAction Stop
    if ($stored.Thumbprint -eq $certificate.Thumbprint) {
        Remove-Item -LiteralPath $publisherStorePath -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $publisherStorePath) { throw [Security.SecurityException]::new('Publisher trust anchor removal failed.') }
        Write-VgtUninstallPhase -Phase 'PublisherTrust' -State 'OK' -Detail $certificate.Thumbprint
    } else {
        Write-VgtUninstallPhase -Phase 'PublisherTrust' -State 'SKIPPED' -Detail 'thumbprint mismatch'
    }
} else {
    Write-VgtUninstallPhase -Phase 'PublisherTrust' -State 'ABSENT' -Detail $certificate.Thumbprint
}

# Runtime credential: overwrite with random bytes, then delete. Evidence/Titan
# data is retained unless -PurgeData is requested so upgrades/reinstalls and
# forensic review do not lose the chain.
$tokenPath = Join-Path $dataRoot 'dashboard.token'
if (Test-Path -LiteralPath $tokenPath -PathType Leaf) {
    if (Remove-VgtSecretFile -Path $tokenPath) {
        Write-VgtUninstallPhase -Phase 'RuntimeToken' -State 'OK' -Detail 'overwritten and removed'
    } else {
        Write-VgtUninstallPhase -Phase 'RuntimeToken' -State 'WARN' -Detail 'token removal incomplete'
    }
} else {
    Write-VgtUninstallPhase -Phase 'RuntimeToken' -State 'ABSENT' -Detail 'no dashboard token present'
}
if ($PurgeData) {
    if (Test-Path -LiteralPath $dataRoot) {
        Assert-VgtNoReparseTraversal -Path $dataRoot -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData))
        Remove-VgtTreeSafely -Path $dataRoot
        Write-VgtUninstallPhase -Phase 'RuntimeData' -State 'OK' -Detail ('purged: {0}' -f $dataRoot)
    }
} else {
    Write-VgtUninstallPhase -Phase 'RuntimeData' -State 'RETAINED' -Detail 'use -PurgeData to remove evidence/runtime data'
}
if (Test-Path -LiteralPath $stateKey) { Remove-Item -LiteralPath $stateKey -Force -ErrorAction SilentlyContinue }
Write-VgtUninstallPhase -Phase 'Uninstaller' -State 'COMPLETE' -Detail 'GeDefense removed'
