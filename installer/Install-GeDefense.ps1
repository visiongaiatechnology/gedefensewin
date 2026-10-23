# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath = '',
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.log$')][string]$DiagnosticLogPath = '',
    # Explicit, auditable rollback switch. The default is fail-closed and
    # refuses to replace a newer installation (SC-FIND-003 local hardening);
    # the externally anchored anti-rollback channel remains an owner-accepted
    # external blocker.
    [switch]$AllowDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense'
$brandingRoot = Join-Path $env:ProgramData 'VGT\Branding'
$installerLogRoot = Join-Path $env:ProgramData 'VGT\InstallerLogs'
$startMenuRoot = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
$stateKey = 'HKLM:\SOFTWARE\VGT\GeDefense'
$operatorGroup = 'VGT GeDefense Operators'
$operatorGroupDescription = 'VGT GeDefense security center operators.'
$installLog = Join-Path $installerLogRoot 'install.log'
$resolvedDiagnosticLog = ''
$script:installLogReady = $false
$script:installLogBuffer = [Collections.Generic.List[string]]::new()
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
        Add-Content -LiteralPath $installLog -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

function Write-VgtInstallPhase {
    param([Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$State,[AllowEmptyString()][string]$Detail = '')
    $safeDetail = if ($Detail) { $Detail.Replace("`r",' ').Replace("`n",' ') } else { '' }
    $line = '{0}|{1}|{2}|{3}' -f [DateTime]::UtcNow.ToString('o'),$Phase,$State,$safeDetail
    # The log target is only used after Initialize-VgtInstallLogging has proven
    # the path reparse-free and applied the restrictive log-directory ACL.
    if (-not $script:installLogReady) {
        [void]$script:installLogBuffer.Add($line)
        return
    }
    Write-VgtLogLine -Line $line
}

trap {
    try {
        $msg = if ($_.Exception) { $_.Exception.Message } else { 'Unknown installer exception' }
        if ($script:installLogReady) {
            Write-VgtInstallPhase -Phase 'Installer' -State 'FAILED' -Detail $msg
        } elseif ($resolvedDiagnosticLog) {
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value ('{0}|Installer|FAILED|{1}' -f [DateTime]::UtcNow.ToString('o'),$msg.Replace("`r",' ').Replace("`n",' ')) -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}
    exit 90
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $operation = if ($Arguments.Count -gt 0) { $Arguments[0] } else { 'unknown' }
    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $nativeOutput = (& "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1 | Out-String).Trim()
        $nativeExitCode = $LASTEXITCODE
        if ($nativeExitCode -eq 0) {
            Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit=0" -f $operation)
            return
        }
        if ($operation -eq 'delete' -and ($nativeExitCode -eq 1072 -or $nativeExitCode -eq 1060)) {
            # 1072 = ERROR_SERVICE_MARKED_FOR_DELETE, 1060 = ERROR_SERVICE_DOES_NOT_EXIST
            Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit={1}|pending_delete" -f $operation,$nativeExitCode)
            return
        }
        if ($operation -eq 'create' -and $nativeExitCode -eq 1072 -and $attempt -lt $maxAttempts) {
            Start-Sleep -Milliseconds 600
            continue
        }
        Write-VgtInstallPhase -Phase 'ServiceControl' -State 'FAILED' -Detail ("{0}|exit={1}|{2}" -f $operation,$nativeExitCode,$nativeOutput)
        throw [InvalidOperationException]::new(("Service operation '{0}' failed with exit code {1}." -f $operation,$nativeExitCode))
    }
}

function Invoke-IcaclsChecked {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Phase
    )
    $nativeOutput = (& "$env:SystemRoot\System32\icacls.exe" $Target @Arguments 2>&1 | Out-String).Trim()
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        Write-VgtInstallPhase -Phase $Phase -State 'FAILED' -Detail ("icacls exit {0}: {1}" -f $nativeExitCode,$nativeOutput)
        throw [Security.SecurityException]::new(("{0} failed with native exit code {1}." -f $Phase,$nativeExitCode))
    }
    Write-VgtInstallPhase -Phase $Phase -State 'OK' -Detail ("icacls exit 0: {0}" -f $nativeOutput)
}

function Assert-VgtInstallerPaths {
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programDataRoot) -or [string]::IsNullOrWhiteSpace($programFilesRoot)) { throw [IO.InvalidDataException]::new('ProgramData/ProgramFiles environment is unavailable.') }
    Assert-VgtNoReparseTraversal -Path $installRoot -AllowedRoot $programFilesRoot
    Assert-VgtNoReparseTraversal -Path $dataRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $brandingRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $installerLogRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $startMenuRoot -AllowedRoot $programDataRoot
}

function Initialize-VgtInstallLogging {
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $localAppDataRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('LocalApplicationData'))
    Assert-VgtInstallerPaths
    if ($DiagnosticLogPath) {
        if ([string]::IsNullOrWhiteSpace($localAppDataRoot)) { throw [IO.InvalidDataException]::new('LocalAppData environment is unavailable.') }
        $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path $localAppDataRoot 'VGT\InstallerDiagnostics')).TrimEnd('\') + '\'
        $candidateDiagnosticLog = [IO.Path]::GetFullPath($DiagnosticLogPath)
        if (-not $candidateDiagnosticLog.StartsWith($diagnosticRoot,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Diagnostic log path escaped the user diagnostic jail.') }
        Assert-VgtNoReparseTraversal -Path $candidateDiagnosticLog -AllowedRoot $localAppDataRoot
        New-VgtSafeDirectory -Path ([IO.Path]::GetDirectoryName($candidateDiagnosticLog)) -AllowedRoot $localAppDataRoot | Out-Null
        $script:resolvedDiagnosticLog = $candidateDiagnosticLog
    }
    New-VgtSafeDirectory -Path $installerLogRoot -AllowedRoot $programDataRoot | Out-Null
    # Restrictive ACL for the persistent installer audit log before the first write.
    Invoke-IcaclsChecked -Target $installerLogRoot -Phase 'InstallerLogACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    Assert-VgtSafeFileTarget -Path $installLog -AllowedRoot $installerLogRoot | Out-Null
    $script:installLogReady = $true
    foreach ($bufferedLine in $script:installLogBuffer) { Write-VgtLogLine -Line $bufferedLine }
    $script:installLogBuffer.Clear()
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative token required.')
}
# Reparse-point validation, restricted log directory creation and ACL hardening
# all complete before the first persistent log line is written.
Initialize-VgtInstallLogging
Write-VgtInstallPhase -Phase 'Elevation' -State 'OK' -Detail $identity.Name
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayload 'bin\gedefense-windows.exe') -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('GeDefense payload is incomplete.')
}
$versionPath = Join-Path $resolvedPayload 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense release version metadata is missing.') }
$releaseVersion = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
if ($releaseVersion -notmatch '^5\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$') { throw [IO.InvalidDataException]::new('GeDefense release version metadata is invalid.') }

# Downgrade guard (SC-FIND-003 local hardening): never silently replace a newer
# installation with an older one. The externally anchored, manipulation-proof
# anti-rollback channel is an owner-accepted external blocker; this guard is the
# local best-effort control and is auditable in the install log.
function ConvertTo-VgtVersionParts {
    param([string]$Value)
    if ($Value -match '^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)') {
        return @([int]$Matches.major, [int]$Matches.minor, [int]$Matches.patch)
    }
    return $null
}
$installedVersionPath = Join-Path $installRoot 'VERSION'
$installedVersion = ''
if (Test-Path -LiteralPath $installedVersionPath -PathType Leaf) {
    $installedVersion = (Get-Content -LiteralPath $installedVersionPath -Raw -Encoding UTF8).Trim()
} else {
    $installedVersion = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
}
$newParts = ConvertTo-VgtVersionParts -Value $releaseVersion
$oldParts = ConvertTo-VgtVersionParts -Value $installedVersion
if ($oldParts -and $newParts) {
    $olderThanInstalled = ($oldParts[0] -gt $newParts[0]) -or
        (($oldParts[0] -eq $newParts[0]) -and ($oldParts[1] -gt $newParts[1])) -or
        (($oldParts[0] -eq $newParts[0]) -and ($oldParts[1] -eq $newParts[1]) -and ($oldParts[2] -gt $newParts[2]))
    if ($olderThanInstalled -and -not $AllowDowngrade) {
        throw [InvalidOperationException]::new(('Downgrade rejected: installed version {0} is newer than release {1}. Use -AllowDowngrade only for an authorized, documented rollback.' -f $installedVersion, $releaseVersion))
    }
    Write-VgtInstallPhase -Phase 'VersionGuard' -State 'OK' -Detail ('installed={0}|release={1}|downgradeAllowed={2}' -f $installedVersion, $releaseVersion, [bool]$AllowDowngrade)
}
$releaseCertificate = Join-Path $resolvedPayload 'vgt-release.cer'
if (-not (Test-Path -LiteralPath $releaseCertificate -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT release certificate is missing.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($releaseCertificate)
$now = [DateTime]::UtcNow
if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now.AddDays(30)) {
    throw [Security.SecurityException]::new('VGT release certificate validation failed.')
}
$scriptSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($scriptSignature.Status -ne 'Valid' -or -not $scriptSignature.SignerCertificate -or $scriptSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('Installer trust anchor validation failed.')
}
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT payload catalog is missing.') }
$catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
if ($catalogSignature.Status -ne 'Valid' -or -not $catalogSignature.SignerCertificate -or $catalogSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('VGT payload catalog signer validation failed.')
}
$catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('VGT payload catalog verification failed.') }
# The signing chain must already be trusted. Only publisher trust is persisted so
# LocalSystem can execute the signed GeDefense maintenance scripts under AllSigned.
# Use the .NET store API instead of Import-Certificate: the cmdlet can request an
# interactive confirmation that is unavailable in the non-interactive elevated
# transaction and would abort the whole install with exit code 90.
$publisherStore = [Security.Cryptography.X509Certificates.X509Store]::new(
    [Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
    [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
try {
    $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($releaseCertificate))
} catch {
    throw [Security.SecurityException]::new(('Trusted publisher import failed: {0}' -f $_.Exception.Message))
} finally {
    $publisherStore.Close()
}
Write-VgtInstallPhase -Phase 'Trust' -State 'OK' -Detail $certificate.Thumbprint
$resolvedInstaller = ''
if ($InstallerPath) {
    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
    $installerSignature = Get-AuthenticodeSignature -LiteralPath $resolvedInstaller
    if ($installerSignature.Status -ne 'Valid' -or -not $installerSignature.SignerCertificate -or $installerSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Standalone installer signature validation failed.') }
}

foreach ($processName in @('GeDefenseTray','GeDefenseCenter')) {
    foreach ($process in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
        $expectedPath = Join-Path $installRoot ("bin\{0}.exe" -f $processName)
        $actualPath = try { [IO.Path]::GetFullPath($process.Path) } catch { '' }
        if ($actualPath -and $actualPath.Equals([IO.Path]::GetFullPath($expectedPath),[StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
    }
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    foreach ($proc in @(Get-Process -Name 'gedefense-windows' -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    foreach ($dism in @(Get-Process -Name 'DismHost' -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $dism.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
    Invoke-ScChecked @('delete',$serviceName)
    Start-Sleep -Milliseconds 700
}
Assert-VgtInstallerPaths
New-VgtSafeDirectory -Path $installRoot -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramFiles)) | Out-Null
New-VgtSafeDirectory -Path $dataRoot -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData)) | Out-Null
New-VgtSafeDirectory -Path $brandingRoot -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData)) | Out-Null
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'bin') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'engine') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'audit') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'xdr') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'LICENSES') -Destination $installRoot -Recurse -Force
foreach ($noticeName in @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','GEOIP_LICENSE_AND_DEPLOYMENT.md')) {
    Copy-Item -LiteralPath (Join-Path $resolvedPayload $noticeName) -Destination (Join-Path $installRoot $noticeName) -Force
}
Copy-Item -LiteralPath $versionPath -Destination (Join-Path $installRoot 'VERSION') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-lockscreen.jpg') -Destination (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-oem-logo.bmp') -Destination (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense-logo-v1.png') -Destination (Join-Path $brandingRoot 'gedefense-logo.png') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense.ico') -Destination (Join-Path $brandingRoot 'gedefense.ico') -Force
Write-VgtInstallPhase -Phase 'Files' -State 'OK' -Detail $installRoot

$operatorGroupCreated = $false
if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    if ($operatorGroupDescription.Length -gt 48) { throw [IO.InvalidDataException]::new('Operator group description exceeds the Windows SAM boundary.') }
    New-LocalGroup -Name $operatorGroup -Description $operatorGroupDescription | Out-Null
    $operatorGroupCreated = $true
}
$operatorGroupObject = Get-LocalGroup -Name $operatorGroup -ErrorAction Stop
$operatorGroupSid = [string]$operatorGroupObject.SID.Value
if ($operatorGroupSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw [Security.SecurityException]::new('Operator group SID validation failed.') }
$identitySid = [string]$identity.User.Value
if ($identitySid -notmatch '^S-1-(?:\d+-)+\d+$') { throw [Security.SecurityException]::new('Installing identity SID validation failed.') }
$installerAddedMembers = [Collections.Generic.List[string]]::new()
if ($identitySid -ne 'S-1-5-18') {
    $isOperator = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction Stop | Where-Object { [string]$_.SID.Value -eq $identitySid }).Count -gt 0
    if (-not $isOperator) {
        Add-LocalGroupMember -Group $operatorGroup -Member $identity.Name -ErrorAction Stop
        [void]$installerAddedMembers.Add($identitySid)
    }
}
Write-VgtInstallPhase -Phase 'OperatorGroup' -State 'OK' -Detail ("{0}|{1}|member={2}" -f $operatorGroup,$operatorGroupSid,$identitySid)
# Product-owned install state: uninstall may only remove trust anchors, runtime
# credentials and group members that this installer actually created.
New-Item -Path $stateKey -Force | Out-Null
New-ItemProperty -Path $stateKey -Name Product -Value 'VGT GeDefense Titan' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $stateKey -Name OperatorGroupCreated -Value ([int]($(if ($operatorGroupCreated) { 1 } else { 0 }))) -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $stateKey -Name OperatorGroupSid -Value $operatorGroupSid -PropertyType String -Force | Out-Null
New-ItemProperty -Path $stateKey -Name InstallerAddedMembers -Value ($installerAddedMembers.ToArray() -join ';') -PropertyType String -Force | Out-Null
Write-VgtInstallPhase -Phase 'InstallState' -State 'OK' -Detail ("groupCreated={0}|members={1}" -f $operatorGroupCreated,$installerAddedMembers.Count)
Invoke-IcaclsChecked -Target $installRoot -Phase 'ProgramACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
# Product data and runtime secrets are SYSTEM/Administrators only. Operators no
# longer read files directly: Center/Tray authenticate through the OS-identity
# operator broker and the master token remains a break-glass credential for
# local administrators. This removes the recursive operator RX ACE that exposed
# evidence/vault keys (DP-FIND-001 / UI-FIND-001).
$dataAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
Invoke-IcaclsChecked -Target $dataRoot -Phase 'DataACL' -Arguments $dataAclArguments
# Branding content is non-secret but was previously left fully inherited. Keep
# Windows/Tray readable (Users RX) without granting standard users write access.
Invoke-IcaclsChecked -Target $brandingRoot -Phase 'BrandingACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
Write-VgtInstallPhase -Phase 'ACL' -State 'OK' -Detail 'Program, data and branding roots secured'

$executable = Join-Path $installRoot 'bin\gedefense-windows.exe'
$quotedExecutable = '"{0}"' -f $executable
Invoke-ScChecked @('create',$serviceName,'binPath=',$quotedExecutable,'start=','auto','obj=','LocalSystem','DisplayName=','VGT GeDefense Master Security System')
Invoke-ScChecked @('description',$serviceName,'VisionGaia Technology sovereign Windows defense and hardening control plane.')
Invoke-ScChecked @('failure',$serviceName,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
Invoke-ScChecked @('failureflag',$serviceName,'1')
Invoke-ScChecked @('sidtype',$serviceName,'unrestricted')
Write-VgtInstallPhase -Phase 'ServiceRegistration' -State 'OK' -Detail $serviceName

$oemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
New-Item -Path $oemPath -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Manufacturer -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Model -Value 'VGT Win11E+ LTSC Security Edition' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name SupportProvider -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Logo -Value (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -PropertyType String -Force | Out-Null
$personalization = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
New-Item -Path $personalization -Force | Out-Null
New-ItemProperty -Path $personalization -Name LockScreenImage -Value (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -PropertyType String -Force | Out-Null
New-ItemProperty -Path $personalization -Name NoChangingLockScreen -Value 1 -PropertyType DWord -Force | Out-Null
Write-VgtInstallPhase -Phase 'Branding' -State 'OK' -Detail 'OEM and lock screen policies applied'

$startMenu = $startMenuRoot
Assert-VgtNoReparseTraversal -Path $startMenu -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData))
New-VgtSafeDirectory -Path $startMenu -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData)) | Out-Null
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startMenu 'GeDefense Security Center.lnk'))
$centerExecutable = Join-Path $installRoot 'bin\GeDefenseCenter.exe'
if (-not (Test-Path -LiteralPath $centerExecutable -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense Center executable is missing.') }
$trayExecutable = Join-Path $installRoot 'bin\GeDefenseTray.exe'
if (-not (Test-Path -LiteralPath $trayExecutable -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense Tray executable is missing.') }
$shortcut.TargetPath = $centerExecutable
$shortcut.Arguments = ''
$shortcut.WorkingDirectory = $installRoot
$shortcut.Description = 'VGT GeDefense Security Center'
$shortcut.IconLocation = (Join-Path $brandingRoot 'gedefense.ico')
$shortcut.Save()

$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'VGTGeDefenseTray' -Value ('"{0}" --tray' -f $trayExecutable) -PropertyType String -Force | Out-Null

$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'VGT GeDefense Security Center' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $releaseVersion -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $installRoot -PropertyType String -Force | Out-Null
if ($resolvedInstaller) {
    $installedSetup = Join-Path $installRoot 'GeDefense-Setup.exe'
    Copy-Item -LiteralPath $resolvedInstaller -Destination $installedSetup -Force
    New-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value $installedSetup -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString -Value ('"{0}" --uninstall' -f $installedSetup) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
}
Write-VgtInstallPhase -Phase 'ApplicationRegistration' -State 'OK' -Detail ("center={0}|tray={1}|autostart=HKLM" -f $centerExecutable,$trayExecutable)

$mhxStateRoot = Join-Path $dataRoot 'mhx'
Assert-VgtNoReparseTraversal -Path $mhxStateRoot -AllowedRoot $dataRoot
New-VgtSafeDirectory -Path $mhxStateRoot -AllowedRoot $dataRoot | Out-Null
$intelligenceRoot = Join-Path $mhxStateRoot 'intelligence'
Assert-VgtNoReparseTraversal -Path $intelligenceRoot -AllowedRoot $dataRoot
New-VgtSafeDirectory -Path $intelligenceRoot -AllowedRoot $dataRoot | Out-Null
Invoke-IcaclsChecked -Target $intelligenceRoot -Phase 'ThreatIntelACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
$mhxModePath = Join-Path $mhxStateRoot 'mode.json'
Assert-VgtSafeFileTarget -Path $mhxModePath -AllowedRoot $dataRoot | Out-Null
$mhxModeTemporary = "$mhxModePath.$PID.tmp"
[ordered]@{ mode = 'guarded'; updatedUtc = [DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath $mhxModeTemporary -Encoding UTF8
Move-Item -LiteralPath $mhxModeTemporary -Destination $mhxModePath -Force
Write-VgtInstallPhase -Phase 'MHXState' -State 'OK' -Detail 'Guarded persisted before service start'

Start-Service -Name $serviceName
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    Start-Sleep -Milliseconds 500
    $state = (Get-Service -Name $serviceName).Status
} while ($state -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
if ($state -ne 'Running') { throw [InvalidOperationException]::new('GeDefense service did not reach Running state.') }
Write-VgtInstallPhase -Phase 'ServiceStart' -State 'OK' -Detail $state
$tokenPath = Join-Path $dataRoot 'dashboard.token'
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense dashboard token was not created.') }
Assert-VgtSafeFileTarget -Path $tokenPath -AllowedRoot $dataRoot | Out-Null
$tokenAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F')
Invoke-IcaclsChecked -Target $tokenPath -Phase 'TokenACL' -Arguments $tokenAclArguments
$defenderDeadline = [DateTime]::UtcNow.AddMinutes(2)
do {
    $defenderReady = [bool]((Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled)
    if (-not $defenderReady) { Start-Sleep -Seconds 2 }
} while (-not $defenderReady -and [DateTime]::UtcNow -lt $defenderDeadline)
if (-not $defenderReady) { throw [InvalidOperationException]::new('Microsoft Defender did not become ready for initial hardening.') }
Write-VgtInstallPhase -Phase 'DefenderReadiness' -State 'OK' -Detail 'Antivirus enabled'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'engine\Invoke-VgtHardening.ps1') -Mode Enforce -Profile EnterpriseBalanced | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial VGT hardening transaction failed.') }
Write-VgtInstallPhase -Phase 'Hardening' -State 'OK' -Detail 'EnterpriseBalanced'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'xdr\Set-VgtMhxProtection.ps1') -Mode Guarded | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial MHX realtime protection transaction failed.') }
Write-VgtInstallPhase -Phase 'MHXRealtime' -State 'OK' -Detail 'Guarded + Defender bridge'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'xdr\Set-VgtMhxAppControl.ps1') -Action Audit | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial App Control audit policy deployment failed.') }
Write-VgtInstallPhase -Phase 'AppControl' -State 'OK' -Detail 'Kernel audit policy deployed'
Write-VgtInstallPhase -Phase 'Installer' -State 'COMPLETE' -Detail ("GeDefense {0} installed" -f $releaseVersion)
