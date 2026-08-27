# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath = '',
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.log$')][string]$DiagnosticLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense'
$brandingRoot = Join-Path $env:ProgramData 'VGT\Branding'
$operatorGroup = 'VGT GeDefense Operators'
$operatorGroupDescription = 'VGT GeDefense security center operators.'
$installLog = Join-Path $dataRoot 'install.log'
$resolvedDiagnosticLog = ''
if ($DiagnosticLogPath) {
    $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VGT\InstallerDiagnostics')).TrimEnd('\') + '\'
    $candidateDiagnosticLog = [IO.Path]::GetFullPath($DiagnosticLogPath)
    if (-not $candidateDiagnosticLog.StartsWith($diagnosticRoot,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Diagnostic log path escaped the user diagnostic jail.') }
    New-Item -Path ([IO.Path]::GetDirectoryName($candidateDiagnosticLog)) -ItemType Directory -Force | Out-Null
    $resolvedDiagnosticLog = $candidateDiagnosticLog
}

function Write-VgtInstallPhase {
    param([Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$State,[AllowEmptyString()][string]$Detail = '')
    New-Item -Path $dataRoot -ItemType Directory -Force | Out-Null
    $safeDetail = $Detail.Replace("`r",' ').Replace("`n",' ')
    $line = '{0}|{1}|{2}|{3}' -f [DateTime]::UtcNow.ToString('o'),$Phase,$State,$safeDetail
    if ($resolvedDiagnosticLog) { Add-Content -LiteralPath $resolvedDiagnosticLog -Value $line -Encoding UTF8 }
    try {
        Add-Content -LiteralPath $installLog -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        if (-not $resolvedDiagnosticLog) { throw }
    }
}

trap {
    Write-VgtInstallPhase -Phase 'Installer' -State 'FAILED' -Detail $_.Exception.Message
    Write-Error ('GeDefense installation failed: {0}' -f $_.Exception.Message)
    exit 90
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $nativeOutput = (& "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1 | Out-String).Trim()
    $nativeExitCode = $LASTEXITCODE
    $operation = if ($Arguments.Count -gt 0) { $Arguments[0] } else { 'unknown' }
    if ($nativeExitCode -ne 0) {
        Write-VgtInstallPhase -Phase 'ServiceControl' -State 'FAILED' -Detail ("{0}|exit={1}|{2}" -f $operation,$nativeExitCode,$nativeOutput)
        throw [InvalidOperationException]::new(("Service operation '{0}' failed with exit code {1}." -f $operation,$nativeExitCode))
    }
    Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit=0" -f $operation)
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

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative token required.')
}
Write-VgtInstallPhase -Phase 'Elevation' -State 'OK' -Detail $identity.Name
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayload 'bin\gedefense-windows.exe') -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('GeDefense payload is incomplete.')
}
$releaseCertificate = Join-Path $resolvedPayload 'vgt-release.cer'
if (-not (Test-Path -LiteralPath $releaseCertificate -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT release certificate is missing.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($releaseCertificate)
if ($certificate.Subject -ne 'CN=VisionGaia Technology VGT Release' -or $certificate.NotAfter -le [DateTime]::UtcNow.AddYears(1)) {
    throw [Security.SecurityException]::new('VGT release certificate validation failed.')
}
$bootstrapSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if (-not $bootstrapSignature.SignerCertificate -or $bootstrapSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('Installer trust anchor validation failed.')
}
Import-Certificate -FilePath $releaseCertificate -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $releaseCertificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
$trustedBootstrapSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($trustedBootstrapSignature.Status -ne 'Valid') { throw [Security.SecurityException]::new('Installer signature validation failed.') }
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT payload catalog is missing.') }
$catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('VGT payload catalog verification failed.') }
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
    Invoke-ScChecked @('delete',$serviceName)
    Start-Sleep -Milliseconds 700
}
New-Item -Path $installRoot,$dataRoot,$brandingRoot -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'bin') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'engine') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'audit') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'xdr') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-lockscreen.jpg') -Destination (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-oem-logo.bmp') -Destination (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense-logo-v1.png') -Destination (Join-Path $brandingRoot 'gedefense-logo.png') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense.ico') -Destination (Join-Path $brandingRoot 'gedefense.ico') -Force
Write-VgtInstallPhase -Phase 'Files' -State 'OK' -Detail $installRoot

if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    if ($operatorGroupDescription.Length -gt 48) { throw [IO.InvalidDataException]::new('Operator group description exceeds the Windows SAM boundary.') }
    New-LocalGroup -Name $operatorGroup -Description $operatorGroupDescription | Out-Null
}
$operatorGroupObject = Get-LocalGroup -Name $operatorGroup -ErrorAction Stop
$operatorGroupSid = [string]$operatorGroupObject.SID.Value
if ($operatorGroupSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw [Security.SecurityException]::new('Operator group SID validation failed.') }
$identitySid = [string]$identity.User.Value
if ($identitySid -notmatch '^S-1-(?:\d+-)+\d+$') { throw [Security.SecurityException]::new('Installing identity SID validation failed.') }
if ($identitySid -ne 'S-1-5-18') {
    $isOperator = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction Stop | Where-Object { [string]$_.SID.Value -eq $identitySid }).Count -gt 0
    if (-not $isOperator) { Add-LocalGroupMember -Group $operatorGroup -Member $identity.Name -ErrorAction Stop }
}
Write-VgtInstallPhase -Phase 'OperatorGroup' -State 'OK' -Detail ("{0}|{1}|member={2}" -f $operatorGroup,$operatorGroupSid,$identitySid)
Invoke-IcaclsChecked -Target $installRoot -Phase 'ProgramACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
$dataAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F',("*{0}:(RX)" -f $operatorGroupSid))
if ($identitySid -ne 'S-1-5-18') { $dataAclArguments += ("*{0}:(RX)" -f $identitySid) }
Invoke-IcaclsChecked -Target $dataRoot -Phase 'DataACL' -Arguments $dataAclArguments
Write-VgtInstallPhase -Phase 'ACL' -State 'OK' -Detail 'Program and data roots secured'

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

$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
New-Item -Path $startMenu -ItemType Directory -Force | Out-Null
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
$shortcut.Save()

$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'VGTGeDefenseTray' -Value ('"{0}" --tray' -f $trayExecutable) -PropertyType String -Force | Out-Null

$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'VGT GeDefense Security Center' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value '2.3.2' -PropertyType String -Force | Out-Null
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
New-Item -Path $mhxStateRoot -ItemType Directory -Force | Out-Null
$mhxModePath = Join-Path $mhxStateRoot 'mode.json'
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
$tokenAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F',("*{0}:R" -f $operatorGroupSid))
if ($identitySid -ne 'S-1-5-18') { $tokenAclArguments += ("*{0}:R" -f $identitySid) }
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
Write-VgtInstallPhase -Phase 'Installer' -State 'COMPLETE' -Detail 'GeDefense 2.3.2 installed'
