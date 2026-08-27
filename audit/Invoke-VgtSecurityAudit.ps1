# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+\.json$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$checks = [Collections.Generic.List[object]]::new()

function Get-VgtRegistryValue {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Add-VgtCheck {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','Warning','NotApplicable')][string]$Status,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Expected,
        [AllowEmptyString()][string]$Actual = ''
    )
    $checks.Add([pscustomobject][ordered]@{Id=$Id;Category=$Category;Title=$Title;Status=$Status;Severity=$Severity;Expected=$Expected;Actual=$Actual})
}

function ConvertTo-VgtState {
    param([bool]$Value)
    if ($Value) { return 'Enabled' }
    return 'Disabled'
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VGT\GeDefense\operations')).TrimEnd('\') + '\'
if (-not $resolvedOutput.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) {
    throw [Security.SecurityException]::new('Audit output path escaped the operation jail.')
}
New-Item -Path (Split-Path -Parent $resolvedOutput) -ItemType Directory -Force | Out-Null

$mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
$mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
$defenderEnabled = [bool]($mpStatus -and $mpStatus.AntivirusEnabled)
Add-VgtCheck 'VGT-D-001' 'Defender' 'Microsoft Defender Antivirus' $(if($defenderEnabled){'Pass'}else{'Fail'}) 'Critical' 'Enabled' (ConvertTo-VgtState $defenderEnabled)
$realTime = [bool]($mpStatus -and $mpStatus.RealTimeProtectionEnabled)
Add-VgtCheck 'VGT-D-002' 'Defender' 'Real-time protection' $(if($realTime){'Pass'}else{'Fail'}) 'Critical' 'Enabled' (ConvertTo-VgtState $realTime)
$behavior = [bool]($mpStatus -and $mpStatus.BehaviorMonitorEnabled)
Add-VgtCheck 'VGT-D-003' 'Defender' 'Behavior monitoring' $(if($behavior){'Pass'}else{'Fail'}) 'High' 'Enabled' (ConvertTo-VgtState $behavior)
$networkProtection = if($mpPreference){[int]$mpPreference.EnableNetworkProtection}else{-1}
Add-VgtCheck 'VGT-D-004' 'Defender' 'Network protection' $(if($networkProtection -eq 1){'Pass'}elseif($networkProtection -eq 2){'Warning'}else{'Fail'}) 'High' 'Block mode (1)' ([string]$networkProtection)
$pua = if($mpPreference){[int]$mpPreference.PUAProtection}else{-1}
Add-VgtCheck 'VGT-D-005' 'Defender' 'Potentially unwanted application protection' $(if($pua -eq 1){'Pass'}elseif($pua -eq 2){'Warning'}else{'Fail'}) 'Medium' 'Block mode (1)' ([string]$pua)
$cloud = if($mpPreference){[int]$mpPreference.MAPSReporting}else{-1}
Add-VgtCheck 'VGT-D-006' 'Defender' 'Cloud-delivered protection' $(if($cloud -ge 1){'Pass'}else{'Fail'}) 'High' 'Basic or advanced membership' ([string]$cloud)
$asrCount = if($mpPreference){@($mpPreference.AttackSurfaceReductionRules_Ids).Count}else{0}
Add-VgtCheck 'VGT-D-007' 'Defender' 'Attack Surface Reduction rules' $(if($asrCount -ge 6){'Pass'}elseif($asrCount -gt 0){'Warning'}else{'Fail'}) 'High' 'At least 6 configured rules' ([string]$asrCount)
$managedExclusions = @()
if ($mpPreference) {
    $managedExclusions = @(@($mpPreference.ExclusionPath) + @($mpPreference.ExclusionProcess) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -notmatch '^(?i)N/A:' })
}
$exclusionCount = $managedExclusions.Count
Add-VgtCheck 'VGT-D-008' 'Defender' 'Defender exclusions' $(if($exclusionCount -eq 0){'Pass'}else{'Warning'}) 'Medium' 'No unmanaged exclusions' ([string]$exclusionCount)

$firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$enabledProfiles = @($firewallProfiles | Where-Object Enabled).Count
Add-VgtCheck 'VGT-N-001' 'Network' 'Windows Firewall profiles' $(if($enabledProfiles -eq 3){'Pass'}elseif($enabledProfiles -gt 0){'Warning'}else{'Fail'}) 'Critical' 'Domain, Private and Public enabled' "$enabledProfiles/3"
$winRmBasic = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic'
Add-VgtCheck 'VGT-N-002' 'Network' 'WinRM Basic authentication' $(if($null -eq $winRmBasic -or [int]$winRmBasic -eq 0){'Pass'}else{'Fail'}) 'High' 'Disabled' ([string]$winRmBasic)
$winRmClear = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic'
Add-VgtCheck 'VGT-N-003' 'Network' 'WinRM unencrypted traffic' $(if($null -eq $winRmClear -or [int]$winRmClear -eq 0){'Pass'}else{'Fail'}) 'High' 'Disabled' ([string]$winRmClear)
$smb1 = Get-CimInstance Win32_OptionalFeature -Filter "Name='SMB1Protocol'" -ErrorAction SilentlyContinue
$smb1Disabled = -not $smb1 -or [int]$smb1.InstallState -ne 1
Add-VgtCheck 'VGT-N-004' 'Network' 'SMBv1 protocol' $(if($smb1Disabled){'Pass'}else{'Fail'}) 'Critical' 'Disabled or absent' $(if($smb1){[string]$smb1.InstallState}else{'Absent'})
$smbSigning = Get-VgtRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
Add-VgtCheck 'VGT-N-005' 'Network' 'SMB server signing' $(if([int]$smbSigning -eq 1){'Pass'}else{'Fail'}) 'High' 'Required (1)' ([string]$smbSigning)
$rdpNla = Get-VgtRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
Add-VgtCheck 'VGT-N-006' 'Network' 'Remote Desktop Network Level Authentication' $(if([int]$rdpNla -eq 1){'Pass'}else{'Fail'}) 'High' 'Required (1)' ([string]$rdpNla)

$secureBoot = try {[bool](Confirm-SecureBootUEFI -ErrorAction Stop)}catch{$false}
Add-VgtCheck 'VGT-P-001' 'Platform' 'Secure Boot' $(if($secureBoot){'Pass'}else{'Fail'}) 'Critical' 'Enabled' (ConvertTo-VgtState $secureBoot)
$tpm = Get-Tpm -ErrorAction SilentlyContinue
$tpmHasState = [bool]($tpm -and $tpm.PSObject.Properties['TpmPresent'] -and $tpm.PSObject.Properties['TpmReady'])
$tpmReady = [bool]($tpmHasState -and $tpm.TpmPresent -and $tpm.TpmReady)
Add-VgtCheck 'VGT-P-002' 'Platform' 'Trusted Platform Module' $(if($tpmReady){'Pass'}else{'Fail'}) 'High' 'Present and ready' (ConvertTo-VgtState $tpmReady)
$osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
$bitLocker = [bool]($osVolume -and [string]$osVolume.ProtectionStatus -eq 'On')
Add-VgtCheck 'VGT-P-003' 'Platform' 'BitLocker OS protection' $(if($bitLocker){'Pass'}else{'Fail'}) 'High' 'Protection on' $(if($osVolume){[string]$osVolume.ProtectionStatus}else{'Unavailable'})
$deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$vbs = [bool]($deviceGuard -and [int]$deviceGuard.VirtualizationBasedSecurityStatus -eq 2)
Add-VgtCheck 'VGT-P-004' 'Platform' 'Virtualization-based security' $(if($vbs){'Pass'}else{'Fail'}) 'High' 'Running' $(if($deviceGuard){[string]$deviceGuard.VirtualizationBasedSecurityStatus}else{'Unavailable'})
$credentialGuard = [bool]($deviceGuard -and @($deviceGuard.SecurityServicesRunning) -contains 1)
Add-VgtCheck 'VGT-P-005' 'Platform' 'Credential Guard' $(if($credentialGuard){'Pass'}else{'Fail'}) 'High' 'Running' (ConvertTo-VgtState $credentialGuard)
$lsa = Get-VgtRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
Add-VgtCheck 'VGT-P-006' 'Platform' 'LSA protected process' $(if([int]$lsa -in 1,2){'Pass'}else{'Fail'}) 'High' 'Enabled (1 or 2)' ([string]$lsa)

$enableLua = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Add-VgtCheck 'VGT-I-001' 'Identity' 'User Account Control' $(if([int]$enableLua -eq 1){'Pass'}else{'Fail'}) 'Critical' 'Enabled (1)' ([string]$enableLua)
$consent = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
Add-VgtCheck 'VGT-I-002' 'Identity' 'Administrator elevation consent' $(if([int]$consent -in 1,2,3,4,5){'Pass'}else{'Fail'}) 'High' 'Consent or credentials required' ([string]$consent)
$guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Where-Object SID -Like '*-501' | Select-Object -First 1
$guestDisabled = [bool]($guest -and $guest.Disabled)
Add-VgtCheck 'VGT-I-003' 'Identity' 'Built-in Guest account' $(if($guestDisabled){'Pass'}else{'Fail'}) 'High' 'Disabled' $(if($guest){ConvertTo-VgtState (-not $guest.Disabled)}else{'Unavailable'})
$inactivity = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
Add-VgtCheck 'VGT-I-004' 'Identity' 'Machine inactivity lock' $(if([int]$inactivity -gt 0 -and [int]$inactivity -le 900){'Pass'}else{'Fail'}) 'Medium' '1-900 seconds' ([string]$inactivity)

$scriptLogging = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Add-VgtCheck 'VGT-L-001' 'Logging' 'PowerShell script block logging' $(if([int]$scriptLogging -eq 1){'Pass'}else{'Fail'}) 'High' 'Enabled (1)' ([string]$scriptLogging)
$processCommandLine = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
Add-VgtCheck 'VGT-L-002' 'Logging' 'Process command-line auditing' $(if([int]$processCommandLine -eq 1){'Pass'}else{'Fail'}) 'High' 'Enabled (1)' ([string]$processCommandLine)
$securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
$securityLogSize = if($securityLog){[int64]$securityLog.MaximumSizeInBytes}else{0}
Add-VgtCheck 'VGT-L-003' 'Logging' 'Security event log capacity' $(if($securityLogSize -ge 201326592){'Pass'}elseif($securityLogSize -ge 67108864){'Warning'}else{'Fail'}) 'Medium' 'At least 192 MiB' ([string]$securityLogSize)
$powerShellV2 = Get-CimInstance Win32_OptionalFeature -Filter "Name='MicrosoftWindowsPowerShellV2'" -ErrorAction SilentlyContinue
$powerShellV2Disabled = -not $powerShellV2 -or [int]$powerShellV2.InstallState -ne 1
Add-VgtCheck 'VGT-L-004' 'Logging' 'Windows PowerShell 2.0 engine' $(if($powerShellV2Disabled){'Pass'}else{'Fail'}) 'High' 'Disabled or absent' $(if($powerShellV2){[string]$powerShellV2.InstallState}else{'Absent'})

$autoRun = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
Add-VgtCheck 'VGT-S-001' 'System' 'AutoPlay for all drive types' $(if([int]$autoRun -eq 255){'Pass'}else{'Fail'}) 'Medium' 'Disabled (255)' ([string]$autoRun)
$smartScreen = Get-VgtRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
Add-VgtCheck 'VGT-S-002' 'System' 'Windows SmartScreen' $(if([int]$smartScreen -eq 1){'Pass'}else{'Fail'}) 'High' 'Enabled (1)' ([string]$smartScreen)
$updateService = Get-Service wuauserv -ErrorAction SilentlyContinue
$updateAvailable = [bool]($updateService -and [string]$updateService.StartType -ne 'Disabled')
Add-VgtCheck 'VGT-S-003' 'System' 'Windows Update service' $(if($updateAvailable){'Pass'}else{'Fail'}) 'Critical' 'Not disabled' $(if($updateService){[string]$updateService.StartType}else{'Missing'})

$passed = @($checks | Where-Object Status -eq 'Pass').Count
$failed = @($checks | Where-Object Status -eq 'Fail').Count
$warnings = @($checks | Where-Object Status -eq 'Warning').Count
$maxScore = $checks.Count * 5
$score = ($passed * 5) + ($warnings * 2) + (@($checks | Where-Object Status -eq 'NotApplicable').Count * 5)
$percent = if($maxScore -gt 0){[math]::Round(($score / $maxScore) * 100,2)}else{0}
$result = [ordered]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    Framework = 'VGT SafetySys Windows Baseline 2.0 (CIS-derived, not a certification)'
    Score = $score
    MaxScore = $maxScore
    Percent = $percent
    Passed = $passed
    Failed = $failed
    Warnings = $warnings
    Checks = @($checks)
}
$result | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
