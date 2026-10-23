# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce','Rollback','Component','ApplyConfig')][string]$Mode,
    [ValidateSet('EnterpriseBalanced','Isolation')][string]$Profile = 'EnterpriseBalanced',
    [ValidateSet('DefenderCloud','ASR','ControlledFolderAccess','Firewall','CredentialGuard','MemoryIntegrity','LSASS','SMB','PowerShellLogging','UAC','USBStorage','RemoteDesktop')][string]$Component,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$ConfigPath,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
Import-Module (Join-Path $moduleRoot 'Vgt.Common.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Vgt.Defender.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Vgt.Identity.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Vgt.Network.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Vgt.System.psm1') -Force

function Get-VgtRegistryDword {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name)
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties[$Name]) { return [int]$item.$Name }
    return -1
}

function Set-VgtComponent {
    param([Parameter(Mandatory)][string]$Id)
    switch ($Id) {
        'DefenderCloud' {
            Set-MpPreference -PUAProtection Enabled -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -EnableNetworkProtection Enabled -CloudBlockLevel HighPlus
        }
        'ASR' {
            $ids = @('56a863a9-875e-4185-98a7-b882c64b5ce5','d4f940ab-401b-4efc-aadc-ad5f3c50688a','3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84','d3e037e1-3eb8-44c8-a917-57927947596d','5beb7efe-fd9a-4556-801d-275e5ffc04cc','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2','c1db55ab-c21a-4637-bb3f-a12568109d35','33ddedf1-c6e0-47cb-833e-de6133960387')
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions @($ids | ForEach-Object { 1 })
        }
        'ControlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess Enabled }
        'Firewall' { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast False -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767 }
        'CredentialGuard' {
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 3
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' 'Enabled' 1
        }
        'MemoryIntegrity' {
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 1
        }
        'LSASS' {
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 2
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPLBoot' 2
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
        }
        'SMB' {
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
            Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
        'PowerShellLogging' {
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
            & (Join-Path $env:SystemRoot 'System32\auditpol.exe') /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Process audit policy activation failed.') }
        }
        'UAC' {
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
            Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1
        }
        'USBStorage' { Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start' 4 }
        'RemoteDesktop' { Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 }
        default { throw [Security.SecurityException]::new('Hardening component validation failed.') }
    }
}

function Get-VgtComponentState {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Audit)
    return @{
        DefenderCloud = [bool]($Audit['CloudProtection'] -and $Audit['NetworkProtection'] -and $Audit['RealTimeProtection'])
        ASR = [bool]($Audit['AsrRules'] -ge 11 -and $Audit['AsrBlockRules'] -ge 11)
        ControlledFolderAccess = [bool]$Audit['ControlledFolderAccess']
        Firewall = [bool]$Audit['Firewall']
        CredentialGuard = [bool]$Audit['CredentialGuard']
        MemoryIntegrity = [bool]($Audit['MemoryIntegrity'] -and $Audit['VulnerableDriverBlocklist'])
        LSASS = [bool]$Audit['LsaProtection']
        SMB = [bool]$Audit['SmbHardening']
        PowerShellLogging = [bool]$Audit['PowerShellLogging']
        UAC = [bool]$Audit['UacSecureDesktop']
        USBStorage = [bool]$Audit['UsbStorageBlocked']
        RemoteDesktop = [bool]$Audit['RemoteDesktopDisabled']
    }
}

function Get-VgtMinimalTelemetry {
    return [ordered]@{
        CapturedUtc = [DateTime]::UtcNow.ToString('o')
        SourcesAttempted = @('Get-MpComputerStatus','Get-MpPreference','Get-MpThreatDetection','Get-MpThreat','Get-NetFirewallProfile')
        Available = $false
        ComputerStatusAvailable = $false
        PreferenceAvailable = $false
        ThreatDetectionAvailable = $false
        ThreatQueryAvailable = $false
        FirewallAvailable = $false
        Status = $null
        Preference = $null
        AttackSurfaceReduction = $null
        Exclusions = $null
        Threats = $null
        Firewall = $null
    }
}

function Get-VgtTelemetry {
    try {
        $telemetry = Get-VgtDefenderTelemetry
        $firewallTelemetry = Get-VgtFirewallTelemetry
        $telemetry['Firewall'] = $firewallTelemetry
        $telemetry['FirewallAvailable'] = [bool]$firewallTelemetry['Available']
        return $telemetry
    } catch {
        $message = [string]$_.Exception.Message
        if ($message.Length -gt 320) { $message = $message.Substring(0,320) }
        Write-VgtEvent -Level WARN -Message ('Defender telemetry unavailable: {0}' -f ($message -replace '[\r\n\0]',' '))
        return Get-VgtMinimalTelemetry
    }
}

function Get-VgtAudit {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
    $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $secureBoot = try { [bool](Confirm-SecureBootUEFI) } catch { $false }
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $bitLocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    $windowsUpdate = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
    $windowsVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $smb1ServerDisabled = (Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -eq 0
    $smb1DriverDisabled = (Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start') -eq 4
    $smb1Disabled = $smb1ServerDisabled -and $smb1DriverDisabled
    if (-not $smb1Disabled) {
        $smb1Cim = Get-CimInstance Win32_OptionalFeature -Filter "Name='SMB1Protocol'" -ErrorAction SilentlyContinue
        if ($smb1Cim -and $smb1Cim.InstallState -eq 3) {
            $smb1Disabled = $true
        }
    }
    $tpmHasState = [bool]($tpm -and $tpm.PSObject.Properties['TpmPresent'] -and $tpm.PSObject.Properties['TpmReady'])
    $asrIds = @($mpPreference.AttackSurfaceReductionRules_Ids)
    $asrActions = @($mpPreference.AttackSurfaceReductionRules_Actions)
    [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        ComputerName = $env:COMPUTERNAME
        WindowsProductName = [string]$windowsVersion.ProductName
        WindowsEditionId = [string]$windowsVersion.EditionID
        WindowsDisplayVersion = [string]$windowsVersion.DisplayVersion
        WindowsBuild = '{0}.{1}' -f $windowsVersion.CurrentBuild,$windowsVersion.UBR
        Defender = [bool]$mpStatus.AntivirusEnabled
        DefenderService = [bool]$mpStatus.AMServiceEnabled
        RealTimeProtection = [bool]$mpStatus.RealTimeProtectionEnabled
        BehaviorProtection = [bool]$mpStatus.BehaviorMonitorEnabled
        IoavProtection = [bool]$mpStatus.IoavProtectionEnabled
        TamperProtection = [bool]$mpStatus.IsTamperProtected
        CloudProtection = [bool]($mpPreference -and [int]$mpPreference.MAPSReporting -ge 1)
        CloudBlockLevel = if($mpPreference){[string]$mpPreference.CloudBlockLevel}else{'Unavailable'}
        SampleSubmission = [bool]($mpPreference -and [int]$mpPreference.SubmitSamplesConsent -ne 2)
        SignatureAgeDays = if($mpStatus -and $null -ne $mpStatus.AntivirusSignatureAge){[int]$mpStatus.AntivirusSignatureAge}else{-1}
        NetworkProtection = ($mpPreference.EnableNetworkProtection -eq 1)
        AsrRules = $asrIds.Count
        AsrBlockRules = @($asrActions | Where-Object { [int]$_ -eq 1 }).Count
        ControlledFolderAccess = [bool]($mpPreference -and [int]$mpPreference.EnableControlledFolderAccess -eq 1)
        Firewall = (@($firewall | Where-Object Enabled).Count -eq 3)
        SecureBoot = $secureBoot
        Tpm = [bool]($tpmHasState -and $tpm.TpmPresent -and $tpm.TpmReady)
        BitLocker = [bool]($bitLocker -and $bitLocker.ProtectionStatus -eq 'On')
        Vbs = [bool]($deviceGuard -and @($deviceGuard.SecurityServicesRunning).Count -gt 0)
        CredentialGuard = [bool]($deviceGuard -and 1 -in @($deviceGuard.SecurityServicesRunning))
        MemoryIntegrity = [bool]($deviceGuard -and 2 -in @($deviceGuard.SecurityServicesRunning))
        LsaProtection = [bool]((Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1,2))
        SmbHardening = [bool]((Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') -eq 1 -and (Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') -eq 1 -and $smb1Disabled)
        PowerShellLogging = [bool]((Get-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1 -and (Get-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1)
        VulnerableDriverBlocklist = [bool]((Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable') -eq 1)
        UacSecureDesktop = [bool]((Get-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1 -and (Get-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop') -eq 1 -and (Get-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin') -eq 2)
        UsbStorageBlocked = [bool]((Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start') -eq 4)
        RemoteDesktopDisabled = [bool]((Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 1)
        WindowsUpdate = [bool]($windowsUpdate -and $windowsUpdate.StartMode -ne 'Disabled')
        DefenderTelemetry = Get-VgtTelemetry
    }
}

function Assert-VgtConfigPathJail {
    param([Parameter(Mandatory)][string]$Path)
    if (-not $env:ProgramData) { throw [Security.SecurityException]::new('ProgramData is unavailable.') }
    $resolved = [IO.Path]::GetFullPath($Path)
    $operationsRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VGT\GeDefense\operations')).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($operationsRoot,[StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('Settings configuration path escaped the operation jail.')
    }
}

function Assert-VgtApplyPreconditions {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Settings)
    if ($Settings.Contains('defender')) { $null = Get-MpPreference -ErrorAction Stop }
    if ($Settings.Contains('firewall')) {
        foreach ($profile in @($Settings['firewall']['profiles'])) {
            $null = Get-NetFirewallProfile -Name ([string]$profile['name']) -ErrorAction Stop
        }
    }
}

function Invoke-VgtApplyConfig {
    param([Parameter(Mandatory)][string]$ConfigPath)
    Assert-VgtConfigPathJail -Path $ConfigPath
    $policy = Read-VgtSettingsConfig -ConfigPath $ConfigPath -MaxBytes 65536
    $settings = $policy.Settings
    Assert-VgtApplyPreconditions -Settings $settings
    $baselinePath = Join-Path (Join-Path (Get-VgtDataRoot) 'State') 'baseline.json'
    $baselineState = 'existing'
    $baselineIntegrity = 'legacy'
    if (-not (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
        $baselineState = 'created'
    } else {
        $existingBaseline = Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not (Test-VgtBaselineState -State $existingBaseline -StateDirectory (Join-Path (Get-VgtDataRoot) 'State'))) {
            throw [Security.SecurityException]::new('Existing VGT baseline failed validation.')
        }
        $baselineIntegrity = Test-VgtBaselineIntegrity -State $existingBaseline
        if ($baselineIntegrity -eq 'Mismatch') {
            throw [Security.SecurityException]::new('Existing VGT baseline failed integrity verification.')
        }
    }
    $before = Get-VgtAudit
    Save-VgtBaseline | Out-Null
    $report = New-Object System.Collections.ArrayList
    if ($settings.Contains('defender')) { Set-VgtDefenderSettings -Settings $settings['defender'] -Report $report }
    if ($settings.Contains('firewall')) { Set-VgtFirewallSettings -Profiles @($settings['firewall']['profiles']) -Report $report }
    $componentStateBefore = Get-VgtComponentState -Audit $before
    if ($settings.Contains('components')) {
        foreach ($component in @($settings['components'])) {
            Set-VgtComponent -Id ([string]$component)
            Write-VgtEvent -Level INFO -Message ('Settings component enforced: {0}' -f [string]$component)
        }
    }
    $after = Get-VgtAudit
    $componentEntries = New-Object System.Collections.ArrayList
    if ($settings.Contains('components')) {
        $componentStateAfter = Get-VgtComponentState -Audit $after
        foreach ($component in @($settings['components'])) {
            $id = [string]$component
            $wasActive = [bool]$componentStateBefore[$id]
            $isActive = [bool]$componentStateAfter[$id]
            [void]$componentEntries.Add([ordered]@{ Id = $id; Before = $wasActive; After = $isActive; Changed = ($wasActive -ne $isActive) })
        }
    }
    $changedCount = 0
    $unchangedCount = 0
    foreach ($entry in $report) { if ([bool]$entry['Changed']) { $changedCount++ } else { $unchangedCount++ } }
    foreach ($entry in $componentEntries) { if ([bool]$entry['Changed']) { $changedCount++ } else { $unchangedCount++ } }
    $applyReport = [ordered]@{
        SchemaVersion = 1
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        SettingsSha256 = [string]$policy.Sha256
        BaselineState = $baselineState
        BaselineIntegrity = $baselineIntegrity
        RollbackAvailable = [bool](Test-Path -LiteralPath $baselinePath -PathType Leaf)
        ChangedCount = $changedCount
        UnchangedCount = $unchangedCount
        Entries = @($report.ToArray())
        Components = @($componentEntries.ToArray())
    }
    Write-VgtEvent -Level INFO -Message ('Settings baseline state: {0} (integrity: {1})' -f $baselineState,$baselineIntegrity)
    foreach ($entry in $report) {
        if ([bool]$entry['Changed']) {
            Write-VgtEvent -Level INFO -Message ('Settings change: {0} = {1}' -f [string]$entry['Setting'],[string]$entry['After'])
        }
    }
    foreach ($componentEntry in $componentEntries) {
        if ([bool]$componentEntry['Changed']) {
            Write-VgtEvent -Level INFO -Message ('Settings component change: {0} = {1}' -f [string]$componentEntry['Id'],[string]$componentEntry['After'])
        }
    }
    Write-VgtEvent -Level INFO -Message ('Settings applied: {0} changed, {1} unchanged.' -f $changedCount,$unchangedCount)
    $after['ApplyReport'] = $applyReport
    return $after
}

function Write-VgtSafeEvent {
    param([Parameter(Mandatory)][ValidateSet('INFO','WARN','ERROR','SECURITY')][string]$Level,[Parameter(Mandatory)][string]$Message)
    $text = [string]$Message
    if ($text.Length -gt 480) { $text = $text.Substring(0,480) }
    $text = $text -replace '[\r\n\0]', ' '
    try { Write-VgtEvent -Level $Level -Message $text } catch { }
}

try {
    Assert-VgtAdministrator
    if ($ConfigPath -and $Mode -ne 'ApplyConfig') {
        throw [Security.SecurityException]::new('Settings configuration is only accepted in ApplyConfig mode.')
    }
    if ($Mode -eq 'ApplyConfig') {
        if (-not $ConfigPath) { throw [Security.SecurityException]::new('Settings configuration is required.') }
        if ($Component) { throw [Security.SecurityException]::new('ApplyConfig does not accept a single component.') }
        $result = Invoke-VgtApplyConfig -ConfigPath $ConfigPath
    } elseif ($Mode -eq 'Audit') {
        $result = Get-VgtAudit
    } elseif ($Mode -eq 'Rollback') {
        Restore-VgtBaseline
        $result = Get-VgtAudit
    } elseif ($Mode -eq 'Component') {
        if (-not $Component) { throw [Security.SecurityException]::new('Hardening component validation failed.') }
        Save-VgtBaseline | Out-Null
        Set-VgtComponent -Id $Component
        Write-VgtEvent -Level INFO -Message ("Component enforced: {0}" -f $Component)
        $result = Get-VgtAudit
    } else {
        $profileFile = if ($Profile -eq 'Isolation') { 'isolation.json' } else { 'enterprise-balanced.json' }
        $profilePath = Join-Path (Join-Path $PSScriptRoot 'profiles') $profileFile
        $configuration = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $configuration.preserveWindowsUpdate) { throw [Security.SecurityException]::new('Profiles may not disable Windows Update.') }
        Save-VgtBaseline | Out-Null
        Set-VgtDefenderBaseline -Profile $configuration
        Set-VgtIdentityBaseline
        Set-VgtNetworkBaseline -Profile $configuration
        Set-VgtSystemBaseline
        Write-VgtEvent -Level INFO -Message ("Profile enforced: {0}" -f $configuration.name)
        $result = Get-VgtAudit
    }
    $json = $result | ConvertTo-Json -Depth 8
    if ($OutputPath) {
        $resolvedParent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $resolvedParent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"
        Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    Write-VgtSafeEvent -Level SECURITY -Message ([string]$_.Exception.Message)
    Write-Error 'VGT security policy rejected the operation.'
    exit 10
} catch {
    Write-VgtSafeEvent -Level ERROR -Message ([string]$_.Exception.Message)
    Write-Error 'VGT hardening operation failed. Review the protected log.'
    exit 20
}
