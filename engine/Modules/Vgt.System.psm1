# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-VgtFirewallProperty {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-VgtFirewallBool {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $null }
    # Get-NetFirewallProfile returns GpoBoolean generated enum values.
    $text = [string]$Value
    if ($text -eq 'True') { return $true }
    if ($text -eq 'False') { return $false }
    try {
        $number = [int]$Value
        if ($number -eq 1) { return $true }
        if ($number -eq 0) { return $false }
    } catch { }
    return $null
}

function ConvertTo-VgtFirewallInt {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [int]$Value } catch { return $null }
}

function ConvertTo-VgtFirewallString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return $text.Trim()
    } catch { return $null }
}

function Assert-VgtSystemAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative token required.')
    }
}

function Get-VgtFirewallTelemetry {
    [CmdletBinding()]
    param()
    $profiles = $null
    $available = $false
    try { $profiles = @(Get-NetFirewallProfile -ErrorAction Stop); $available = $true } catch { $profiles = $null }
    $items = [System.Collections.Generic.List[object]]::new()
    $enabledCount = 0
    $profileCount = 0
    if ($available) {
        foreach ($profile in $profiles) {
            $name = ConvertTo-VgtFirewallString (Get-VgtFirewallProperty $profile 'Name')
            $enabled = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $profile 'Enabled')
            if ($enabled) { $enabledCount++ }
            $profileCount++
            [void]$items.Add([ordered]@{
                Name = $name
                Enabled = $enabled
                DefaultInboundAction = ConvertTo-VgtFirewallString (Get-VgtFirewallProperty $profile 'DefaultInboundAction')
                DefaultOutboundAction = ConvertTo-VgtFirewallString (Get-VgtFirewallProperty $profile 'DefaultOutboundAction')
                NotifyOnListen = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $profile 'NotifyOnListen')
                AllowUnicastResponseToMulticast = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $profile 'AllowUnicastResponseToMulticast')
                LogBlocked = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $profile 'LogBlocked')
                LogAllowed = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $profile 'LogAllowed')
                LogMaxSizeKilobytes = ConvertTo-VgtFirewallInt (Get-VgtFirewallProperty $profile 'LogMaxSizeKilobytes')
            })
        }
    }
    return [ordered]@{
        Available = $available
        ProfileCount = $profileCount
        EnabledProfileCount = $enabledCount
        Profiles = @($items.ToArray())
    }
}

function New-VgtFirewallApplyEntry {
    param([Parameter(Mandatory)][string]$Setting,[Parameter(Mandatory)][bool]$Changed,$Before = $null,$After = $null)
    return [ordered]@{ Setting = $Setting; Changed = [bool]$Changed; Before = $Before; After = $After }
}

function Set-VgtFirewallSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Profiles,
        [Parameter(Mandatory)][System.Collections.ArrayList]$Report
    )
    Assert-VgtSystemAdministrator
    foreach ($profileSetting in $Profiles) {
        $name = [string]$profileSetting['name']
        $current = Get-NetFirewallProfile -Name $name -ErrorAction Stop
        $setParameters = @{}
        if ($profileSetting.Contains('enabled')) {
            $before = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $current 'Enabled')
            $desired = [bool]$profileSetting['enabled']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['Enabled'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.enabled') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('defaultInboundAction')) {
            $before = ConvertTo-VgtFirewallString (Get-VgtFirewallProperty $current 'DefaultInboundAction')
            $desired = [string]$profileSetting['defaultInboundAction']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['DefaultInboundAction'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.defaultInboundAction') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('defaultOutboundAction')) {
            $before = ConvertTo-VgtFirewallString (Get-VgtFirewallProperty $current 'DefaultOutboundAction')
            $desired = [string]$profileSetting['defaultOutboundAction']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['DefaultOutboundAction'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.defaultOutboundAction') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('notifyOnListen')) {
            $before = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $current 'NotifyOnListen')
            $desired = [bool]$profileSetting['notifyOnListen']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['NotifyOnListen'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.notifyOnListen') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('allowUnicastResponseToMulticast')) {
            $before = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $current 'AllowUnicastResponseToMulticast')
            $desired = [bool]$profileSetting['allowUnicastResponseToMulticast']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['AllowUnicastResponseToMulticast'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.allowUnicastResponseToMulticast') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('logBlocked')) {
            $before = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $current 'LogBlocked')
            $desired = [bool]$profileSetting['logBlocked']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['LogBlocked'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.logBlocked') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('logAllowed')) {
            $before = ConvertTo-VgtFirewallBool (Get-VgtFirewallProperty $current 'LogAllowed')
            $desired = [bool]$profileSetting['logAllowed']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['LogAllowed'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.logAllowed') -Changed $changed -Before $before -After $desired))
        }
        if ($profileSetting.Contains('logMaxSizeKilobytes')) {
            $before = ConvertTo-VgtFirewallInt (Get-VgtFirewallProperty $current 'LogMaxSizeKilobytes')
            $desired = [int]$profileSetting['logMaxSizeKilobytes']
            $changed = $null -eq $before -or $before -ne $desired
            if ($changed) { $setParameters['LogMaxSizeKilobytes'] = $desired }
            [void]$Report.Add((New-VgtFirewallApplyEntry -Setting ('firewall.profiles.' + $name + '.logMaxSizeKilobytes') -Changed $changed -Before $before -After $desired))
        }
        if ($setParameters.Count -gt 0) { Set-NetFirewallProfile -Name $name @setParameters }
    }
}

function Set-VgtSystemBaseline {
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride' 0
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverrideMask' 3
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'DisableMSI' 1
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled' 1
}

Export-ModuleMember -Function Get-VgtFirewallTelemetry,Set-VgtFirewallSettings,Set-VgtSystemBaseline

