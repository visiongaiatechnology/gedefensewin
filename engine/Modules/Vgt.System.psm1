# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

Export-ModuleMember -Function Set-VgtSystemBaseline
