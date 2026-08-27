# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-VgtIdentityBaseline {
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 2
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPLBoot' 2
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 3
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' 'Enabled' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1
}

Export-ModuleMember -Function Set-VgtIdentityBaseline
