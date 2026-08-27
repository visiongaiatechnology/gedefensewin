# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-VgtNetworkBaseline {
    param([Parameter(Mandatory)][pscustomobject]$Profile)
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction $Profile.defaultOutboundAction -NotifyOnListen True -AllowUnicastResponseToMulticast False
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767
    Set-VgtRegistryDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
    Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' 0
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    if ($Profile.disableRemoteDesktop) {
        Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    }
    if ($Profile.disableUsbStorage) {
        Set-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start' 4
    }
}

Export-ModuleMember -Function Set-VgtNetworkBaseline
