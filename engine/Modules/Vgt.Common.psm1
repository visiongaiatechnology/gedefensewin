# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-VgtAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative token required.')
    }
}

function Get-VgtDataRoot {
    $root = Join-Path $env:ProgramData 'VGT\SecurityCenter'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        New-Item -Path $root -ItemType Directory -Force | Out-Null
    }
    return $root
}

function Write-VgtEvent {
    param(
        [Parameter(Mandatory)][ValidateSet('INFO','WARN','ERROR','SECURITY')][string]$Level,
        [Parameter(Mandatory)][ValidateLength(1,512)][string]$Message
    )
    $logDirectory = Join-Path (Get-VgtDataRoot) 'Logs'
    if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }
    $safeMessage = $Message -replace '[\r\n\0]', ' '
    $record = '{0:o}`t{1}`t{2}' -f [DateTime]::UtcNow,$Level,$safeMessage
    Add-Content -LiteralPath (Join-Path $logDirectory 'hardening.log') -Value $record -Encoding UTF8
}

function Set-VgtRegistryDword {
    param(
        [Parameter(Mandatory)][ValidatePattern('^HKLM:\\')][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_. -]{1,128}$')][string]$Name,
        [Parameter(Mandatory)][uint32]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Save-VgtBaseline {
    $stateDirectory = Join-Path (Get-VgtDataRoot) 'State'
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        New-Item -Path $stateDirectory -ItemType Directory -Force | Out-Null
    }
    $target = Join-Path $stateDirectory 'baseline.json'
    if (Test-Path -LiteralPath $target -PathType Leaf) { return $target }

    $registryTargets = @(
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPLBoot'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ConsentPromptBehaviorAdmin'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','PromptOnSecureDesktop'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard','EnableVirtualizationBasedSecurity'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard','RequirePlatformSecurityFeatures'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard','Enabled'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity','Enabled'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast'),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature'),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature'),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters','DisabledComponents'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections'),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR','Start'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config','VulnerableDriverBlocklistEnable'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management','FeatureSettingsOverride'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management','FeatureSettingsOverrideMask'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','DisableMSI'),
        @('HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings','Enabled')
    )
    $registry = foreach ($targetValue in $registryTargets) {
        $path = $targetValue[0]
        $name = $targetValue[1]
        $exists = Test-Path -LiteralPath $path
        $valueExists = $false
        $value = $null
        if ($exists) {
            $property = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $property) {
                $valueExists = $true
                $value = [uint32]$property.$name
            }
        }
        [ordered]@{ path = $path; name = $name; existed = $valueExists; value = $value }
    }
    $firewall = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,AllowUnicastResponseToMulticast,LogBlocked,LogAllowed,LogMaxSizeKilobytes
    $defender = Get-MpPreference | Select-Object PUAProtection,MAPSReporting,SubmitSamplesConsent,EnableNetworkProtection,CloudBlockLevel,EnableControlledFolderAccess,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $auditPolicy = Join-Path $stateDirectory 'audit-policy.csv'
    $auditPolicyTool = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $auditPolicyTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows audit policy tool is unavailable.') }
    & $auditPolicyTool /backup "/file:$auditPolicy" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $auditPolicy -PathType Leaf)) {
        throw [InvalidOperationException]::new('Audit policy backup failed.')
    }
    $state = [ordered]@{
        format = 2
        createdUtc = [DateTime]::UtcNow.ToString('o')
        registry = @($registry)
        firewall = @($firewall)
        defender = $defender
        smb1State = if ($smb1) { [string]$smb1.State } else { 'Unavailable' }
        auditPolicy = $auditPolicy
    }
    $temporary = "$target.$PID.tmp"
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $target -Force
    return $target
}

function Restore-VgtBaseline {
    $target = Join-Path (Join-Path (Get-VgtDataRoot) 'State') 'baseline.json'
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT baseline is unavailable.') }
    $state = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($state.format -ne 2) { throw [InvalidDataException]::new('Unsupported VGT baseline format.') }
    foreach ($entry in @($state.registry)) {
        if ($entry.path -notmatch '^HKLM:\\' -or $entry.name -notmatch '^[A-Za-z0-9_. -]{1,128}$') {
            throw [Security.SecurityException]::new('Baseline registry path validation failed.')
        }
        if ([bool]$entry.existed) {
            Set-VgtRegistryDword -Path $entry.path -Name $entry.name -Value ([uint32]$entry.value)
        } elseif (Test-Path -LiteralPath $entry.path) {
            Remove-ItemProperty -LiteralPath $entry.path -Name $entry.name -ErrorAction SilentlyContinue
        }
    }
    foreach ($profile in @($state.firewall)) {
        Set-NetFirewallProfile -Name $profile.Name -Enabled ([bool]$profile.Enabled) -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction -NotifyOnListen ([bool]$profile.NotifyOnListen) -AllowUnicastResponseToMulticast ([bool]$profile.AllowUnicastResponseToMulticast) -LogBlocked ([bool]$profile.LogBlocked) -LogAllowed ([bool]$profile.LogAllowed) -LogMaxSizeKilobytes ([uint32]$profile.LogMaxSizeKilobytes)
    }
    $defender = $state.defender
    Set-MpPreference -PUAProtection $defender.PUAProtection -MAPSReporting $defender.MAPSReporting -SubmitSamplesConsent $defender.SubmitSamplesConsent -EnableNetworkProtection $defender.EnableNetworkProtection -CloudBlockLevel $defender.CloudBlockLevel -EnableControlledFolderAccess $defender.EnableControlledFolderAccess
    $currentRules = @((Get-MpPreference).AttackSurfaceReductionRules_Ids)
    if ($currentRules.Count -gt 0) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $currentRules }
    if (@($defender.AttackSurfaceReductionRules_Ids).Count -gt 0) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids @($defender.AttackSurfaceReductionRules_Ids) -AttackSurfaceReductionRules_Actions @($defender.AttackSurfaceReductionRules_Actions)
    }
    if ($state.smb1State -eq 'Enabled') {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart | Out-Null
    } elseif ($state.smb1State -eq 'Disabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
    }
    if (-not (Test-Path -LiteralPath $state.auditPolicy -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('Audit policy baseline is unavailable.')
    }
    $auditPolicyTool = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $auditPolicyTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows audit policy tool is unavailable.') }
    & $auditPolicyTool /restore ("/file:{0}" -f $state.auditPolicy) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Audit policy restore failed.') }
    Write-VgtEvent -Level INFO -Message 'Baseline restored.'
}

Export-ModuleMember -Function Assert-VgtAdministrator,Get-VgtDataRoot,Write-VgtEvent,Set-VgtRegistryDword,Save-VgtBaseline,Restore-VgtBaseline

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjSVXgHHS6hno1
# WmpGVurxhz/JfdDt9UwURvLECdqUCqCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
# m08OD57tPeOLMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEg
# VGVjaG5vbG9neSBWR1QgUmVsZWFzZTAeFw0yNjA4MjExMzUyNDFaFw0zNjA4MjEx
# MjAyNDBaMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEgVGVjaG5vbG9neSBWR1QgUmVs
# ZWFzZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAL5pFqzqfhSchgN3
# OSKoeRbHXQIUtVwI7Q5go/7UvOFVMV0d/Au5Q5yPFOr351VqQyZlLWehwPG88Wdh
# TEPxfzYXDeJFgG6MwdjVaA10WklxDzSu8XQQzQKvoSOtf6b76xYswPdR8WaUOvYL
# NVYHG38cZCE/Vmt8W29/+8bT0SFoMv8S++3YUL3BaTTVBj5wcunaQYu7bcBUFz8M
# wCWGaqZUwWi/7sZPb5Ix0KKnMarxxAAM/y1GaRnWDQavGSuFZ18LmMh+Agd6znFZ
# 6pH1USuu0NreFUOWNg2ANEmGAO4XTnst3ILT4Eab/Jsjmw4nRm8rckRaWVKJxcRc
# P7ukJJi3cV11JegdsYSBGKvZ8TUNiSRuVI0MGg1IJl4ga/dir1crp0DnqezcC/6y
# 9mxsnxuJLpW8I1nLdRLjE1ow5VshhvEMFjPoYbcowpcI0EUFj/clBpA+rHjPjkYF
# jw8oow+tYqnEK/GkrYkzGwGxpApKcECh5GGHgQ5iSgKuNTPueQIDAQABo0YwRDAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFDBP
# H8Z9qi6vrLw8FPD3k/kz+c1gMA0GCSqGSIb3DQEBCwUAA4IBgQBIQe+HN5spItMd
# 884eV6JR3H8xGr8DeNpgjuhQnRnQqWB60Et6ehQwQFDg5Ft8iU4sGzdEQB4U+q79
# 9oReJ6G1CuV6yXXqDe/Ljr5DGfGr+Wah4RuRi/QGhUUeIyyn8h5kXwOgGWz4VA5I
# 9CmN+onZHRLnv3Lu9mKyUqo7ll5WaWEd/r3hvBqe30Rg0IanD8qpWXEbshlayTux
# 8WMgjW3nA7tEWXmToCJpRk8DsaGU5m6rNxVa6zSS7qF2JiMWnZZBsr76cQsMYvTk
# ZgshPz+OTsl84mR7i/BalTIyuI74TWd+8LdcBB+FpmhXvYmKAPQKQg25dHGWbVlB
# E7kK29X38hvaQBO6lVT7mtTOPx2auMTmas6LLU+1XGFNm4zvwuydpf/4ltPSYlNp
# K8Ij5vkp2DjXOaJF02BoqBkZt6w4wQPuCdu3OOTH3A3hymQrVD0tP408qNkLuzd5
# xI+m7oTQCw6SYCxeEUEOooR7XMWuxE1R/KyLlPRCI1zi9DjhLawxggJyMIICbgIB
# ATBAMCwxKjAoBgNVBAMMIVZpc2lvbkdhaWEgVGVjaG5vbG9neSBWR1QgUmVsZWFz
# ZQIQXORetgQfkZtPDg+e7T3jizANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDc3JJ/yGaF
# aXDb+7ToDOzGH/hQgS+LK3NU9F3GIztJGzANBgkqhkiG9w0BAQEFAASCAYBkByyJ
# pw5ysuN4hgxosGzjgNbEjQRMKtNHoSDxxaRk1FGrEsv31Wupmd6MS55PC2k1jNWF
# m9GDSs0ecbRJYYNbgGhNvTvrU5VPQRJ6LqDi7eG1DM1lRPwxra8O048ppfdzw0dR
# 591dBgRe+bUxu9F/ByHdhIGZawZU55jq2bSDq6aS1VbuSMR5W7MI/o7HDPiSr72t
# yP60DZ1Mc2D//Du2Bkic4GITdMyIX2fngH63SatIyeXxJW0FKS7IZiFYIW4FiOOo
# PdE+meOjpTd7hiuK+ccfb6S4646WkB4Vo3YgAyW7dUA6PgAW9HvDy5n2kKwgakU2
# zcDNJbJDZxJ7tbxVJ4zWMiSx4A4EEuhPR22lJ4ivvLqKnqU9J/nhLqRj2gvST2u5
# CKIVsPGphU+0c6a3EYpMy3A1lI/TlZaZ5M9yivYDY1XwOY/ocYVQJHaTuexdZOso
# EiFikxBYXHHUQCDXss40J1pvbrtmF6NymKYsdZgGSVWRpdJES2j2v/Q7bbo=
# SIG # End signature block
