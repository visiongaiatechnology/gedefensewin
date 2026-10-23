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

function Get-VgtBaselineRegistryAllowlist {
    # HP-FIND-006: restore may only touch the exact registry values this product
    # captured. A baseline JSON entry outside this table is tampering/corruption.
    return @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' = @('RunAsPPL','RunAsPPLBoot','LmCompatibilityLevel')
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' = @('UseLogonCredential')
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @('EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' = @('EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' = @('Enabled')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' = @('Enabled')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' = @('EnableMulticast')
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' = @('RequireSecuritySignature')
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' = @('RequireSecuritySignature')
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' = @('DisabledComponents')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' = @('fDenyTSConnections')
        'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' = @('Start')
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' = @('VulnerableDriverBlocklistEnable')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' = @('FeatureSettingsOverride','FeatureSettingsOverrideMask')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @('EnableScriptBlockLogging')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' = @('EnableModuleLogging')
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' = @('ProcessCreationIncludeCmdLine_Enabled')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' = @('AlwaysInstallElevated','DisableMSI')
        'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' = @('Enabled')
    }
}

function Test-VgtBaselineRegistryEntry {
    param([Parameter(Mandatory)][object]$Entry)
    if ($null -eq $Entry) { return $false }
    $allowlist = Get-VgtBaselineRegistryAllowlist
    $pathProperty = $Entry.PSObject.Properties['path']
    $nameProperty = $Entry.PSObject.Properties['name']
    if ($null -eq $pathProperty -or $null -eq $nameProperty) { return $false }
    $path = [string]$pathProperty.Value
    $name = [string]$nameProperty.Value
    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name)) { return $false }
    if (-not $allowlist.ContainsKey($path)) { return $false }
    if (@($allowlist[$path]) -notcontains $name) { return $false }
    $existedProperty = $Entry.PSObject.Properties['existed']
    if ($null -eq $existedProperty -or $null -eq $existedProperty.Value) { return $false }
    if (-not ($existedProperty.Value -is [bool])) { return $false }
    if ([bool]$existedProperty.Value) {
        $valueProperty = $Entry.PSObject.Properties['value']
        if ($null -eq $valueProperty -or $null -eq $valueProperty.Value) { return $false }
        $number = 0L
        if (-not [long]::TryParse([string]$valueProperty.Value,[ref]$number)) { return $false }
        if ($number -lt 0 -or $number -gt [long][uint32]::MaxValue) { return $false }
    }
    return $true
}

function Test-VgtBaselineFirewallProfile {
    param([Parameter(Mandatory)][object]$Profile)
    if ($null -eq $Profile) { return $false }
    $nameProperty = $Profile.PSObject.Properties['Name']
    if ($null -eq $nameProperty -or [string]$nameProperty.Value -notin @('Domain','Private','Public')) { return $false }
    foreach ($booleanName in @('Enabled','NotifyOnListen','AllowUnicastResponseToMulticast','LogBlocked','LogAllowed')) {
        $property = $Profile.PSObject.Properties[$booleanName]
        if ($null -eq $property -or $null -eq $property.Value -or -not ($property.Value -is [bool])) { return $false }
    }
    foreach ($actionName in @('DefaultInboundAction','DefaultOutboundAction')) {
        $property = $Profile.PSObject.Properties[$actionName]
        if ($null -eq $property -or [string]$property.Value -notin @('Allow','Block','NotConfigured')) { return $false }
    }
    $sizeProperty = $Profile.PSObject.Properties['LogMaxSizeKilobytes']
    if ($null -eq $sizeProperty -or $null -eq $sizeProperty.Value) { return $false }
    $size = 0L
    if (-not [long]::TryParse([string]$sizeProperty.Value,[ref]$size)) { return $false }
    if ($size -lt 1 -or $size -gt 32767) { return $false }
    return $true
}

function Get-VgtBaselinePropertyValues {
    param([Parameter(Mandatory)][object]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return @() }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return @() }
    return @($property.Value)
}

function Test-VgtBaselineDefenderPreference {
    param([Parameter(Mandatory)][object]$Defender)
    if ($null -eq $Defender) { return $false }
    $enums = @{
        PUAProtection = @(0,1,2)
        MAPSReporting = @(0,1,2)
        SubmitSamplesConsent = @(0,1,2,3)
        EnableNetworkProtection = @(0,1,2)
        CloudBlockLevel = @(0,1,2,4,6)
        EnableControlledFolderAccess = @(0,1,2)
    }
    foreach ($settingName in $enums.Keys) {
        $values = Get-VgtBaselinePropertyValues -Object $Defender -Name $settingName
        if ($values.Count -ne 1) { return $false }
        $number = 0L
        if (-not [long]::TryParse([string]$values[0],[ref]$number)) { return $false }
        if (@($enums[$settingName]) -notcontains [int]$number) { return $false }
    }
    if ($null -eq $Defender.PSObject.Properties['AttackSurfaceReductionRules_Ids']) { return $false }
    if ($null -eq $Defender.PSObject.Properties['AttackSurfaceReductionRules_Actions']) { return $false }
    $ids = @(Get-VgtBaselinePropertyValues -Object $Defender -Name 'AttackSurfaceReductionRules_Ids')
    $actions = @(Get-VgtBaselinePropertyValues -Object $Defender -Name 'AttackSurfaceReductionRules_Actions')
    if ($ids.Count -ne $actions.Count) { return $false }
    if ($ids.Count -gt 256) { return $false }
    $seen = @{}
    for ($index = 0; $index -lt $ids.Count; $index++) {
        $id = ([string]$ids[$index]).Trim()
        if ($id -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { return $false }
        $key = $id.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return $false }
        $seen[$key] = $true
        $action = 0L
        if (-not [long]::TryParse([string]$actions[$index],[ref]$action)) { return $false }
        if (@(0,1,2,6) -notcontains [int]$action) { return $false }
    }
    return $true
}

function Test-VgtBaselineAuditPolicyPath {
    param([AllowEmptyString()][string]$Path = '',[Parameter(Mandatory)][string]$StateDirectory)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($StateDirectory)) { return $false }
    try {
        $resolvedState = [IO.Path]::GetFullPath($StateDirectory).TrimEnd('\') + '\'
        $resolved = [IO.Path]::GetFullPath($Path)
    } catch { return $false }
    if (-not $resolved.StartsWith($resolvedState,[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ([string]::Equals($resolved.TrimEnd('\'),$resolvedState.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($resolved -notmatch '(?i)\\audit-policy\.csv$') { return $false }
    if ($resolved.IndexOf(':',2) -ge 0) { return $false }
    try { $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop } catch { return $false }
    if ($null -eq $item -or [bool]$item.PSIsContainer) { return $false }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    return $true
}

function Get-VgtBaselineIntegrityMaterial {
    param([Parameter(Mandatory)][object]$State)
    # Only the security-relevant content is bound; createdUtc and the integrity
    # field itself are excluded so the hash is reproducible after a JSON
    # round-trip.
    $material = [ordered]@{
        format = [int]$State.format
        registry = @($State.registry)
        firewall = @($State.firewall)
        defender = $State.defender
        smb1State = [string]$State.smb1State
        auditPolicy = [string]$State.auditPolicy
    }
    return ($material | ConvertTo-Json -Depth 6 -Compress)
}

function Get-VgtBaselineIntegrityHash {
    param([Parameter(Mandatory)][object]$State)
    $material = Get-VgtBaselineIntegrityMaterial -State $State
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

# Returns 'Valid' when the stored SHA-256 matches the canonical content,
# 'Legacy' when the baseline predates integrity metadata and 'Mismatch' when
# the content was altered after it was captured.
function Test-VgtBaselineIntegrity {
    param([Parameter(Mandatory)][object]$State)
    $integrityProperty = $State.PSObject.Properties['integrity']
    if ($null -eq $integrityProperty -or $null -eq $integrityProperty.Value) { return 'Legacy' }
    $integrity = $integrityProperty.Value
    $algorithmProperty = $integrity.PSObject.Properties['algorithm']
    $hashProperty = $integrity.PSObject.Properties['baselineSha256']
    if ($null -eq $algorithmProperty -or $null -eq $hashProperty) { return 'Mismatch' }
    if ([string]$algorithmProperty.Value -ne 'SHA256') { return 'Mismatch' }
    $stored = ([string]$hashProperty.Value).Trim().ToLowerInvariant()
    if ($stored -notmatch '^[0-9a-f]{64}$') { return 'Mismatch' }
    $computed = Get-VgtBaselineIntegrityHash -State $State
    if (-not [string]::Equals($stored,$computed,[StringComparison]::Ordinal)) { return 'Mismatch' }
    return 'Valid'
}

function Test-VgtBaselineState {
    param([Parameter(Mandatory)][object]$State,[Parameter(Mandatory)][string]$StateDirectory)
    if ($null -eq $State) { return $false }
    $formatProperty = $State.PSObject.Properties['format']
    if ($null -eq $formatProperty) { return $false }
    $format = 0
    if (-not [int]::TryParse([string]$formatProperty.Value,[ref]$format)) { return $false }
    if ($format -ne 2) { return $false }
    $registry = @($State.registry)
    if ($registry.Count -lt 1 -or $registry.Count -gt 64) { return $false }
    $seenRegistry = @{}
    foreach ($entry in $registry) {
        if (-not (Test-VgtBaselineRegistryEntry -Entry $entry)) { return $false }
        $key = (([string]$entry.path) + '|' + ([string]$entry.name)).ToLowerInvariant()
        if ($seenRegistry.ContainsKey($key)) { return $false }
        $seenRegistry[$key] = $true
    }
    $firewall = @($State.firewall)
    if ($firewall.Count -ne 3) { return $false }
    $profileNames = @{}
    foreach ($profile in $firewall) {
        if (-not (Test-VgtBaselineFirewallProfile -Profile $profile)) { return $false }
        $profileNames[([string]$profile.Name).ToLowerInvariant()] = $true
    }
    if ($profileNames.Count -ne 3) { return $false }
    if (-not (Test-VgtBaselineDefenderPreference -Defender $State.defender)) { return $false }
    $smb1Property = $State.PSObject.Properties['smb1State']
    if ($null -eq $smb1Property -or [string]$smb1Property.Value -notin @('Enabled','Disabled')) { return $false }
    $auditPolicyProperty = $State.PSObject.Properties['auditPolicy']
    if ($null -eq $auditPolicyProperty) { return $false }
    if (-not (Test-VgtBaselineAuditPolicyPath -Path ([string]$auditPolicyProperty.Value) -StateDirectory $StateDirectory)) { return $false }
    return $true
}

function Save-VgtBaseline {
    $stateDirectory = Join-Path (Get-VgtDataRoot) 'State'
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        New-Item -Path $stateDirectory -ItemType Directory -Force | Out-Null
    }
    $target = Join-Path $stateDirectory 'baseline.json'
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        # The rollback anchor stays write-once, but an existing anchor must be
        # structurally valid and integrity-checked before it may be used later.
        $existing = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not (Test-VgtBaselineState -State $existing -StateDirectory $stateDirectory)) {
            # Baselines written by older 5.x builds used numeric firewall enums
            # and therefore no longer satisfy the current canonical schema. Do
            # not brick upgrades on that legacy shape: preserve the old anchor
            # for forensics and create a fresh canonical baseline below.
            $legacyShape = $false
            try {
                $format = [int]$existing.format
                $legacyShape = ($format -eq 2) -and
                    ($null -ne $existing.createdUtc) -and
                    (@($existing.registry).Count -ge 1) -and
                    (@($existing.firewall).Count -eq 3) -and
                    ($null -ne $existing.defender)
            } catch { $legacyShape = $false }
            if (-not $legacyShape) {
                throw [Security.SecurityException]::new('Existing VGT baseline failed validation.')
            }
            $legacyArchive = Join-Path $stateDirectory ('baseline.legacy-{0}.json' -f [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
            Move-Item -LiteralPath $target -Destination $legacyArchive -Force
            Write-VgtEvent -Level WARN -Message ('Legacy hardening baseline archived after schema upgrade: {0}' -f (Split-Path -Leaf $legacyArchive))
        } else {
            $existingIntegrity = Test-VgtBaselineIntegrity -State $existing
            if ($existingIntegrity -eq 'Mismatch') {
                throw [Security.SecurityException]::new('Existing VGT baseline failed integrity verification.')
            }
            return $target
        }
    }

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
    $smb1Server = (Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
    $smb1Driver = (Get-VgtRegistryDword 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start')
    $smb1State = if ($smb1Server -eq 0 -and $smb1Driver -eq 4) { 'Disabled' } else { 'Enabled' }
    $auditPolicy = Join-Path $stateDirectory 'audit-policy.csv'
    $auditPolicyTool = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $auditPolicyTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows audit policy tool is unavailable.') }
    # auditpol /backup refuses to overwrite an existing file. Write to a fresh
    # temporary CSV, then replace the previous anchor atomically (keeping the old
    # one as a forensic legacy copy) so upgrades and reinstalls can proceed.
    $auditTemporary = Join-Path $stateDirectory ('audit-policy-{0}.tmp.csv' -f $PID)
    if (Test-Path -LiteralPath $auditTemporary) { Remove-Item -LiteralPath $auditTemporary -Force }
    & $auditPolicyTool /backup "/file:$auditTemporary" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $auditTemporary -PathType Leaf)) {
        throw [InvalidOperationException]::new('Audit policy backup failed.')
    }
    if (Test-Path -LiteralPath $auditPolicy -PathType Leaf) {
        $legacyAudit = Join-Path $stateDirectory ('audit-policy.legacy-{0}.csv' -f [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
        Move-Item -LiteralPath $auditPolicy -Destination $legacyAudit -Force
    }
    Move-Item -LiteralPath $auditTemporary -Destination $auditPolicy -Force
    $state = [ordered]@{
        format = 2
        createdUtc = [DateTime]::UtcNow.ToString('o')
        registry = @($registry)
        firewall = @($firewall)
        defender = $defender
        smb1State = $smb1State
        auditPolicy = $auditPolicy
    }
    $state['integrity'] = [ordered]@{
        algorithm = 'SHA256'
        baselineSha256 = (Get-VgtBaselineIntegrityHash -State ([pscustomobject]$state))
    }
    $temporary = "$target.$PID.tmp"
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $target -Force
    return $target
}

function Test-VgtBaselineRestoredState {
    param([Parameter(Mandatory)][object]$State)
    foreach ($entry in @($State.registry)) {
        $property = Get-ItemProperty -LiteralPath ([string]$entry.path) -Name ([string]$entry.name) -ErrorAction SilentlyContinue
        if ([bool]$entry.existed) {
            if ($null -eq $property) { return $false }
            $actual = 0L
            if (-not [long]::TryParse([string]$property.(([string]$entry.name)),[ref]$actual)) { return $false }
            if ([long]$entry.value -ne $actual) { return $false }
        } elseif ($null -ne $property) {
            return $false
        }
    }
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    foreach ($expected in @($State.firewall)) {
        $actual = @($profiles | Where-Object { [string]$_.Name -eq [string]$expected.Name } | Select-Object -First 1)
        if ($actual.Count -ne 1) { return $false }
        $profile = $actual[0]
        if ([bool]$profile.Enabled -ne [bool]$expected.Enabled) { return $false }
        if ([string]$profile.DefaultInboundAction -ne [string]$expected.DefaultInboundAction) { return $false }
        if ([string]$profile.DefaultOutboundAction -ne [string]$expected.DefaultOutboundAction) { return $false }
        if ([bool]$profile.NotifyOnListen -ne [bool]$expected.NotifyOnListen) { return $false }
        if ([bool]$profile.AllowUnicastResponseToMulticast -ne [bool]$expected.AllowUnicastResponseToMulticast) { return $false }
        if ([bool]$profile.LogBlocked -ne [bool]$expected.LogBlocked) { return $false }
        if ([bool]$profile.LogAllowed -ne [bool]$expected.LogAllowed) { return $false }
        if ([uint32]$profile.LogMaxSizeKilobytes -ne [uint32]$expected.LogMaxSizeKilobytes) { return $false }
    }
    $preference = Get-MpPreference -ErrorAction Stop
    $expectedDefender = $State.defender
    foreach ($settingName in @('PUAProtection','MAPSReporting','SubmitSamplesConsent','EnableNetworkProtection','CloudBlockLevel','EnableControlledFolderAccess')) {
        if ([long]$preference.$settingName -ne [long]$expectedDefender.$settingName) { return $false }
    }
    $actualRules = @{}
    $actualIds = @(Get-VgtBaselinePropertyValues -Object $preference -Name 'AttackSurfaceReductionRules_Ids')
    $actualActions = @(Get-VgtBaselinePropertyValues -Object $preference -Name 'AttackSurfaceReductionRules_Actions')
    for ($index = 0; $index -lt $actualIds.Count; $index++) {
        $actualRules[([string]$actualIds[$index]).ToLowerInvariant()] = [int]$actualActions[$index]
    }
    $expectedRules = @{}
    $expectedIds = @(Get-VgtBaselinePropertyValues -Object $expectedDefender -Name 'AttackSurfaceReductionRules_Ids')
    $expectedActions = @(Get-VgtBaselinePropertyValues -Object $expectedDefender -Name 'AttackSurfaceReductionRules_Actions')
    for ($index = 0; $index -lt $expectedIds.Count; $index++) {
        $expectedRules[([string]$expectedIds[$index]).ToLowerInvariant()] = [int]$expectedActions[$index]
    }
    if ($actualRules.Count -ne $expectedRules.Count) { return $false }
    foreach ($key in $expectedRules.Keys) {
        if (-not $actualRules.ContainsKey($key)) { return $false }
        if ($actualRules[$key] -ne $expectedRules[$key]) { return $false }
    }
    return $true
}

function Restore-VgtBaseline {
    $stateDirectory = Join-Path (Get-VgtDataRoot) 'State'
    $target = Join-Path $stateDirectory 'baseline.json'
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT baseline is unavailable.') }
    $state = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-VgtBaselineState -State $state -StateDirectory $stateDirectory)) {
        throw [Security.SecurityException]::new('VGT baseline validation failed.')
    }
    $integrity = Test-VgtBaselineIntegrity -State $state
    if ($integrity -eq 'Mismatch') {
        throw [Security.SecurityException]::new('VGT baseline integrity verification failed.')
    }
    if ($integrity -eq 'Legacy') {
        Write-VgtEvent -Level WARN -Message 'Baseline lacks integrity metadata (legacy format); content validation passed.'
    }
    foreach ($entry in @($state.registry)) {
        if ([bool]$entry.existed) {
            Set-VgtRegistryDword -Path ([string]$entry.path) -Name ([string]$entry.name) -Value ([uint32]$entry.value)
        } elseif (Test-Path -LiteralPath ([string]$entry.path)) {
            Remove-ItemProperty -LiteralPath ([string]$entry.path) -Name ([string]$entry.name) -ErrorAction SilentlyContinue
        }
    }
    foreach ($profile in @($state.firewall)) {
        Set-NetFirewallProfile -Name ([string]$profile.Name) -Enabled ([bool]$profile.Enabled) -DefaultInboundAction ([string]$profile.DefaultInboundAction) -DefaultOutboundAction ([string]$profile.DefaultOutboundAction) -NotifyOnListen ([bool]$profile.NotifyOnListen) -AllowUnicastResponseToMulticast ([bool]$profile.AllowUnicastResponseToMulticast) -LogBlocked ([bool]$profile.LogBlocked) -LogAllowed ([bool]$profile.LogAllowed) -LogMaxSizeKilobytes ([uint32]$profile.LogMaxSizeKilobytes)
    }
    $defender = $state.defender
    Set-MpPreference -PUAProtection $defender.PUAProtection -MAPSReporting $defender.MAPSReporting -SubmitSamplesConsent $defender.SubmitSamplesConsent -EnableNetworkProtection $defender.EnableNetworkProtection -CloudBlockLevel $defender.CloudBlockLevel -EnableControlledFolderAccess $defender.EnableControlledFolderAccess
    $currentRules = @((Get-MpPreference).AttackSurfaceReductionRules_Ids)
    if ($currentRules.Count -gt 0) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $currentRules }
    if (@($defender.AttackSurfaceReductionRules_Ids).Count -gt 0) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids @($defender.AttackSurfaceReductionRules_Ids) -AttackSurfaceReductionRules_Actions @($defender.AttackSurfaceReductionRules_Actions)
    }
    if ($state.smb1State -eq 'Enabled') {
        Set-VgtRegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 1
        Set-VgtRegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 3
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    } elseif ($state.smb1State -eq 'Disabled') {
        Set-VgtRegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0
        Set-VgtRegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }
    $auditPolicy = [string]$state.auditPolicy
    if (-not (Test-VgtBaselineAuditPolicyPath -Path $auditPolicy -StateDirectory $stateDirectory)) {
        throw [Security.SecurityException]::new('Audit policy baseline path validation failed.')
    }
    $auditPolicyTool = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $auditPolicyTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows audit policy tool is unavailable.') }
    & $auditPolicyTool /restore ("/file:{0}" -f $auditPolicy) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Audit policy restore failed.') }
    if (-not (Test-VgtBaselineRestoredState -State $state)) {
        throw [Security.SecurityException]::new('VGT baseline restore verification failed.')
    }
    Write-VgtEvent -Level INFO -Message 'Baseline restored and verified.'
}

Export-ModuleMember -Function Assert-VgtAdministrator,Get-VgtDataRoot,Write-VgtEvent,Set-VgtRegistryDword,Save-VgtBaseline,Restore-VgtBaseline

