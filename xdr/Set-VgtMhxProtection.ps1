# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Monitor','Guarded','Sovereign','Restore')][string]$Mode,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative protection transaction required.')
    }
}

function Get-StatePath {
    $root = Join-Path $env:ProgramData 'VGT\GeDefense\mhx'
    [IO.Directory]::CreateDirectory($root) | Out-Null
    return Join-Path $root 'windows-policy-baseline.json'
}

function Test-VgtMhxBaselineState {
    # HP-FIND-006: values persisted in the MHX baseline are restored with SYSTEM
    # authority. Validate every field against fixed allowlists before any
    # firewall, ASR or network default is changed.
    param([Parameter(Mandatory)][object]$State)
    if ($null -eq $State) { return $false }
    $formatProperty = $State.PSObject.Properties['Format']
    if ($null -ne $formatProperty -and $null -ne $formatProperty.Value) {
        $format = 0
        if (-not [int]::TryParse([string]$formatProperty.Value,[ref]$format)) { return $false }
        if ($format -ne 2) { return $false }
    }
    $profilesProperty = $State.PSObject.Properties['FirewallProfiles']
    if ($null -eq $profilesProperty -or $null -eq $profilesProperty.Value) { return $false }
    $profiles = @($profilesProperty.Value)
    if ($profiles.Count -lt 1 -or $profiles.Count -gt 3) { return $false }
    $seenProfiles = @{}
    foreach ($profile in $profiles) {
        if ($null -eq $profile) { return $false }
        $nameProperty = $profile.PSObject.Properties['Name']
        $actionProperty = $profile.PSObject.Properties['DefaultOutboundAction']
        if ($null -eq $nameProperty -or $null -eq $actionProperty) { return $false }
        $name = [string]$nameProperty.Value
        if ($name -notin @('Domain','Private','Public')) { return $false }
        if ($seenProfiles.ContainsKey($name.ToLowerInvariant())) { return $false }
        $seenProfiles[$name.ToLowerInvariant()] = $true
        if ([string]$actionProperty.Value -notin @('Allow','Block','NotConfigured')) { return $false }
    }
    $idsProperty = $State.PSObject.Properties['AsrIds']
    $actionsProperty = $State.PSObject.Properties['AsrActions']
    if ($null -eq $idsProperty -or $null -eq $actionsProperty) { return $false }
    $ids = @()
    if ($null -ne $idsProperty.Value) { $ids = @($idsProperty.Value) }
    $actions = @()
    if ($null -ne $actionsProperty.Value) { $actions = @($actionsProperty.Value) }
    if ($ids.Count -ne $actions.Count) { return $false }
    if ($ids.Count -gt 256) { return $false }
    $seenIds = @{}
    for ($index = 0; $index -lt $ids.Count; $index++) {
        $id = ([string]$ids[$index]).Trim()
        if ($id -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { return $false }
        $key = $id.ToLowerInvariant()
        if ($seenIds.ContainsKey($key)) { return $false }
        $seenIds[$key] = $true
        $action = 0L
        if (-not [long]::TryParse([string]$actions[$index],[ref]$action)) { return $false }
        if (@(0,1,2,6) -notcontains [int]$action) { return $false }
    }
    return $true
}

function Get-VgtMhxBaselineIntegrityMaterial {
    param([Parameter(Mandatory)][object]$State)
    $material = [ordered]@{
        Format = [int]$State.Format
        FirewallProfiles = @($State.FirewallProfiles)
        AsrIds = @($State.AsrIds)
        AsrActions = @($State.AsrActions)
    }
    return ($material | ConvertTo-Json -Depth 5 -Compress)
}

function Get-VgtMhxBaselineIntegrityHash {
    param([Parameter(Mandatory)][object]$State)
    $material = Get-VgtMhxBaselineIntegrityMaterial -State $State
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Test-VgtMhxBaselineIntegrity {
    param([Parameter(Mandatory)][object]$State)
    $integrityProperty = $State.PSObject.Properties['Integrity']
    if ($null -eq $integrityProperty -or $null -eq $integrityProperty.Value) { return 'Legacy' }
    $integrity = $integrityProperty.Value
    $algorithmProperty = $integrity.PSObject.Properties['Algorithm']
    $hashProperty = $integrity.PSObject.Properties['BaselineSha256']
    if ($null -eq $algorithmProperty -or $null -eq $hashProperty) { return 'Mismatch' }
    if ([string]$algorithmProperty.Value -ne 'SHA256') { return 'Mismatch' }
    $stored = ([string]$hashProperty.Value).Trim().ToLowerInvariant()
    if ($stored -notmatch '^[0-9a-f]{64}$') { return 'Mismatch' }
    $computed = Get-VgtMhxBaselineIntegrityHash -State $State
    if (-not [string]::Equals($stored,$computed,[StringComparison]::Ordinal)) { return 'Mismatch' }
    return 'Valid'
}

function Save-Baseline {
    $path = Get-StatePath
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $existing = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not (Test-VgtMhxBaselineState -State $existing)) {
            # Older 5.x baselines predate the canonical schema and would brick
            # upgrades. Archive the legacy anchor for forensics and rebuild.
            $legacyShape = $false
            try {
                $legacyShape = ([int]$existing.Format -eq 2) -and ($null -ne $existing.TimestampUtc) -and
                    (@($existing.FirewallProfiles).Count -ge 1) -and ($null -ne $existing.AsrIds)
            } catch { $legacyShape = $false }
            if (-not $legacyShape) {
                throw [Security.SecurityException]::new('Existing MHX baseline failed validation.')
            }
            $legacyArchive = Join-Path (Split-Path -Parent $path) ('windows-policy-baseline.legacy-{0}.json' -f [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
            Move-Item -LiteralPath $path -Destination $legacyArchive -Force
            Write-Warning ('Legacy MHX baseline archived after schema upgrade: {0}' -f (Split-Path -Leaf $legacyArchive))
        } else {
            $existingIntegrity = Test-VgtMhxBaselineIntegrity -State $existing
            if ($existingIntegrity -eq 'Mismatch') {
                throw [Security.SecurityException]::new('Existing MHX baseline failed integrity verification.')
            }
            return
        }
    }
    $preference = Get-MpPreference
    # Persist firewall actions as their canonical string names. Select-Object
    # serializes the enum numerically, which the validator correctly rejects on
    # the next transaction/install; storing strings keeps the write-once anchor
    # self-consistent across upgrades.
    $firewallProfiles = @(Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{
            Name = [string]$_.Name
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
        }
    })
    $state = [ordered]@{
        Format = 2
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        FirewallProfiles = $firewallProfiles
        AsrIds = @($preference.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ })
        AsrActions = @($preference.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
    }
    $state['Integrity'] = [ordered]@{
        Algorithm = 'SHA256'
        BaselineSha256 = (Get-VgtMhxBaselineIntegrityHash -State ([pscustomobject]$state))
    }
    $temporary = "$path.$PID.tmp"
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $path -Force
}

function Set-AsrRule {
    param([Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][ValidateSet(0,1,2,6)][int]$Action)
    $preference = Get-MpPreference
    $rules = [ordered]@{}
    $ids = @($preference.AttackSurfaceReductionRules_Ids)
    $actions = @($preference.AttackSurfaceReductionRules_Actions)
    for ($index = 0; $index -lt $ids.Count; $index++) { $rules[[string]$ids[$index]] = [int]$actions[$index] }
    $rules[$Id] = $Action
    Set-MpPreference -AttackSurfaceReductionRules_Ids @($rules.Keys) -AttackSurfaceReductionRules_Actions @($rules.Values)
}

function Enable-ProcessTelemetry {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
    $auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    & $auditpol /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Process creation auditing could not be enabled.') }
}

function Enable-NetworkBlockTelemetry {
    $auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    & $auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('WFP failure auditing could not be enabled.') }
}

function Remove-VgtFirewallRules {
    Get-NetFirewallRule -Group 'VGT GeDefense Sovereign' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
}

function Add-SovereignAllowRules {
    Remove-VgtFirewallRules
    $svchost = Join-Path $env:SystemRoot 'System32\svchost.exe'
    New-NetFirewallRule -DisplayName 'VGT Sovereign - DNS UDP' -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service 'Dnscache' -Protocol UDP -RemotePort 53 | Out-Null
    New-NetFirewallRule -DisplayName 'VGT Sovereign - DNS TCP' -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service 'Dnscache' -Protocol TCP -RemotePort 53 | Out-Null
    New-NetFirewallRule -DisplayName 'VGT Sovereign - DHCP' -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service 'Dhcp' -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    New-NetFirewallRule -DisplayName 'VGT Sovereign - Time Sync' -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service 'W32Time' -Protocol UDP -RemotePort 123 | Out-Null
    foreach ($service in @('wuauserv','BITS','CryptSvc')) {
        New-NetFirewallRule -DisplayName "VGT Sovereign - $service HTTPS" -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service $service -Protocol TCP -RemotePort 443 | Out-Null
        New-NetFirewallRule -DisplayName "VGT Sovereign - $service HTTP" -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $svchost -Service $service -Protocol TCP -RemotePort 80 | Out-Null
    }
    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path -LiteralPath $platformRoot -PathType Container) {
        Get-ChildItem -LiteralPath $platformRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object {
            foreach ($binary in @('MsMpEng.exe','MpDefenderCoreService.exe','NisSrv.exe','MpCmdRun.exe')) {
                $candidate = Join-Path $_.FullName $binary
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    New-NetFirewallRule -DisplayName "VGT Sovereign - Defender $binary" -Group 'VGT GeDefense Sovereign' -Direction Outbound -Action Allow -Program $candidate -Protocol Any | Out-Null
                }
            }
        }
    }
}

function Restore-NetworkBaseline {
    $path = Get-StatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        # HP-FIND-006: never fail open with "allow everything" when the
        # operator baseline is missing or was removed.
        throw [Security.SecurityException]::new('MHX network baseline is unavailable; refusing to relax outbound defaults.')
    }
    $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-VgtMhxBaselineState -State $state)) {
        throw [Security.SecurityException]::new('MHX network baseline validation failed.')
    }
    $integrity = Test-VgtMhxBaselineIntegrity -State $state
    if ($integrity -eq 'Mismatch') {
        throw [Security.SecurityException]::new('MHX network baseline integrity verification failed.')
    }
    if ($integrity -eq 'Legacy') {
        Write-Warning 'MHX network baseline has no integrity metadata (legacy format); structural validation passed.'
    }
    # Mutate firewall state only after the persisted baseline has passed
    # validation, so a rejected restore leaves the previous rules untouched.
    Remove-VgtFirewallRules
    foreach ($profile in @($state.FirewallProfiles)) {
        Set-NetFirewallProfile -Name ([string]$profile.Name) -DefaultOutboundAction ([string]$profile.DefaultOutboundAction)
    }
    $applied = @(Get-NetFirewallProfile)
    foreach ($profile in @($state.FirewallProfiles)) {
        $actual = @($applied | Where-Object { [string]$_.Name -eq [string]$profile.Name } | Select-Object -First 1)
        if ($actual.Count -ne 1) {
            throw [Security.SecurityException]::new('MHX network baseline restore verification failed.')
        }
        if ([string]$actual[0].DefaultOutboundAction -ne [string]$profile.DefaultOutboundAction) {
            throw [Security.SecurityException]::new('MHX network baseline restore verification failed.')
        }
    }
}

function Restore-AsrBaseline {
    $path = Get-StatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw [Security.SecurityException]::new('MHX ASR baseline is unavailable.')
    }
    $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-VgtMhxBaselineState -State $state)) {
        throw [Security.SecurityException]::new('MHX ASR baseline validation failed.')
    }
    $integrity = Test-VgtMhxBaselineIntegrity -State $state
    if ($integrity -eq 'Mismatch') {
        throw [Security.SecurityException]::new('MHX ASR baseline integrity verification failed.')
    }
    $ids = @()
    if ($null -ne $state.AsrIds) { $ids = @($state.AsrIds) }
    $actions = @()
    if ($null -ne $state.AsrActions) { $actions = @($state.AsrActions) }
    if ($ids.Count -ne $actions.Count) {
        throw [Security.SecurityException]::new('MHX ASR baseline rule/action counts differ.')
    }
    if ($ids.Count -gt 0) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions @($actions | ForEach-Object { [int]$_ })
    } else {
        $currentIds = @((Get-MpPreference).AttackSurfaceReductionRules_Ids)
        if ($currentIds.Count -gt 0) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $currentIds }
    }
    $preference = Get-MpPreference
    $actualRules = @{}
    $actualIds = @($preference.AttackSurfaceReductionRules_Ids)
    $actualActions = @($preference.AttackSurfaceReductionRules_Actions)
    for ($index = 0; $index -lt $actualIds.Count; $index++) {
        $actualRules[([string]$actualIds[$index]).ToLowerInvariant()] = [int]$actualActions[$index]
    }
    $expectedRules = @{}
    for ($index = 0; $index -lt $ids.Count; $index++) {
        $expectedRules[([string]$ids[$index]).ToLowerInvariant()] = [int]$actions[$index]
    }
    if ($actualRules.Count -ne $expectedRules.Count) {
        throw [Security.SecurityException]::new('MHX ASR baseline restore verification failed.')
    }
    foreach ($key in $expectedRules.Keys) {
        if (-not $actualRules.ContainsKey($key) -or $actualRules[$key] -ne $expectedRules[$key]) {
            throw [Security.SecurityException]::new('MHX ASR baseline restore verification failed.')
        }
    }
}

try {
    Assert-Administrator
    $defender = Get-MpComputerStatus
    if (-not $defender.AntivirusEnabled -or -not $defender.RealTimeProtectionEnabled) {
        throw [Security.SecurityException]::new('Defender realtime protection is required for MHX enforcement.')
    }
    Save-Baseline
    Enable-ProcessTelemetry
    Enable-NetworkBlockTelemetry
    Set-MpPreference -PUAProtection Enabled -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -EnableNetworkProtection Enabled
    if ($Mode -eq 'Restore') {
        Restore-NetworkBaseline
        Restore-AsrBaseline
    } elseif ($Mode -eq 'Monitor') {
        Restore-NetworkBaseline
        Set-AsrRule -Id '5beb7efe-fd9a-4556-801d-275e5ffc04cc' -Action 2
    } elseif ($Mode -eq 'Guarded') {
        Restore-NetworkBaseline
        Set-AsrRule -Id '5beb7efe-fd9a-4556-801d-275e5ffc04cc' -Action 1
    } else {
        Add-SovereignAllowRules
        Set-AsrRule -Id '5beb7efe-fd9a-4556-801d-275e5ffc04cc' -Action 1
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    }
    $result = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        Mode = $Mode.ToLowerInvariant()
        DefenderRealtime = [bool](Get-MpComputerStatus).RealTimeProtectionEnabled
        NetworkDefaultDeny = [bool]($Mode -eq 'Sovereign')
        ScriptObfuscationBlock = [bool]($Mode -notin @('Monitor','Restore'))
        ProcessTelemetry = $true
        WfpBlockTelemetry = $true
    }
    $json = $result | ConvertTo-Json -Depth 4
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"
        Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    Write-Error 'MHX protection transaction was rejected.'
    exit 10
} catch {
    Write-Error 'MHX protection transaction failed.'
    exit 20
}

