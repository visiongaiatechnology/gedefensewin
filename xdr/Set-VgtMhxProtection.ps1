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

function Save-Baseline {
    $path = Get-StatePath
    if (Test-Path -LiteralPath $path -PathType Leaf) { return }
    $preference = Get-MpPreference
    $state = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        FirewallProfiles = @(Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction)
        AsrIds = @($preference.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ })
        AsrActions = @($preference.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
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
    Remove-VgtFirewallRules
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
        return
    }
    $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($profile in @($state.FirewallProfiles)) {
        Set-NetFirewallProfile -Name ([string]$profile.Name) -DefaultOutboundAction ([string]$profile.DefaultOutboundAction)
    }
}

function Restore-AsrBaseline {
    $path = Get-StatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $state = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $ids = @($state.AsrIds)
    $actions = @($state.AsrActions)
    if ($ids.Count -gt 0 -and $ids.Count -eq $actions.Count) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions
    } else {
        $currentIds = @((Get-MpPreference).AttackSurfaceReductionRules_Ids)
        if ($currentIds.Count -gt 0) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $currentIds }
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
