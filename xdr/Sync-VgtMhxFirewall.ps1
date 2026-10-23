# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$IndicatorPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedGeneration,
    [Parameter(Mandatory)][ValidateRange(1,250000)][int]$ExpectedIndicators,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$groupPrefix = 'VGT GeDefense Threat Intelligence'
$keywordPrefix = 'VGT_GEDEFENSE_TI_'
$maximumSnapshotBytes = 16MB
$maximumIndicators = 250000
# The immutable catalog currently defines nine feeds. Operator overrides may
# promote or demote any of them, so the blocking cardinality is dynamic rather
# than the old fixed 3..4 baseline.
$maximumBlockingFeeds = 9
$maximumStaticIndicators = 25000
$dynamicShardIndicators = 512
$dynamicShardCharacters = 24000
$staticShardIndicators = 200

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative firewall transaction required.')
    }
}

function Resolve-IndicatorFile {
    $jail = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VGT\GeDefense\mhx\intelligence')).TrimEnd('\') + '\'
    $resolved = (Resolve-Path -LiteralPath $IndicatorPath -ErrorAction Stop).Path
    if (-not $resolved.StartsWith($jail,[StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new('Indicator path escaped jail.')
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt $maximumSnapshotBytes -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw [Security.SecurityException]::new('Indicator file boundary validation failed.')
    }
    return $resolved
}

function Test-Cidr {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Length -lt 3 -or $Value.Length -gt 49 -or $Value -notmatch '^[0-9a-fA-F\.:/]+$') { return $false }
    $parts = $Value.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0],[ref]$address)) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1],[ref]$prefix)) { return $false }
    $maximum = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
    return $prefix -ge 1 -and $prefix -le $maximum
}

function Get-BlockGenerationHash {
    param([Parameter(Mandatory)][string[]]$Indicators)
    $canonical = "VGT-GEDEFENSE-TI-BLOCK-V2`n" + [string]::Join("`n",$Indicators)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Test-FixedTimeString {
    param([Parameter(Mandatory)][string]$Left,[Parameter(Mandatory)][string]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $diff = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $diff = $diff -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    return $diff -eq 0
}

function Read-EnforcementSnapshot {
    param([Parameter(Mandatory)][string]$Path)
    $snapshot = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$snapshot.schemaVersion -ne 2) { throw [Security.SecurityException]::new('Threat intelligence schema validation failed.') }
    $generation = [string]$snapshot.generationSha256
    if ($generation -notmatch '^[a-f0-9]{64}$') { throw [Security.SecurityException]::new('Threat intelligence generation validation failed.') }
    $protectionGeneration = [string]$snapshot.protectionGenerationSha256
    $protectedPrefixCount = [int]$snapshot.protectedPrefixCount
    if ($protectionGeneration -notmatch '^[a-f0-9]{64}$' -or $protectedPrefixCount -lt 0 -or $protectedPrefixCount -gt 256) {
        throw [Security.SecurityException]::new('Protected network policy metadata validation failed.')
    }
    $indicators = @($snapshot.blockIndicators)
    if ($indicators.Count -lt 1 -or $indicators.Count -gt $maximumIndicators -or $indicators.Count -ne $ExpectedIndicators) { throw [Security.SecurityException]::new('Indicator count boundary validation failed.') }
    if ([int]$snapshot.blockingFeedCount -lt 1 -or [int]$snapshot.blockingFeedCount -gt $maximumBlockingFeeds) { throw [Security.SecurityException]::new('Blocking feed cardinality validation failed.') }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $previous = ''
    foreach ($indicatorValue in $indicators) {
        $indicator = [string]$indicatorValue
        if (-not (Test-Cidr -Value $indicator) -or -not $seen.Add($indicator)) {
            throw [Security.SecurityException]::new('Indicator CIDR validation failed.')
        }
        if ($previous -ne '' -and [string]::CompareOrdinal($previous,$indicator) -ge 0) {
            throw [Security.SecurityException]::new('Indicator canonical ordering validation failed.')
        }
        $previous = $indicator
    }
    $computedGeneration = Get-BlockGenerationHash -Indicators ([string[]]$indicators)
    if (-not (Test-FixedTimeString -Left $generation -Right $computedGeneration) -or -not (Test-FixedTimeString -Left $generation -Right $ExpectedGeneration)) {
        throw [Security.SecurityException]::new('Threat intelligence generation integrity validation failed.')
    }
    return [pscustomobject]@{ Generation=$generation; ProtectionGeneration=$protectionGeneration; ProtectedPrefixCount=$protectedPrefixCount; Indicators=@($indicators) }
}

function Test-DynamicKeywordSupport {
    $required = @(
        'New-NetFirewallDynamicKeywordAddress',
        'Get-NetFirewallDynamicKeywordAddress',
        'Remove-NetFirewallDynamicKeywordAddress'
    )
    foreach ($command in $required) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { return $false }
    }
    $ruleCommand = Get-Command 'New-NetFirewallRule' -ErrorAction Stop
    return $ruleCommand.Parameters.ContainsKey('RemoteDynamicKeywordAddresses')
}

function Remove-StagingRules {
    param([Parameter(Mandatory)][string]$Group)
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Remove-DynamicObjects {
    param([Parameter(Mandatory)][Collections.Generic.List[string]]$Ids)
    foreach ($id in $Ids) {
        Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction SilentlyContinue
    }
}

function Remove-OldRuleGenerations {
    param([Parameter(Mandatory)][string]$KeepGroup)
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Group -like "$groupPrefix *" -and $_.Group -ne $KeepGroup } |
        Remove-NetFirewallRule -ErrorAction Stop
}

function Remove-UnreferencedVgtDynamicObjects {
    param([Parameter(Mandatory)][Collections.Generic.List[string]]$KeepIds)
    $keep = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $KeepIds) { [void]$keep.Add($id) }
    foreach ($item in @(Get-NetFirewallDynamicKeywordAddress -All -ErrorAction SilentlyContinue)) {
        if ([string]$item.Keyword -like "$keywordPrefix*" -and -not $keep.Contains([string]$item.Id)) {
            Remove-NetFirewallDynamicKeywordAddress -Id ([string]$item.Id) -ErrorAction Stop
        }
    }
}


function Add-DynamicShard {
    param(
        [Parameter(Mandatory)][string[]]$Indicators,
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Generation,
        [Parameter(Mandatory)][string]$Transaction,
        [Parameter(Mandatory)][int]$ShardIndex
    )
    $id = '{' + [Guid]::NewGuid().ToString() + '}'
    try {
        $keyword = "$keywordPrefix$Transaction-$ShardIndex"
        $addresses = [string]::Join(',',@($Indicators))
        New-NetFirewallDynamicKeywordAddress -Id $id -Keyword $keyword -Addresses $addresses -AutoResolve $false -ErrorAction Stop | Out-Null
        $ruleBase = "VGT-GeDefense-TI-$Transaction-$ShardIndex"
        New-NetFirewallRule -Name "$ruleBase-OUT" -DisplayName "VGT TI OUT $($Generation.Substring(0,12))/$ShardIndex" -Group $Group -Direction Outbound -Action Block -RemoteDynamicKeywordAddresses $id -Protocol Any -ErrorAction Stop | Out-Null
        New-NetFirewallRule -Name "$ruleBase-IN" -DisplayName "VGT TI IN $($Generation.Substring(0,12))/$ShardIndex" -Group $Group -Direction Inbound -Action Block -RemoteDynamicKeywordAddresses $id -Protocol Any -ErrorAction Stop | Out-Null
        return $id
    } catch {
        Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction SilentlyContinue
        throw
    }
}

function Commit-DynamicKeywordGeneration {
    param(
        [Parameter(Mandatory)][string[]]$Indicators,
        [Parameter(Mandatory)][string]$Generation
    )
    $transaction = [Guid]::NewGuid().ToString('N')
    $group = "$groupPrefix $($Generation.Substring(0,16)) $transaction"
    $ids = [Collections.Generic.List[string]]::new()
    $shard = [Collections.Generic.List[string]]::new()
    $characters = 0
    $shardIndex = 0
    $committed = $false
    $cleanupPending = $false

    try {
        foreach ($indicator in $Indicators) {
            $additional = $indicator.Length + $(if ($shard.Count -gt 0) { 1 } else { 0 })
            if ($shard.Count -ge $dynamicShardIndicators -or ($characters + $additional) -gt $dynamicShardCharacters) {
                $id = Add-DynamicShard -Indicators $shard.ToArray() -Group $group -Generation $Generation -Transaction $transaction -ShardIndex $shardIndex
                [void]$ids.Add($id)
                $shardIndex++
                $shard.Clear()
                $characters = 0
            }
            [void]$shard.Add($indicator)
            $characters += $additional
        }
        if ($shard.Count -gt 0) {
            $id = Add-DynamicShard -Indicators $shard.ToArray() -Group $group -Generation $Generation -Transaction $transaction -ShardIndex $shardIndex
            [void]$ids.Add($id)
            $shardIndex++
        }
        if ($ids.Count -lt 1) { throw [InvalidOperationException]::new('Dynamic keyword staging produced no shards.') }
        $rules = @(Get-NetFirewallRule -Group $group -ErrorAction Stop)
        if ($rules.Count -ne ($ids.Count * 2) -or @($rules | Where-Object Enabled -ne 'True').Count -ne 0) {
            throw [InvalidOperationException]::new('Dynamic keyword firewall verification failed.')
        }
        foreach ($id in $ids) {
            if (-not (Get-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop)) {
                throw [InvalidOperationException]::new('Dynamic keyword address verification failed.')
            }
        }
        $committed = $true
        $rulesCleaned = $true
        try { Remove-OldRuleGenerations -KeepGroup $group } catch { $cleanupPending = $true; $rulesCleaned = $false }
        if ($rulesCleaned) {
            try { Remove-UnreferencedVgtDynamicObjects -KeepIds $ids } catch { $cleanupPending = $true }
        }
        return [pscustomobject]@{ Rules=$rules.Count; Shards=$ids.Count; Mode='DYNAMIC_KEYWORD'; CleanupPending=$cleanupPending; Group=$group }
    } catch {
        if (-not $committed) {
            Remove-StagingRules -Group $group
            Remove-DynamicObjects -Ids $ids
        }
        throw
    }
}

function Commit-StaticGeneration {
    param(
        [Parameter(Mandatory)][string[]]$Indicators,
        [Parameter(Mandatory)][string]$Generation
    )
    if ($Indicators.Count -lt 1 -or $Indicators.Count -gt $maximumStaticIndicators) {
        throw [Security.SecurityException]::new('Static firewall fallback indicator boundary rejected.')
    }
    $transaction = [Guid]::NewGuid().ToString('N')
    $group = "$groupPrefix $($Generation.Substring(0,16)) STATIC $transaction"
    $cleanupPending = $false
    try {
        for ($offset = 0; $offset -lt $Indicators.Count; $offset += $staticShardIndicators) {
            $last = [Math]::Min($offset + $staticShardIndicators - 1,$Indicators.Count - 1)
            $chunk = @($Indicators[$offset..$last])
            $ruleBase = "VGT-GeDefense-TI-$transaction-$offset"
            New-NetFirewallRule -Name "$ruleBase-OUT" -DisplayName "VGT TI OUT $($Generation.Substring(0,12))/$offset" -Group $group -Direction Outbound -Action Block -RemoteAddress $chunk -Protocol Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -Name "$ruleBase-IN" -DisplayName "VGT TI IN $($Generation.Substring(0,12))/$offset" -Group $group -Direction Inbound -Action Block -RemoteAddress $chunk -Protocol Any -ErrorAction Stop | Out-Null
        }
        $rules = @(Get-NetFirewallRule -Group $group -ErrorAction Stop)
        $expectedShards = [Math]::Ceiling($Indicators.Count / [double]$staticShardIndicators)
        if ($rules.Count -ne ($expectedShards * 2) -or @($rules | Where-Object Enabled -ne 'True').Count -ne 0) {
            throw [InvalidOperationException]::new('Static firewall generation verification failed.')
        }
        $rulesCleaned = $true
        try { Remove-OldRuleGenerations -KeepGroup $group } catch { $cleanupPending = $true; $rulesCleaned = $false }
        if ($rulesCleaned -and (Get-Command 'Get-NetFirewallDynamicKeywordAddress' -ErrorAction SilentlyContinue)) {
            $empty = [Collections.Generic.List[string]]::new()
            try { Remove-UnreferencedVgtDynamicObjects -KeepIds $empty } catch { $cleanupPending = $true }
        }
        return [pscustomobject]@{ Rules=$rules.Count; Shards=[int]$expectedShards; Mode='STATIC_RULE_FALLBACK'; CleanupPending=$cleanupPending; Group=$group }
    } catch {
        Remove-StagingRules -Group $group
        throw
    }
}

function Write-Result {
    param([Parameter(Mandatory)][object]$Value)
    $json = $Value | ConvertTo-Json -Depth 4
    if (-not $OutputPath) { $json; return }
    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
    $temporary = "$OutputPath.$PID.tmp"
    Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
}

try {
    Assert-Administrator
    $resolved = Resolve-IndicatorFile
    $snapshot = Read-EnforcementSnapshot -Path $resolved
    $transaction = $null
    if (Test-DynamicKeywordSupport) {
        try {
            $transaction = Commit-DynamicKeywordGeneration -Indicators $snapshot.Indicators -Generation $snapshot.Generation
        } catch {
            $transaction = Commit-StaticGeneration -Indicators $snapshot.Indicators -Generation $snapshot.Generation
        }
    } else {
        $transaction = Commit-StaticGeneration -Indicators $snapshot.Indicators -Generation $snapshot.Generation
    }
    Write-Result ([ordered]@{
        TimestampUtc=[DateTime]::UtcNow.ToString('o')
        Indicators=$snapshot.Indicators.Count
        Rules=[int]$transaction.Rules
        Shards=[int]$transaction.Shards
        Generation=$snapshot.Generation
        Mode=[string]$transaction.Mode
        CleanupPending=[bool]$transaction.CleanupPending
        ProtectionGeneration=[string]$snapshot.ProtectionGeneration
        ProtectedPrefixCount=[int]$snapshot.ProtectedPrefixCount
    })
    exit 0
} catch [Security.SecurityException] {
    Write-Error "Threat intelligence firewall transaction was rejected: $($_.Exception.Message)"
    exit 10
} catch {
    Write-Error "Threat intelligence firewall transaction failed: $($_.Exception.Message)"
    exit 20
}
