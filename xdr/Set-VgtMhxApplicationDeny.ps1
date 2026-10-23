# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Add','Remove','List','Verify')][string]$Action,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$ApplicationPath,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense\mhx'
$denyFile = Join-Path $dataRoot 'application-denies.json'
$ruleGroup = 'VGT GeDefense Sovereign Denies'
$maximumEntries = 64

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative application network-deny transaction required.')
    }
}

function Read-Entries {
    if (-not (Test-Path -LiteralPath $denyFile -PathType Leaf)) { return @() }
    $item = Get-Item -LiteralPath $denyFile -Force
    if ($item.Length -le 0 -or $item.Length -gt 1MB -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw [Security.SecurityException]::new('Application-deny database boundary validation failed.')
    }
    $parsed = Get-Content -LiteralPath $denyFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $entries = @($parsed.entries)
    if ($entries.Count -gt $maximumEntries) {
        throw [Security.SecurityException]::new('Application-deny database exceeds the bounded entry count.')
    }
    return $entries
}

function Write-Entries([array]$Entries) {
    if ($Entries.Count -gt $maximumEntries) {
        throw [Security.SecurityException]::new('Application-deny entry count exceeded.')
    }
    [IO.Directory]::CreateDirectory($dataRoot) | Out-Null
    $temporary = "$denyFile.$PID.tmp"
    [ordered]@{ version=1; updatedUtc=[DateTime]::UtcNow.ToString('o'); entries=@($Entries) } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $denyFile -Force
}

function Resolve-Application {
    if ([string]::IsNullOrWhiteSpace($ApplicationPath)) {
        throw [Security.SecurityException]::new('Application path is required.')
    }
    $resolved = (Resolve-Path -LiteralPath $ApplicationPath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -and $item.Extension -eq '.exe' -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        return $resolved
    }
    throw [Security.SecurityException]::new('Application file validation failed.')
}

function New-DenyEntry([string]$Path) {
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{
        path=$Path
        sha256=$hash
        addedUtc=[DateTime]::UtcNow.ToString('o')
        rule="VGT Deny $($hash.Substring(0,16))"
    }
}

function Sync-Rules([array]$Entries) {
    Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    $verified = @()
    foreach ($entry in $Entries) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $entry.path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
        $hash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne [string]$entry.sha256) { continue }
        New-NetFirewallRule -DisplayName ([string]$entry.rule) -Group $ruleGroup -Direction Outbound -Action Block -Program ([string]$entry.path) -Protocol Any | Out-Null
        New-NetFirewallRule -DisplayName ("{0} Inbound" -f [string]$entry.rule) -Group $ruleGroup -Direction Inbound -Action Block -Program ([string]$entry.path) -Protocol Any | Out-Null
        $verified += $entry
    }
    return @($verified)
}

try {
    Assert-Administrator
    $entries = @(Read-Entries)
    if ($Action -eq 'Add') {
        $resolved = Resolve-Application
        $entry = New-DenyEntry -Path $resolved
        $entries = @($entries | Where-Object { -not ([string]$_.path).Equals($resolved,[StringComparison]::OrdinalIgnoreCase) }) + @($entry)
        if ($entries.Count -gt $maximumEntries) {
            throw [Security.SecurityException]::new('Application-deny entry limit reached.')
        }
    } elseif ($Action -eq 'Remove') {
        $resolvedCandidate = [IO.Path]::GetFullPath($ApplicationPath)
        $entries = @($entries | Where-Object { -not ([string]$_.path).Equals($resolvedCandidate,[StringComparison]::OrdinalIgnoreCase) })
    }
    if ($Action -in @('Add','Remove','Verify')) {
        $entries = @(Sync-Rules -Entries $entries)
        Write-Entries -Entries $entries
    }
    $result = [ordered]@{
        TimestampUtc=[DateTime]::UtcNow.ToString('o')
        Entries=@($entries)
        Count=$entries.Count
        RuleGroup=$ruleGroup
        Enforced=$true
    }
    $json = $result | ConvertTo-Json -Depth 5
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.')
        }
        $temporary = "$OutputPath.$PID.tmp"
        Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else {
        $json
    }
    exit 0
} catch [Security.SecurityException] {
    Write-Error 'Application network-deny transaction was rejected.'
    exit 10
} catch {
    Write-Error 'Application network-deny transaction failed.'
    exit 20
}

