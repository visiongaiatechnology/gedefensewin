# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$IndicatorPath,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$groupPrefix = 'VGT GeDefense Threat Intelligence'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative firewall transaction required.') }
}

function Resolve-IndicatorFile {
    $jail = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VGT\GeDefense\mhx\intelligence')).TrimEnd('\') + '\'
    $resolved = (Resolve-Path -LiteralPath $IndicatorPath -ErrorAction Stop).Path
    if (-not $resolved.StartsWith($jail,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Indicator path escaped jail.') }
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le 4MB -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $resolved }
    throw [Security.SecurityException]::new('Indicator file boundary validation failed.')
}

function Test-Cidr {
    param([Parameter(Mandatory)][string]$Value)
    $parts = $Value.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0],[ref]$address)) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1],[ref]$prefix)) { return $false }
    $maximum = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
    return $prefix -ge 0 -and $prefix -le $maximum
}

try {
    Assert-Administrator
    $resolved = Resolve-IndicatorFile
    $snapshot = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json
    $indicators = @($snapshot.indicators)
    if ($indicators.Count -lt 1 -or $indicators.Count -gt 25000) { throw [Security.SecurityException]::new('Indicator count boundary validation failed.') }
    foreach ($indicator in $indicators) { if (-not (Test-Cidr -Value ([string]$indicator))) { throw [Security.SecurityException]::new('Indicator CIDR validation failed.') } }
    $generation = [Guid]::NewGuid().ToString('N')
    $stagingGroup = "$groupPrefix $generation"
    for ($offset = 0; $offset -lt $indicators.Count; $offset += 200) {
        $last = [Math]::Min($offset + 199,$indicators.Count - 1)
        $chunk = @($indicators[$offset..$last])
        New-NetFirewallRule -DisplayName "VGT MHX TI OUT $offset" -Group $stagingGroup -Direction Outbound -Action Block -RemoteAddress $chunk -Protocol Any | Out-Null
        New-NetFirewallRule -DisplayName "VGT MHX TI IN $offset" -Group $stagingGroup -Direction Inbound -Action Block -RemoteAddress $chunk -Protocol Any | Out-Null
    }
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like "$groupPrefix *" -and $_.Group -ne $stagingGroup } | Remove-NetFirewallRule
    $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); Indicators=$indicators.Count; Rules=@(Get-NetFirewallRule -Group $stagingGroup).Count; Generation=$generation }
    $json = $result | ConvertTo-Json -Depth 3
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"
        Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    Write-Error 'Threat intelligence firewall transaction was rejected.'
    exit 10
} catch {
    Write-Error 'Threat intelligence firewall transaction failed.'
    exit 20
}
