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
$allowFile = Join-Path $dataRoot 'application-allows.json'
$ruleGroup = 'VGT GeDefense Sovereign Allows'
$script:databaseNeedsRepair = $false

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative allow transaction required.') }
}

function Backup-CorruptDatabase([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = "{0}.corrupt-{1}-{2}" -f $Path, [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'), $PID
            Move-Item -LiteralPath $Path -Destination $backup -Force -ErrorAction Stop
        }
    } catch {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Read-Entries {
    if (-not (Test-Path -LiteralPath $allowFile -PathType Leaf)) { return @() }
    $item = Get-Item -LiteralPath $allowFile -Force
    if ($item.Length -gt 1MB -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw [Security.SecurityException]::new('Allow database boundary validation failed.') }
    if ($item.Length -le 0) {
        Backup-CorruptDatabase -Path $allowFile
        $script:databaseNeedsRepair = $true
        return @()
    }
    $raw = Get-Content -LiteralPath $allowFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.IndexOf([char]0) -ge 0) {
        Backup-CorruptDatabase -Path $allowFile
        $script:databaseNeedsRepair = $true
        return @()
    }
    try {
        $parsed = $raw | ConvertFrom-Json
    } catch {
        Backup-CorruptDatabase -Path $allowFile
        $script:databaseNeedsRepair = $true
        return @()
    }
    if ($null -eq $parsed -or $null -eq $parsed.PSObject.Properties['entries'] -or $null -eq $parsed.entries) {
        Backup-CorruptDatabase -Path $allowFile
        $script:databaseNeedsRepair = $true
        return @()
    }
    return @($parsed.entries)
}

function Write-Entries([array]$Entries) {
    [IO.Directory]::CreateDirectory($dataRoot) | Out-Null
    $temporary = "$allowFile.$PID.tmp"
    [ordered]@{ version=1; updatedUtc=[DateTime]::UtcNow.ToString('o'); entries=@($Entries) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $allowFile -Force
}

function Resolve-Application {
    if ([string]::IsNullOrWhiteSpace($ApplicationPath)) { throw [Security.SecurityException]::new('Application path is required.') }
    $resolved = (Resolve-Path -LiteralPath $ApplicationPath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -and $item.Extension -eq '.exe' -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $resolved }
    throw [Security.SecurityException]::new('Application file validation failed.')
}

function New-VerifiedEntry([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw [Security.SecurityException]::new('Only valid Authenticode applications can receive sovereign network access.') }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{ path=$Path; sha256=$hash; signer=[string]$signature.SignerCertificate.Subject; addedUtc=[DateTime]::UtcNow.ToString('o'); rule="VGT Sovereign Allow $($hash.Substring(0,16))" }
}

function Sync-Rules([array]$Entries) {
    $existingRules = @(Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue)
    if ($Entries.Count -eq 0 -and $existingRules.Count -eq 0) {
        return @()
    }
    if ($existingRules.Count -gt 0) {
        $existingRules | Remove-NetFirewallRule
    }
    $verified = @()
    foreach ($entry in $Entries) {
        if ($null -eq $entry -or $null -eq $entry.PSObject.Properties['path'] -or $null -eq $entry.PSObject.Properties['sha256'] -or $null -eq $entry.PSObject.Properties['signer'] -or $null -eq $entry.PSObject.Properties['rule']) { continue }
        $entryPath = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($entryPath) -or -not (Test-Path -LiteralPath $entryPath -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $entryPath -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
        $hash = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = Get-AuthenticodeSignature -LiteralPath $entryPath
        if ($hash -ne [string]$entry.sha256 -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or [string]$signature.SignerCertificate.Subject -ne [string]$entry.signer) { continue }
        New-NetFirewallRule -DisplayName ([string]$entry.rule) -Group $ruleGroup -Direction Outbound -Action Allow -Program $entryPath -Protocol Any | Out-Null
        $verified += $entry
    }
    return @($verified)
}

try {
    Assert-Administrator
    $entries = @(Read-Entries)
    $initialCount = $entries.Count
    if ($Action -eq 'Add') {
        $resolved = Resolve-Application
        $entry = New-VerifiedEntry -Path $resolved
        $entries = @($entries | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['path'] -and -not ([string]$_.path).Equals($resolved,[StringComparison]::OrdinalIgnoreCase) }) + @($entry)
    } elseif ($Action -eq 'Remove') {
        $resolvedCandidate = [IO.Path]::GetFullPath($ApplicationPath)
        $entries = @($entries | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['path'] -and -not ([string]$_.path).Equals($resolvedCandidate,[StringComparison]::OrdinalIgnoreCase) })
    }
    if ($Action -ne 'List') {
        $verifiedEntries = @(Sync-Rules -Entries $entries)
        if ($Action -in @('Add','Remove') -or $script:databaseNeedsRepair -or $verifiedEntries.Count -ne $initialCount -or -not (Test-Path -LiteralPath $allowFile -PathType Leaf)) {
            Write-Entries -Entries $verifiedEntries
        }
        $entries = $verifiedEntries
    }
    $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); Entries=@($entries); Count=$entries.Count }
    $json = $result | ConvertTo-Json -Depth 5
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"; Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8; Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    Write-Error 'Sovereign application allow transaction was rejected.'
    exit 10
} catch {
    Write-Error 'Sovereign application allow transaction failed.'
    exit 20
}

