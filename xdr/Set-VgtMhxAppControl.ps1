# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce','Remove','Status')][string]$Action,
    [ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$stateRoot = Join-Path $env:ProgramData 'VGT\GeDefense\mhx\appcontrol'
$statePath = Join-Path $stateRoot 'active-policy.json'
$allowPath = Join-Path $env:ProgramData 'VGT\GeDefense\mhx\application-allows.json'
$ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
$example = Join-Path $env:SystemRoot 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml'
$diagnosticPath = Join-Path $stateRoot 'diagnostics.jsonl'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative App Control transaction required.') }
}

function Backup-CorruptJsonFile([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = "{0}.corrupt-{1}-{2}" -f $Path, [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'), $PID
            Move-Item -LiteralPath $Path -Destination $backup -Force -ErrorAction Stop
        }
    } catch {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Read-SafeJson([string]$Path, [int]$MaximumBytes = 1MB) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw [Security.SecurityException]::new("App Control database boundary validation failed for $Path.")
    }
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        Backup-CorruptJsonFile -Path $Path
        return $null
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.IndexOf([char]0) -ge 0) {
        Backup-CorruptJsonFile -Path $Path
        return $null
    }
    try {
        return ($raw | ConvertFrom-Json)
    } catch {
        Backup-CorruptJsonFile -Path $Path
        return $null
    }
}

function Read-State {
    $parsed = Read-SafeJson -Path $statePath
    if ($null -eq $parsed -or $null -eq $parsed.PSObject.Properties['policyId'] -or $null -eq $parsed.PSObject.Properties['enforced'] -or $null -eq $parsed.PSObject.Properties['allowedApplications']) {
        if (Test-Path -LiteralPath $statePath -PathType Leaf) { Backup-CorruptJsonFile -Path $statePath }
        return $null
    }
    return $parsed
}

function Invoke-CiTool([string[]]$Arguments) {
    $raw = & $ciTool @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $detail = (($raw | ForEach-Object { [string]$_ }) -join ' ').Trim()
        throw [InvalidOperationException]::new("CiTool transaction failed with exit code $LASTEXITCODE. $detail")
    }
    return ($raw -join "`n")
}

function Write-ProtectedDiagnostic([string]$DiagnosticId, [System.Management.Automation.ErrorRecord]$Record) {
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    $commandName = ''
    $scriptLine = 0
    if ($null -ne $Record.InvocationInfo) {
        if ($null -ne $Record.InvocationInfo.MyCommand) { $commandName = [string]$Record.InvocationInfo.MyCommand }
        $scriptLine = [int]$Record.InvocationInfo.ScriptLineNumber
    }
    $entry = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        diagnosticId = $DiagnosticId
        action = $Action
        exceptionType = $Record.Exception.GetType().FullName
        message = $Record.Exception.Message
        command = $commandName
        scriptLine = $scriptLine
        category = [string]$Record.CategoryInfo.Category
    } | ConvertTo-Json -Compress
    Add-Content -LiteralPath $diagnosticPath -Value $entry -Encoding UTF8
}

function Get-AllowedPaths {
    $database = Read-SafeJson -Path $allowPath
    if ($null -eq $database -or $null -eq $database.PSObject.Properties['entries'] -or $null -eq $database.entries) {
        if (Test-Path -LiteralPath $allowPath -PathType Leaf) { Backup-CorruptJsonFile -Path $allowPath }
        return @()
    }
    $result = @()
    foreach ($entry in @($database.entries)) {
        if ($null -eq $entry -or $null -eq $entry.PSObject.Properties['path'] -or $null -eq $entry.PSObject.Properties['sha256'] -or $null -eq $entry.PSObject.Properties['signer']) { continue }
        $entryPath = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($entryPath) -or -not (Test-Path -LiteralPath $entryPath -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $entryPath -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
        $hash = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = Get-AuthenticodeSignature -LiteralPath $entryPath
        if ($hash -eq [string]$entry.sha256 -and $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and [string]$signature.SignerCertificate.Subject -eq [string]$entry.signer) { $result += $entryPath }
    }
    return @($result)
}

function Deploy-Policy([bool]$Enforced) {
    if (-not (Test-Path -LiteralPath $installRoot -PathType Container) -or -not (Test-Path -LiteralPath $example -PathType Leaf) -or -not (Test-Path -LiteralPath $ciTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('App Control prerequisites are unavailable.') }
    $previous = Read-State
    $allowed = @(Get-AllowedPaths)
    if ($previous -and [bool]$previous.enforced -eq $Enforced -and [int]$previous.allowedApplications -eq $allowed.Count) {
        $existingCip = Join-Path $env:SystemRoot ("System32\CodeIntegrity\CiPolicies\Active\{0}.cip" -f [string]$previous.policyId)
        if (Test-Path -LiteralPath $existingCip -PathType Leaf) {
            return $previous
        }
    }
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    $transaction = Join-Path $stateRoot ([Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($transaction) | Out-Null
    try {
        $base = Join-Path $transaction 'base.xml'; Copy-Item -LiteralPath $example -Destination $base -Force
        $vgtRules = Join-Path $transaction 'vgt-rules.xml'
        New-CIPolicy -ScanPath $installRoot -FilePath $vgtRules -Level Publisher -Fallback Hash -UserPEs -MultiplePolicyFormat -NoScript -NoShadowCopy | Out-Null
        $policies = @($base,$vgtRules)
        if ($allowed.Count -gt 0) {
            $rules = @($allowed | ForEach-Object { New-CIPolicyRule -DriverFilePath $_ -Level Hash })
            $operatorRules = Join-Path $transaction 'operator-rules.xml'
            New-CIPolicy -FilePath $operatorRules -Rules $rules -UserPEs -MultiplePolicyFormat | Out-Null
            $policies += $operatorRules
        }
        $merged = Join-Path $transaction 'VGT-GeDefense-Sovereign.xml'
        Merge-CIPolicy -PolicyPaths $policies -OutputFilePath $merged | Out-Null
        [string]$policyName = if ($Enforced) { 'VGT GeDefense Sovereign Enforced' } else { 'VGT GeDefense Sovereign Audit' }
        Set-CIPolicyIdInfo -FilePath $merged -PolicyName $policyName -ResetPolicyID | Out-Null
        Set-RuleOption -FilePath $merged -Option 10 | Out-Null
        if ($Enforced) { Set-RuleOption -FilePath $merged -Option 3 -Delete | Out-Null } else { Set-RuleOption -FilePath $merged -Option 3 | Out-Null }
        $policyId = (Select-Xml -Path $merged -XPath "//*[local-name()='PolicyID']").Node.InnerText
        if ($policyId -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { throw [Security.SecurityException]::new('Generated App Control policy ID validation failed.') }
        $binary = Join-Path $transaction ("{0}.cip" -f $policyId)
        ConvertFrom-CIPolicy -XmlFilePath $merged -BinaryFilePath $binary | Out-Null
        Invoke-CiTool @('--update-policy',$binary,'-json') | Out-Null
        if ($previous -and [string]$previous.policyId -and [string]$previous.policyId -ne $policyId) {
            $prevId = [string]$previous.policyId
            $rawGuid = $prevId.Trim('{','}')
            try {
                Invoke-CiTool @('--remove-policy',$prevId,'-json') | Out-Null
            } catch {
                try {
                    Invoke-CiTool @('--remove-policy',$rawGuid,'-json') | Out-Null
                } catch {
                    # Ignored: previous policy already removed or not present (0x80070002)
                }
            }
        }
        $state = [ordered]@{ policyId=$policyId; enforced=$Enforced; deployedUtc=[DateTime]::UtcNow.ToString('o'); allowedApplications=$allowed.Count; recoveryOptions=@(9,10) }
        $temporary = "$statePath.$PID.tmp"; $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporary -Encoding UTF8; Move-Item -LiteralPath $temporary -Destination $statePath -Force
        return $state
    } finally {
        Remove-Item -LiteralPath $transaction -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    Assert-Administrator
    if ($Action -eq 'Remove') {
        $state = Read-State
        if ($state) {
            $prevId = [string]$state.policyId
            $rawGuid = $prevId.Trim('{','}')
            try {
                Invoke-CiTool @('--remove-policy',$prevId,'-json') | Out-Null
            } catch {
                try {
                    Invoke-CiTool @('--remove-policy',$rawGuid,'-json') | Out-Null
                } catch {
                    # Ignored: already removed or not present
                }
            }
            Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        }
        $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); State='REMOVED'; PolicyId=''; Enforced=$false; KernelEnforcement=$false }
    } elseif ($Action -eq 'Status') {
        $state = Read-State
        $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); State=if($state){'DEPLOYED'}else{'ABSENT'}; PolicyId=if($state){[string]$state.policyId}else{''}; Enforced=[bool]($state -and $state.enforced); KernelEnforcement=[bool]($state -and $state.enforced) }
    } else {
        $state = Deploy-Policy -Enforced ($Action -eq 'Enforce')
        $result = [ordered]@{ TimestampUtc=[DateTime]::UtcNow.ToString('o'); State='DEPLOYED'; PolicyId=[string]$state.policyId; Enforced=[bool]$state.enforced; KernelEnforcement=[bool]$state.enforced }
    }
    $json = $result | ConvertTo-Json -Depth 4
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw [IO.DirectoryNotFoundException]::new('Output directory unavailable.') }
        $temporary = "$OutputPath.$PID.tmp"; Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8; Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    } else { $json }
    exit 0
} catch [Security.SecurityException] {
    $diagnosticId = [Guid]::NewGuid().ToString('N')
    Write-ProtectedDiagnostic -DiagnosticId $diagnosticId -Record $_
    Write-Error "App Control transaction was rejected. Diagnostic ID: $diagnosticId" -ErrorAction Continue
    exit 10
} catch {
    $diagnosticId = [Guid]::NewGuid().ToString('N')
    Write-ProtectedDiagnostic -DiagnosticId $diagnosticId -Record $_
    Write-Error "App Control transaction failed. Diagnostic ID: $diagnosticId" -ErrorAction Continue
    exit 20
}

