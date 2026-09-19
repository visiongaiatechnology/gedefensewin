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

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
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
    if (-not (Test-Path -LiteralPath $allowPath -PathType Leaf)) { return @() }
    $database = Get-Content -LiteralPath $allowPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $result = @()
    foreach ($entry in @($database.entries)) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { continue }
        $hash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = Get-AuthenticodeSignature -LiteralPath $entry.path
        if ($hash -eq [string]$entry.sha256 -and $signature.Status -eq 'Valid' -and [string]$signature.SignerCertificate.Subject -eq [string]$entry.signer) { $result += [string]$entry.path }
    }
    return @($result)
}

function Deploy-Policy([bool]$Enforced) {
    if (-not (Test-Path -LiteralPath $installRoot -PathType Container) -or -not (Test-Path -LiteralPath $example -PathType Leaf) -or -not (Test-Path -LiteralPath $ciTool -PathType Leaf)) { throw [IO.FileNotFoundException]::new('App Control prerequisites are unavailable.') }
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    $transaction = Join-Path $stateRoot ([Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($transaction) | Out-Null
    $base = Join-Path $transaction 'base.xml'; Copy-Item -LiteralPath $example -Destination $base -Force
    $vgtRules = Join-Path $transaction 'vgt-rules.xml'
    New-CIPolicy -ScanPath $installRoot -FilePath $vgtRules -Level Publisher -Fallback Hash -UserPEs -MultiplePolicyFormat -NoScript | Out-Null
    $policies = @($base,$vgtRules)
    $allowed = @(Get-AllowedPaths)
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
    $previous = Read-State
    if ($previous -and [string]$previous.policyId -ne $policyId) { Invoke-CiTool @('--remove-policy',[string]$previous.policyId,'-json') | Out-Null }
    $state = [ordered]@{ policyId=$policyId; enforced=$Enforced; deployedUtc=[DateTime]::UtcNow.ToString('o'); allowedApplications=$allowed.Count; recoveryOptions=@(9,10) }
    $temporary = "$statePath.$PID.tmp"; $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporary -Encoding UTF8; Move-Item -LiteralPath $temporary -Destination $statePath -Force
    return $state
}

try {
    Assert-Administrator
    if ($Action -eq 'Remove') {
        $state = Read-State
        if ($state) { Invoke-CiTool @('--remove-policy',[string]$state.policyId,'-json') | Out-Null; Remove-Item -LiteralPath $statePath -Force }
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

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA49uTg1ADQZAYD
# wCZZnV0v6IPbC3HUNi9OsW03Hw7SiqCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCx/slA5GKw
# 4EK7CuQC8X+kTNjH983+ITflr+BQyxnQPDANBgkqhkiG9w0BAQEFAASCAYCqAeDm
# i8IPdQ5ovRvQFP4pTzkKXYYRnrhlvw3PihUt5dt9QMWnhcqLTbNr1fP3vnkf0rco
# JwzKj3vxgBCXh8kx8D2We+VL7Art40jwRKwU+NdFWOhtbseodXaD1EEmSbbK3djU
# VLm+tJQrJicRUM/hGKqxhIE6EStlxB82PK8PVBfRvvI9klO1jvtG2fzqOU5rf8O9
# R8Cb9JEJNWa67d2LRmZCde8tNAnxe+wovFvNb049Sy5BQUlufCdrUN7EPXZBQQ4+
# ppxK2jy0TMQX31DoGFm6NmmtU6iRleDpg40GNVN2PDRiHTwNlRJt4I8utqvylsEw
# 9bnjppDpGNed7pGEcK2fAw0OTMF+7q5KUOBgb+6lkxvrIBLJvASkblK2kxBKE1JE
# zhjKxlKYP7DpA9uXCiCBlKVPvLZcCabO4MsQWSOGMzDTXEHrDyZEDG1GLcDAJJoy
# fvBYUgHSNVDM7+/8tni/GxjZN9A+QOYPWiNp82zDQhtiv1Q473U/VcpijVQ=
# SIG # End signature block
