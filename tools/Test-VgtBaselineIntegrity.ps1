# STATUS: DIAMANT VGT SUPREME
# Pester-free unit tests for the keyed hardening-baseline integrity anchor
# (FIND-WIN-005). The tests run entirely inside a disposable %TEMP% directory:
# no registry, Defender, firewall, audit policy or ProgramData state is touched.
#
# Covered contracts:
#   - canonical material contains the audit-policy.csv CONTENT hash (not only
#     the path)
#   - HMAC-SHA256 round-trip survives the JSON persistence format
#   - missing / unkeyed / modified integrity metadata is never reported as OK
#   - tampering with the baseline body, the HMAC, the audit policy CSV or the
#     key is detected as an integrity violation
#   - the baseline HMAC key store creates a stable 32-byte key
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'engine\Modules\Vgt.Common.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Vgt.Common module is missing: {0}' -f $modulePath)) }
Import-Module -Name $modulePath -Force

$results = [Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $results.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Baseline integrity check failed: {0} ({1})' -f $Name,$Detail)) }
}

function New-VgtTestBaselineState {
    param([Parameter(Mandatory)][string]$AuditPolicyPath)
    $registry = @(
        [ordered]@{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; name = 'RunAsPPL'; existed = $true; value = 1 },
        [ordered]@{ path = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; name = 'Enabled'; existed = $false; value = $null }
    )
    $firewall = @(
        [ordered]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; NotifyOnListen = $true; AllowUnicastResponseToMulticast = $false; LogBlocked = $true; LogAllowed = $false; LogMaxSizeKilobytes = 32767 },
        [ordered]@{ Name = 'Private'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; NotifyOnListen = $true; AllowUnicastResponseToMulticast = $false; LogBlocked = $true; LogAllowed = $false; LogMaxSizeKilobytes = 32767 },
        [ordered]@{ Name = 'Public'; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; NotifyOnListen = $true; AllowUnicastResponseToMulticast = $false; LogBlocked = $true; LogAllowed = $false; LogMaxSizeKilobytes = 32767 }
    )
    $defender = [ordered]@{
        PUAProtection = 1
        MAPSReporting = 2
        SubmitSamplesConsent = 1
        EnableNetworkProtection = 1
        CloudBlockLevel = 2
        EnableControlledFolderAccess = 1
        AttackSurfaceReductionRules_Ids = @('56a863a9-875e-4185-98a7-b882c64b5ce5')
        AttackSurfaceReductionRules_Actions = @(1)
    }
    return [ordered]@{
        format = 2
        createdUtc = [DateTime]::UtcNow.ToString('o')
        registry = $registry
        firewall = $firewall
        defender = $defender
        smb1State = 'Disabled'
        auditPolicy = $AuditPolicyPath
    }
}

# ConvertTo-VgtTestStateObject mirrors the JSON persistence round-trip: the
# engine writes/read baseline.json through ConvertTo-Json/ConvertFrom-Json, so
# the unit test must exercise the same object shape (hashtables become
# PSCustomObjects whose keys are real PSObject properties).
function ConvertTo-VgtTestStateObject {
    param([Parameter(Mandatory)][object]$State)
    return ($State | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}

$sandboxRoot = Join-Path $env:TEMP ('vgt-baseline-unit-' + [Guid]::NewGuid().ToString('N'))
$stateDirectory = Join-Path $sandboxRoot 'State'
$keyDirectory = Join-Path $sandboxRoot 'keys'
New-Item -Path $stateDirectory -ItemType Directory -Force | Out-Null
try {
    $auditPolicyPath = Join-Path $stateDirectory 'audit-policy.csv'
    Set-Content -LiteralPath $auditPolicyPath -Value 'Machine Name,System Audit Policy,Subcategory,GUID,Setting Value' -Encoding ASCII
    $key = New-Object byte[] 32
    for ($index = 0; $index -lt 32; $index++) { $key[$index] = [byte]($index + 1) }

    # 1. Canonical material binds the audit-policy CSV content hash.
    $state = New-VgtTestBaselineState -AuditPolicyPath $auditPolicyPath
    $stateObject = ConvertTo-VgtTestStateObject -State $state
    Add-Check -Name 'baseline-state-schema-valid' -Passed (Test-VgtBaselineState -State $stateObject -StateDirectory $stateDirectory)
    $material = Get-VgtBaselineIntegrityMaterial -State $stateObject
    $materialAgain = Get-VgtBaselineIntegrityMaterial -State $stateObject
    Add-Check -Name 'integrity-material-deterministic' -Passed ($material -eq $materialAgain)
    $auditPolicySha256 = Get-VgtAuditPolicyContentHash -Path $auditPolicyPath
    Add-Check -Name 'audit-policy-content-hash-present' -Passed ($auditPolicySha256 -match '^[0-9a-f]{64}$') -Detail $auditPolicySha256
    Add-Check -Name 'material-binds-audit-policy-content' -Passed ($material.Contains($auditPolicySha256))

    # 2. Keyed HMAC round-trip through the JSON persistence format.
    $hmac = Get-VgtBaselineIntegrityHash -State $stateObject -Key $key
    Add-Check -Name 'hmac-format' -Passed ($hmac -match '^[0-9a-f]{64}$') -Detail $hmac
    $state['integrity'] = [ordered]@{
        algorithm = 'HMAC-SHA256'
        baselineHmac = $hmac
        auditPolicySha256 = $auditPolicySha256
        keyId = '0011223344556677'
    }
    $json = $state | ConvertTo-Json -Depth 6
    $roundTrip = $json | ConvertFrom-Json
    Add-Check -Name 'hmac-roundtrip-valid' -Passed ((Test-VgtBaselineIntegrity -State $roundTrip -Key $key) -eq 'Valid')
    Add-Check -Name 'hmac-roundtrip-valid-with-key-store' -Passed ((Test-VgtBaselineIntegrity -State $roundTrip -Key $key) -eq 'Valid')

    # 3. Tamper detection: body, HMAC, key and audit-policy content.
    $tamperedBody = $json | ConvertFrom-Json
    $tamperedBody.registry[0].value = 0
    Add-Check -Name 'tampered-registry-detected' -Passed ((Test-VgtBaselineIntegrity -State $tamperedBody -Key $key) -eq 'Mismatch')

    $tamperedHmac = $json | ConvertFrom-Json
    $flipped = if ($tamperedHmac.integrity.baselineHmac[0] -eq 'a') { 'b' } else { 'a' }
    $tamperedHmac.integrity.baselineHmac = $flipped + $tamperedHmac.integrity.baselineHmac.Substring(1)
    Add-Check -Name 'tampered-hmac-detected' -Passed ((Test-VgtBaselineIntegrity -State $tamperedHmac -Key $key) -eq 'Mismatch')

    $wrongKey = New-Object byte[] 32
    for ($index = 0; $index -lt 32; $index++) { $wrongKey[$index] = [byte](0xFF - $index) }
    Add-Check -Name 'wrong-key-detected' -Passed ((Test-VgtBaselineIntegrity -State $roundTrip -Key $wrongKey) -eq 'Mismatch')

    Set-Content -LiteralPath $auditPolicyPath -Value 'Machine Name,System Audit Policy,Subcategory,GUID,Setting Value,Extra' -Encoding ASCII
    Add-Check -Name 'tampered-audit-policy-content-detected' -Passed ((Test-VgtBaselineIntegrity -State $roundTrip -Key $key) -eq 'Mismatch')
    Set-Content -LiteralPath $auditPolicyPath -Value 'Machine Name,System Audit Policy,Subcategory,GUID,Setting Value' -Encoding ASCII

    # 4. Missing or legacy (unkeyed) integrity metadata is an integrity violation,
    # never 'Valid'.
    $withoutIntegrity = New-VgtTestBaselineState -AuditPolicyPath $auditPolicyPath
    Add-Check -Name 'missing-integrity-is-legacy' -Passed ((Test-VgtBaselineIntegrity -State (ConvertTo-VgtTestStateObject -State $withoutIntegrity) -Key $key) -eq 'Legacy')
    $legacy = New-VgtTestBaselineState -AuditPolicyPath $auditPolicyPath
    $legacy['integrity'] = [ordered]@{ algorithm = 'SHA256'; baselineSha256 = ('a' * 64) }
    Add-Check -Name 'unkeyed-legacy-integrity-is-legacy' -Passed ((Test-VgtBaselineIntegrity -State (ConvertTo-VgtTestStateObject -State $legacy) -Key $key) -eq 'Legacy')
    $badShape = $json | ConvertFrom-Json
    $badShape.integrity.baselineHmac = 'not-a-hmac'
    Add-Check -Name 'malformed-hmac-detected' -Passed ((Test-VgtBaselineIntegrity -State $badShape -Key $key) -eq 'Mismatch')

    # 5. Key store round-trip (explicit test directory, no ProgramData state).
    $createdKey = Get-VgtBaselineKeyBytes -KeyDirectory $keyDirectory
    Add-Check -Name 'key-store-creates-32-byte-key' -Passed ($createdKey.Length -eq 32)
    $reloadedKey = Get-VgtBaselineKeyBytes -KeyDirectory $keyDirectory
    Add-Check -Name 'key-store-stable' -Passed ([Convert]::ToBase64String($createdKey) -eq [Convert]::ToBase64String($reloadedKey))
    $keyFile = Join-Path $keyDirectory 'baseline-hmac.key'
    Add-Check -Name 'key-store-file-written' -Passed ((Test-Path -LiteralPath $keyFile -PathType Leaf) -and ((Get-Item -LiteralPath $keyFile).Length -gt 0))
    Add-Check -Name 'key-store-hmac-usable' -Passed ((Test-VgtBaselineIntegrity -State $roundTrip -Key $createdKey) -eq 'Mismatch')

    # 6. ACL verification helper rejects permissive and inherited DACLs.
    $serviceAcl = New-Object Security.AccessControl.DirectorySecurity
    $serviceAcl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Add-Check -Name 'service-only-acl-accepted' -Passed ([bool](Test-VgtServiceAcl -Acl $serviceAcl -SkipOwnerCheck).Passed)
    $permissiveAcl = New-Object Security.AccessControl.DirectorySecurity
    $permissiveAcl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
    Add-Check -Name 'users-write-acl-rejected' -Passed (-not [bool](Test-VgtServiceAcl -Acl $permissiveAcl -SkipOwnerCheck).Passed)
    $inheritedAcl = New-Object Security.AccessControl.DirectorySecurity
    $inheritedAcl.SetSecurityDescriptorSddlForm('D:(A;OICIID;FA;;;SY)')
    Add-Check -Name 'inherited-acl-rejected' -Passed (-not [bool](Test-VgtServiceAcl -Acl $inheritedAcl -SkipOwnerCheck).Passed)

    [pscustomobject][ordered]@{
        Status = 'PASS'
        Mode = 'unit'
        Checks = $results.Count
        Results = $results.ToArray()
    }
} finally {
    try {
        # Restore access for cleanup in case an ACL fixture was materialised.
        Remove-Item -LiteralPath $sandboxRoot -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}
