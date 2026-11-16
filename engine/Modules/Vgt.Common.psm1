# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# FIND-WIN-005: service-owned state lives below %ProgramData%\VGT. The product
# root and SecurityCenter root are hardened to LocalSystem/Administrators only
# and the result is verified by reading the effective DACL back. The cache only
# avoids re-applying the (idempotent) ACL on every log line within one process.
$script:VgtSystemSid = 'S-1-5-18'
$script:VgtAdministratorsSid = 'S-1-5-32-544'
$script:VgtUsersSid = 'S-1-5-32-545'
$script:VgtDataRootCache = ''
$script:VgtBaselineKeyCache = $null

function Assert-VgtAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw [Security.SecurityException]::new('Administrative token required.')
    }
}

function Get-VgtNormalizedPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw [IO.InvalidDataException]::new('Path must not be empty.') }
    if ($Path.IndexOfAny([char[]]@([char]0,[char]10,[char]13)) -ge 0) { throw [IO.InvalidDataException]::new('Path contains control characters.') }
    return [IO.Path]::GetFullPath($Path)
}

function Test-VgtReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    $full = Get-VgtNormalizedPath -Path $Path
    if (-not [IO.File]::Exists($full) -and -not [IO.Directory]::Exists($full)) { return $false }
    return [bool]([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint)
}

function Assert-VgtNoReparseTraversal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Get-VgtNormalizedPath -Path $Path
    $root = Get-VgtNormalizedPath -Path $AllowedRoot
    if ($root.Length -gt 3) { $root = $root.TrimEnd('\') }
    $rootPrefix = if ($root.EndsWith('\')) { $root } else { $root + '\' }
    if ($full -ne $root) {
        if (-not $full.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw [Security.SecurityException]::new(('Path escaped the allowed root: {0}' -f $full))
        }
    }
    $current = $full
    $guard = 0
    while ($true) {
        if ($current -eq $root) { break }
        if (Test-VgtReparsePoint -Path $current) {
            throw [Security.SecurityException]::new(('Reparse point in the protected path chain: {0}' -f $current))
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
        $current = $parent
        $guard++
        if ($guard -gt 64) { throw [Security.SecurityException]::new('Path traversal evaluation exceeded the safety bound.') }
    }
}

function Resolve-VgtIdentitySid {
    param([Parameter(Mandatory)][object]$Identity)
    if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    $text = [string]$Identity
    try {
        $sid = ([Security.Principal.NTAccount]::new($text)).Translate([Security.Principal.SecurityIdentifier])
        if ($null -ne $sid) { return $sid.Value }
    } catch {}
    try { return ([Security.Principal.SecurityIdentifier]::new($text)).Value } catch { return '' }
}

# Test-VgtServiceAcl verifies an effective ACL: inheritance disabled, no
# inherited ACE, allow ACEs limited to the expected service principals and the
# owner held by LocalSystem or Administrators.
function Test-VgtServiceAcl {
    param(
        [Parameter(Mandatory)][object]$Acl,
        [switch]$AllowsUsersRead,
        [switch]$SkipOwnerCheck
    )
    if (-not $Acl.AreAccessRulesProtected) { return [pscustomobject][ordered]@{ Passed = $false; Detail = 'DACL inheritance is still enabled' } }
    $allowedSids = @($script:VgtSystemSid,$script:VgtAdministratorsSid)
    if ($AllowsUsersRead) { $allowedSids += $script:VgtUsersSid }
    foreach ($rule in @($Acl.Access)) {
        if ($rule.IsInherited) { return [pscustomobject][ordered]@{ Passed = $false; Detail = 'inherited ACE remains in the effective DACL' } }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = Resolve-VgtIdentitySid -Identity $rule.IdentityReference
        if ($allowedSids -notcontains $sid) {
            return [pscustomobject][ordered]@{ Passed = $false; Detail = ('allow ACE grants a non-service principal: {0}' -f $sid) }
        }
    }
    if (-not $SkipOwnerCheck) {
        $ownerSid = Resolve-VgtIdentitySid -Identity $Acl.Owner
        if ($ownerSid -ne $script:VgtSystemSid -and $ownerSid -ne $script:VgtAdministratorsSid) {
            return [pscustomobject][ordered]@{ Passed = $false; Detail = ('object owner is not a service principal: {0}' -f $ownerSid) }
        }
    }
    return [pscustomobject][ordered]@{ Passed = $true; Detail = 'explicit DACL grants only LocalSystem/Administrators' }
}

# Invoke-VgtIcaclsMutation applies one native DACL mutation and fails closed on a
# non-zero exit code. Only DACL operations are used, so the service never needs
# SeSecurityPrivilege and repeated hardening stays idempotent.
function Invoke-VgtIcaclsMutation {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Operation
    )
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows icacls.exe is unavailable.') }
    $nativeOutput = (& $icacls $Path @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw [Security.SecurityException]::new(('ACL {0} failed for {1}: {2}' -f $Operation,$Path,$nativeOutput))
    }
}

# Set-VgtServiceAcl applies an inheritance-protected explicit DACL, moves the
# owner to a service principal and verifies the read-back result fail-closed.
# LocalSystem/Administrators only by default; Windows-readable non-secret content
# (Branding) may opt into Users read/execute. The reset+grant sequence is
# idempotent and never leaves foreign explicit ACEs behind.
function Set-VgtServiceAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowsUsersRead,
        [switch]$SkipOwnerCheck
    )
    $full = Get-VgtNormalizedPath -Path $Path
    $isDirectory = [IO.Directory]::Exists($full)
    if (-not $isDirectory -and -not [IO.File]::Exists($full)) { throw [IO.FileNotFoundException]::new(('ACL target is missing: {0}' -f $full)) }
    $inheritFlags = if ($isDirectory) { '(OI)(CI)' } else { '' }
    Invoke-VgtIcaclsMutation -Path $full -Arguments @('/reset') -Operation 'reset'
    Invoke-VgtIcaclsMutation -Path $full -Arguments @('/inheritance:r') -Operation 'inheritance-remove'
    Invoke-VgtIcaclsMutation -Path $full -Arguments @('/grant:r',("*S-1-5-18:{0}F" -f $inheritFlags),("*S-1-5-32-544:{0}F" -f $inheritFlags)) -Operation 'grant-service'
    if ($AllowsUsersRead) {
        $userRights = if ($isDirectory) { '(OI)(CI)RX' } else { 'R' }
        Invoke-VgtIcaclsMutation -Path $full -Arguments @('/grant:r',("*S-1-5-32-545:{0}" -f $userRights)) -Operation 'grant-users-read'
    }
    if (-not $SkipOwnerCheck) {
        $ownerSid = Resolve-VgtIdentitySid -Identity (Get-Acl -LiteralPath $full).Owner
        if ($ownerSid -ne $script:VgtSystemSid -and $ownerSid -ne $script:VgtAdministratorsSid) {
            Invoke-VgtIcaclsMutation -Path $full -Arguments @('/setowner','*S-1-5-32-544') -Operation 'setowner'
            $hardenedOwner = Resolve-VgtIdentitySid -Identity (Get-Acl -LiteralPath $full).Owner
            if ($hardenedOwner -ne $script:VgtAdministratorsSid) {
                throw [Security.SecurityException]::new(('ACL owner hardening failed for {0}: owner={1}' -f $full,$hardenedOwner))
            }
        }
    }
    $verification = Test-VgtServiceAcl -Acl (Get-Acl -LiteralPath $full) -AllowsUsersRead:$AllowsUsersRead -SkipOwnerCheck:$SkipOwnerCheck
    if (-not [bool]$verification.Passed) {
        throw [Security.SecurityException]::new(('ACL verification failed for {0}: {1}' -f $full,$verification.Detail))
    }
    return $verification
}

function Get-VgtDataRoot {
    if ($script:VgtDataRootCache) {
        if ([IO.Directory]::Exists($script:VgtDataRootCache) -and -not (Test-VgtReparsePoint -Path $script:VgtDataRootCache)) { return $script:VgtDataRootCache }
        $script:VgtDataRootCache = ''
    }
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $vgtRoot = Join-Path $programDataRoot 'VGT'
    Assert-VgtNoReparseTraversal -Path $vgtRoot -AllowedRoot $programDataRoot
    if ([IO.File]::Exists($vgtRoot)) { throw [IO.InvalidDataException]::new('%ProgramData%\VGT is a file, not a directory.') }
    if (-not [IO.Directory]::Exists($vgtRoot)) { New-Item -Path $vgtRoot -ItemType Directory -Force | Out-Null }
    Set-VgtServiceAcl -Path $vgtRoot | Out-Null
    $root = Join-Path $vgtRoot 'SecurityCenter'
    Assert-VgtNoReparseTraversal -Path $root -AllowedRoot $programDataRoot
    if ([IO.File]::Exists($root)) { throw [IO.InvalidDataException]::new('%ProgramData%\VGT\SecurityCenter is a file, not a directory.') }
    if (-not [IO.Directory]::Exists($root)) { New-Item -Path $root -ItemType Directory -Force | Out-Null }
    Set-VgtServiceAcl -Path $root | Out-Null
    $script:VgtDataRootCache = $root
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
        Set-VgtServiceAcl -Path $logDirectory | Out-Null
    }
    Assert-VgtNoReparseTraversal -Path $logDirectory -AllowedRoot (Get-VgtDataRoot)
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
        # Enforce an array: a single scalar would not expose .Count under
        # Set-StrictMode -Version Latest (PowerShell 5.1) and would break the
        # baseline schema validation.
        $values = @(Get-VgtBaselinePropertyValues -Object $Defender -Name $settingName)
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

# FIND-WIN-005: audit-policy.csv content (not just its path) is bound into the
# authenticated baseline material, so replacing the CSV is detected.
function Get-VgtAuditPolicyContentHash {
    param([AllowEmptyString()][string]$Path = '')
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    if (Test-VgtReparsePoint -Path $Path) { return '' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VgtBaselineKeyDirectory {
    return (Join-Path $env:ProgramData 'VGT\GeDefense\keys')
}

# Get-VgtBaselineKeyBytes returns the 32-byte HMAC key for the baseline anchor.
# The production key lives below %ProgramData%\VGT\GeDefense\keys and is created
# empty, receives the SYSTEM/Administrators-only DACL and only then stores the
# key material (no readable window for secret bytes). The explicit -KeyDirectory
# parameter exists for the unit tests; production callers never pass it.
function Get-VgtBaselineKeyBytes {
    param([AllowEmptyString()][string]$KeyDirectory = '')
    $isProduction = [string]::IsNullOrWhiteSpace($KeyDirectory)
    if ($isProduction -and $null -ne $script:VgtBaselineKeyCache) { return $script:VgtBaselineKeyCache }
    $targetDirectory = if ($isProduction) { [IO.Path]::GetFullPath((Get-VgtBaselineKeyDirectory)) } else { [IO.Path]::GetFullPath($KeyDirectory) }
    if ([IO.File]::Exists($targetDirectory)) { throw [IO.InvalidDataException]::new('Baseline key path is a file, not a directory.') }
    if (-not [IO.Directory]::Exists($targetDirectory)) { New-Item -Path $targetDirectory -ItemType Directory -Force | Out-Null }
    if ($isProduction) { Set-VgtServiceAcl -Path $targetDirectory | Out-Null }
    $keyPath = Join-Path $targetDirectory 'baseline-hmac.key'
    Assert-VgtNoReparseTraversal -Path $keyPath -AllowedRoot $targetDirectory
    if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
        if (Test-VgtReparsePoint -Path $keyPath) { throw [Security.SecurityException]::new('Baseline key file is a reparse point.') }
        $encoded = (Get-Content -LiteralPath $keyPath -Raw -Encoding ASCII).Trim()
        $key = $null
        try { $key = [Convert]::FromBase64String($encoded) } catch { throw [Security.SecurityException]::new('Baseline key file is corrupt.') }
        if ($null -eq $key -or $key.Length -ne 32) { throw [Security.SecurityException]::new('Baseline key material is invalid.') }
        if ($isProduction) { Set-VgtServiceAcl -Path $keyPath | Out-Null }
        if ($isProduction) { $script:VgtBaselineKeyCache = $key }
        return $key
    }
    $null = New-Item -Path $keyPath -ItemType File -Force
    # DACL before the first secret byte: the file exists but is still empty.
    if ($isProduction) { Set-VgtServiceAcl -Path $keyPath | Out-Null }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $key = New-Object byte[] 32
        $rng.GetBytes($key)
    } finally { $rng.Dispose() }
    $encodedBytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($key))
    $stream = [IO.File]::Open($keyPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $stream.Write($encodedBytes,0,$encodedBytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ($isProduction) { Set-VgtServiceAcl -Path $keyPath | Out-Null }
    if ($isProduction) { $script:VgtBaselineKeyCache = $key }
    return $key
}

function Get-VgtBaselineKeyId {
    param([Parameter(Mandatory)][byte[]]$Key)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Key))).Replace('-','').Substring(0,16).ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Test-VgtConstantTimeHexEqual {
    param([AllowEmptyString()][string]$Left = '',[AllowEmptyString()][string]$Right = '')
    if ($Left.Length -ne $Right.Length -or $Left.Length -eq 0) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    return ($difference -eq 0)
}

function Get-VgtBaselineIntegrityMaterial {
    param([Parameter(Mandatory)][object]$State)
    # Only the security-relevant content is bound; createdUtc and the integrity
    # field itself are excluded so the HMAC is reproducible after a JSON
    # round-trip. The audit policy CSV content hash binds the file content, not
    # just the path.
    $auditPolicyPath = [string]$State.auditPolicy
    $material = [ordered]@{
        format = [int]$State.format
        registry = @($State.registry)
        firewall = @($State.firewall)
        defender = $State.defender
        smb1State = [string]$State.smb1State
        auditPolicy = $auditPolicyPath
        auditPolicySha256 = (Get-VgtAuditPolicyContentHash -Path $auditPolicyPath)
    }
    return ($material | ConvertTo-Json -Depth 6 -Compress)
}

# Get-VgtBaselineIntegrityHash returns the keyed HMAC-SHA256 over the canonical
# baseline material. The legacy unkeyed SHA-256 does not authenticate content and
# is never produced or accepted as 'Valid'.
function Get-VgtBaselineIntegrityHash {
    param([Parameter(Mandatory)][object]$State,[byte[]]$Key,[AllowEmptyString()][string]$KeyDirectory = '')
    if ($null -eq $Key) { $Key = Get-VgtBaselineKeyBytes -KeyDirectory $KeyDirectory }
    if ($null -eq $Key -or $Key.Length -ne 32) { throw [Security.SecurityException]::new('Baseline HMAC key is invalid.') }
    $material = Get-VgtBaselineIntegrityMaterial -State $State
    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    try {
        return ([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').ToLowerInvariant()
    } finally { $hmac.Dispose() }
}

# Returns 'Valid' only when the keyed HMAC and the bound audit-policy content
# hash match. 'Legacy' (unkeyed SHA-256 or no integrity metadata) and 'Mismatch'
# are integrity violations: callers must fail closed instead of treating them as
# OK (FIND-WIN-005).
function Test-VgtBaselineIntegrity {
    param([Parameter(Mandatory)][object]$State,[byte[]]$Key,[AllowEmptyString()][string]$KeyDirectory = '')
    $integrityProperty = $State.PSObject.Properties['integrity']
    if ($null -eq $integrityProperty -or $null -eq $integrityProperty.Value) { return 'Legacy' }
    $integrity = $integrityProperty.Value
    $algorithmProperty = $integrity.PSObject.Properties['algorithm']
    if ($null -eq $algorithmProperty) { return 'Mismatch' }
    if ([string]$algorithmProperty.Value -ne 'HMAC-SHA256') {
        # Unkeyed legacy integrity (SHA256) cannot be authenticated and must
        # never be treated as valid; it is reported as an integrity violation.
        if ([string]$algorithmProperty.Value -eq 'SHA256') { return 'Legacy' }
        return 'Mismatch'
    }
    $hmacProperty = $integrity.PSObject.Properties['baselineHmac']
    if ($null -eq $hmacProperty) { return 'Mismatch' }
    $stored = ([string]$hmacProperty.Value).Trim().ToLowerInvariant()
    if ($stored -notmatch '^[0-9a-f]{64}$') { return 'Mismatch' }
    $auditPolicyProperty = $State.PSObject.Properties['auditPolicy']
    if ($null -eq $auditPolicyProperty) { return 'Mismatch' }
    $auditPolicySha256 = Get-VgtAuditPolicyContentHash -Path ([string]$auditPolicyProperty.Value)
    if ([string]::IsNullOrWhiteSpace($auditPolicySha256)) { return 'Mismatch' }
    $storedAuditProperty = $integrity.PSObject.Properties['auditPolicySha256']
    if ($null -eq $storedAuditProperty) { return 'Mismatch' }
    if (([string]$storedAuditProperty.Value).Trim().ToLowerInvariant() -ne $auditPolicySha256) { return 'Mismatch' }
    if ($null -eq $Key) {
        try { $Key = Get-VgtBaselineKeyBytes -KeyDirectory $KeyDirectory } catch { return 'Mismatch' }
    }
    if ($null -eq $Key -or $Key.Length -ne 32) { return 'Mismatch' }
    $computed = Get-VgtBaselineIntegrityHash -State $State -Key $Key
    if (-not (Test-VgtConstantTimeHexEqual -Left $stored -Right $computed)) { return 'Mismatch' }
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

# Get-VgtStateDirectory returns the authenticated-state directory below
# SecurityCenter. The directory is created through the reparse-safe path chain
# and receives an explicit service-only DACL so the baseline anchor and the
# audit policy copy cannot be replaced by a non-privileged principal.
function Get-VgtStateDirectory {
    $stateDirectory = Join-Path (Get-VgtDataRoot) 'State'
    $dataRoot = Get-VgtDataRoot
    Assert-VgtNoReparseTraversal -Path $stateDirectory -AllowedRoot $dataRoot
    if ([IO.File]::Exists($stateDirectory)) { throw [IO.InvalidDataException]::new('VGT state path is a file, not a directory.') }
    if (-not [IO.Directory]::Exists($stateDirectory)) { New-Item -Path $stateDirectory -ItemType Directory -Force | Out-Null }
    Set-VgtServiceAcl -Path $stateDirectory | Out-Null
    return $stateDirectory
}

function Save-VgtBaseline {
    $stateDirectory = Get-VgtStateDirectory
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
            if ($existingIntegrity -eq 'Legacy') {
                # An unkeyed/absent HMAC cannot authenticate the anchor. It is
                # never treated as valid: the untrusted file is preserved for
                # forensics and a fresh keyed baseline is captured from the live
                # system below (the untrusted content is never re-signed).
                $untrustedArchive = Join-Path $stateDirectory ('baseline.untrusted-{0}.json' -f [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
                Move-Item -LiteralPath $target -Destination $untrustedArchive -Force
                Write-VgtEvent -Level SECURITY -Message ('Unauthenticated hardening baseline archived (missing/invalid HMAC); capturing a fresh keyed baseline: {0}' -f (Split-Path -Leaf $untrustedArchive))
            } else {
                return $target
            }
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
    Set-VgtServiceAcl -Path $auditPolicy | Out-Null
    $auditPolicySha256 = Get-VgtAuditPolicyContentHash -Path $auditPolicy
    if ([string]::IsNullOrWhiteSpace($auditPolicySha256)) { throw [Security.SecurityException]::new('Audit policy baseline content hash is unavailable.') }
    $state = [ordered]@{
        format = 2
        createdUtc = [DateTime]::UtcNow.ToString('o')
        registry = @($registry)
        firewall = @($firewall)
        defender = $defender
        smb1State = $smb1State
        auditPolicy = $auditPolicy
    }
    $integrityKey = Get-VgtBaselineKeyBytes
    $state['integrity'] = [ordered]@{
        algorithm = 'HMAC-SHA256'
        baselineHmac = (Get-VgtBaselineIntegrityHash -State ([pscustomobject]$state) -Key $integrityKey)
        auditPolicySha256 = $auditPolicySha256
        keyId = (Get-VgtBaselineKeyId -Key $integrityKey)
    }
    $temporary = "$target.$PID.tmp"
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $target -Force
    Set-VgtServiceAcl -Path $target | Out-Null
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
    $stateDirectory = Get-VgtStateDirectory
    $target = Join-Path $stateDirectory 'baseline.json'
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT baseline is unavailable.') }
    $state = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-VgtBaselineState -State $state -StateDirectory $stateDirectory)) {
        throw [Security.SecurityException]::new('VGT baseline validation failed.')
    }
    # FIND-WIN-005: a missing, legacy (unkeyed) or mismatching HMAC is an
    # integrity violation. Rollback must never proceed on an unauthenticated
    # anchor.
    $integrity = Test-VgtBaselineIntegrity -State $state
    if ($integrity -ne 'Valid') {
        throw [Security.SecurityException]::new(('VGT baseline integrity verification failed ({0}); rollback rejected.' -f $integrity))
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

Export-ModuleMember -Function Assert-VgtAdministrator,Get-VgtDataRoot,Write-VgtEvent,Set-VgtRegistryDword,Save-VgtBaseline,Restore-VgtBaseline,Get-VgtStateDirectory,Test-VgtBaselineState,Test-VgtBaselineIntegrity,Get-VgtBaselineIntegrityMaterial,Get-VgtBaselineIntegrityHash,Get-VgtBaselineKeyBytes,Get-VgtAuditPolicyContentHash,Get-VgtBaselineKeyDirectory,Test-VgtServiceAcl

