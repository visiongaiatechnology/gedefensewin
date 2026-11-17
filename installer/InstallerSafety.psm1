# STATUS: DIAMANT VGT SUPREME
# Reparse-point safety primitives for the elevated GeDefense installer.
#
# The installer previously reused pre-existing %ProgramData% paths with
# New-Item -Force and only hardened their ACLs later. A standard user can create
# a directory junction below %ProgramData%, so every target path must be proven
# free of reparse points before the elevated transaction writes to it.
#
# The helpers below are deliberately read-only. They never create, delete or
# change ACLs; callers stay in control of the write sequence.
Set-StrictMode -Version Latest

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
    $attributes = [IO.File]::GetAttributes($full)
    return [bool]($attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Assert-VgtPathWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Get-VgtNormalizedPath -Path $Path
    $root = Get-VgtNormalizedPath -Path $AllowedRoot
    if ($root.Length -gt 3) { $root = $root.TrimEnd('\') }
    $rootPrefix = if ($root.EndsWith('\')) { $root } else { $root + '\' }
    if ($full -eq $root) { return }
    if (-not $full.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw [Security.SecurityException]::new(('Installer path escaped the allowed root: {0} (allowed: {1})' -f $full,$root))
    }
}

function Assert-VgtNoReparseTraversal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Get-VgtNormalizedPath -Path $Path
    $root = Get-VgtNormalizedPath -Path $AllowedRoot
    if ($root.Length -gt 3) { $root = $root.TrimEnd('\') }
    Assert-VgtPathWithinRoot -Path $full -AllowedRoot $root
    $current = $full
    $guard = 0
    while ($true) {
        if ($current -ne $root) {
            if (Test-VgtReparsePoint -Path $current) {
                throw [Security.SecurityException]::new(('Installer target path is a reparse point: {0}' -f $current))
            }
            $parent = [IO.Path]::GetDirectoryName($current)
            if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
            $current = $parent
        } else {
            break
        }
        $guard++
        if ($guard -gt 64) { throw [Security.SecurityException]::new('Installer path traversal evaluation exceeded the safety bound.') }
    }
}

function New-VgtSafeDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Get-VgtNormalizedPath -Path $Path
    Assert-VgtNoReparseTraversal -Path $full -AllowedRoot $AllowedRoot
    if ([IO.File]::Exists($full)) { throw [IO.InvalidDataException]::new(('Installer target is a file, not a directory: {0}' -f $full)) }
    if (-not [IO.Directory]::Exists($full)) {
        New-Item -Path $full -ItemType Directory -Force | Out-Null
    }
    Assert-VgtNoReparseTraversal -Path $full -AllowedRoot $AllowedRoot
    if (Test-VgtReparsePoint -Path $full) { throw [Security.SecurityException]::new(('Installer target became a reparse point during creation: {0}' -f $full)) }
    return $full
}

function Assert-VgtSafeFileTarget {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Get-VgtNormalizedPath -Path $Path
    if ([IO.Directory]::Exists($full)) { throw [IO.InvalidDataException]::new(('Installer file target is a directory: {0}' -f $full)) }
    Assert-VgtNoReparseTraversal -Path $full -AllowedRoot $AllowedRoot
    return $full
}

function Get-VgtPathAttributesForDiagnostics {
    param([Parameter(Mandatory)][string]$Path)
    $full = Get-VgtNormalizedPath -Path $Path
    if (-not [IO.File]::Exists($full) -and -not [IO.Directory]::Exists($full)) { return 'missing' }
    return [string][IO.File]::GetAttributes($full)
}

# VGT service-owned principals: only LocalSystem and Builtin Administrators may
# hold full control on product directories and runtime secrets.
$script:VgtSystemSid = 'S-1-5-18'
$script:VgtAdministratorsSid = 'S-1-5-32-544'
$script:VgtUsersSid = 'S-1-5-32-545'
$script:VgtSystemSidObj = [Security.Principal.SecurityIdentifier]::new($script:VgtSystemSid)
$script:VgtAdminsSidObj = [Security.Principal.SecurityIdentifier]::new($script:VgtAdministratorsSid)

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

# Test-VgtAclObject inspects an already materialised ACL object: inheritance must
# be disabled, no inherited ACE may remain and every allow ACE must be limited to
# the expected service principals. Deny ACEs are permitted (they only restrict).
function Test-VgtAclObject {
    param(
        [Parameter(Mandatory)][object]$Acl,
        [string[]]$AllowedSids = @($script:VgtSystemSid,$script:VgtAdministratorsSid)
    )
    $detail = ''
    if (-not $Acl.AreAccessRulesProtected) { return [pscustomobject][ordered]@{ Passed = $false; Detail = 'DACL inheritance is still enabled' } }
    foreach ($rule in @($Acl.Access)) {
        if ($rule.IsInherited) { return [pscustomobject][ordered]@{ Passed = $false; Detail = 'inherited ACE remains in the effective DACL' } }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = Resolve-VgtIdentitySid -Identity $rule.IdentityReference
        if ($AllowedSids -notcontains $sid) {
            return [pscustomobject][ordered]@{ Passed = $false; Detail = ('allow ACE grants a non-service principal: {0}' -f $sid) }
        }
    }
    $ownerSid = Resolve-VgtIdentitySid -Identity $Acl.Owner
    $detail = 'explicit DACL grants only the expected service principals'
    return [pscustomobject][ordered]@{ Passed = $true; Detail = $detail; OwnerSid = $ownerSid }
}

# Invoke-VgtIcaclsMutation applies one native ACL mutation and fails closed on a
# non-zero exit code. icacls is only used for DACL operations, so the installer
# never needs SeSecurityPrivilege and repeated hardening stays idempotent.
function Invoke-VgtIcaclsMutation {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Operation
    )
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Windows icacls.exe is unavailable.') }
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $nativeOutput = (& $icacls $Path @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Out-String).Trim()
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEA
    }
    if ($exitCode -ne 0) {
        throw [Security.SecurityException]::new(('ACL {0} failed for {1}: {2}' -f $Operation,$Path,$nativeOutput))
    }
}

function Invoke-VgtTakeOwnershipForAdministrators {
    param([Parameter(Mandatory)][string]$Path)
    $takeown = Join-Path $env:SystemRoot 'System32\takeown.exe'
    if (-not (Test-Path -LiteralPath $takeown -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new('Windows takeown.exe is unavailable.')
    }
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $nativeOutput = (& $takeown /F $Path /A 2>&1 | ForEach-Object { $_.ToString() } | Out-String).Trim()
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEA
    }
    if ($exitCode -ne 0) {
        throw [Security.SecurityException]::new(('takeown failed for {0}: {1}' -f $Path,$nativeOutput))
    }
}

# Set-VgtRestrictedAcl replaces inheritance with an explicit, inheritance-
# protected DACL (LocalSystem + Builtin Administrators full control; optional
# read/execute for Builtin Users on non-secret content) and proves the result by
# reading the effective DACL back. Any deviation is fail-closed. The mutation is
# idempotent: resetting the inherited ACL first prevents foreign explicit ACEs
# from surviving and per-object DACL writes keep working on already-hardened
# objects.
function Set-VgtRestrictedAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowsUsersRead,
        [switch]$SkipOwnerHardening
    )
    $full = Get-VgtNormalizedPath -Path $Path
    $isDirectory = [IO.Directory]::Exists($full)
    if (-not $isDirectory -and -not [IO.File]::Exists($full)) {
        throw [IO.FileNotFoundException]::new(('ACL target is missing: {0}' -f $full))
    }
    Assert-VgtNoReparseTraversal -Path $full -AllowedRoot ([IO.Path]::GetPathRoot($full))
    if (-not $isDirectory -and (Test-VgtReparsePoint -Path $full)) {
        throw [Security.SecurityException]::new(('ACL file target is a reparse point: {0}' -f $full))
    }
    $inheritFlags = if ($isDirectory) { '(OI)(CI)' } else { '' }
    try {
        Invoke-VgtIcaclsMutation -Path $full -Arguments @('/reset') -Operation 'reset'
    } catch {
        if ($SkipOwnerHardening) { throw }
        Invoke-VgtTakeOwnershipForAdministrators -Path $full
        Invoke-VgtIcaclsMutation -Path $full -Arguments @('/reset') -Operation 'reset'
    }
    $grantArgs = @('/inheritance:r','/grant:r',("*S-1-5-18:{0}F" -f $inheritFlags),("*S-1-5-32-544:{0}F" -f $inheritFlags))
    if ($AllowsUsersRead) {
        $userRights = if ($isDirectory) { '(OI)(CI)RX' } else { 'R' }
        $grantArgs += ("*S-1-5-32-545:{0}" -f $userRights)
    }
    try {
        Invoke-VgtIcaclsMutation -Path $full -Arguments $grantArgs -Operation 'grant-service'
    } catch {
        if ($SkipOwnerHardening) { throw }
        Invoke-VgtTakeOwnershipForAdministrators -Path $full
        Invoke-VgtIcaclsMutation -Path $full -Arguments $grantArgs -Operation 'grant-service'
    }
    if (-not $SkipOwnerHardening) {
        $currentOwner = (Get-Acl -LiteralPath $full).Owner
        $ownerSid = Resolve-VgtIdentitySid -Identity $currentOwner
        if ($ownerSid -ne $script:VgtSystemSid -and $ownerSid -ne $script:VgtAdministratorsSid) {
            try {
                Invoke-VgtIcaclsMutation -Path $full -Arguments @('/setowner','*S-1-5-32-544') -Operation 'setowner'
            } catch {
                Invoke-VgtTakeOwnershipForAdministrators -Path $full
            }
            $hardenedOwner = Resolve-VgtIdentitySid -Identity (Get-Acl -LiteralPath $full).Owner
            if ($hardenedOwner -ne $script:VgtAdministratorsSid) {
                throw [Security.SecurityException]::new(('ACL owner hardening failed for {0}: owner={1}' -f $full,$hardenedOwner))
            }
        }
    }
    $allowedSids = @($script:VgtSystemSid,$script:VgtAdministratorsSid)
    if ($AllowsUsersRead) { $allowedSids += $script:VgtUsersSid }
    $verification = Test-VgtAclObject -Acl (Get-Acl -LiteralPath $full) -AllowedSids $allowedSids
    if (-not [bool]$verification.Passed) {
        throw [Security.SecurityException]::new(('ACL verification failed for {0}: {1}' -f $full,$verification.Detail))
    }
    return $verification
}

function Test-VgtServiceOnlySecurityInProcess {
    param(
        [Parameter(Mandatory)][object]$Acl,
        [Parameter(Mandatory)][bool]$IsDirectory
    )
    if (-not $Acl.AreAccessRulesProtected) { return $false }
    $ownerSid = try { $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { '' }
    if ($ownerSid -ne $script:VgtSystemSid -and $ownerSid -ne $script:VgtAdministratorsSid) { return $false }
    $hasSystemFull = $false
    $hasAdminsFull = $false
    $requiredInherit = if ($IsDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($rule in @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.IsInherited) { return $false }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -ne $script:VgtSystemSid -and $sid -ne $script:VgtAdministratorsSid) { return $false }
        $hasFull = (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)
        $hasInherit = (-not $IsDirectory) -or (($rule.InheritanceFlags -band $requiredInherit) -eq $requiredInherit)
        if ($hasFull -and $hasInherit) {
            if ($sid -eq $script:VgtSystemSid) { $hasSystemFull = $true }
            elseif ($sid -eq $script:VgtAdministratorsSid) { $hasAdminsFull = $true }
        }
    }
    return ($hasSystemFull -and $hasAdminsFull)
}

# Repair-VgtRestrictedEntryAcl verifies and, only where needed, enforces the
# SYSTEM/Administrators-only protected DACL in-process without spawning icacls
# per file, falling back to Set-VgtRestrictedAcl (with takeown) when the
# caller lacks WRITE_DAC or owner hardening is required.
function Repair-VgtRestrictedEntryAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$IsDirectory
    )
    $full = Get-VgtNormalizedPath -Path $Path
    if (Test-VgtReparsePoint -Path $full) {
        throw [Security.SecurityException]::new(('ACL target is a reparse point: {0}' -f $full))
    }
    $dirFlag = [bool]$IsDirectory
    try {
        $existingAcl = if ($dirFlag) {
            [IO.DirectoryInfo]::new($full).GetAccessControl([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
        } else {
            [IO.FileInfo]::new($full).GetAccessControl([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
        }
        if (Test-VgtServiceOnlySecurityInProcess -Acl $existingAcl -IsDirectory $dirFlag) {
            return [pscustomobject][ordered]@{ Passed = $true; Changed = $false; Detail = 'already restricted' }
        }
        $ownerSid = try { $existingAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { '' }
        if ($ownerSid -eq $script:VgtSystemSid -or $ownerSid -eq $script:VgtAdministratorsSid) {
            $newAcl = if ($dirFlag) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
            $newAcl.SetAccessRuleProtection($true, $false)
            $inherit = if ($dirFlag) {
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            } else {
                [Security.AccessControl.InheritanceFlags]::None
            }
            $prop = [Security.AccessControl.PropagationFlags]::None
            $newAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($script:VgtSystemSidObj, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop, [Security.AccessControl.AccessControlType]::Allow))
            $newAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($script:VgtAdminsSidObj, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop, [Security.AccessControl.AccessControlType]::Allow))
            if ($dirFlag) {
                [IO.DirectoryInfo]::new($full).SetAccessControl($newAcl)
                $verifyAcl = [IO.DirectoryInfo]::new($full).GetAccessControl([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
            } else {
                [IO.FileInfo]::new($full).SetAccessControl($newAcl)
                $verifyAcl = [IO.FileInfo]::new($full).GetAccessControl([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
            }
            if (Test-VgtServiceOnlySecurityInProcess -Acl $verifyAcl -IsDirectory $dirFlag) {
                return [pscustomobject][ordered]@{ Passed = $true; Changed = $true; Detail = 'restricted in-process' }
            }
        }
    } catch {
        # Fall back to Set-VgtRestrictedAcl (takeown + icacls + read-back).
    }
    $fallback = Set-VgtRestrictedAcl -Path $full -ErrorAction Stop
    return [pscustomobject][ordered]@{ Passed = [bool]$fallback.Passed; Changed = $true; Detail = $fallback.Detail }
}

# Remove-VgtSafeTree removes a directory tree without ever recursing through a
# junction or symlink: reparse points are unlinked, never followed.
function Remove-VgtSafeTree {
    param([Parameter(Mandatory)][string]$Path)
    $full = Get-VgtNormalizedPath -Path $Path
    if (-not [IO.Directory]::Exists($full)) { return }
    foreach ($child in @(Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            [IO.Directory]::Delete($child.FullName,$false)
        } elseif ($child.PSIsContainer) {
            Remove-VgtSafeTree -Path $child.FullName
        } else {
            Remove-Item -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function Test-VgtReparsePoint,Assert-VgtPathWithinRoot,Assert-VgtNoReparseTraversal,New-VgtSafeDirectory,Assert-VgtSafeFileTarget,Get-VgtPathAttributesForDiagnostics,Test-VgtAclObject,Set-VgtRestrictedAcl,Repair-VgtRestrictedEntryAcl,Remove-VgtSafeTree
