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
    $root = (Get-VgtNormalizedPath -Path $AllowedRoot).TrimEnd('\')
    if ($full -eq $root) { return }
    $rootPrefix = $root + '\'
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
    $root = (Get-VgtNormalizedPath -Path $AllowedRoot).TrimEnd('\')
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

Export-ModuleMember -Function Test-VgtReparsePoint,Assert-VgtPathWithinRoot,Assert-VgtNoReparseTraversal,New-VgtSafeDirectory,Assert-VgtSafeFileTarget,Get-VgtPathAttributesForDiagnostics
