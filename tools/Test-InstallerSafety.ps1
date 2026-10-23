# STATUS: DIAMANT VGT SUPREME
# Regression test for installer/InstallerSafety.psm1.
#
# Runs inside a disposable %TEMP% directory and proves that reparse-point
# targets/ancestors are rejected before any write, while normal directories and
# files are accepted. Directory junctions are created with cmd.exe mklink /J,
# which does not require elevation and is available on supported Windows hosts.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'installer\InstallerSafety.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Installer safety module is missing: {0}' -f $modulePath)) }
Import-Module -Name $modulePath -Force

$results = [Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $results.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Installer safety check failed: {0} ({1})' -f $Name,$Detail)) }
}

function Remove-VgtTestDirectory {
    param([string]$Path)
    if (-not [IO.Directory]::Exists($Path)) { return }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            [IO.Directory]::Delete($child.FullName,$false)
        } elseif ($child.PSIsContainer) {
            Remove-VgtTestDirectory -Path $child.FullName
        } else {
            Remove-Item -LiteralPath $child.FullName -Force
        }
    }
    [IO.Directory]::Delete($Path,$false)
}

$sandboxRoot = Join-Path $env:TEMP ('vgt-installer-safety-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $sandboxRoot -ItemType Directory -Force | Out-Null
try {
    $allowedRoot = Join-Path $sandboxRoot 'ProgramData'
    New-Item -Path $allowedRoot -ItemType Directory -Force | Out-Null

    # 1. Missing path below a trusted root is accepted and created.
    $fresh = Join-Path $allowedRoot 'VGT\GeDefense'
    $created = New-VgtSafeDirectory -Path $fresh -AllowedRoot $allowedRoot
    Add-Check -Name 'fresh-directory-created' -Passed ([IO.Directory]::Exists($created)) -Detail $created
    Add-Check -Name 'fresh-directory-not-reparse' -Passed (-not (Test-VgtReparsePoint -Path $fresh))

    # 2. Existing regular directory passes the traversal check.
    Assert-VgtNoReparseTraversal -Path $fresh -AllowedRoot $allowedRoot
    Add-Check -Name 'regular-directory-accepted' -Passed $true

    # 3. Directory junction as the target leaf is rejected.
    $junctionTarget = Join-Path $sandboxRoot 'attacker-target'
    New-Item -Path $junctionTarget -ItemType Directory -Force | Out-Null
    $junctionLink = Join-Path $allowedRoot 'VGT\Branding'
    New-Item -Path (Split-Path -Parent $junctionLink) -ItemType Directory -Force | Out-Null
    & "$env:SystemRoot\System32\cmd.exe" /c mklink /J "`"$junctionLink`"" "`"$junctionTarget`"" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-VgtReparsePoint -Path $junctionLink)) {
        throw [InvalidOperationException]::new('Unable to create the directory-junction test fixture (test environment limitation).')
    }
    $junctionRejected = $false
    try { Assert-VgtNoReparseTraversal -Path $junctionLink -AllowedRoot $allowedRoot } catch { $junctionRejected = $true }
    Add-Check -Name 'junction-target-rejected' -Passed $junctionRejected

    $junctionWriteRejected = $false
    try { New-VgtSafeDirectory -Path $junctionLink -AllowedRoot $allowedRoot | Out-Null } catch { $junctionWriteRejected = $true }
    Add-Check -Name 'junction-write-rejected' -Passed $junctionWriteRejected

    # 4. Reparse point in an ancestor is rejected for a non-existent child.
    $nestedChild = Join-Path $junctionLink 'nested\deep'
    $ancestorRejected = $false
    try { Assert-VgtNoReparseTraversal -Path $nestedChild -AllowedRoot $allowedRoot } catch { $ancestorRejected = $true }
    Add-Check -Name 'junction-ancestor-rejected' -Passed $ancestorRejected

    # 5. Paths outside the allowed root are rejected.
    $outsideRejected = $false
    try { Assert-VgtNoReparseTraversal -Path (Join-Path $sandboxRoot 'outside') -AllowedRoot $allowedRoot } catch { $outsideRejected = $true }
    Add-Check -Name 'outside-root-rejected' -Passed $outsideRejected

    # 6. File targets: regular files pass, directories are refused.
    $safeFile = Assert-VgtSafeFileTarget -Path (Join-Path $allowedRoot 'VGT\install.log') -AllowedRoot $allowedRoot
    Add-Check -Name 'safe-file-target-accepted' -Passed ($safeFile.Length -gt 0)
    $fileTargetIsDirectoryRejected = $false
    try { Assert-VgtSafeFileTarget -Path $fresh -AllowedRoot $allowedRoot | Out-Null } catch { $fileTargetIsDirectoryRejected = $true }
    Add-Check -Name 'file-target-directory-rejected' -Passed $fileTargetIsDirectoryRejected

    [pscustomobject][ordered]@{
        Status = 'PASS'
        Checks = $results.Count
        Results = $results.ToArray()
    }
} finally {
    Remove-VgtTestDirectory -Path $sandboxRoot
}
