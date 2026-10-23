# STATUS: DIAMANT VGT SUPREME
# Static regression checks for the installer hardening sequence (SC-FIND-008 /
# SC-FIND-011). These checks parse the real scripts with the PowerShell AST and
# verify that the reparse-point validation, the restricted log-directory ACL and
# the unchanged data-root ACL ordering are present in the intended order.
#
# This is a static gate, not a live installation test: it proves the code
# structure, not runtime behaviour on a target host.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$installPath = Join-Path $projectRoot 'installer\Install-GeDefense.ps1'
$uninstallPath = Join-Path $projectRoot 'installer\Uninstall-GeDefense.ps1'
$checks = [Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Installer hardening check failed: {0} ({1})' -f $Name,$Detail)) }
}

function Get-VgtFunctionBody {
    param([string]$Text,[string]$FunctionName)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw [IO.InvalidDataException]::new(('PowerShell parse failure while analysing {0}' -f $FunctionName)) }
    $functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },$true))
    $match = @($functions | Where-Object { $_.Name -eq $FunctionName })
    if ($match.Count -ne 1) { throw [IO.InvalidDataException]::new(('Expected exactly one function {0}, found {1}.' -f $FunctionName,$match.Count)) }
    return $match[0].Body.Extent.Text
}

function Assert-Order {
    param([string]$Name,[string]$Text,[string]$First,[string]$Second)
    $firstIndex = $Text.IndexOf($First,[StringComparison]::Ordinal)
    $secondIndex = $Text.IndexOf($Second,[StringComparison]::Ordinal)
    Add-Check -Name $Name -Passed ($firstIndex -ge 0 -and $secondIndex -ge 0 -and $firstIndex -lt $secondIndex) -Detail ('first={0} second={1}' -f $firstIndex,$secondIndex)
}

foreach ($path in @($installPath,$uninstallPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Installer script is missing: {0}' -f $path)) }
}
$install = Get-Content -LiteralPath $installPath -Raw -Encoding UTF8
$uninstall = Get-Content -LiteralPath $uninstallPath -Raw -Encoding UTF8

# 1. Safety module import and early reparse validation.
Add-Check -Name 'install-imports-safety-module' -Passed ($install.Contains("Import-Module -Name `$safetyModule -Force"))
Add-Check -Name 'uninstall-imports-safety-module' -Passed ($uninstall.Contains("Import-Module -Name `$safetyModule -Force"))
$assertPathsBody = Get-VgtFunctionBody -Text $install -FunctionName 'Assert-VgtInstallerPaths'
foreach ($expected in @('$installRoot','$dataRoot','$brandingRoot','$installerLogRoot','$startMenuRoot')) {
    Add-Check -Name ('assert-paths-covers-' + $expected.TrimStart('$')) -Passed ($assertPathsBody.Contains(('Assert-VgtNoReparseTraversal -Path {0}' -f $expected)))
}
Assert-Order -Name 'initialize-logging-before-first-phase-write' -Text $install -First 'Initialize-VgtInstallLogging' -Second "Write-VgtInstallPhase -Phase 'Elevation'"

# 2. The log path is never written before the restricted log ACL exists.
$writePhaseBody = Get-VgtFunctionBody -Text $install -FunctionName 'Write-VgtInstallPhase'
$writeLogLineBody = Get-VgtFunctionBody -Text $install -FunctionName 'Write-VgtLogLine'
Add-Check -Name 'write-phase-buffers-until-ready' -Passed ($writePhaseBody.Contains('installLogReady') -and $writePhaseBody.Contains('Write-VgtLogLine'))
Add-Check -Name 'write-phase-no-direct-log-write' -Passed (-not $writePhaseBody.Contains('Add-Content -LiteralPath $installLog'))
Add-Check -Name 'log-line-writer-is-single-write-path' -Passed ($writeLogLineBody.Contains('Add-Content -LiteralPath $installLog'))
$initBody = Get-VgtFunctionBody -Text $install -FunctionName 'Initialize-VgtInstallLogging'
Add-Check -Name 'init-validates-paths-first' -Passed ($initBody.Contains('Assert-VgtInstallerPaths') -and ($initBody.IndexOf('Assert-VgtInstallerPaths',[StringComparison]::Ordinal) -lt $initBody.IndexOf('New-VgtSafeDirectory -Path $installerLogRoot',[StringComparison]::Ordinal)))
Add-Check -Name 'init-hardens-log-acl' -Passed ($initBody.Contains("Invoke-IcaclsChecked -Target `$installerLogRoot -Phase 'InstallerLogACL'") -and $initBody.Contains('*S-1-5-18:(OI)(CI)F') -and $initBody.Contains('*S-1-5-32-544:(OI)(CI)F'))
$aclIndex = $initBody.IndexOf("Invoke-IcaclsChecked -Target `$installerLogRoot",[StringComparison]::Ordinal)
$readyIndex = $initBody.IndexOf('$script:installLogReady = $true',[StringComparison]::Ordinal)
$flushIndex = $initBody.IndexOf('Write-VgtLogLine -Line $bufferedLine',[StringComparison]::Ordinal)
Add-Check -Name 'init-acl-before-ready-before-first-write' -Passed ($aclIndex -ge 0 -and $readyIndex -gt $aclIndex -and $flushIndex -gt $readyIndex)

# 3. Target directories are created only through the reparse-safe helper.
Add-Check -Name 'no-raw-force-create-of-target-roots' -Passed (-not $install.Contains('New-Item -Path $installRoot,$dataRoot,$brandingRoot'))
foreach ($expected in @('$installRoot','$dataRoot','$brandingRoot')) {
    Add-Check -Name ('safe-create-' + $expected.TrimStart('$')) -Passed ($install.Contains(('New-VgtSafeDirectory -Path {0} -AllowedRoot' -f $expected)))
}
Assert-Order -Name 'path-validation-before-root-creation' -Text $install -First 'Assert-VgtInstallerPaths' -Second 'New-VgtSafeDirectory -Path $installRoot'
Add-Check -Name 'mhx-directories-reparse-checked' -Passed ($install.Contains('Assert-VgtNoReparseTraversal -Path $mhxStateRoot -AllowedRoot $dataRoot') -and $install.Contains('Assert-VgtNoReparseTraversal -Path $intelligenceRoot -AllowedRoot $dataRoot'))
Add-Check -Name 'startmenu-reparse-checked' -Passed ($install.Contains('Assert-VgtNoReparseTraversal -Path $startMenu -AllowedRoot'))
Add-Check -Name 'token-path-reparse-checked' -Passed ($install.Contains('Assert-VgtSafeFileTarget -Path $tokenPath -AllowedRoot $dataRoot'))

# 4. The proven data-root ACL sequence must stay SYSTEM/Administrators-only.
# The operator group no longer reads product data directly; Center/Tray use the
# OS-identity operator broker and the master token is break-glass only
# (DP-FIND-001 / UI-FIND-001, 5.1.4).
$dataAclCount = ([Regex]::Matches($install,"-Target \`$dataRoot -Phase 'DataACL'")).Count
Add-Check -Name 'data-acl-applied-exactly-once' -Passed ($dataAclCount -eq 1) -Detail ('count={0}' -f $dataAclCount)
$dataAclIndex = $install.IndexOf('$dataAclArguments')
$dataAclBlock = if ($dataAclIndex -ge 0) { $install.Substring($dataAclIndex, [Math]::Min(320, $install.Length - $dataAclIndex)) } else { '' }
Add-Check -Name 'data-acl-system-admin-only' -Passed ($dataAclBlock.Contains("'/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'") -and -not $dataAclBlock.Contains('OperatorGroupSid'))
Assert-Order -Name 'data-acl-before-service-start' -Text $install -First "Invoke-IcaclsChecked -Target `$dataRoot -Phase 'DataACL'" -Second 'Start-Service -Name $serviceName'
$tokenAclIndex = $install.IndexOf('$tokenAclArguments')
$tokenAclBlock = if ($tokenAclIndex -ge 0) { $install.Substring($tokenAclIndex, [Math]::Min(240, $install.Length - $tokenAclIndex)) } else { '' }
Add-Check -Name 'token-acl-system-admin-only' -Passed ($tokenAclBlock.Contains("'/grant:r','*S-1-5-18:F','*S-1-5-32-544:F'") -and -not $tokenAclBlock.Contains('OperatorGroupSid'))
Add-Check -Name 'installer-has-downgrade-guard' -Passed ($install.Contains('Downgrade rejected') -and $install.Contains('[switch]$AllowDowngrade'))
Add-Check -Name 'branding-acl-hardened' -Passed ($install.Contains("Invoke-IcaclsChecked -Target `$brandingRoot -Phase 'BrandingACL'") -and $install.Contains('*S-1-5-32-545:(OI)(CI)RX'))

# 5. Product ownership marker for safe uninstall of group/trust state.
Add-Check -Name 'install-records-group-ownership' -Passed ($install.Contains("New-ItemProperty -Path `$stateKey -Name OperatorGroupCreated") -and $install.Contains("New-ItemProperty -Path `$stateKey -Name InstallerAddedMembers"))
Add-Check -Name 'uninstall-reads-ownership-marker' -Passed ($uninstall.Contains('OperatorGroupCreated') -and $uninstall.Contains('InstallerAddedMembers'))
Add-Check -Name 'uninstall-retains-legacy-groups' -Passed ($uninstall.Contains("no product ownership marker (pre-5.1.3 install)"))

# 6. Uninstall removes trust anchor/token safely and never touches the root store.
Add-Check -Name 'uninstall-removes-publisher-trust' -Passed ($uninstall.Contains("Cert:\LocalMachine\TrustedPublisher\`$(`$certificate.Thumbprint)") -and $uninstall.Contains('Remove-Item -LiteralPath $publisherStorePath -Force'))
Add-Check -Name 'uninstall-never-touches-root-store' -Passed (-not $uninstall.Contains('Cert:\LocalMachine\Root'))
Add-Check -Name 'uninstall-wipes-token' -Passed ($uninstall.Contains('Remove-VgtSecretFile -Path $tokenPath') -and $uninstall.Contains('RandomNumberGenerator'))
Add-Check -Name 'uninstall-purge-data-switch' -Passed ($uninstall.Contains('[switch]$PurgeData') -and $uninstall.Contains('Remove-VgtTreeSafely -Path $dataRoot'))
Add-Check -Name 'uninstall-accepts-diagnostic-log-parameter' -Passed ($uninstall.Contains('[string]$DiagnosticLogPath'))
Assert-Order -Name 'uninstall-logging-before-removal' -Text $uninstall -First 'Initialize-VgtUninstallLogging' -Second 'Remove-NetFirewallRule'
Add-Check -Name 'uninstall-run-key-uses-remove-itemproperty' -Passed ($uninstall.Contains("Remove-ItemProperty -LiteralPath `$runKey -Name 'VGTGeDefenseTray'"))

# 7. Bootstrap always passed -DiagnosticLogPath for Install and Uninstall; the
# uninstall script must expose the parameter or the elevated child exits early.
$bootstrap = Get-Content -LiteralPath (Join-Path $projectRoot 'installer\Bootstrap-GeDefense.ps1') -Raw -Encoding UTF8
Add-Check -Name 'bootstrap-passes-diagnostic-log' -Passed ($bootstrap.Contains("'-DiagnosticLogPath'"))
Add-Check -Name 'bootstrap-does-not-self-root' -Passed (-not $bootstrap.Contains('Cert:\CurrentUser\Root'))

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = 'static-ast'
    Checks = $checks.Count
    Results = $checks.ToArray()
}
