# STATUS: DIAMANT VGT SUPREME
# Static + parser regression checks for the hardened installer/engine sequence.
#
# The checks parse the real scripts with the PowerShell AST and verify:
#   - every changed PowerShell file parses without errors
#   - %ProgramData%\VGT and SecurityCenter receive explicit, read-back verified
#     SYSTEM/Administrators DACLs (FIND-WIN-005)
#   - the hardening baseline is HMAC-authenticated and binds the audit-policy CSV
#     content (FIND-WIN-005)
#   - the payload is staged into a protected ProgramData directory and the final
#     Program Files destination is re-verified after the copy (FIND-WIN-013)
#   - the Inno installer hard-pins the release certificate thumbprint, keeps no
#     permanent {app}\payload and preserves the running uninstaller (FIND-WIN-014)
#   - the downgrade guard compares prerelease suffixes (FIND-WIN-022)
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
$bootstrapPath = Join-Path $projectRoot 'installer\Bootstrap-GeDefense.ps1'
$safetyPath = Join-Path $projectRoot 'installer\InstallerSafety.psm1'
$commonPath = Join-Path $projectRoot 'engine\Modules\Vgt.Common.psm1'
$innoPath = Join-Path $projectRoot 'installer\inno\GeDefense.iss'
$installerMainPath = Join-Path $projectRoot 'src\GeDefense\windows\cmd\gedefense-installer\main.go'
$checks = [Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name,[bool]$Passed,[string]$Detail = '')
    $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if (-not $Passed) { throw [InvalidOperationException]::new(('Installer hardening check failed: {0} ({1})' -f $Name,$Detail)) }
}

function Get-VgtParsedAst {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('File is missing: {0}' -f $Path)) }
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) {
        throw [IO.InvalidDataException]::new(('PowerShell parse failure in {0}: {1}' -f $Path,(@($errors | ForEach-Object { $_.Message }) -join '; ')))
    }
    return $ast
}

function Get-VgtFunctionBody {
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][string]$FunctionName)
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

# 1. Parser gate for every changed PowerShell file.
foreach ($path in @($installPath,$uninstallPath,$bootstrapPath,$safetyPath,$commonPath,(Join-Path $projectRoot 'tools\Test-VgtBaselineIntegrity.ps1'))) {
    $null = Get-VgtParsedAst -Path $path
    Add-Check -Name ('ps-parser-ok-' + (Split-Path -Leaf $path)) -Passed $true -Detail $path
}

$install = Get-Content -LiteralPath $installPath -Raw -Encoding UTF8
$uninstall = Get-Content -LiteralPath $uninstallPath -Raw -Encoding UTF8
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw -Encoding UTF8
$safety = Get-Content -LiteralPath $safetyPath -Raw -Encoding UTF8
$common = Get-Content -LiteralPath $commonPath -Raw -Encoding UTF8
$inno = Get-Content -LiteralPath $innoPath -Raw -Encoding UTF8
$installerMain = Get-Content -LiteralPath $installerMainPath -Raw -Encoding UTF8

# 2. Safety module import and early reparse validation.
Add-Check -Name 'install-imports-safety-module' -Passed ($install.Contains("Import-Module -Name `$safetyModule -Force"))
Add-Check -Name 'uninstall-imports-safety-module' -Passed ($uninstall.Contains("Import-Module -Name `$safetyModule -Force"))
$assertPathsBody = Get-VgtFunctionBody -Text $install -FunctionName 'Assert-VgtInstallerPaths'
foreach ($expected in @('$installRoot','$programDataVgtRoot','$dataRoot','$securityCenterRoot','$installerCacheRoot','$brandingRoot','$installerLogRoot','$startMenuRoot')) {
    Add-Check -Name ('assert-paths-covers-' + $expected.TrimStart('$')) -Passed ($assertPathsBody.Contains(('Assert-VgtNoReparseTraversal -Path {0}' -f $expected)))
}
Assert-Order -Name 'initialize-logging-before-first-phase-write' -Text $install -First 'Initialize-VgtInstallLogging' -Second "Write-VgtInstallPhase -Phase 'Elevation'"

# 3. Explicit, read-back verified ACLs (no blind icacls sequence any more).
Add-Check -Name 'install-no-blind-icacls' -Passed (-not $install.Contains('Invoke-IcaclsChecked'))
Add-Check -Name 'safety-exports-restricted-acl' -Passed ($safety.Contains('function Set-VgtRestrictedAcl') -and $safety.Contains('function Invoke-VgtIcaclsMutation') -and $safety.Contains("'/reset'") -and $safety.Contains("'/inheritance:r'") -and $safety.Contains("'/grant:r'"))
Add-Check -Name 'safety-acl-verifies-readback' -Passed ($safety.Contains('function Test-VgtAclObject') -and $safety.Contains("AreAccessRulesProtected"))
$initBody = Get-VgtFunctionBody -Text $install -FunctionName 'Initialize-VgtInstallLogging'
Add-Check -Name 'product-root-acl-before-log' -Passed ($initBody.Contains("Set-VgtInstallAcl -Target `$programDataVgtRoot -Phase 'ProductRootACL'") -and ($initBody.IndexOf("Set-VgtInstallAcl -Target `$programDataVgtRoot",[StringComparison]::Ordinal) -lt $initBody.IndexOf('New-VgtSafeDirectory -Path $installerLogRoot',[StringComparison]::Ordinal)))
Add-Check -Name 'installer-log-acl-before-first-write' -Passed ($initBody.Contains("Set-VgtInstallAcl -Target `$installerLogRoot -Phase 'InstallerLogACL'") -and ($initBody.IndexOf("Set-VgtInstallAcl -Target `$installerLogRoot",[StringComparison]::Ordinal) -lt $initBody.IndexOf('$script:installLogReady = $true',[StringComparison]::Ordinal)))
foreach ($expectedAcl in @(
    "Set-VgtInstallAcl -Target `$installRoot -Phase 'ProgramACL' -AllowsUsersRead",
    "Set-VgtInstallAcl -Target `$dataRoot -Phase 'DataACL'",
    "Set-VgtInstallAcl -Target `$securityCenterRoot -Phase 'SecurityCenterACL'",
    "Set-VgtInstallAcl -Target `$installerCacheRoot -Phase 'InstallerCacheACL'",
    "Set-VgtInstallAcl -Target `$brandingRoot -Phase 'BrandingACL' -AllowsUsersRead",
    "Set-VgtInstallAcl -Target `$tokenPath -Phase 'TokenACL'",
    "Set-VgtInstallAcl -Target `$intelligenceRoot -Phase 'ThreatIntelACL'"
)) {
    Add-Check -Name ('install-acl-' + $expectedAcl.Split(' ')[2].TrimStart('$')) -Passed ($install.Contains($expectedAcl))
}
Assert-Order -Name 'data-acl-before-payload-copy' -Text $install -First "Set-VgtInstallAcl -Target `$dataRoot -Phase 'DataACL'" -Second "Copy-Item -LiteralPath (Join-Path `$resolvedPayload 'bin')"
Assert-Order -Name 'data-acl-before-service-start' -Text $install -First "Set-VgtInstallAcl -Target `$dataRoot -Phase 'DataACL'" -Second 'Start-Service -Name $serviceName'
Add-Check -Name 'data-acl-has-no-operator-group' -Passed (-not $install.Contains('OperatorGroupSid:(OI)') -and -not $install.Contains('/grant:r'))

# 4. Protected payload staging and destination re-verification (FIND-WIN-013).
Add-Check -Name 'install-stages-payload-protected' -Passed ($install.Contains('function Initialize-VgtProtectedPayloadStage') -and $install.Contains("Set-VgtInstallAcl -Target `$stage -Phase 'StagingACL'"))
Add-Check -Name 'install-restages-before-trust-checks' -Passed ($install.Contains('$resolvedPayload = Initialize-VgtProtectedPayloadStage -SourcePayload $resolvedSourcePayload') -and ($install.IndexOf('$resolvedPayload = Initialize-VgtProtectedPayloadStage',[StringComparison]::Ordinal) -lt $install.IndexOf('$catalog = Test-FileCatalog',[StringComparison]::Ordinal)))
Add-Check -Name 'install-verifies-destination-after-copy' -Passed ($install.Contains('function Assert-VgtInstalledPayload') -and $install.Contains('Get-FileHash -LiteralPath $destination') -and $install.Contains('Get-AuthenticodeSignature -LiteralPath $destination'))
Assert-Order -Name 'destination-verify-after-copy' -Text $install -First "Copy-Item -LiteralPath (Join-Path `$resolvedPayload 'bin')" -Second 'Assert-VgtInstalledPayload -StageRoot'
Add-Check -Name 'install-rejects-reparse-in-transport' -Passed ($install.Contains('Payload transport tree contains a reparse point'))
Add-Check -Name 'install-cleans-protected-stage' -Passed ($install.Contains("Write-VgtInstallPhase -Phase 'PayloadCleanup'") -and $install.Contains('Remove-VgtSafeTree -Path $script:protectedPayloadStage'))
Add-Check -Name 'go-installer-elevates-before-extract' -Passed ($installerMain.Contains('runElevatedSelf') -and $installerMain.Contains('if !elevated {') -and ($installerMain.IndexOf('if !elevated {',[StringComparison]::Ordinal) -lt $installerMain.IndexOf('createInstallerStaging()',[StringComparison]::Ordinal)))
Add-Check -Name 'go-installer-no-localappdata-staging' -Passed (-not $installerMain.Contains('os.UserCacheDir') -and -not $installerMain.Contains('os.MkdirTemp("", "vgt-setup-")'))
Add-Check -Name 'go-installer-protects-staging' -Passed ($installerMain.Contains('hardenInstallerStagingDirectory') -and $installerMain.Contains('assertNoReparseComponents'))

# 5. Hardening-baseline HMAC protection (FIND-WIN-005).
Add-Check -Name 'common-hmac-baseline' -Passed ($common.Contains('HMACSHA256') -and $common.Contains("algorithm = 'HMAC-SHA256'") -and $common.Contains('baselineHmac'))
Add-Check -Name 'common-binds-audit-policy-content' -Passed ($common.Contains('auditPolicySha256') -and $common.Contains('Get-VgtAuditPolicyContentHash'))
Add-Check -Name 'common-uses-constant-time-compare' -Passed ($common.Contains('function Test-VgtConstantTimeHexEqual'))
Add-Check -Name 'common-baseline-key-store' -Passed ($common.Contains('Get-VgtBaselineKeyBytes') -and $common.Contains("'VGT\GeDefense\keys'") -and $common.Contains('baseline-hmac.key'))
Add-Check -Name 'common-no-unkeyed-sha256-integrity' -Passed (-not $common.Contains("algorithm = 'SHA256'") -and -not $common.Contains('baselineSha256 = (Get-VgtBaselineIntegrityHash'))
Add-Check -Name 'common-legacy-baseline-is-violation' -Passed ($common.Contains("if (`$integrity -ne 'Valid')") -and $common.Contains('rollback rejected'))
Add-Check -Name 'common-data-root-hardened' -Passed ($common.Contains('function Get-VgtDataRoot') -and $common.Contains('Set-VgtServiceAcl -Path $vgtRoot') -and $common.Contains("Set-VgtServiceAcl -Path `$root"))
Add-Check -Name 'common-reparse-checks' -Passed ($common.Contains('function Test-VgtReparsePoint') -and $common.Contains('function Assert-VgtNoReparseTraversal'))

# 6. Inno thumbprint pin, transient payload, uninstaller preservation.
Add-Check -Name 'inno-thumbprint-pinned' -Passed ($inno.Contains('#define ExpectedReleaseThumbprint "1E7B1641FC2E8EB82735216829C13721E3B9D895"') -and $inno.Contains('VerifyEmbeddedCertificateThumbprint'))
Assert-Order -Name 'inno-thumbprint-check-before-root-import' -Text $inno -First 'VerifyEmbeddedCertificateThumbprint(CertificatePath)' -Second 'certutil.exe'
Add-Check -Name 'inno-no-permanent-app-payload' -Passed (-not $inno.Contains('DestDir: "{app}\payload"') -and -not $inno.Contains('DestDir: "{tmp}\vgt-payload"') -and $inno.Contains('DestDir: "{commonappdata}\VGT\GeDefense\inno-transport"') -and $inno.Contains('PrepareInnoTransportStage') -and $inno.Contains('DelTree(PayloadRoot, True, True, True)'))
Assert-Order -Name 'inno-transport-stage-hardened-before-bootstrap' -Text $inno -First 'PrepareInnoTransportStage;' -Second 'RunBootstrap;'
Add-Check -Name 'inno-uninstall-uses-installed-script' -Passed ($inno.Contains('{app}\installer\Uninstall-GeDefense.ps1') -and -not $inno.Contains('-Operation Uninstall'))
Add-Check -Name 'inno-import-readback-verified' -Passed ($inno.Contains('VerifyImportedCertificate') -and $inno.Contains('Get-ChildItem Cert:\LocalMachine\Root'))
Add-Check -Name 'inno-records-root-import-marker' -Passed ($inno.Contains('RootCertImportedThumbprint'))
Add-Check -Name 'uninstall-preserves-inno-uninstaller' -Passed ($uninstall.Contains('$preservedNames = @(''GeDefense-Setup.exe'',''unins000.exe'',''unins000.dat''') -and $uninstall.Contains("'installer')"))
Add-Check -Name 'uninstall-root-removal-guarded-by-marker' -Passed ($uninstall.Contains('RootCertImportedThumbprint') -and $uninstall.Contains("Cert:\LocalMachine\Root") -and $uninstall.Contains('marker thumbprint mismatch'))
Add-Check -Name 'bootstrap-installer-path-optional' -Passed (-not $bootstrap.Contains('[Parameter(Mandatory)][ValidatePattern(''^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$'')][string]$InstallerPath'))
Add-Check -Name 'uninstall-supports-installed-trust-mode' -Passed ($uninstall.Contains('release-trust.txt') -and $uninstall.Contains('fullPayloadMode'))
Add-Check -Name 'uninstall-purges-product-data-roots' -Passed ($uninstall.Contains('@($dataRoot,$securityCenterRoot,$installerCacheRoot)'))

# 7. FIND-WIN-022: prerelease-aware downgrade comparison (negative tests).
$versionFunctions = @('ConvertTo-VgtVersionParts','Compare-VgtVersionParts')
$versionTokens = $null
$versionErrors = $null
$versionAst = [Management.Automation.Language.Parser]::ParseInput($install,[ref]$versionTokens,[ref]$versionErrors)
if (@($versionErrors).Count -ne 0) { throw [IO.InvalidDataException]::new('PowerShell parse failure while extracting the version guard functions.') }
$versionFunctionNodes = @($versionAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $versionFunctions -contains $node.Name },$true))
Add-Check -Name 'version-functions-present' -Passed ($versionFunctionNodes.Count -eq 2)
foreach ($functionNode in $versionFunctionNodes) { . ([scriptblock]::Create($functionNode.Extent.Text)) }
function Test-VgtDowngradeCase {
    param([string]$Installed,[string]$Release,[int]$ExpectedSign)
    $old = ConvertTo-VgtVersionParts -Value $Installed
    $new = ConvertTo-VgtVersionParts -Value $Release
    if ($null -eq $old -or $null -eq $new) { return $ExpectedSign -eq -99 }
    $sign = [Math]::Sign((Compare-VgtVersionParts -Left $new -Right $old))
    return ($sign -eq $ExpectedSign)
}
$downgradeCases = @(
    @('5.3.1-beta.2','5.3.1',1),
    @('5.3.1','5.3.1-beta.2',-1),
    @('5.3.2','5.3.1',-1),
    @('5.3.1','5.3.2',1),
    @('5.3.0-beta.2','5.3.0',1),
    @('5.3.1-beta.2','5.3.1-beta.10',1),
    @('5.3.1-beta.10','5.3.1-beta.2',-1),
    @('5.3.0','5.3.0',0),
    @('5.2.9','5.3.0-beta.2',1)
)
foreach ($downgradeCase in $downgradeCases) {
    Add-Check -Name ('downgrade-compare-' + $downgradeCase[0] + '-vs-' + $downgradeCase[1]) -Passed (Test-VgtDowngradeCase -Installed $downgradeCase[0] -Release $downgradeCase[1] -ExpectedSign ([int]$downgradeCase[2]))
}
Add-Check -Name 'install-uses-prerelease-compare' -Passed ($install.Contains('Compare-VgtVersionParts -Left $newParts -Right $oldParts') -and -not $install.Contains('$olderThanInstalled = ($oldParts[0] -gt $newParts[0])'))

[pscustomobject][ordered]@{
    Status = 'PASS'
    Mode = 'static-ast'
    Checks = $checks.Count
    Results = $checks.ToArray()
}
