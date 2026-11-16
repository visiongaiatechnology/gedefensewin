# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath = '',
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.log$')][string]$DiagnosticLogPath = '',
    # Explicit, auditable rollback switch. The default is fail-closed and
    # refuses to replace a newer installation (SC-FIND-003 local hardening);
    # the externally anchored anti-rollback channel remains an owner-accepted
    # external blocker.
    [switch]$AllowDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$programDataVgtRoot = Join-Path $env:ProgramData 'VGT'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense'
$securityCenterRoot = Join-Path $env:ProgramData 'VGT\SecurityCenter'
$installerCacheRoot = Join-Path $env:ProgramData 'VGT\InstallerCache'
$brandingRoot = Join-Path $env:ProgramData 'VGT\Branding'
$installerLogRoot = Join-Path $env:ProgramData 'VGT\InstallerLogs'
$startMenuRoot = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
$stateKey = 'HKLM:\SOFTWARE\VGT\GeDefense'
$operatorGroup = 'VGT GeDefense Operators'
$operatorGroupDescription = 'VGT GeDefense security center operators.'
$installLog = Join-Path $installerLogRoot 'install.log'
$resolvedDiagnosticLog = ''
$script:installLogReady = $false
$script:installLogBuffer = [Collections.Generic.List[string]]::new()
$script:protectedPayloadStage = ''
$safetyModule = Join-Path $PSScriptRoot 'InstallerSafety.psm1'
if (-not (Test-Path -LiteralPath $safetyModule -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Installer safety module is missing.') }
Import-Module -Name $safetyModule -Force

function Write-VgtLogLine {
    param([Parameter(Mandatory)][string]$Line)
    if ($resolvedDiagnosticLog) {
        try {
            Add-Content -LiteralPath $resolvedDiagnosticLog -Value $Line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 50
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
    }
    try {
        Add-Content -LiteralPath $installLog -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

function Write-VgtInstallPhase {
    param([Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$State,[AllowEmptyString()][string]$Detail = '')
    $safeDetail = if ($Detail) { $Detail.Replace("`r",' ').Replace("`n",' ') } else { '' }
    $line = '{0}|{1}|{2}|{3}' -f [DateTime]::UtcNow.ToString('o'),$Phase,$State,$safeDetail
    # The log target is only used after Initialize-VgtInstallLogging has proven
    # the path reparse-free and applied the restrictive log-directory ACL.
    if (-not $script:installLogReady) {
        [void]$script:installLogBuffer.Add($line)
        return
    }
    Write-VgtLogLine -Line $line
}

trap {
    try {
        $msg = if ($_.Exception) { $_.Exception.Message } else { 'Unknown installer exception' }
        if ($script:installLogReady) {
            Write-VgtInstallPhase -Phase 'Installer' -State 'FAILED' -Detail $msg
        } elseif ($resolvedDiagnosticLog) {
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value ('{0}|Installer|FAILED|{1}' -f [DateTime]::UtcNow.ToString('o'),$msg.Replace("`r",' ').Replace("`n",' ')) -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
        if ($script:protectedPayloadStage -and [IO.Directory]::Exists($script:protectedPayloadStage)) {
            try { Remove-VgtSafeTree -Path $script:protectedPayloadStage } catch {}
        }
    } catch {}
    exit 90
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $operation = if ($Arguments.Count -gt 0) { $Arguments[0] } else { 'unknown' }
    $maxAttempts = 15
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $nativeOutput = (& "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1 | Out-String).Trim()
        $nativeExitCode = $LASTEXITCODE
        if ($nativeExitCode -eq 0) {
            Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit=0" -f $operation)
            return
        }
        if ($operation -eq 'delete' -and ($nativeExitCode -eq 1072 -or $nativeExitCode -eq 1060)) {
            # 1072 = ERROR_SERVICE_MARKED_FOR_DELETE, 1060 = ERROR_SERVICE_DOES_NOT_EXIST
            Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit={1}|pending_delete" -f $operation,$nativeExitCode)
            return
        }
        if ($operation -eq 'create' -and $nativeExitCode -eq 1072 -and $attempt -lt $maxAttempts) {
            Start-Sleep -Milliseconds 600
            continue
        }
        Write-VgtInstallPhase -Phase 'ServiceControl' -State 'FAILED' -Detail ("{0}|exit={1}|{2}" -f $operation,$nativeExitCode,$nativeOutput)
        throw [InvalidOperationException]::new(("Service operation '{0}' failed with exit code {1}." -f $operation,$nativeExitCode))
    }
}

function Set-VgtInstallAcl {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Phase,
        [switch]$AllowsUsersRead
    )
    try {
        $verification = Set-VgtRestrictedAcl -Path $Target -AllowsUsersRead:$AllowsUsersRead -ErrorAction Stop
    } catch {
        Write-VgtInstallPhase -Phase $Phase -State 'FAILED' -Detail $_.Exception.Message
        throw [Security.SecurityException]::new(('{0} failed: {1}' -f $Phase,$_.Exception.Message))
    }
    Write-VgtInstallPhase -Phase $Phase -State 'OK' -Detail $verification.Detail
}

function Assert-VgtInstallerPaths {
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programDataRoot) -or [string]::IsNullOrWhiteSpace($programFilesRoot)) { throw [IO.InvalidDataException]::new('ProgramData/ProgramFiles environment is unavailable.') }
    Assert-VgtNoReparseTraversal -Path $installRoot -AllowedRoot $programFilesRoot
    Assert-VgtNoReparseTraversal -Path $programDataVgtRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $dataRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $securityCenterRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $installerCacheRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $brandingRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $installerLogRoot -AllowedRoot $programDataRoot
    Assert-VgtNoReparseTraversal -Path $startMenuRoot -AllowedRoot $programDataRoot
}

function Initialize-VgtInstallLogging {
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $localAppDataRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('LocalApplicationData'))
    Assert-VgtInstallerPaths
    # %ProgramData%\VGT is the single product root. A standard user can create a
    # directory below %ProgramData% and would then own the whole product tree, so
    # the root is created through the reparse-safe helper and immediately receives
    # an inheritance-protected SYSTEM/Administrators-only DACL before any child
    # directory or log line is written (FIND-WIN-005).
    New-VgtSafeDirectory -Path $programDataVgtRoot -AllowedRoot $programDataRoot | Out-Null
    Set-VgtInstallAcl -Target $programDataVgtRoot -Phase 'ProductRootACL'
    if ($DiagnosticLogPath) {
        if ([string]::IsNullOrWhiteSpace($localAppDataRoot)) { throw [IO.InvalidDataException]::new('LocalAppData environment is unavailable.') }
        $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path $localAppDataRoot 'VGT\InstallerDiagnostics')).TrimEnd('\') + '\'
        $candidateDiagnosticLog = [IO.Path]::GetFullPath($DiagnosticLogPath)
        if (-not $candidateDiagnosticLog.StartsWith($diagnosticRoot,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Diagnostic log path escaped the user diagnostic jail.') }
        Assert-VgtNoReparseTraversal -Path $candidateDiagnosticLog -AllowedRoot $localAppDataRoot
        New-VgtSafeDirectory -Path ([IO.Path]::GetDirectoryName($candidateDiagnosticLog)) -AllowedRoot $localAppDataRoot | Out-Null
        $script:resolvedDiagnosticLog = $candidateDiagnosticLog
    }
    New-VgtSafeDirectory -Path $installerLogRoot -AllowedRoot $programDataRoot | Out-Null
    # Restrictive ACL for the persistent installer audit log before the first write.
    Set-VgtInstallAcl -Target $installerLogRoot -Phase 'InstallerLogACL'
    Assert-VgtSafeFileTarget -Path $installLog -AllowedRoot $installerLogRoot | Out-Null
    $script:installLogReady = $true
    foreach ($bufferedLine in $script:installLogBuffer) { Write-VgtLogLine -Line $bufferedLine }
    $script:installLogBuffer.Clear()
}

# FIND-WIN-013: the payload is copied into an Administrators/SYSTEM-only stage
# below %ProgramData%\VGT\GeDefense\staging before it is trusted or copied into
# Program Files. The unprivileged/user-writable transport location is never a
# trust basis: the signed catalog is verified against this protected copy and the
# final destination is verified again after the copy.
function Initialize-VgtProtectedPayloadStage {
    param([Parameter(Mandatory)][string]$SourcePayload)
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
    $stagingParent = Join-Path $dataRoot 'staging'
    New-VgtSafeDirectory -Path $dataRoot -AllowedRoot $programDataRoot | Out-Null
    Set-VgtInstallAcl -Target $dataRoot -Phase 'DataACL'
    New-VgtSafeDirectory -Path $stagingParent -AllowedRoot $programDataRoot | Out-Null
    Set-VgtInstallAcl -Target $stagingParent -Phase 'StagingACL'
    foreach ($stale in @(Get-ChildItem -LiteralPath $stagingParent -Force -ErrorAction SilentlyContinue)) {
        try {
            if ($stale.Attributes -band [IO.FileAttributes]::ReparsePoint) { [IO.Directory]::Delete($stale.FullName,$false) }
            elseif ($stale.PSIsContainer) { Remove-VgtSafeTree -Path $stale.FullName }
            else { Remove-Item -LiteralPath $stale.FullName -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
    foreach ($sourceItem in @(Get-ChildItem -LiteralPath $SourcePayload -Recurse -Force)) {
        if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw [Security.SecurityException]::new(('Payload transport tree contains a reparse point: {0}' -f $sourceItem.FullName))
        }
    }
    $stage = Join-Path $stagingParent ([Guid]::NewGuid().ToString('N'))
    New-VgtSafeDirectory -Path $stage -AllowedRoot $programDataRoot | Out-Null
    Set-VgtInstallAcl -Target $stage -Phase 'StagingACL'
    $stagedEntries = @(Get-ChildItem -LiteralPath $SourcePayload -Force)
    if ($stagedEntries.Count -eq 0) {
        throw [IO.IOException]::new('Source payload directory is empty during staging.')
    }
    foreach ($entry in $stagedEntries) {
        Copy-Item -LiteralPath $entry.FullName -Destination $stage -Recurse -Force
    }
    Assert-VgtNoReparseTraversal -Path $stage -AllowedRoot $programDataRoot
    $script:protectedPayloadStage = $stage
    Write-VgtInstallPhase -Phase 'PayloadStaging' -State 'OK' -Detail $stage
    return $stage
}

# Get-VgtStageDestinationPath maps a staged payload-relative path to the final
# install location. Paths that the installer does not copy are ignored.
function Get-VgtStageDestinationPath {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$BrandingRoot
    )
    $normalized = $RelativePath -replace '/','\'
    $parts = $normalized -split '\\'
    if ($parts.Count -lt 1 -or [string]::IsNullOrWhiteSpace($parts[0])) { return '' }
    switch ($parts[0]) {
        'bin' { return Join-Path $InstallRoot $normalized }
        'engine' { return Join-Path $InstallRoot $normalized }
        'audit' { return Join-Path $InstallRoot $normalized }
        'xdr' { return Join-Path $InstallRoot $normalized }
        'LICENSES' { return Join-Path $InstallRoot $normalized }
        'installer' {
            if ($parts.Count -eq 2 -and @('Uninstall-GeDefense.ps1','InstallerSafety.psm1','vgt-release.cer','release-trust.txt') -contains $parts[1]) {
                return Join-Path (Join-Path $InstallRoot 'installer') $parts[1]
            }
            return ''
        }
        'branding' {
            if ($parts.Count -ne 2) { return '' }
            $mappedName = switch ($parts[1]) {
                'vgt-lockscreen.jpg' { 'vgt-lockscreen.jpg' }
                'vgt-oem-logo.bmp' { 'vgt-oem-logo.bmp' }
                'gedefense-logo-v1.png' { 'gedefense-logo.png' }
                'gedefense.ico' { 'gedefense.ico' }
                default { '' }
            }
            if (-not $mappedName) { return '' }
            return Join-Path $BrandingRoot $mappedName
        }
        default {
            if ($parts.Count -eq 1 -and @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','GEOIP_LICENSE_AND_DEPLOYMENT.md','VERSION') -contains $parts[0]) {
                return Join-Path $InstallRoot $parts[0]
            }
            return ''
        }
    }
}

# Assert-VgtInstalledPayload re-verifies the installed tree AFTER the copy: every
# shipped file must match the SHA-256 of the catalog-verified protected stage and
# every signed artifact must still carry a valid VGT signature at the final
# location. A payload swapped during the copy therefore fails closed.
function Assert-VgtInstalledPayload {
    param(
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$BrandingRoot,
        [Parameter(Mandatory)][object]$Certificate
    )
    $signedExtensions = @('.exe','.dll','.ps1','.psm1','.sys','.cat')
    $verifiedFiles = 0
    foreach ($stagedFile in @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force)) {
        $relative = $stagedFile.FullName.Substring($StageRoot.Length).TrimStart('\')
        $destination = Get-VgtStageDestinationPath -RelativePath $relative -InstallRoot $InstallRoot -BrandingRoot $BrandingRoot
        if ([string]::IsNullOrWhiteSpace($destination)) { continue }
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw [Security.SecurityException]::new(('Installed payload file is missing after copy: {0}' -f $relative))
        }
        $sourceHash = (Get-FileHash -LiteralPath $stagedFile.FullName -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($sourceHash -ne $destinationHash) {
            throw [Security.SecurityException]::new(('Installed payload file failed hash verification after copy: {0}' -f $relative))
        }
        if ($signedExtensions -contains [IO.Path]::GetExtension($relative).ToLowerInvariant()) {
            $sourceSignature = Get-AuthenticodeSignature -LiteralPath $stagedFile.FullName
            $destinationSignature = Get-AuthenticodeSignature -LiteralPath $destination
            if ($sourceSignature.Status -eq 'Valid') {
                if ($destinationSignature.Status -ne 'Valid' -or -not $destinationSignature.SignerCertificate -or $destinationSignature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint) {
                    throw [Security.SecurityException]::new(('Authenticode verification failed at the install destination: {0}' -f $relative))
                }
            } elseif ($destinationSignature.Status -eq 'HashMismatch') {
                throw [Security.SecurityException]::new(('Installed payload signature was invalidated during copy: {0}' -f $relative))
            }
        }
        $verifiedFiles++
    }
    if ($verifiedFiles -lt 10) { throw [Security.SecurityException]::new('Installed payload verification did not cover the expected file set.') }
    Write-VgtInstallPhase -Phase 'PayloadVerify' -State 'OK' -Detail ('{0} files verified at destination' -f $verifiedFiles)
}

# Copy-VgtInstallerSupportFiles installs the signed maintenance script and the
# trust anchor marker that the Inno uninstaller needs. The marker records the
# thumbprint that was verified from the signed catalog, so uninstall can remove
# only product-imported trust anchors.
function Copy-VgtInstallerSupportFiles {
    param(
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][object]$Certificate
    )
    $installerDirectory = Join-Path $InstallRoot 'installer'
    New-VgtSafeDirectory -Path $installerDirectory -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramFiles)) | Out-Null
    foreach ($supportName in @('Uninstall-GeDefense.ps1','InstallerSafety.psm1')) {
        $supportSource = Join-Path (Join-Path $StageRoot 'installer') $supportName
        if (-not (Test-Path -LiteralPath $supportSource -PathType Leaf)) { throw [IO.FileNotFoundException]::new(('Installed uninstaller support file is missing in the payload: {0}' -f $supportName)) }
        Copy-Item -LiteralPath $supportSource -Destination (Join-Path $installerDirectory $supportName) -Force
    }
    Copy-Item -LiteralPath (Join-Path $StageRoot 'vgt-release.cer') -Destination (Join-Path $installerDirectory 'vgt-release.cer') -Force
    Set-Content -LiteralPath (Join-Path $installerDirectory 'release-trust.txt') -Value ([string]$Certificate.Thumbprint) -Encoding ASCII
    Write-VgtInstallPhase -Phase 'UninstallerTrust' -State 'OK' -Detail ([string]$Certificate.Thumbprint)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative token required.')
}
# Reparse-point validation, restricted log directory creation and ACL hardening
# all complete before the first persistent log line is written.
Initialize-VgtInstallLogging
Write-VgtInstallPhase -Phase 'Elevation' -State 'OK' -Detail $identity.Name
$resolvedSourcePayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $resolvedSourcePayload 'bin\gedefense-windows.exe') -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('GeDefense payload is incomplete.')
}
# No trust decision is made on the transport path. The payload is staged into an
# Administrators/SYSTEM-only directory and every subsequent check (catalog,
# signatures, hashes) is performed against this protected copy.
$resolvedPayload = Initialize-VgtProtectedPayloadStage -SourcePayload $resolvedSourcePayload
$versionPath = Join-Path $resolvedPayload 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense release version metadata is missing.') }
$releaseVersion = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
if ($releaseVersion -notmatch '^[56]\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]*)?$') { throw [IO.InvalidDataException]::new('GeDefense release version metadata is invalid.') }

# Downgrade guard (SC-FIND-003 local hardening): never silently replace a newer
# installation with an older one. The externally anchored, manipulation-proof
# anti-rollback channel is an owner-accepted external blocker; this guard is the
# local best-effort control and is auditable in the install log.
# FIND-WIN-022: the comparison includes the -beta.N prerelease suffix. A final
# release is newer than every prerelease of the same base version and numeric
# prerelease identifiers are compared numerically (SemVer ordering), so
# 5.3.1-beta.2 < 5.3.1 < 5.3.2.
function ConvertTo-VgtVersionParts {
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<pre>[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$') {
        $prerelease = ''
        if ($Matches.ContainsKey('pre')) { $prerelease = [string]$Matches.pre }
        return [pscustomobject][ordered]@{
            Major = [int]$Matches.major
            Minor = [int]$Matches.minor
            Patch = [int]$Matches.patch
            Prerelease = $prerelease
        }
    }
    return $null
}

function Compare-VgtVersionParts {
    param([Parameter(Mandatory)][object]$Left,[Parameter(Mandatory)][object]$Right)
    foreach ($partName in @('Major','Minor','Patch')) {
        if ([int]$Left.$partName -gt [int]$Right.$partName) { return 1 }
        if ([int]$Left.$partName -lt [int]$Right.$partName) { return -1 }
    }
    $leftPre = [string]$Left.Prerelease
    $rightPre = [string]$Right.Prerelease
    if ([string]::IsNullOrEmpty($leftPre) -and [string]::IsNullOrEmpty($rightPre)) { return 0 }
    # A final release outranks every prerelease of the same base version.
    if ([string]::IsNullOrEmpty($leftPre)) { return 1 }
    if ([string]::IsNullOrEmpty($rightPre)) { return -1 }
    $leftIdentifiers = @($leftPre -split '\.')
    $rightIdentifiers = @($rightPre -split '\.')
    $identifierCount = [Math]::Max($leftIdentifiers.Count,$rightIdentifiers.Count)
    for ($index = 0; $index -lt $identifierCount; $index++) {
        if ($index -ge $leftIdentifiers.Count) { return -1 }
        if ($index -ge $rightIdentifiers.Count) { return 1 }
        $leftValue = $leftIdentifiers[$index]
        $rightValue = $rightIdentifiers[$index]
        $leftNumber = 0L
        $rightNumber = 0L
        $leftIsNumber = [long]::TryParse($leftValue,[ref]$leftNumber)
        $rightIsNumber = [long]::TryParse($rightValue,[ref]$rightNumber)
        if ($leftIsNumber -and $rightIsNumber) {
            if ($leftNumber -gt $rightNumber) { return 1 }
            if ($leftNumber -lt $rightNumber) { return -1 }
            continue
        }
        if ($leftIsNumber) { return -1 }
        if ($rightIsNumber) { return 1 }
        $compare = [string]::CompareOrdinal($leftValue,$rightValue)
        if ($compare -gt 0) { return 1 }
        if ($compare -lt 0) { return -1 }
    }
    return 0
}
$installedVersionPath = Join-Path $installRoot 'VERSION'
$installedVersion = ''
if (Test-Path -LiteralPath $installedVersionPath -PathType Leaf) {
    $installedVersion = (Get-Content -LiteralPath $installedVersionPath -Raw -Encoding UTF8).Trim()
} else {
    # A previous uninstall or an interrupted transaction can leave the install
    # directory without VERSION and without a complete uninstall entry. Treat
    # that as "no installed version" instead of failing under StrictMode.
    $installedEntry = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense' -ErrorAction SilentlyContinue
    if ($null -ne $installedEntry -and $null -ne $installedEntry.PSObject.Properties['DisplayVersion']) {
        $installedVersion = [string]$installedEntry.DisplayVersion
    }
}
$newParts = ConvertTo-VgtVersionParts -Value $releaseVersion
$oldParts = ConvertTo-VgtVersionParts -Value $installedVersion
if ($null -ne $oldParts -and $null -ne $newParts) {
    $olderThanInstalled = (Compare-VgtVersionParts -Left $newParts -Right $oldParts) -lt 0
    if ($olderThanInstalled -and -not $AllowDowngrade) {
        throw [InvalidOperationException]::new(('Downgrade rejected: installed version {0} is newer than release {1}. Use -AllowDowngrade only for an authorized, documented rollback.' -f $installedVersion, $releaseVersion))
    }
    Write-VgtInstallPhase -Phase 'VersionGuard' -State 'OK' -Detail ('installed={0}|release={1}|downgradeAllowed={2}' -f $installedVersion, $releaseVersion, [bool]$AllowDowngrade)
}
$releaseCertificate = Join-Path $resolvedPayload 'vgt-release.cer'
if (-not (Test-Path -LiteralPath $releaseCertificate -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT release certificate is missing.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($releaseCertificate)
$now = [DateTime]::UtcNow
if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now.AddDays(30)) {
    throw [Security.SecurityException]::new('VGT release certificate validation failed.')
}
$scriptSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($scriptSignature.Status -ne 'Valid' -or -not $scriptSignature.SignerCertificate -or $scriptSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('Installer trust anchor validation failed.')
}
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('VGT payload catalog is missing.') }
$catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
if ($catalogSignature.Status -ne 'Valid' -or -not $catalogSignature.SignerCertificate -or $catalogSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw [Security.SecurityException]::new('VGT payload catalog signer validation failed.')
}
$catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('VGT payload catalog verification failed.') }
# The signing chain must already be trusted. Only publisher trust is persisted so
# LocalSystem can execute the signed GeDefense maintenance scripts under AllSigned.
# Use the .NET store API instead of Import-Certificate: the cmdlet can request an
# interactive confirmation that is unavailable in the non-interactive elevated
# transaction and would abort the whole install with exit code 90.
$publisherStore = [Security.Cryptography.X509Certificates.X509Store]::new(
    [Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
    [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
try {
    $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($releaseCertificate))
} catch {
    throw [Security.SecurityException]::new(('Trusted publisher import failed: {0}' -f $_.Exception.Message))
} finally {
    $publisherStore.Close()
}
Write-VgtInstallPhase -Phase 'Trust' -State 'OK' -Detail $certificate.Thumbprint
$resolvedInstaller = ''
if ($InstallerPath) {
    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
    $installerSignature = Get-AuthenticodeSignature -LiteralPath $resolvedInstaller
    if ($installerSignature.Status -ne 'Valid' -or -not $installerSignature.SignerCertificate -or $installerSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Standalone installer signature validation failed.') }
}

foreach ($processName in @('GeDefenseTray','GeDefenseCenter')) {
    foreach ($process in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
        $expectedPath = Join-Path $installRoot ("bin\{0}.exe" -f $processName)
        $actualPath = try { [IO.Path]::GetFullPath($process.Path) } catch { '' }
        if ($actualPath -and $actualPath.Equals([IO.Path]::GetFullPath($expectedPath),[StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
    }
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    foreach ($proc in @(Get-Process -Name 'gedefense-windows' -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    foreach ($dism in @(Get-Process -Name 'DismHost' -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $dism.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
    Invoke-ScChecked @('delete',$serviceName)
    Start-Sleep -Milliseconds 700
}
Assert-VgtInstallerPaths
$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles)
$programDataRoot = [IO.Path]::GetFullPath($env:ProgramData)
# All product roots are created and hardened BEFORE files are copied into them
# so every copied child inherits the restricted DACL instead of the permissive
# ProgramData/ProgramFiles default.
New-VgtSafeDirectory -Path $installRoot -AllowedRoot $programFilesRoot | Out-Null
Set-VgtInstallAcl -Target $installRoot -Phase 'ProgramACL' -AllowsUsersRead
New-VgtSafeDirectory -Path $dataRoot -AllowedRoot $programDataRoot | Out-Null
# Product data and runtime secrets are SYSTEM/Administrators only. Operators no
# longer read files directly: Center/Tray authenticate through the OS-identity
# operator broker and the master token remains a break-glass credential for
# local administrators. This removes the recursive operator RX ACE that exposed
# evidence/vault keys (DP-FIND-001 / UI-FIND-001).
Set-VgtInstallAcl -Target $dataRoot -Phase 'DataACL'
New-VgtSafeDirectory -Path $securityCenterRoot -AllowedRoot $programDataRoot | Out-Null
Set-VgtInstallAcl -Target $securityCenterRoot -Phase 'SecurityCenterACL'
New-VgtSafeDirectory -Path (Join-Path $securityCenterRoot 'Logs') -AllowedRoot $programDataRoot | Out-Null
New-VgtSafeDirectory -Path (Join-Path $securityCenterRoot 'State') -AllowedRoot $programDataRoot | Out-Null
Set-VgtInstallAcl -Target (Join-Path $securityCenterRoot 'Logs') -Phase 'SecurityCenterACL'
Set-VgtInstallAcl -Target (Join-Path $securityCenterRoot 'State') -Phase 'SecurityCenterACL'
New-VgtSafeDirectory -Path $installerCacheRoot -AllowedRoot $programDataRoot | Out-Null
Set-VgtInstallAcl -Target $installerCacheRoot -Phase 'InstallerCacheACL'
New-VgtSafeDirectory -Path $brandingRoot -AllowedRoot $programDataRoot | Out-Null
# Branding content is non-secret but must stay readable for Windows/Tray (Users
# RX) without granting standard users write access.
Set-VgtInstallAcl -Target $brandingRoot -Phase 'BrandingACL' -AllowsUsersRead
Write-VgtInstallPhase -Phase 'ACL' -State 'OK' -Detail 'Program, VGT, data, SecurityCenter, cache and branding roots secured'
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'bin') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'engine') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'audit') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'xdr') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'LICENSES') -Destination $installRoot -Recurse -Force
foreach ($noticeName in @('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','GEOIP_LICENSE_AND_DEPLOYMENT.md')) {
    Copy-Item -LiteralPath (Join-Path $resolvedPayload $noticeName) -Destination (Join-Path $installRoot $noticeName) -Force
}
Copy-Item -LiteralPath $versionPath -Destination (Join-Path $installRoot 'VERSION') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-lockscreen.jpg') -Destination (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-oem-logo.bmp') -Destination (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense-logo-v1.png') -Destination (Join-Path $brandingRoot 'gedefense-logo.png') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense.ico') -Destination (Join-Path $brandingRoot 'gedefense.ico') -Force
Copy-VgtInstallerSupportFiles -StageRoot $resolvedPayload -InstallRoot $installRoot -Certificate $certificate
# The final Program Files content is verified again against the protected stage
# after the copy, so a payload swapped during the copy window fails closed.
Assert-VgtInstalledPayload -StageRoot $resolvedPayload -InstallRoot $installRoot -BrandingRoot $brandingRoot -Certificate $certificate
Write-VgtInstallPhase -Phase 'Files' -State 'OK' -Detail $installRoot

$operatorGroupCreated = $false
if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    if ($operatorGroupDescription.Length -gt 48) { throw [IO.InvalidDataException]::new('Operator group description exceeds the Windows SAM boundary.') }
    New-LocalGroup -Name $operatorGroup -Description $operatorGroupDescription | Out-Null
    $operatorGroupCreated = $true
}
$operatorGroupObject = Get-LocalGroup -Name $operatorGroup -ErrorAction Stop
$operatorGroupSid = [string]$operatorGroupObject.SID.Value
if ($operatorGroupSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw [Security.SecurityException]::new('Operator group SID validation failed.') }
$identitySid = [string]$identity.User.Value
if ($identitySid -notmatch '^S-1-(?:\d+-)+\d+$') { throw [Security.SecurityException]::new('Installing identity SID validation failed.') }
$installerAddedMembers = [Collections.Generic.List[string]]::new()
if ($identitySid -ne 'S-1-5-18') {
    $isOperator = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction Stop | Where-Object { [string]$_.SID.Value -eq $identitySid }).Count -gt 0
    if (-not $isOperator) {
        Add-LocalGroupMember -Group $operatorGroup -Member $identity.Name -ErrorAction Stop
        [void]$installerAddedMembers.Add($identitySid)
    }
}
Write-VgtInstallPhase -Phase 'OperatorGroup' -State 'OK' -Detail ("{0}|{1}|member={2}" -f $operatorGroup,$operatorGroupSid,$identitySid)
# Product-owned install state: uninstall may only remove trust anchors, runtime
# credentials and group members that this installer actually created.
New-Item -Path $stateKey -Force | Out-Null
New-ItemProperty -Path $stateKey -Name Product -Value 'VGT GeDefense Titan' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $stateKey -Name OperatorGroupCreated -Value ([int]($(if ($operatorGroupCreated) { 1 } else { 0 }))) -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $stateKey -Name OperatorGroupSid -Value $operatorGroupSid -PropertyType String -Force | Out-Null
New-ItemProperty -Path $stateKey -Name InstallerAddedMembers -Value ($installerAddedMembers.ToArray() -join ';') -PropertyType String -Force | Out-Null
Write-VgtInstallPhase -Phase 'InstallState' -State 'OK' -Detail ("groupCreated={0}|members={1}" -f $operatorGroupCreated,$installerAddedMembers.Count)

$executable = Join-Path $installRoot 'bin\gedefense-windows.exe'
$quotedExecutable = '"{0}"' -f $executable
Invoke-ScChecked @('create',$serviceName,'binPath=',$quotedExecutable,'start=','auto','obj=','LocalSystem','DisplayName=','VGT GeDefense Master Security System')
Invoke-ScChecked @('description',$serviceName,'VisionGaia Technology sovereign Windows defense and hardening control plane.')
Invoke-ScChecked @('failure',$serviceName,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
Invoke-ScChecked @('failureflag',$serviceName,'1')
Invoke-ScChecked @('sidtype',$serviceName,'unrestricted')
Write-VgtInstallPhase -Phase 'ServiceRegistration' -State 'OK' -Detail $serviceName

$oemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
New-Item -Path $oemPath -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Manufacturer -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Model -Value 'VGT Win11E+ LTSC Security Edition' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name SupportProvider -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oemPath -Name Logo -Value (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -PropertyType String -Force | Out-Null
$personalization = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
New-Item -Path $personalization -Force | Out-Null
New-ItemProperty -Path $personalization -Name LockScreenImage -Value (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -PropertyType String -Force | Out-Null
New-ItemProperty -Path $personalization -Name NoChangingLockScreen -Value 1 -PropertyType DWord -Force | Out-Null
Write-VgtInstallPhase -Phase 'Branding' -State 'OK' -Detail 'OEM and lock screen policies applied'

$startMenu = $startMenuRoot
Assert-VgtNoReparseTraversal -Path $startMenu -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData))
New-VgtSafeDirectory -Path $startMenu -AllowedRoot ([IO.Path]::GetFullPath($env:ProgramData)) | Out-Null
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startMenu 'GeDefense Security Center.lnk'))
$centerExecutable = Join-Path $installRoot 'bin\GeDefenseCenter.exe'
if (-not (Test-Path -LiteralPath $centerExecutable -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense Center executable is missing.') }
$trayExecutable = Join-Path $installRoot 'bin\GeDefenseTray.exe'
if (-not (Test-Path -LiteralPath $trayExecutable -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense Tray executable is missing.') }
$shortcut.TargetPath = $centerExecutable
$shortcut.Arguments = ''
$shortcut.WorkingDirectory = $installRoot
$shortcut.Description = 'VGT GeDefense Security Center'
$shortcut.IconLocation = (Join-Path $brandingRoot 'gedefense.ico')
$shortcut.Save()

$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'VGTGeDefenseTray' -Value ('"{0}" --tray' -f $trayExecutable) -PropertyType String -Force | Out-Null

$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'VGT GeDefense Security Center' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $releaseVersion -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'VisionGaia Technology' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $installRoot -PropertyType String -Force | Out-Null
if ($resolvedInstaller) {
    $installedSetup = Join-Path $installRoot 'GeDefense-Setup.exe'
    Copy-Item -LiteralPath $resolvedInstaller -Destination $installedSetup -Force
    New-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value $installedSetup -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString -Value ('"{0}" --uninstall' -f $installedSetup) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
}
Write-VgtInstallPhase -Phase 'ApplicationRegistration' -State 'OK' -Detail ("center={0}|tray={1}|autostart=HKLM" -f $centerExecutable,$trayExecutable)

$mhxStateRoot = Join-Path $dataRoot 'mhx'
Assert-VgtNoReparseTraversal -Path $mhxStateRoot -AllowedRoot $dataRoot
New-VgtSafeDirectory -Path $mhxStateRoot -AllowedRoot $dataRoot | Out-Null
$intelligenceRoot = Join-Path $mhxStateRoot 'intelligence'
Assert-VgtNoReparseTraversal -Path $intelligenceRoot -AllowedRoot $dataRoot
New-VgtSafeDirectory -Path $intelligenceRoot -AllowedRoot $dataRoot | Out-Null
Set-VgtInstallAcl -Target $intelligenceRoot -Phase 'ThreatIntelACL'
$mhxModePath = Join-Path $mhxStateRoot 'mode.json'
Assert-VgtSafeFileTarget -Path $mhxModePath -AllowedRoot $dataRoot | Out-Null
$mhxModeTemporary = "$mhxModePath.$PID.tmp"
[ordered]@{ mode = 'guarded'; updatedUtc = [DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath $mhxModeTemporary -Encoding UTF8
Move-Item -LiteralPath $mhxModeTemporary -Destination $mhxModePath -Force
Write-VgtInstallPhase -Phase 'MHXState' -State 'OK' -Detail 'Guarded persisted before service start'

Start-Service -Name $serviceName
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    Start-Sleep -Milliseconds 500
    $state = (Get-Service -Name $serviceName).Status
} while ($state -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
if ($state -ne 'Running') { throw [InvalidOperationException]::new('GeDefense service did not reach Running state.') }
Write-VgtInstallPhase -Phase 'ServiceStart' -State 'OK' -Detail $state
$tokenPath = Join-Path $dataRoot 'dashboard.token'
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense dashboard token was not created.') }
Assert-VgtSafeFileTarget -Path $tokenPath -AllowedRoot $dataRoot | Out-Null
Set-VgtInstallAcl -Target $tokenPath -Phase 'TokenACL'
$defenderDeadline = [DateTime]::UtcNow.AddMinutes(2)
do {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $defenderReady = [bool]($null -ne $mpStatus -and $null -ne $mpStatus.PSObject.Properties['AntivirusEnabled'] -and $mpStatus.AntivirusEnabled)
    if (-not $defenderReady) { Start-Sleep -Seconds 2 }
} while (-not $defenderReady -and [DateTime]::UtcNow -lt $defenderDeadline)
if (-not $defenderReady) { throw [InvalidOperationException]::new('Microsoft Defender did not become ready for initial hardening.') }
Write-VgtInstallPhase -Phase 'DefenderReadiness' -State 'OK' -Detail 'Antivirus enabled'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'engine\Invoke-VgtHardening.ps1') -Mode Enforce -Profile EnterpriseBalanced | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial VGT hardening transaction failed.') }
Write-VgtInstallPhase -Phase 'Hardening' -State 'OK' -Detail 'EnterpriseBalanced'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'xdr\Set-VgtMhxProtection.ps1') -Mode Guarded | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial MHX realtime protection transaction failed.') }
Write-VgtInstallPhase -Phase 'MHXRealtime' -State 'OK' -Detail 'Guarded + Defender bridge'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $installRoot 'xdr\Set-VgtMhxAppControl.ps1') -Action Audit | Out-Null
if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Initial App Control audit policy deployment failed.') }
Write-VgtInstallPhase -Phase 'AppControl' -State 'OK' -Detail 'Kernel audit policy deployed'
# The protected payload stage is transient: the installed files have been
# verified at their final destination, so no staging copy is retained.
if ($script:protectedPayloadStage -and [IO.Directory]::Exists($script:protectedPayloadStage)) {
    try {
        Remove-VgtSafeTree -Path $script:protectedPayloadStage
        Write-VgtInstallPhase -Phase 'PayloadCleanup' -State 'OK' -Detail 'protected staging removed'
        $script:protectedPayloadStage = ''
    } catch {
        Write-VgtInstallPhase -Phase 'PayloadCleanup' -State 'WARN' -Detail $_.Exception.Message
    }
}
$stagingParent = Join-Path $dataRoot 'staging'
if (Test-Path -LiteralPath $stagingParent -PathType Container) {
    if (@(Get-ChildItem -LiteralPath $stagingParent -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -LiteralPath $stagingParent -Force -ErrorAction SilentlyContinue
    }
}
Write-VgtInstallPhase -Phase 'Installer' -State 'COMPLETE' -Detail ("GeDefense {0} installed" -f $releaseVersion)
