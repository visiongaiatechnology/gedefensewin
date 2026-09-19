# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0"]+$')][string]$PayloadRoot,
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.exe$')][string]$InstallerPath = '',
    [ValidatePattern('^$|^[A-Za-z]:\\[^\r\n\0"]+\.log$')][string]$DiagnosticLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$dataRoot = Join-Path $env:ProgramData 'VGT\GeDefense'
$brandingRoot = Join-Path $env:ProgramData 'VGT\Branding'
$operatorGroup = 'VGT GeDefense Operators'
$operatorGroupDescription = 'VGT GeDefense security center operators.'
$installLog = Join-Path $dataRoot 'install.log'
$resolvedDiagnosticLog = ''
if ($DiagnosticLogPath) {
    $diagnosticRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VGT\InstallerDiagnostics')).TrimEnd('\') + '\'
    $candidateDiagnosticLog = [IO.Path]::GetFullPath($DiagnosticLogPath)
    if (-not $candidateDiagnosticLog.StartsWith($diagnosticRoot,[StringComparison]::OrdinalIgnoreCase)) { throw [Security.SecurityException]::new('Diagnostic log path escaped the user diagnostic jail.') }
    New-Item -Path ([IO.Path]::GetDirectoryName($candidateDiagnosticLog)) -ItemType Directory -Force | Out-Null
    $resolvedDiagnosticLog = $candidateDiagnosticLog
}

function Write-VgtInstallPhase {
    param([Parameter(Mandatory)][string]$Phase,[Parameter(Mandatory)][string]$State,[AllowEmptyString()][string]$Detail = '')
    New-Item -Path $dataRoot -ItemType Directory -Force | Out-Null
    $safeDetail = $Detail.Replace("`r",' ').Replace("`n",' ')
    $line = '{0}|{1}|{2}|{3}' -f [DateTime]::UtcNow.ToString('o'),$Phase,$State,$safeDetail
    if ($resolvedDiagnosticLog) {
        try {
            Add-Content -LiteralPath $resolvedDiagnosticLog -Value $line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 50
            try { Add-Content -LiteralPath $resolvedDiagnosticLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }
    }
    try {
        Add-Content -LiteralPath $installLog -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        if (-not $resolvedDiagnosticLog) { throw }
    }
}

trap {
    try {
        Write-VgtInstallPhase -Phase 'Installer' -State 'FAILED' -Detail $_.Exception.Message
    } catch {}
    exit 90
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $nativeOutput = (& "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1 | Out-String).Trim()
    $nativeExitCode = $LASTEXITCODE
    $operation = if ($Arguments.Count -gt 0) { $Arguments[0] } else { 'unknown' }
    if ($nativeExitCode -ne 0) {
        Write-VgtInstallPhase -Phase 'ServiceControl' -State 'FAILED' -Detail ("{0}|exit={1}|{2}" -f $operation,$nativeExitCode,$nativeOutput)
        throw [InvalidOperationException]::new(("Service operation '{0}' failed with exit code {1}." -f $operation,$nativeExitCode))
    }
    Write-VgtInstallPhase -Phase 'ServiceControl' -State 'OK' -Detail ("{0}|exit=0" -f $operation)
}

function Invoke-IcaclsChecked {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Phase
    )
    $nativeOutput = (& "$env:SystemRoot\System32\icacls.exe" $Target @Arguments 2>&1 | Out-String).Trim()
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        Write-VgtInstallPhase -Phase $Phase -State 'FAILED' -Detail ("icacls exit {0}: {1}" -f $nativeExitCode,$nativeOutput)
        throw [Security.SecurityException]::new(("{0} failed with native exit code {1}." -f $Phase,$nativeExitCode))
    }
    Write-VgtInstallPhase -Phase $Phase -State 'OK' -Detail ("icacls exit 0: {0}" -f $nativeOutput)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative token required.')
}
Write-VgtInstallPhase -Phase 'Elevation' -State 'OK' -Detail $identity.Name
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayload 'bin\gedefense-windows.exe') -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('GeDefense payload is incomplete.')
}
$versionPath = Join-Path $resolvedPayload 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('GeDefense release version metadata is missing.') }
$releaseVersion = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
if ($releaseVersion -notmatch '^4\.[0-9]+\.[0-9]+-beta\.[1-9][0-9]*$') { throw [IO.InvalidDataException]::new('GeDefense release version metadata is invalid.') }
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
Import-Certificate -FilePath $releaseCertificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
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
    Invoke-ScChecked @('delete',$serviceName)
    Start-Sleep -Milliseconds 700
}
New-Item -Path $installRoot,$dataRoot,$brandingRoot -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'bin') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'engine') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'audit') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'xdr') -Destination $installRoot -Recurse -Force
Copy-Item -LiteralPath $versionPath -Destination (Join-Path $installRoot 'VERSION') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-lockscreen.jpg') -Destination (Join-Path $brandingRoot 'vgt-lockscreen.jpg') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\vgt-oem-logo.bmp') -Destination (Join-Path $brandingRoot 'vgt-oem-logo.bmp') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense-logo-v1.png') -Destination (Join-Path $brandingRoot 'gedefense-logo.png') -Force
Copy-Item -LiteralPath (Join-Path $resolvedPayload 'branding\gedefense.ico') -Destination (Join-Path $brandingRoot 'gedefense.ico') -Force
Write-VgtInstallPhase -Phase 'Files' -State 'OK' -Detail $installRoot

if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    if ($operatorGroupDescription.Length -gt 48) { throw [IO.InvalidDataException]::new('Operator group description exceeds the Windows SAM boundary.') }
    New-LocalGroup -Name $operatorGroup -Description $operatorGroupDescription | Out-Null
}
$operatorGroupObject = Get-LocalGroup -Name $operatorGroup -ErrorAction Stop
$operatorGroupSid = [string]$operatorGroupObject.SID.Value
if ($operatorGroupSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw [Security.SecurityException]::new('Operator group SID validation failed.') }
$identitySid = [string]$identity.User.Value
if ($identitySid -notmatch '^S-1-(?:\d+-)+\d+$') { throw [Security.SecurityException]::new('Installing identity SID validation failed.') }
if ($identitySid -ne 'S-1-5-18') {
    $isOperator = @(Get-LocalGroupMember -Group $operatorGroup -ErrorAction Stop | Where-Object { [string]$_.SID.Value -eq $identitySid }).Count -gt 0
    if (-not $isOperator) { Add-LocalGroupMember -Group $operatorGroup -Member $identity.Name -ErrorAction Stop }
}
Write-VgtInstallPhase -Phase 'OperatorGroup' -State 'OK' -Detail ("{0}|{1}|member={2}" -f $operatorGroup,$operatorGroupSid,$identitySid)
Invoke-IcaclsChecked -Target $installRoot -Phase 'ProgramACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
$dataAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F',("*{0}:(RX)" -f $operatorGroupSid))
if ($identitySid -ne 'S-1-5-18') { $dataAclArguments += ("*{0}:(RX)" -f $identitySid) }
Invoke-IcaclsChecked -Target $dataRoot -Phase 'DataACL' -Arguments $dataAclArguments
Write-VgtInstallPhase -Phase 'ACL' -State 'OK' -Detail 'Program and data roots secured'

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

$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
New-Item -Path $startMenu -ItemType Directory -Force | Out-Null
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
New-Item -Path $mhxStateRoot -ItemType Directory -Force | Out-Null
$intelligenceRoot = Join-Path $mhxStateRoot 'intelligence'
New-Item -Path $intelligenceRoot -ItemType Directory -Force | Out-Null
Invoke-IcaclsChecked -Target $intelligenceRoot -Phase 'ThreatIntelACL' -Arguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
$mhxModePath = Join-Path $mhxStateRoot 'mode.json'
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
$tokenAclArguments = @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F',("*{0}:R" -f $operatorGroupSid))
if ($identitySid -ne 'S-1-5-18') { $tokenAclArguments += ("*{0}:R" -f $identitySid) }
Invoke-IcaclsChecked -Target $tokenPath -Phase 'TokenACL' -Arguments $tokenAclArguments
$defenderDeadline = [DateTime]::UtcNow.AddMinutes(2)
do {
    $defenderReady = [bool]((Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled)
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
Write-VgtInstallPhase -Phase 'Installer' -State 'COMPLETE' -Detail ("GeDefense {0} installed" -f $releaseVersion)

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGxIz0Ys9jQS+f
# 2xErJdjBf0OC3RDkJCvzP5MNYGKPuqCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCOuMWhCnPi
# pnD0u8hOyhmyKzNjUi+RBuegaNzjuyVfSTANBgkqhkiG9w0BAQEFAASCAYC7OlJ2
# /TXgBhl1ZlF7DP+k4qTHVpOGv9OL7Ns1OnRqqJmTcVC4DsX8BVU3zQ6k7RrRrv//
# 94PQUPwObv9Eq9rmnuAtV5YD18fHQi1q5y7CbZxDx3iCE80Mfl5O76sVXI9LCKsS
# lP9hwygS4U7AOfp2ycLm17TZhjgBKEW7QcaHLsNf4tkwpBsYE+MgcwKgx8YB1fsf
# 8cyde71NIC7Fhxe4eGB5EkXTIgGS322VhcibNBu+O99zsCySwmzD+q59aL0H7ja8
# DHwxNKvdDoDi29/Gku0wpPYzTNfA/KkfyKRWVl0NYevP7uRutVyATUj+bK0aGHzc
# OLBzOxjFJnDTyGvM6bS/UPFxuQdCKCE4JFNqwMlNFGlG29HA2rpfIMrfIOcxptN6
# etyZGfS5vaTqpBKSDfk3Z29MHxV+/oGgODcyGa0yW1ecfvzKUnKXeFYESM0BEriK
# qUGIPkOGGSL+2nWJLwKxBuTJYIx1ToanjwrzgsVN3T71vomQI8snkg7ZF+g=
# SIG # End signature block
