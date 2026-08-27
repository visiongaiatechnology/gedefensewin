# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+$')][string]$PayloadRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'VGTGeDefense'
$installRoot = Join-Path $env:ProgramFiles 'VGT\GeDefense'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VGT'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw [Security.SecurityException]::new('Administrative token required.') }
$resolvedPayload = (Resolve-Path -LiteralPath $PayloadRoot -ErrorAction Stop).Path
$certificatePath = Join-Path $resolvedPayload 'vgt-release.cer'
$catalogPath = Join-Path $resolvedPayload 'vgt-payload.cat'
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or -not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Signed uninstall payload is incomplete.') }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$signature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw [Security.SecurityException]::new('Uninstaller signature validation failed.') }
$catalog = Test-FileCatalog -Path $resolvedPayload -CatalogFilePath $catalogPath -Detailed
if ($catalog.Status -ne 'Valid') { throw [Security.SecurityException]::new('Uninstall payload catalog validation failed.') }

foreach ($processName in @('GeDefenseTray','GeDefenseCenter')) {
    foreach ($process in @(Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
        $expectedPath = Join-Path $installRoot ("bin\{0}.exe" -f $processName)
        $actualPath = try { [IO.Path]::GetFullPath($process.Path) } catch { '' }
        if ($actualPath -and $actualPath.Equals([IO.Path]::GetFullPath($expectedPath),[StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
    }
}

$protectionScript = Join-Path $installRoot 'xdr\Set-VgtMhxProtection.ps1'
if (Test-Path -LiteralPath $protectionScript -PathType Leaf) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File $protectionScript -Mode Restore | Out-Null
}
$appControlScript = Join-Path $installRoot 'xdr\Set-VgtMhxAppControl.ps1'
if (Test-Path -LiteralPath $appControlScript -PathType Leaf) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File $appControlScript -Action Remove | Out-Null
}
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like 'VGT GeDefense Threat Intelligence *' -or $_.Group -in @('VGT GeDefense Sovereign','VGT GeDefense Sovereign Allows') } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & "$env:SystemRoot\System32\sc.exe" delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [InvalidOperationException]::new('Service removal failed.') }
}
Get-ScheduledTask -TaskName 'VGT GeDefense*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $startMenu) { Remove-Item -LiteralPath $startMenu -Recurse -Force }
if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Force }
if (Test-Path -LiteralPath $runKey) { Remove-ItemProperty -LiteralPath $runKey -Name 'VGTGeDefenseTray' -ErrorAction SilentlyContinue }
if (Get-LocalGroup -Name 'VGT GeDefense Operators' -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name 'VGT GeDefense Operators' }
if (Test-Path -LiteralPath $installRoot) {
    Get-ChildItem -LiteralPath $installRoot -Force | Where-Object Name -ne 'GeDefense-Setup.exe' | Remove-Item -Recurse -Force
    $installedSetup = Join-Path $installRoot 'GeDefense-Setup.exe'
    if (Test-Path -LiteralPath $installedSetup -PathType Leaf) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VgtPendingDelete {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existingName, string newName, int flags);
    public static bool Schedule(string path) { return MoveFileEx(path, null, 4); }
}
'@
        if (-not [VgtPendingDelete]::Schedule($installedSetup)) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    }
}
