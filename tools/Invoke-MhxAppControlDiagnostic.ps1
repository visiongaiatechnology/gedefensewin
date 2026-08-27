# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [Security.SecurityException]::new('Administrative diagnostic execution required.')
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'xdr\Set-VgtMhxAppControl.ps1'
$protectedDiagnostic = Join-Path $env:ProgramData 'VGT\GeDefense\mhx\appcontrol\diagnostics.jsonl'
$exportPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.jsonl'
$statusPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic-status.json'
$stdoutPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.stdout.log'
$stderrPath = Join-Path $projectRoot 'work\mhx-appcontrol-diagnostic.stderr.log'

if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new('MHX App Control module is unavailable.')
}

try {
    $child = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $modulePath), '-Action', 'Audit'
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -Wait -PassThru -WindowStyle Hidden

    if (Test-Path -LiteralPath $protectedDiagnostic -PathType Leaf) {
        Copy-Item -LiteralPath $protectedDiagnostic -Destination $exportPath -Force
    }
    $status = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        state = if ($child.ExitCode -eq 0) { 'SUCCEEDED' } else { 'CHILD_FAILED' }
        childExitCode = $child.ExitCode
        protectedDiagnosticExists = Test-Path -LiteralPath $protectedDiagnostic -PathType Leaf
        stdoutBytes = if (Test-Path -LiteralPath $stdoutPath) { (Get-Item -LiteralPath $stdoutPath).Length } else { 0 }
        stderrBytes = if (Test-Path -LiteralPath $stderrPath) { (Get-Item -LiteralPath $stderrPath).Length } else { 0 }
    }
    $status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    exit $child.ExitCode
} catch {
    $status = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        state = 'WRAPPER_FAILED'
        exceptionType = $_.Exception.GetType().FullName
        message = $_.Exception.Message
        scriptLine = $_.InvocationInfo.ScriptLineNumber
    }
    $status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    exit 90
}
