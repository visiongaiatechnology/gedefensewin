# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $projectRoot 'src\GeDefense\windows'
$go = Join-Path $env:ProgramFiles 'Go\bin\go.exe'
$stdout = Join-Path $projectRoot 'work\mhx-watcher-integration.stdout.log'
$stderr = Join-Path $projectRoot 'work\mhx-watcher-integration.stderr.log'
$status = Join-Path $projectRoot 'work\mhx-watcher-integration.status.json'
if (-not (Test-Path -LiteralPath $go -PathType Leaf)) { throw [IO.FileNotFoundException]::new('Go runtime unavailable.') }

# End-to-end Security 4688 integration: the Go test subscribes through the
# native wevtapi sensor (no WMI process-trace bridge), spawns an
# encoded-command process and expects it in the 4688 stream. The test skips
# cleanly when process creation auditing / Security log access is unavailable.
$env:VGT_MHX_INTEGRATION = '1'
$process = Start-Process -FilePath $go -WorkingDirectory $sourceRoot -ArgumentList @('test', '-run', 'TestProcessWatcherStreamsSecurity4688', '-count=1', '-v', './internal/mhx') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru -WindowStyle Hidden
[ordered]@{ timestampUtc = [DateTime]::UtcNow.ToString('o'); source = 'Security/4688'; test = 'TestProcessWatcherStreamsSecurity4688'; exitCode = $process.ExitCode } | ConvertTo-Json | Set-Content -LiteralPath $status -Encoding UTF8
exit $process.ExitCode
