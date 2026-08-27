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
$env:VGT_MHX_INTEGRATION = '1'
$process = Start-Process -FilePath $go -WorkingDirectory $sourceRoot -ArgumentList @('test','-run','TestProcessWatcherReceivesEncodedCommand','-count=1','-v','./internal/mhx') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru -WindowStyle Hidden
[ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); exitCode=$process.ExitCode } | ConvertTo-Json | Set-Content -LiteralPath $status -Encoding UTF8
exit $process.ExitCode
