# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot 'work\mhx-process-trace-diagnostic.json'
$sourceId = 'VGT_MHX_ProcessTrace_Diagnostic'
$probe = $null

try {
    Register-CimIndicationEvent -Namespace 'root/cimv2' -ClassName 'Win32_ProcessStartTrace' -SourceIdentifier $sourceId | Out-Null
    $probe = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 8') -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    $matched = $null
    $observed = 0
    while ([DateTime]::UtcNow -lt $deadline -and $null -eq $matched) {
        $event = Wait-Event -SourceIdentifier $sourceId -Timeout 1
        if ($null -eq $event) { continue }
        try {
            $observed++
            $trace = $event.SourceEventArgs.NewEvent
            if ([uint32]$trace.ProcessID -eq [uint32]$probe.Id) {
                $matched = [ordered]@{
                    processId = [uint32]$trace.ProcessID
                    parentProcessId = [uint32]$trace.ParentProcessID
                    processName = [string]$trace.ProcessName
                    sessionId = [uint32]$trace.SessionID
                }
            }
        } finally {
            Remove-Event -EventIdentifier $event.EventIdentifier -ErrorAction SilentlyContinue
        }
    }
    if ($matched) {
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$probe.Id) -ErrorAction Stop
        $parent = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$process.ParentProcessId) -ErrorAction SilentlyContinue
        $signature = if ($process.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $process.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
        $parentSignature = if ($parent -and $parent.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $parent.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
        $sha = if ($process.ExecutablePath) { (Get-FileHash -LiteralPath $process.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
        $parentSha = if ($parent -and $parent.ExecutablePath) { (Get-FileHash -LiteralPath $parent.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
        $result = [ordered]@{
            timestampUtc=[DateTime]::UtcNow.ToString('o'); state='ENRICHED'; observed=$observed; probeId=$probe.Id; match=$matched
            process=[ordered]@{ image=[string]$process.Name; path=[string]$process.ExecutablePath; commandLine=[string]$process.CommandLine; signerStatus=if($signature){[string]$signature.Status}else{'Unknown'}; signer=if($signature -and $signature.SignerCertificate){[string]$signature.SignerCertificate.Subject}else{''}; sha256=[string]$sha }
            parent=[ordered]@{ image=if($parent){[string]$parent.Name}else{''}; path=if($parent){[string]$parent.ExecutablePath}else{''}; signerStatus=if($parentSignature){[string]$parentSignature.Status}else{'Unknown'}; signer=if($parentSignature -and $parentSignature.SignerCertificate){[string]$parentSignature.SignerCertificate.Subject}else{''}; sha256=[string]$parentSha }
        }
    } else {
        $result = [ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); state='NOT_MATCHED'; observed=$observed; probeId=$probe.Id; match=$null }
    }
} catch {
    $result = [ordered]@{ timestampUtc=[DateTime]::UtcNow.ToString('o'); state='FAILED'; exceptionType=$_.Exception.GetType().FullName; message=$_.Exception.Message; line=$_.InvocationInfo.ScriptLineNumber }
} finally {
    if ($probe -and -not $probe.HasExited) { Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue }
    Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputPath -Encoding UTF8
if ($result.state -ne 'ENRICHED') { exit 1 }
exit 0
