# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot 'work\mhx-process-trace-diagnostic.json'
$probe = $null

function Read-VgtSecurity4688 {
    param([string]$XPath = '', [switch]$Newest)
    try {
        if ($Newest) { @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4688 } -MaxEvents 1 -ErrorAction Stop) }
        else { @(Get-WinEvent -LogName 'Security' -FilterXPath $XPath -MaxEvents 128 -ErrorAction Stop) }
    } catch {
        if ($_.FullyQualifiedErrorId.Split(',')[0] -eq 'NoMatchingEventsFound') { return @() }
        throw
    }
}

function ConvertFrom-VgtProcessId {
    param([string]$Value)
    $trimmed = ([string]$Value).Trim()
    if ($trimmed -match '^0[xX][0-9a-fA-F]{1,8}$') { return [long][Convert]::ToInt64($trimmed.Substring(2), 16) }
    $parsed = 0L
    if ([long]::TryParse($trimmed, [ref]$parsed) -and $parsed -gt 0) { return $parsed }
    return 0L
}

# Native Security 4688 diagnostics: the MHX process sensor subscribes to the
# same channel/event id through wevtapi (no WMI process-trace bridge
# and no persistent PowerShell telemetry child process).
try {
    $auditPolicy = -1L
    try {
        $auditPolicy = [long](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction Stop).ProcessCreationIncludeCmdLine_Enabled
    } catch { $auditPolicy = -1L }
    $latest = @(Read-VgtSecurity4688 -Newest)
    $cursor = if ($latest.Count -gt 0) { [long]$latest[0].RecordId } else { 0L }
    $probe = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 8') -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    $matched = $null
    $observed = 0
    while ([DateTime]::UtcNow -lt $deadline -and $null -eq $matched) {
        Start-Sleep -Milliseconds 500
        $query = "*[System[EventID=4688 and EventRecordID > $cursor]]"
        $events = @(Read-VgtSecurity4688 -XPath $query)
        foreach ($item in $events) {
            $cursor = [Math]::Max($cursor, [long]$item.RecordId)
            $observed++
            $xml = [xml]$item.ToXml()
            $fields = @{}
            foreach ($entry in @($xml.Event.EventData.Data)) {
                if ($null -eq $entry.Name) { continue }
                $fields[[string]$entry.Name] = [string]$entry.'#text'
            }
            $newProcessId = ConvertFrom-VgtProcessId ([string]$fields['NewProcessId'])
            if ($newProcessId -ne [long]$probe.Id) { continue }
            $parentProcessId = 0L
            if ($fields.ContainsKey('CreatorProcessId')) { $parentProcessId = ConvertFrom-VgtProcessId ([string]$fields['CreatorProcessId']) }
            if ($parentProcessId -eq 0 -and $fields.ContainsKey('ProcessId')) { $parentProcessId = ConvertFrom-VgtProcessId ([string]$fields['ProcessId']) }
            $commandLine = ''
            if ($fields.ContainsKey('CommandLine')) { $commandLine = [string]$fields['CommandLine'] }
            $matched = [ordered]@{
                recordId        = [long]$item.RecordId
                timeCreatedUtc  = $item.TimeCreated.ToUniversalTime().ToString('o')
                processId       = $newProcessId
                parentProcessId = $parentProcessId
                image           = [string]$fields['NewProcessName']
                parentImage     = if ($fields.ContainsKey('ParentProcessName')) { [string]$fields['ParentProcessName'] } else { '' }
                commandLine     = $commandLine
            }
        }
    }
    $state = 'NOT_MATCHED'
    if ($null -ne $matched) {
        if ([string]::IsNullOrWhiteSpace([string]$matched.commandLine)) { $state = 'MATCHED_WITHOUT_COMMAND_LINE' }
        else { $state = 'ENRICHED' }
    }
    $result = [ordered]@{
        timestampUtc          = [DateTime]::UtcNow.ToString('o')
        state                 = $state
        source                = 'Security/4688'
        auditCmdLinePolicy    = $auditPolicy
        observed              = $observed
        cursor                = $cursor
        probeId               = $probe.Id
        match                 = $matched
    }
} catch {
    $result = [ordered]@{
        timestampUtc    = [DateTime]::UtcNow.ToString('o')
        state           = 'FAILED'
        source          = 'Security/4688'
        exceptionType   = $_.Exception.GetType().FullName
        message         = $_.Exception.Message
        line            = $_.InvocationInfo.ScriptLineNumber
    }
} finally {
    if ($probe -and -not $probe.HasExited) { Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue }
}

$builder = New-Object System.Text.StringBuilder
$null = $builder.Append(($result | ConvertTo-Json -Depth 6))
[IO.File]::WriteAllText($outputPath, $builder.ToString(), [Text.UTF8Encoding]::new($false))
if ($result.state -ne 'ENRICHED') { exit 1 }
exit 0
