# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+\.json$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$findings = [Collections.Generic.List[object]]::new()
$scanned = 0

function Add-VgtFinding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [AllowEmptyString()][string]$Entity = '',
        [AllowEmptyString()][string]$Evidence = ''
    )
    if ($findings.Count -ge 500) { return }
    $material = "$Severity|$Category|$Title|$Entity|$Evidence"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $id = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').Substring(0,16) } finally { $sha.Dispose() }
    $findings.Add([pscustomobject][ordered]@{Id=$id;TimestampUtc=[DateTime]::UtcNow.ToString('o');Severity=$Severity;Category=$Category;Title=$Title;Description=$Description;Entity=$Entity;Evidence=$Evidence})
}

function Get-VgtExecutableFromCommand {
    param([AllowEmptyString()][string]$CommandLine = '')
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded -match '^"([^"\r\n]+\.exe)"') { return $Matches[1] }
    if ($expanded -match '^([^\r\n]+?\.exe)(?:\s|$)') { return $Matches[1].Trim() }
    return ''
}

function Test-VgtUserWritablePath {
    param([AllowEmptyString()][string]$Path = '')
    return $Path -match '(?i)\\Users\\[^\\]+\\(?:AppData|Downloads|Desktop|Temp)\\|\\Windows\\Temp\\|\\ProgramData\\[^\\]+\\Temp\\'
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VGT\GeDefense\operations')).TrimEnd('\') + '\'
if (-not $resolvedOutput.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)) {
    throw [Security.SecurityException]::new('XDR output path escaped the operation jail.')
}
New-Item -Path (Split-Path -Parent $resolvedOutput) -ItemType Directory -Force | Out-Null

$connectionsByPid = @{}
foreach ($connection in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object -First 2000)) {
    $scanned++
    if ($connection.RemoteAddress -in '127.0.0.1','::1','0.0.0.0','::') { continue }
    $pidKey = [string]$connection.OwningProcess
    if (-not $connectionsByPid.ContainsKey($pidKey)) { $connectionsByPid[$pidKey] = [Collections.Generic.List[string]]::new() }
    $connectionsByPid[$pidKey].Add("$($connection.RemoteAddress):$($connection.RemotePort)")
}

$processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object -First 1500)
foreach ($process in $processes) {
    $scanned++
    $path = [string]$process.ExecutablePath
    $commandLine = [string]$process.CommandLine
    $pidKey = [string]$process.ProcessId
    if ($commandLine -match '(?i)(?:\s|^)-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|DownloadString\s*\(|FromBase64String\s*\(|Reflection\.Assembly') {
        Add-VgtFinding 'High' 'Execution' 'Suspicious encoded or in-memory command line' 'A live process uses an execution pattern commonly associated with fileless payloads. Validate parentage and operator intent.' "$($process.Name) [$pidKey]" ($commandLine.Substring(0,[Math]::Min(800,$commandLine.Length)))
    }
    if ($path -and (Test-VgtUserWritablePath $path) -and $connectionsByPid.ContainsKey($pidKey)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
        if (-not $signature -or $signature.Status -ne 'Valid') {
            Add-VgtFinding 'High' 'Network' 'Unsigned user-writable executable has remote connections' 'An unsigned process launched from a user-writable directory communicates with a remote endpoint.' "$path [$pidKey]" (($connectionsByPid[$pidKey] | Select-Object -First 10) -join ', ')
        }
    }
}

$runLocations = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($location in $runLocations) {
    foreach ($item in @(Get-ItemProperty -Path $location -ErrorAction SilentlyContinue)) {
        foreach ($property in $item.PSObject.Properties | Where-Object Name -NotMatch '^PS') {
            $scanned++
            $executable = Get-VgtExecutableFromCommand ([string]$property.Value)
            if ($executable -and (Test-VgtUserWritablePath $executable)) {
                $signature = Get-AuthenticodeSignature -LiteralPath $executable -ErrorAction SilentlyContinue
                if (-not $signature -or $signature.Status -ne 'Valid') {
                    Add-VgtFinding 'High' 'Persistence' 'Unsigned user-writable autorun' 'A Run key launches an unsigned executable from a user-writable directory.' $executable "$($property.Name) @ $location"
                }
            }
        }
    }
}

foreach ($consumerClass in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
    foreach ($consumer in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $consumerClass -ErrorAction SilentlyContinue | Select-Object -First 100)) {
        $scanned++
        $details = ($consumer | Select-Object Name,CommandLineTemplate,ExecutablePath,ScriptingEngine,ScriptText | ConvertTo-Json -Compress -Depth 3)
        $severity = if($consumerClass -eq 'ActiveScriptEventConsumer'){'High'}else{'Medium'}
        Add-VgtFinding $severity 'Persistence' 'Permanent WMI event consumer present' 'Permanent WMI consumers are a legitimate administration mechanism but also a durable persistence primitive. Verify provenance.' ([string]$consumer.Name) $details
    }
}

foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -First 1000)) {
    $scanned++
    $servicePath = [string]$service.PathName
    if ($servicePath -match '^\s*[^"\r\n]+\s+[^"\r\n]+\.exe(?:\s|$)') {
        Add-VgtFinding 'Medium' 'Persistence' 'Unquoted service executable path' 'A service path containing spaces is not quoted and may permit executable path hijacking when directory permissions are weak.' ([string]$service.Name) ($servicePath.Substring(0,[Math]::Min(800,$servicePath.Length)))
    }
    $serviceExecutable = Get-VgtExecutableFromCommand $servicePath
    if ($serviceExecutable -and (Test-VgtUserWritablePath $serviceExecutable)) {
        Add-VgtFinding 'Critical' 'Persistence' 'Service executable in user-writable directory' 'A privileged service references an executable in a user-writable location.' ([string]$service.Name) $serviceExecutable
    }
}

foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object -First 1500)) {
    foreach ($action in @($task.Actions)) {
        $scanned++
        $executeProperty = $action.PSObject.Properties['Execute']
        if (-not $executeProperty -and $action.PSObject.Properties['CimInstanceProperties']) { $executeProperty = $action.CimInstanceProperties['Execute'] }
        $execute = if($executeProperty){[Environment]::ExpandEnvironmentVariables([string]$executeProperty.Value)}else{''}
        if ($execute -and (Test-VgtUserWritablePath $execute)) {
            $signature = Get-AuthenticodeSignature -LiteralPath $execute -ErrorAction SilentlyContinue
            if (-not $signature -or $signature.Status -ne 'Valid') {
                Add-VgtFinding 'High' 'Persistence' 'Unsigned scheduled task action in user-writable directory' 'A scheduled task launches an unsigned executable from a user-writable location.' "$($task.TaskPath)$($task.TaskName)" $execute
            }
        }
    }
}

$preference = Get-MpPreference -ErrorAction SilentlyContinue
if ($preference) {
    foreach ($exclusion in @($preference.ExclusionPath) + @($preference.ExclusionProcess)) {
        $scanned++
        if ([string]::IsNullOrWhiteSpace([string]$exclusion) -or [string]$exclusion -match '^(?i)N/A:') { continue }
        $severity = if(([string]$exclusion) -match '^(?i)([A-Z]:\\|\*|\\Users\\|\\Windows\\)'){'High'}else{'Medium'}
        Add-VgtFinding $severity 'DefenseEvasion' 'Microsoft Defender exclusion configured' 'Defender exclusions reduce inspection coverage and require explicit business justification.' ([string]$exclusion) 'Get-MpPreference exclusion inventory'
    }
}

foreach ($threat in @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object InitialDetectionTime -GT ([DateTime]::UtcNow.AddDays(-30)) | Select-Object -First 200)) {
    $scanned++
    Add-VgtFinding 'High' 'Malware' 'Recent Microsoft Defender threat detection' 'Microsoft Defender recorded a threat detection during the last 30 days. Confirm remediation and affected resources.' ([string]$threat.ThreatID) ((@($threat.Resources) | Select-Object -First 10) -join ', ')
}

$critical = @($findings | Where-Object Severity -eq 'Critical').Count
$high = @($findings | Where-Object Severity -eq 'High').Count
$medium = @($findings | Where-Object Severity -eq 'Medium').Count
$low = @($findings | Where-Object Severity -eq 'Low').Count
[ordered]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    Engine = 'VGT MHX 5.0 read-only XDR'
    Scanned = $scanned
    Critical = $critical
    High = $high
    Medium = $medium
    Low = $low
    Findings = @($findings)
} | ConvertTo-Json -Depth 7 -Compress | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
