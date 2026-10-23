# STATUS: DIAMANT VGT SUPREME
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\[^\r\n\0]+\.json$')][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$findings = [Collections.Generic.List[object]]::new()
$scanned = 0
# HP-FIND-003: the scan runs as LocalSystem and must never let attacker
# controlled autorun/scheduled-task/live-process paths turn into SYSTEM file
# opens. Signature enrichment is restricted to local fixed-disk paths inside a
# hard time budget; anything else is reported without opening the path.
$signatureBudget = @{ DeadlineUtc = ([DateTime]::UtcNow.AddSeconds(90)); Checks = 0; MaxChecks = 64; Exhausted = $false }

function Get-VgtSafeText {
    param([AllowEmptyString()][string]$Text = '',[ValidateRange(1,4096)][int]$MaxLength = 512)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = $Text -replace '[\x00-\x1F\x7F]',' '
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0,$MaxLength) }
    return $clean
}

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
    $safeEntity = Get-VgtSafeText $Entity 800
    $safeEvidence = Get-VgtSafeText $Evidence 1024
    $material = "$Severity|$Category|$Title|$safeEntity|$safeEvidence"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $id = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').Substring(0,16) } finally { $sha.Dispose() }
    $findings.Add([pscustomobject][ordered]@{Id=$id;TimestampUtc=[DateTime]::UtcNow.ToString('o');Severity=$Severity;Category=$Category;Title=$Title;Description=$Description;Entity=$safeEntity;Evidence=$safeEvidence})
}


function Get-VgtEvidenceMetadata {
    param([AllowEmptyString()][string]$Text = '')
    if ([string]::IsNullOrEmpty($Text)) { return 'sha256=;bytes=0' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    return ("sha256={0};bytes={1}" -f $digest,$bytes.Length)
}

function Get-VgtExecutableFromCommand {
    param([AllowEmptyString()][string]$CommandLine = '')
    if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.Length -gt 8192) { return '' }
    try { $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim()) } catch { return '' }
    if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded.Length -gt 8192) { return '' }
    if ($expanded -match '^"([^"\r\n]+\.exe)"') { return $Matches[1] }
    if ($expanded -match '^([^\r\n]+?\.exe)(?:\s|$)') { return $Matches[1].Trim() }
    return ''
}

# Classifies a path from untrusted autorun/task/process metadata without opening
# it. Kind values: Invalid, NonLocal (UNC/device/relative/non-fixed drive),
# AlternateDataStream, LocalFixed. Only LocalFixed paths may ever be opened.
function Get-VgtPathTrust {
    param([AllowEmptyString()][string]$Path = '')
    $result = [ordered]@{ Kind='Invalid'; Path=''; UserWritable=$false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]$result }
    if ($Path.Length -gt 4096) { return [pscustomobject]$result }
    $candidate = $Path.Trim()
    if ($candidate.Length -eq 0 -or $candidate.IndexOfAny([char[]]@([char]0,[char]10,[char]13)) -ge 0) { return [pscustomobject]$result }
    try { $candidate = [Environment]::ExpandEnvironmentVariables($candidate) } catch { return [pscustomobject]$result }
    $candidate = $candidate -replace '/','\'
    if ($candidate -match '^\\\\') { $result.Kind = 'NonLocal'; return [pscustomobject]$result }
    if ($candidate -notmatch '^[A-Za-z]:\\') { return [pscustomobject]$result }
    if ($candidate.IndexOf(':',2) -ge 0) { $result.Kind = 'AlternateDataStream'; return [pscustomobject]$result }
    try { $full = [IO.Path]::GetFullPath($candidate) } catch { return [pscustomobject]$result }
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.IndexOf(':',2) -ge 0) { return [pscustomobject]$result }
    try { $drive = [IO.DriveInfo]::new($full.Substring(0,3)) } catch { return [pscustomobject]$result }
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { $result.Kind = 'NonLocal'; return [pscustomobject]$result }
    $result.Kind = 'LocalFixed'
    $result.Path = $full
    $result.UserWritable = $full -match '(?i)\\Users\\[^\\]+\\(?:AppData|Downloads|Desktop|Temp)\\|\\Windows\\Temp\\|\\ProgramData\\[^\\]+\\Temp\\'
    return [pscustomobject]$result
}

function Test-VgtLocalFixedPath {
    param([AllowEmptyString()][string]$Path = '')
    return ((Get-VgtPathTrust $Path).Kind -eq 'LocalFixed')
}

# Walks the existing path components and rejects reparse points. It only runs
# after Get-VgtPathTrust proved the path is a local fixed-disk path.
function Test-VgtPathNoReparse {
    param([AllowEmptyString()][string]$Path = '')
    if ($Path -notmatch '^[A-Za-z]:\\') { return $false }
    if ($Path.IndexOf(':',2) -ge 0) { return $false }
    try {
        $root = [IO.Path]::GetPathRoot($Path)
        $cursor = $root
        foreach ($segment in @($Path.Substring($root.Length) -split '\\')) {
            if ([string]::IsNullOrEmpty($segment)) { continue }
            $cursor = Join-Path $cursor $segment
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
            if ($null -eq $item) { break }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

# Runs a fixed script block in an isolated runspace and abandons it after a hard
# timeout. The signature cmdlet has no native timeout; a blocked file open
# must never stall the whole scan (HP-FIND-003).
function Invoke-VgtBoundedScript {
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [AllowEmptyCollection()][object[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 5
    )
    if ($TimeoutSeconds -lt 1) { $TimeoutSeconds = 1 }
    if ($TimeoutSeconds -gt 60) { $TimeoutSeconds = 60 }
    $shell = [PowerShell]::Create()
    $async = $null
    try {
        [void]$shell.AddScript($Script.ToString())
        foreach ($argument in $ArgumentList) { [void]$shell.AddArgument($argument) }
        $async = $shell.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $stop = $shell.BeginStop($null,$null)
            [void]$stop.AsyncWaitHandle.WaitOne(2000)
            return [pscustomobject][ordered]@{ Completed=$false; TimedOut=$true; Value=$null }
        }
        $value = @($shell.EndInvoke($async))
        if ($value.Count -gt 0) { return [pscustomobject][ordered]@{ Completed=$true; TimedOut=$false; Value=$value[0] } }
        return [pscustomobject][ordered]@{ Completed=$true; TimedOut=$false; Value=$null }
    } catch {
        return [pscustomobject][ordered]@{ Completed=$false; TimedOut=$false; Value=$null }
    } finally {
        try { $shell.Dispose() } catch { }
    }
}

function Get-VgtSignatureStatus {
    param(
        [AllowEmptyString()][string]$Path = '',
        [hashtable]$Budget = $null,
        [int]$TimeoutSeconds = 5
    )
    $status = [ordered]@{ Status='NotEvaluated'; FileAccess=$false }
    $trust = Get-VgtPathTrust $Path
    if ($trust.Kind -ne 'LocalFixed' -or $trust.Path -eq '') { $status.Status = 'RejectedLocalOnly'; return [pscustomobject]$status }
    if (-not (Test-VgtPathNoReparse $trust.Path)) { $status.Status = 'RejectedReparse'; return [pscustomobject]$status }
    if ($null -eq $Budget) { $Budget = @{ DeadlineUtc = ([DateTime]::UtcNow.AddSeconds(90)); Checks = 0; MaxChecks = 64; Exhausted = $false } }
    if ([int]$Budget.Checks -ge [int]$Budget.MaxChecks -or [DateTime]::UtcNow -gt [DateTime]$Budget.DeadlineUtc) {
        $Budget.Exhausted = $true
        $status.Status = 'BudgetExhausted'
        return [pscustomobject]$status
    }
    $Budget.Checks = [int]$Budget.Checks + 1
    $status.FileAccess = $true
    $bounded = Invoke-VgtBoundedScript -Script {
        param($candidate)
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $candidate -ErrorAction Stop
            if ($null -eq $signature -or [string]::IsNullOrWhiteSpace([string]$signature.Status)) { 'Unavailable' } else { [string]$signature.Status }
        } catch { 'Unavailable' }
    } -ArgumentList @($trust.Path) -TimeoutSeconds $TimeoutSeconds
    if (-not $bounded.Completed) {
        $status.Status = if ($bounded.TimedOut) { 'Timeout' } else { 'Unavailable' }
        return [pscustomobject]$status
    }
    $value = if ($null -ne $bounded.Value) { [string]$bounded.Value } else { '' }
    if ($value -in @('Valid','NotSigned','HashMismatch','NotTrusted','UnknownError','NotSupportedFileFormat','Incompatible')) {
        $status.Status = $value
    } else {
        $status.Status = 'Unavailable'
    }
    return [pscustomobject]$status
}

function Add-VgtSignatureFinding {
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Entity,
        [Parameter(Mandatory)][string]$Evidence
    )
    Add-VgtFinding $Severity $Category $Title $Description $Entity $Evidence
}

# Signature findings only ever derive from bounded local-only evaluation. A
# negative status keeps the former high-severity finding; incomplete
# verification is reported as unverified instead of being silently treated as
# unsigned (no fake pass in either direction).
function Add-VgtSignatureFindings {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SignatureStatus,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$UnsignedTitle,
        [Parameter(Mandatory)][string]$UnsignedDescription,
        [Parameter(Mandatory)][string]$SignedTitle,
        [Parameter(Mandatory)][string]$ReparseTitle,
        [Parameter(Mandatory)][string]$UnverifiedTitle,
        [AllowEmptyString()][string]$Entity = '',
        [AllowEmptyString()][string]$Context = ''
    )
    $safePath = Get-VgtSafeText $Path 800
    $evidence = ("path=$safePath; signature=$SignatureStatus; $Context").Trim()
    if ($SignatureStatus -eq 'Valid') { return }
    if ($SignatureStatus -eq 'RejectedReparse') {
        Add-VgtSignatureFinding 'High' $Category $ReparseTitle 'A target path traverses a reparse point. The scan refused to open the file, so no signature verification was performed.' $Entity $evidence
        return
    }
    if ($SignatureStatus -in @('NotSigned','HashMismatch','NotTrusted','UnknownError','NotSupportedFileFormat','Incompatible')) {
        Add-VgtSignatureFinding 'High' $Category $UnsignedTitle $UnsignedDescription $Entity $evidence
        return
    }
    Add-VgtSignatureFinding 'Medium' $Category $UnverifiedTitle 'The bounded signature check did not complete (timeout, scan budget or non-local target). Treat the result as unverified rather than signed.' $Entity $evidence
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
    if ($commandLine -match '(?i)(?:\s|^)-(?:ec|e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|DownloadString\s*\(|FromBase64String\s*\(|Reflection\.Assembly') {
        $commandEvidence = Get-VgtEvidenceMetadata $commandLine
        Add-VgtFinding 'High' 'Execution' 'Suspicious encoded or in-memory command line' 'A live process uses an execution pattern commonly associated with fileless payloads. Validate parentage and operator intent.' "$($process.Name) [$pidKey]" $commandEvidence
    }
    if (-not $path -or -not $connectionsByPid.ContainsKey($pidKey)) { continue }
    $trust = Get-VgtPathTrust $path
    if ($trust.Kind -eq 'LocalFixed' -and [bool]$trust.UserWritable) {
        $signature = Get-VgtSignatureStatus -Path $trust.Path -Budget $signatureBudget
        Add-VgtSignatureFindings -Path $trust.Path -SignatureStatus $signature.Status -Category 'Network' `
            -UnsignedTitle 'Unsigned user-writable executable has remote connections' `
            -UnsignedDescription 'An unsigned process launched from a user-writable directory communicates with a remote endpoint.' `
            -SignedTitle 'Signed user-writable executable has remote connections' `
            -ReparseTitle 'User-writable process image traverses a reparse point' `
            -UnverifiedTitle 'Process image signature could not be verified' `
            -Entity "$($process.Name) [$pidKey]" `
            -Context (($connectionsByPid[$pidKey] | Select-Object -First 10) -join ', ')
    } elseif ($trust.Kind -in @('NonLocal','AlternateDataStream')) {
        Add-VgtSignatureFinding 'Medium' 'Network' 'Network-connected process image uses a non-local path' 'The process image path is not a plain local fixed-disk path. Signature verification was skipped and the scan never opened the path.' "$($process.Name) [$pidKey]" ((Get-VgtSafeText $path 800) + "; kind=$($trust.Kind)")
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
            if (-not $executable) { continue }
            $trust = Get-VgtPathTrust $executable
            $context = "$($property.Name) @ $location"
            if ($trust.Kind -eq 'NonLocal') {
                Add-VgtSignatureFinding 'High' 'Persistence' 'Autorun references a non-local executable path' 'A Run key launches an executable from a UNC, device or non-fixed-drive path. The scan reported the target without opening it, so no SYSTEM network authentication occurred.' (Get-VgtSafeText $executable 800) "kind=$($trust.Kind); $context"
                continue
            }
            if ($trust.Kind -eq 'AlternateDataStream') {
                Add-VgtSignatureFinding 'High' 'Persistence' 'Autorun references an alternate-data-stream path' 'A Run key target uses an alternate data stream path. The scan refused to open it.' (Get-VgtSafeText $executable 800) "kind=$($trust.Kind); $context"
                continue
            }
            if ($trust.Kind -eq 'LocalFixed' -and [bool]$trust.UserWritable) {
                $signature = Get-VgtSignatureStatus -Path $trust.Path -Budget $signatureBudget
                Add-VgtSignatureFindings -Path $trust.Path -SignatureStatus $signature.Status -Category 'Persistence' `
                    -UnsignedTitle 'Unsigned user-writable autorun' `
                    -UnsignedDescription 'A Run key launches an unsigned executable from a user-writable directory.' `
                    -SignedTitle 'Signed user-writable autorun' `
                    -ReparseTitle 'Autorun target traverses a reparse point' `
                    -UnverifiedTitle 'Autorun signature could not be verified' `
                    -Entity $trust.Path -Context $context
            }
        }
    }
}

foreach ($consumerClass in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
    foreach ($consumer in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $consumerClass -ErrorAction SilentlyContinue | Select-Object -First 100)) {
        $scanned++
        $sensitiveMaterial = (([string]$consumer.CommandLineTemplate) + "`n" + ([string]$consumer.ScriptText))
        $details = [ordered]@{
            class = $consumerClass
            executablePath = Get-VgtSafeText ([string]$consumer.ExecutablePath) 800
            scriptingEngine = Get-VgtSafeText ([string]$consumer.ScriptingEngine) 256
            sensitiveEvidence = Get-VgtEvidenceMetadata $sensitiveMaterial
        } | ConvertTo-Json -Compress
        $severity = if($consumerClass -eq 'ActiveScriptEventConsumer'){'High'}else{'Medium'}
        Add-VgtFinding $severity 'Persistence' 'Permanent WMI event consumer present' 'Permanent WMI consumers are a legitimate administration mechanism but also a durable persistence primitive. Verify provenance.' ([string]$consumer.Name) $details
    }
}

foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -First 1000)) {
    $scanned++
    $servicePath = [string]$service.PathName
    if ($servicePath -match '^\s*[^"\r\n]+\s+[^"\r\n]+\.exe(?:\s|$)') {
        Add-VgtFinding 'Medium' 'Persistence' 'Unquoted service executable path' 'A service path containing spaces is not quoted and may permit executable path hijacking when directory permissions are weak.' ([string]$service.Name) (Get-VgtSafeText $servicePath 800)
    }
    $serviceExecutable = Get-VgtExecutableFromCommand $servicePath
    if (-not $serviceExecutable) { continue }
    $trust = Get-VgtPathTrust $serviceExecutable
    if ($trust.Kind -eq 'NonLocal') {
        Add-VgtSignatureFinding 'High' 'Persistence' 'Service references a non-local executable path' 'A privileged service references an executable outside local fixed storage. The scan reported it without opening the path.' ([string]$service.Name) ((Get-VgtSafeText $serviceExecutable 800) + "; kind=$($trust.Kind)")
        continue
    }
    if ($trust.Kind -eq 'LocalFixed' -and [bool]$trust.UserWritable) {
        Add-VgtFinding 'Critical' 'Persistence' 'Service executable in user-writable directory' 'A privileged service references an executable in a user-writable location.' ([string]$service.Name) $trust.Path
    }
}

foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object -First 1500)) {
    foreach ($action in @($task.Actions)) {
        $scanned++
        $executeProperty = $action.PSObject.Properties['Execute']
        if (-not $executeProperty -and $action.PSObject.Properties['CimInstanceProperties']) { $executeProperty = $action.CimInstanceProperties['Execute'] }
        $execute = if($executeProperty){[string]$executeProperty.Value}else{''}
        if ([string]::IsNullOrWhiteSpace($execute)) { continue }
        $trust = Get-VgtPathTrust $execute
        $context = "$($task.TaskPath)$($task.TaskName)"
        if ($trust.Kind -eq 'NonLocal') {
            Add-VgtSignatureFinding 'High' 'Persistence' 'Scheduled task action references a non-local executable path' 'A scheduled task launches an executable from a UNC, device or non-fixed-drive path. The scan reported the target without opening it, so no SYSTEM network authentication occurred.' (Get-VgtSafeText $execute 800) "kind=$($trust.Kind); $context"
            continue
        }
        if ($trust.Kind -eq 'AlternateDataStream') {
            Add-VgtSignatureFinding 'High' 'Persistence' 'Scheduled task action references an alternate-data-stream path' 'A scheduled task target uses an alternate data stream path. The scan refused to open it.' (Get-VgtSafeText $execute 800) "kind=$($trust.Kind); $context"
            continue
        }
        if ($trust.Kind -eq 'LocalFixed' -and [bool]$trust.UserWritable) {
            $signature = Get-VgtSignatureStatus -Path $trust.Path -Budget $signatureBudget
            Add-VgtSignatureFindings -Path $trust.Path -SignatureStatus $signature.Status -Category 'Persistence' `
                -UnsignedTitle 'Unsigned scheduled task action in user-writable directory' `
                -UnsignedDescription 'A scheduled task launches an unsigned executable from a user-writable location.' `
                -SignedTitle 'Signed scheduled task action in user-writable directory' `
                -ReparseTitle 'Scheduled task action traverses a reparse point' `
                -UnverifiedTitle 'Scheduled task signature could not be verified' `
                -Entity $trust.Path -Context $context
        }
    }
}

$preference = Get-MpPreference -ErrorAction SilentlyContinue
if ($preference) {
    foreach ($exclusion in @($preference.ExclusionPath) + @($preference.ExclusionProcess)) {
        $scanned++
        if ([string]::IsNullOrWhiteSpace([string]$exclusion) -or [string]$exclusion -match '^(?i)N/A:') { continue }
        $severity = if(([string]$exclusion) -match '^(?i)([A-Z]:\\|\*|\\Users\\|\\Windows\\)'){'High'}else{'Medium'}
        Add-VgtFinding $severity 'DefenseEvasion' 'Microsoft Defender exclusion configured' 'Defender exclusions reduce inspection coverage and require explicit business justification.' (Get-VgtSafeText ([string]$exclusion) 800) 'Get-MpPreference exclusion inventory'
    }
}

foreach ($threat in @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object InitialDetectionTime -GT ([DateTime]::UtcNow.AddDays(-30)) | Select-Object -First 200)) {
    $scanned++
    Add-VgtFinding 'High' 'Malware' 'Recent Microsoft Defender threat detection' 'Microsoft Defender recorded a threat detection during the last 30 days. Confirm remediation and affected resources.' ([string]$threat.ThreatID) ((@($threat.Resources) | Select-Object -First 10) -join ', ')
}

if ([bool]$signatureBudget.Exhausted) {
    Add-VgtSignatureFinding 'Medium' 'Detection' 'XDR signature verification budget was exhausted' 'The scan stopped opening files for signature verification to stay inside its time budget. Signature-dependent findings are incomplete for this run.' 'xdr-scan' ("checks={0}; limit={1}; deadline={2:o}" -f $signatureBudget.Checks,$signatureBudget.MaxChecks,$signatureBudget.DeadlineUtc)
}

$critical = @($findings | Where-Object Severity -eq 'Critical').Count
$high = @($findings | Where-Object Severity -eq 'High').Count
$medium = @($findings | Where-Object Severity -eq 'Medium').Count
$low = @($findings | Where-Object Severity -eq 'Low').Count
[ordered]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    Engine = 'VGT MHX 7.0 read-only XDR'
    Scanned = $scanned
    Critical = $critical
    High = $high
    Medium = $medium
    Low = $low
    Findings = @($findings)
} | ConvertTo-Json -Depth 7 -Compress | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
