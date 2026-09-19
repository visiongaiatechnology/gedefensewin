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
        $commandEvidence = Get-VgtEvidenceMetadata $commandLine
        Add-VgtFinding 'High' 'Execution' 'Suspicious encoded or in-memory command line' 'A live process uses an execution pattern commonly associated with fileless payloads. Validate parentage and operator intent.' "$($process.Name) [$pidKey]" $commandEvidence
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
        $sensitiveMaterial = (([string]$consumer.CommandLineTemplate) + "`n" + ([string]$consumer.ScriptText))
        $details = [ordered]@{
            class = $consumerClass
            executablePath = [string]$consumer.ExecutablePath
            scriptingEngine = [string]$consumer.ScriptingEngine
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
    Engine = 'VGT MHX 7.0 read-only XDR'
    Scanned = $scanned
    Critical = $critical
    High = $high
    Medium = $medium
    Low = $low
    Findings = @($findings)
} | ConvertTo-Json -Depth 7 -Compress | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8

# SIG # Begin signature block
# MIIHSAYJKoZIhvcNAQcCoIIHOTCCBzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDUbTZz3cu6TK0i
# FzggVqpwe8qipf9bacU3+k4hNBB7/qCCBCwwggQoMIICkKADAgECAhBc5F62BB+R
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC/jqsyCcVD
# JbhaQyNzrocAuwEz0YKzT/X74WlKDQcB1zANBgkqhkiG9w0BAQEFAASCAYC5GFOR
# iAOYI3MD9XIwwFTw/OPeQl98dA+zBrCj0PurZ2EzKzQ4HZphk88ZhvIAhPwKt2Zg
# qv18WK+I4lXCAZtqTuxL/mdoseUammZS2gxYf5Z7uazYQi42sUY2/NiLE8we7Xp8
# TFK7FevVSrqITzEg8C7JfAYN4JnI0uhcCc1k0l4QUsQZNEl4ehUsHlnRqQsbTeK0
# gcy/kGPi+IMaPvWuRz79/gRMIR2AGU3UxuUbAZmIhgBsudT8ssySWXypZFl6G4hl
# VhTWYo6IWfLNM5fSvy8n5Dlu80q6Yu6b4uQf7qch5jivLTZGEudLotkp6vUIWanZ
# 2ncn0CBhpzbchKxuuOnDIHg0mjCTXt/dRaUIMWLQnqxFpYAuqdKMkWtnyrcRGdXr
# bFJiW+cjjEjFFDlwFWJTSLq/jw6U9mY9ThO52kHLgxU07mPj2yFQuHcyZoTGHwil
# T5iwCkwtHTjPKv1T4lbkmQG3pn/Hg9Wi8bIkpWml89QqYWno9q18j+G0Bf4=
# SIG # End signature block
