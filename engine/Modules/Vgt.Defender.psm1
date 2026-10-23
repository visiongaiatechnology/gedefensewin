# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:VgtSettingsMaxBytes = 65536
$script:VgtAsrActionNumberMap = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }
$script:VgtAsrActionNames = @('Disabled','Enabled','AuditMode','Warn')
$script:VgtAsrActionConfigMap = @{ 'enabled' = 'Enabled'; 'block' = 'Enabled'; 'auditmode' = 'AuditMode'; 'audit' = 'AuditMode'; 'disabled' = 'Disabled'; 'warn' = 'Warn' }
$script:VgtAsrActionConfigNames = @('Enabled','AuditMode','Disabled','Warn','Block','Audit')
$script:VgtCloudBlockLevelMap = @{ 0 = 'Default'; 1 = 'Normal'; 2 = 'High'; 4 = 'HighPlus'; 6 = 'ZeroTolerance' }
$script:VgtCloudBlockLevelNames = @('Default','Normal','High','HighPlus','ZeroTolerance')
$script:VgtMapsReportingMap = @{ 0 = 'Disabled'; 1 = 'Basic'; 2 = 'Advanced' }
$script:VgtMapsReportingNames = @('Disabled','Basic','Advanced')
$script:VgtSampleConsentMap = @{ 0 = 'AlwaysPrompt'; 1 = 'SendSafeSamples'; 2 = 'NeverSend'; 3 = 'SendAllSamples' }
$script:VgtSampleConsentNames = @('AlwaysPrompt','SendSafeSamples','NeverSend','SendAllSamples')
$script:VgtDefenderModeMap = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode' }
$script:VgtDefenderModeNames = @('Enabled','AuditMode','Disabled')
$script:VgtSupportedComponents = @('DefenderCloud','ASR','ControlledFolderAccess','Firewall','CredentialGuard','MemoryIntegrity','LSASS','SMB','PowerShellLogging','UAC','USBStorage','RemoteDesktop')
$script:VgtAsrRuleCatalog = @(
    [ordered]@{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Label = 'Block executable content from email client and webmail' },
    [ordered]@{ Id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Label = 'Block all Office applications from creating child processes' },
    [ordered]@{ Id = '3b576869-a4ec-4529-8536-b80a7769e899'; Label = 'Block Office applications from creating executable content' },
    [ordered]@{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Label = 'Block Office applications from injecting code into other processes' },
    [ordered]@{ Id = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Label = 'Block JavaScript or VBScript from launching downloaded executable content' },
    [ordered]@{ Id = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Label = 'Block execution of potentially obfuscated scripts' },
    [ordered]@{ Id = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Label = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion' },
    [ordered]@{ Id = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Label = 'Block untrusted and unsigned processes that run from USB' },
    [ordered]@{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Label = 'Block credential stealing from the Windows local security authority subsystem' },
    [ordered]@{ Id = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Label = 'Block persistence through WMI event subscription' },
    [ordered]@{ Id = '33ddedf1-c6e0-47cb-833e-de6133960387'; Label = 'Block process creations originating from PSExec and WMI commands' }
)
$script:VgtAsrRuleIds = @($script:VgtAsrRuleCatalog | ForEach-Object { [string]$_['Id'] })

function Get-VgtPropertyValue {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-VgtOptionalBool {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    return $null
}

function ConvertTo-VgtOptionalInt {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [int]$Value } catch { return $null }
}

function ConvertTo-VgtOptionalString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [string]$Value } catch { return $null }
}

function ConvertTo-VgtOptionalDateString {
    param($Value)
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('o') }
    return $null
}

function ConvertTo-VgtEnumName {
    param($Value,[Parameter(Mandatory)][hashtable]$NumberMap,[Parameter(Mandatory)][string[]]$Names)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $text = $Value.Trim()
        foreach ($name in $Names) { if ($name -eq $text) { return $name } }
        $parsed = 0
        if ([int]::TryParse($text,[ref]$parsed) -and $NumberMap.ContainsKey($parsed)) { return [string]$NumberMap[$parsed] }
        return $text
    }
    $number = 0
    try { $number = [int]$Value } catch { return [string]$Value }
    if ($NumberMap.ContainsKey($number)) { return [string]$NumberMap[$number] }
    return [string]$number
}

function Format-VgtSafeToken {
    param([string]$Value)
    $text = [string]$Value
    $text = $text -replace '[^A-Za-z0-9_.:-]', '?'
    if ($text.Length -gt 64) { $text = $text.Substring(0,64) }
    return $text
}

function Get-VgtCollectionCount {
    param($Object,[Parameter(Mandatory)][string]$Name)
    $value = Get-VgtPropertyValue $Object $Name
    if ($null -eq $value) { return $null }
    return @($value).Count
}

function Get-VgtExclusionValues {
    param($Preference,[Parameter(Mandatory)][string]$Name)
    $value = Get-VgtPropertyValue $Preference $Name
    if ($null -eq $value) { return $null }
    $values = @($value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
    if ($values.Count -eq 0) { return @() }
    foreach ($entry in $values) {
        if ($entry -match '^(?i)N/A') { return $null }
    }
    return $values
}

function Get-VgtAsrTelemetry {
    param([Parameter(Mandatory)]$Preference)
    $ids = @(Get-VgtPropertyValue $Preference 'AttackSurfaceReductionRules_Ids')
    $actions = @(Get-VgtPropertyValue $Preference 'AttackSurfaceReductionRules_Actions')
    $configured = [ordered]@{}
    $order = [System.Collections.Generic.List[string]]::new()
    $limit = $script:VgtAsrRuleCatalog.Count + 64
    $truncated = $false
    for ($index = 0; $index -lt $ids.Count; $index++) {
        $rawId = [string]$ids[$index]
        $guid = [guid]::Empty
        if (-not [guid]::TryParse($rawId,[ref]$guid)) { continue }
        $id = $guid.ToString().ToLowerInvariant()
        if ($configured.Contains($id)) { continue }
        if ($order.Count -ge $limit) { $truncated = $true; break }
        $rawAction = $null
        if ($index -lt $actions.Count) { $rawAction = ConvertTo-VgtOptionalInt $actions[$index] }
        $configured[$id] = $rawAction
        [void]$order.Add($id)
    }
    $rules = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    $enabledCount = 0
    $auditCount = 0
    $warnCount = 0
    foreach ($definition in $script:VgtAsrRuleCatalog) {
        $id = [string]$definition['Id']
        $entry = [ordered]@{ Id = $id; Label = [string]$definition['Label']; Recommended = $true; Configured = $false; Action = $null; ActionName = $null }
        if ($configured.Contains($id)) {
            $rawAction = $configured[$id]
            $entry['Configured'] = $true
            $entry['Action'] = $rawAction
            $entry['ActionName'] = ConvertTo-VgtEnumName $rawAction $script:VgtAsrActionNumberMap $script:VgtAsrActionNames
        } else {
            [void]$missing.Add($id)
        }
        [void]$rules.Add($entry)
    }
    # Counts reflect every configured rule; the rule list stays bounded.
    foreach ($id in $order) {
        $actionName = ConvertTo-VgtEnumName $configured[$id] $script:VgtAsrActionNumberMap $script:VgtAsrActionNames
        if ($actionName -eq 'Enabled') { $enabledCount++ } elseif ($actionName -eq 'AuditMode') { $auditCount++ } elseif ($actionName -eq 'Warn') { $warnCount++ }
        if ($script:VgtAsrRuleIds -ccontains $id) { continue }
        [void]$rules.Add([ordered]@{ Id = $id; Label = $null; Recommended = $false; Configured = $true; Action = $configured[$id]; ActionName = $actionName })
    }
    return [ordered]@{
        Available = $true
        RulesTruncated = $truncated
        ConfiguredCount = $order.Count
        EnabledCount = $enabledCount
        AuditCount = $auditCount
        WarnCount = $warnCount
        RecommendedCount = $script:VgtAsrRuleCatalog.Count
        RecommendedMissing = @($missing.ToArray())
        Rules = @($rules.ToArray())
    }
}

function Get-VgtDefenderTelemetry {
    [CmdletBinding()]
    param()
    $captured = [DateTime]::UtcNow.ToString('o')
    $status = $null
    $statusAvailable = $false
    try { $status = Get-MpComputerStatus -ErrorAction Stop; $statusAvailable = $true } catch { $status = $null }
    $preference = $null
    $preferenceAvailable = $false
    try { $preference = Get-MpPreference -ErrorAction Stop; $preferenceAvailable = $true } catch { $preference = $null }
    $detections = $null
    $detectionAvailable = $false
    try { $detections = @(Get-MpThreatDetection -ErrorAction Stop); $detectionAvailable = $true } catch { $detections = $null }
    $threats = $null
    $threatAvailable = $false
    try { $threats = @(Get-MpThreat -ErrorAction Stop); $threatAvailable = $true } catch { $threats = $null }

    $statusReport = $null
    if ($statusAvailable) {
        $statusReport = [ordered]@{
            AntivirusEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'AntivirusEnabled')
            AntispywareEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'AntispywareEnabled')
            AMServiceEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'AMServiceEnabled')
            RealTimeProtectionEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'RealTimeProtectionEnabled')
            BehaviorMonitorEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'BehaviorMonitorEnabled')
            IoavProtectionEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'IoavProtectionEnabled')
            OnAccessProtectionEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'OnAccessProtectionEnabled')
            IsTamperProtected = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'IsTamperProtected')
            NISEnabled = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'NISEnabled')
            DefenderSignaturesOutOfDate = ConvertTo-VgtOptionalBool (Get-VgtPropertyValue $status 'DefenderSignaturesOutOfDate')
            AntivirusSignatureVersion = ConvertTo-VgtOptionalString (Get-VgtPropertyValue $status 'AntivirusSignatureVersion')
            AntivirusSignatureAge = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $status 'AntivirusSignatureAge')
            AntivirusSignatureLastUpdated = ConvertTo-VgtOptionalDateString (Get-VgtPropertyValue $status 'AntivirusSignatureLastUpdated')
            AntispywareSignatureVersion = ConvertTo-VgtOptionalString (Get-VgtPropertyValue $status 'AntispywareSignatureVersion')
            AntispywareSignatureAge = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $status 'AntispywareSignatureAge')
            AntispywareSignatureLastUpdated = ConvertTo-VgtOptionalDateString (Get-VgtPropertyValue $status 'AntispywareSignatureLastUpdated')
            NISSignatureVersion = ConvertTo-VgtOptionalString (Get-VgtPropertyValue $status 'NISSignatureVersion')
            NISSignatureAge = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $status 'NISSignatureAge')
            AMEngineVersion = ConvertTo-VgtOptionalString (Get-VgtPropertyValue $status 'AMEngineVersion')
            AMProductVersion = ConvertTo-VgtOptionalString (Get-VgtPropertyValue $status 'AMProductVersion')
            QuickScanAge = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $status 'QuickScanAge')
            FullScanAge = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $status 'FullScanAge')
        }
    }

    $preferenceReport = $null
    if ($preferenceAvailable) {
        $cloudRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'CloudBlockLevel')
        $mapsRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'MAPSReporting')
        $consentRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'SubmitSamplesConsent')
        $puaRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'PUAProtection')
        $networkRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'EnableNetworkProtection')
        $cfaRaw = ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'EnableControlledFolderAccess')
        $preferenceReport = [ordered]@{
            CloudBlockLevel = ConvertTo-VgtEnumName $cloudRaw $script:VgtCloudBlockLevelMap $script:VgtCloudBlockLevelNames
            CloudBlockLevelRaw = $cloudRaw
            MAPSReporting = ConvertTo-VgtEnumName $mapsRaw $script:VgtMapsReportingMap $script:VgtMapsReportingNames
            MAPSReportingRaw = $mapsRaw
            SubmitSamplesConsent = ConvertTo-VgtEnumName $consentRaw $script:VgtSampleConsentMap $script:VgtSampleConsentNames
            SubmitSamplesConsentRaw = $consentRaw
            PUAProtection = ConvertTo-VgtEnumName $puaRaw $script:VgtDefenderModeMap $script:VgtDefenderModeNames
            PUAProtectionRaw = $puaRaw
            NetworkProtection = ConvertTo-VgtEnumName $networkRaw $script:VgtDefenderModeMap $script:VgtDefenderModeNames
            NetworkProtectionRaw = $networkRaw
            ControlledFolderAccess = ConvertTo-VgtEnumName $cfaRaw $script:VgtDefenderModeMap $script:VgtDefenderModeNames
            ControlledFolderAccessRaw = $cfaRaw
            ControlledFolderAccessAllowedApplicationsCount = Get-VgtCollectionCount $preference 'ControlledFolderAccessAllowedApplications'
            ControlledFolderAccessProtectedFoldersCount = Get-VgtCollectionCount $preference 'ControlledFolderAccessProtectedFolders'
        }
    }

    $asrReport = $null
    $exclusionReport = $null
    if ($preferenceAvailable) {
        $asrReport = Get-VgtAsrTelemetry -Preference $preference
        $pathValues = Get-VgtExclusionValues $preference 'ExclusionPath'
        $processValues = Get-VgtExclusionValues $preference 'ExclusionProcess'
        $extensionValues = Get-VgtExclusionValues $preference 'ExclusionExtension'
        $ipValues = Get-VgtExclusionValues $preference 'ExclusionIpAddress'
        $extensions = [System.Collections.Generic.List[string]]::new()
        $extensionsTruncated = $false
        if ($null -ne $extensionValues) {
            foreach ($extension in $extensionValues) {
                if ($extensions.Count -ge 32) { $extensionsTruncated = $true; break }
                $text = [string]$extension
                if ($text -match '^\.?[A-Za-z0-9_-]{1,24}$') { [void]$extensions.Add($text) }
            }
        }
        $exclusionReport = [ordered]@{
            Available = [bool]($null -ne $pathValues -or $null -ne $processValues -or $null -ne $extensionValues -or $null -ne $ipValues)
            # PowerShell unrolls a single-element function result to a scalar. Wrap every
            # optional collection before reading .Count; under Set-StrictMode a scalar
            # string has no Count property, which previously made the whole Defender
            # telemetry snapshot unavailable whenever exactly one exclusion existed.
            PathCount = if ($null -ne $pathValues) { @($pathValues).Count } else { $null }
            ProcessCount = if ($null -ne $processValues) { @($processValues).Count } else { $null }
            ExtensionCount = if ($null -ne $extensionValues) { @($extensionValues).Count } else { $null }
            IpAddressCount = if ($null -ne $ipValues) { @($ipValues).Count } else { $null }
            Extensions = @($extensions.ToArray())
            ExtensionsTruncated = $extensionsTruncated
        }
    }

    $threatReport = $null
    if ($detectionAvailable -or $threatAvailable) {
        $detectionCount = $null
        $latestDetection = $null
        if ($detectionAvailable) {
            $detectionCount = $detections.Count
            $latestTime = $null
            foreach ($detection in $detections) {
                $value = Get-VgtPropertyValue $detection 'InitialDetectionTime'
                if ($value -is [DateTime] -and ($null -eq $latestTime -or $value -gt $latestTime)) { $latestTime = $value }
            }
            if ($null -ne $latestTime) { $latestDetection = $latestTime.ToUniversalTime().ToString('o') }
        }
        $activeThreatCount = $null
        if ($threatAvailable) { $activeThreatCount = $threats.Count }
        $threatReport = [ordered]@{
            Available = $true
            DetectionQueryAvailable = $detectionAvailable
            ThreatQueryAvailable = $threatAvailable
            DetectionCount = $detectionCount
            ActiveThreatCount = $activeThreatCount
            LatestDetectionUtc = $latestDetection
        }
    }

    return [ordered]@{
        CapturedUtc = $captured
        SourcesAttempted = @('Get-MpComputerStatus','Get-MpPreference','Get-MpThreatDetection','Get-MpThreat','Get-NetFirewallProfile')
        Available = [bool]($statusAvailable -or $preferenceAvailable)
        ComputerStatusAvailable = $statusAvailable
        PreferenceAvailable = $preferenceAvailable
        ThreatDetectionAvailable = $detectionAvailable
        ThreatQueryAvailable = $threatAvailable
        FirewallAvailable = $false
        Status = $statusReport
        Preference = $preferenceReport
        AttackSurfaceReduction = $asrReport
        Exclusions = $exclusionReport
        Threats = $threatReport
        Firewall = $null
    }
}

function Get-VgtAsrRuleCatalog {
    [CmdletBinding()]
    param()
    return @($script:VgtAsrRuleCatalog | ForEach-Object { [ordered]@{ Id = [string]$_['Id']; Label = [string]$_['Label'] } })
}

function Assert-VgtSettingsProperties {
    param($Object,[string[]]$Allowed,[Parameter(Mandatory)][string]$Context)
    if ($null -eq $Object) { throw [Security.SecurityException]::new(('Settings {0}: object required.' -f $Context)) }
    if ($Object -isnot [pscustomobject]) { throw [Security.SecurityException]::new(('Settings {0}: JSON object required.' -f $Context)) }
    foreach ($property in $Object.PSObject.Properties) {
        if ($Allowed -cnotcontains $property.Name) {
            throw [Security.SecurityException]::new(('Settings {0}: unsupported property {1}.' -f $Context,(Format-VgtSafeToken -Value $property.Name)))
        }
    }
}

function Get-VgtJsonProperty {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return [pscustomobject][ordered]@{ Present = $false; Value = $null } }
    return [pscustomobject][ordered]@{ Present = $true; Value = $property.Value }
}

function Resolve-VgtSettingsEnum {
    param($Value,[string[]]$Names,[Parameter(Mandatory)][string]$Context)
    if ($Value -isnot [string]) { throw [Security.SecurityException]::new(('Settings {0}: string value required.' -f $Context)) }
    $text = $Value.Trim()
    foreach ($name in $Names) { if ($name -eq $text) { return $name } }
    throw [Security.SecurityException]::new(('Settings {0}: unsupported value.' -f $Context))
}

function Resolve-VgtSettingsBoolean {
    param($Value,[Parameter(Mandatory)][string]$Context)
    if ($Value -isnot [bool]) { throw [Security.SecurityException]::new(('Settings {0}: boolean value required.' -f $Context)) }
    return [bool]$Value
}

function Resolve-VgtSettingsInteger {
    param($Value,[Parameter(Mandatory)][string]$Context,[Parameter(Mandatory)][int]$Minimum,[Parameter(Mandatory)][int]$Maximum)
    $number = [long]0
    if ($Value -is [int] -or $Value -is [long]) {
        $number = [long]$Value
    } elseif ($Value -is [double] -and [math]::Floor([double]$Value) -eq [double]$Value) {
        $number = [long]$Value
    } else {
        throw [Security.SecurityException]::new(('Settings {0}: integer value required.' -f $Context))
    }
    if ($number -lt $Minimum -or $number -gt $Maximum) { throw [Security.SecurityException]::new(('Settings {0}: value outside boundary.' -f $Context)) }
    return [int]$number
}

function Resolve-VgtAsrActionSetting {
    param($Value,[Parameter(Mandatory)][string]$Context)
    if ($Value -isnot [string]) { throw [Security.SecurityException]::new(('Settings {0}: string value required.' -f $Context)) }
    $key = $Value.Trim().ToLowerInvariant()
    if (-not $script:VgtAsrActionConfigMap.ContainsKey($key)) { throw [Security.SecurityException]::new(('Settings {0}: unsupported value.' -f $Context)) }
    return [string]$script:VgtAsrActionConfigMap[$key]
}

function Read-VgtSettingsConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath,[int]$MaxBytes = 65536)
    if ($MaxBytes -lt 1 -or $MaxBytes -gt 65536) { throw [Security.SecurityException]::new('Settings configuration size boundary invalid.') }
    $resolved = [IO.Path]::GetFullPath($ConfigPath)
    $file = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($file.PSIsContainer) { throw [Security.SecurityException]::new('Settings configuration must be a regular file.') }
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw [Security.SecurityException]::new('Settings configuration reparse point rejected.') }
    if ($file.Length -le 0 -or $file.Length -gt $MaxBytes) { throw [Security.SecurityException]::new('Settings configuration size rejected.') }
    $bytes = [IO.File]::ReadAllBytes($resolved)
    if ($bytes.Length -ne $file.Length) { throw [Security.SecurityException]::new('Settings configuration changed while reading.') }
    $strictUtf8 = New-Object Text.UTF8Encoding($false,$true)
    try { $text = $strictUtf8.GetString($bytes) } catch { throw [Security.SecurityException]::new('Settings configuration encoding rejected.') }
    if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
    if ($text.IndexOf([char]0) -ge 0) { throw [Security.SecurityException]::new('Settings configuration control byte rejected.') }
    try { $json = ConvertFrom-Json -InputObject $text -ErrorAction Stop } catch { throw [Security.SecurityException]::new('Settings configuration JSON rejected.') }
    if ($null -eq $json) { throw [Security.SecurityException]::new('Settings configuration JSON rejected.') }
    Assert-VgtSettingsProperties $json @('schemaVersion','defender','firewall','components') 'root'
    $schemaEntry = Get-VgtJsonProperty $json 'schemaVersion'
    if (-not $schemaEntry.Present) { throw [Security.SecurityException]::new('Settings schemaVersion is required.') }
    $null = Resolve-VgtSettingsInteger $schemaEntry.Value 'schemaVersion' 1 1

    $settings = [ordered]@{ schemaVersion = 1 }
    $hasSettings = $false

    $defenderEntry = Get-VgtJsonProperty $json 'defender'
    if ($defenderEntry.Present -and $null -ne $defenderEntry.Value) {
        $defender = $defenderEntry.Value
        Assert-VgtSettingsProperties $defender @('cloudBlockLevel','mapsReporting','submitSamplesConsent','networkProtection','puaProtection','controlledFolderAccess','asrRules') 'defender'
        $normalizedDefender = [ordered]@{}
        $enumFields = @(
            @('cloudBlockLevel', $script:VgtCloudBlockLevelNames),
            @('mapsReporting', $script:VgtMapsReportingNames),
            @('submitSamplesConsent', $script:VgtSampleConsentNames),
            @('networkProtection', $script:VgtDefenderModeNames),
            @('puaProtection', $script:VgtDefenderModeNames),
            @('controlledFolderAccess', $script:VgtDefenderModeNames)
        )
        foreach ($field in $enumFields) {
            $entry = Get-VgtJsonProperty $defender $field[0]
            if ($entry.Present -and $null -ne $entry.Value) {
                $normalizedDefender[$field[0]] = Resolve-VgtSettingsEnum $entry.Value $field[1] ('defender.' + $field[0])
            }
        }
        $asrEntry = Get-VgtJsonProperty $defender 'asrRules'
        if ($asrEntry.Present -and $null -ne $asrEntry.Value) {
            $rules = $asrEntry.Value
            if ($null -eq $rules -or $rules -isnot [System.Array]) { throw [Security.SecurityException]::new('Settings defender.asrRules: array required.') }
            if ($rules.Count -lt 1 -or $rules.Count -gt $script:VgtAsrRuleCatalog.Count) { throw [Security.SecurityException]::new('Settings defender.asrRules: count rejected.') }
            $seenRules = @{}
            $normalizedRules = [System.Collections.Generic.List[object]]::new()
            foreach ($rule in $rules) {
                Assert-VgtSettingsProperties $rule @('id','action') 'defender.asrRules[]'
                $idEntry = Get-VgtJsonProperty $rule 'id'
                if (-not $idEntry.Present) { throw [Security.SecurityException]::new('Settings defender.asrRules: id required.') }
                if ($idEntry.Value -isnot [string]) { throw [Security.SecurityException]::new('Settings defender.asrRules: id must be a string.') }
                $guid = [guid]::Empty
                if (-not [guid]::TryParse($idEntry.Value.Trim(),[ref]$guid)) { throw [Security.SecurityException]::new('Settings defender.asrRules: invalid id.') }
                $ruleId = $guid.ToString().ToLowerInvariant()
                if ($script:VgtAsrRuleIds -cnotcontains $ruleId) { throw [Security.SecurityException]::new('Settings defender.asrRules: unsupported id.') }
                if ($seenRules.ContainsKey($ruleId)) { throw [Security.SecurityException]::new('Settings defender.asrRules: duplicate id.') }
                $seenRules[$ruleId] = $true
                $actionEntry = Get-VgtJsonProperty $rule 'action'
                if (-not $actionEntry.Present) { throw [Security.SecurityException]::new('Settings defender.asrRules: action required.') }
                $action = Resolve-VgtAsrActionSetting $actionEntry.Value ('defender.asrRules.' + $ruleId + '.action')
                [void]$normalizedRules.Add([ordered]@{ id = $ruleId; action = $action })
            }
            $normalizedDefender['asrRules'] = @($normalizedRules.ToArray())
        }
        if ($normalizedDefender.Count -eq 0) { throw [Security.SecurityException]::new('Settings defender: no supported settings.') }
        $settings['defender'] = $normalizedDefender
        $hasSettings = $true
    }

    $firewallEntry = Get-VgtJsonProperty $json 'firewall'
    if ($firewallEntry.Present -and $null -ne $firewallEntry.Value) {
        Assert-VgtSettingsProperties $firewallEntry.Value @('profiles') 'firewall'
        $profilesEntry = Get-VgtJsonProperty $firewallEntry.Value 'profiles'
        if (-not $profilesEntry.Present) { throw [Security.SecurityException]::new('Settings firewall.profiles is required.') }
        $profiles = $profilesEntry.Value
        if ($null -eq $profiles -or $profiles -isnot [System.Array]) { throw [Security.SecurityException]::new('Settings firewall.profiles: array required.') }
        if ($profiles.Count -lt 1 -or $profiles.Count -gt 3) { throw [Security.SecurityException]::new('Settings firewall.profiles: count rejected.') }
        $seenProfiles = @{}
        $normalizedProfiles = [System.Collections.Generic.List[object]]::new()
        foreach ($profile in $profiles) {
            Assert-VgtSettingsProperties $profile @('name','enabled','defaultInboundAction','defaultOutboundAction','notifyOnListen','allowUnicastResponseToMulticast','logBlocked','logAllowed','logMaxSizeKilobytes') 'firewall.profiles[]'
            $nameEntry = Get-VgtJsonProperty $profile 'name'
            if (-not $nameEntry.Present) { throw [Security.SecurityException]::new('Settings firewall.profiles: name required.') }
            $name = Resolve-VgtSettingsEnum $nameEntry.Value @('Domain','Private','Public') 'firewall.profiles[].name'
            if ($seenProfiles.ContainsKey($name)) { throw [Security.SecurityException]::new('Settings firewall.profiles: duplicate name.') }
            $seenProfiles[$name] = $true
            $normalizedProfile = [ordered]@{ name = $name }
            foreach ($field in @('enabled','notifyOnListen','allowUnicastResponseToMulticast','logBlocked','logAllowed')) {
                $entry = Get-VgtJsonProperty $profile $field
                if ($entry.Present -and $null -ne $entry.Value) { $normalizedProfile[$field] = Resolve-VgtSettingsBoolean $entry.Value ('firewall.' + $name + '.' + $field) }
            }
            foreach ($field in @(@('defaultInboundAction', @('Block','Allow')), @('defaultOutboundAction', @('Allow','Block')))) {
                $entry = Get-VgtJsonProperty $profile $field[0]
                if ($entry.Present -and $null -ne $entry.Value) { $normalizedProfile[$field[0]] = Resolve-VgtSettingsEnum $entry.Value $field[1] ('firewall.' + $name + '.' + $field[0]) }
            }
            $sizeEntry = Get-VgtJsonProperty $profile 'logMaxSizeKilobytes'
            if ($sizeEntry.Present -and $null -ne $sizeEntry.Value) { $normalizedProfile['logMaxSizeKilobytes'] = Resolve-VgtSettingsInteger $sizeEntry.Value ('firewall.' + $name + '.logMaxSizeKilobytes') 1 32767 }
            if ($normalizedProfile.Count -le 1) { throw [Security.SecurityException]::new('Settings firewall.profiles: no supported settings.') }
            [void]$normalizedProfiles.Add($normalizedProfile)
        }
        $settings['firewall'] = [ordered]@{ profiles = @($normalizedProfiles.ToArray()) }
        $hasSettings = $true
    }

    $componentsEntry = Get-VgtJsonProperty $json 'components'
    if ($componentsEntry.Present -and $null -ne $componentsEntry.Value) {
        $components = $componentsEntry.Value
        if ($null -eq $components -or $components -isnot [System.Array]) { throw [Security.SecurityException]::new('Settings components: array required.') }
        if ($components.Count -lt 1 -or $components.Count -gt $script:VgtSupportedComponents.Count) { throw [Security.SecurityException]::new('Settings components: count rejected.') }
        $seenComponents = @{}
        $normalizedComponents = [System.Collections.Generic.List[string]]::new()
        foreach ($component in $components) {
            if ($component -isnot [string]) { throw [Security.SecurityException]::new('Settings components: string required.') }
            $id = $component.Trim()
            if ($script:VgtSupportedComponents -cnotcontains $id) { throw [Security.SecurityException]::new('Settings components: unsupported component.') }
            if ($seenComponents.ContainsKey($id)) { throw [Security.SecurityException]::new('Settings components: duplicate component.') }
            $seenComponents[$id] = $true
            [void]$normalizedComponents.Add($id)
        }
        $settings['components'] = @($normalizedComponents.ToArray())
        $hasSettings = $true
    }

    if (-not $hasSettings) { throw [Security.SecurityException]::new('Settings configuration contains no supported settings.') }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    $hashHex = -join @($hash | ForEach-Object { $_.ToString('x2') })
    return [pscustomobject][ordered]@{ Settings = $settings; Sha256 = $hashHex }
}

function New-VgtSettingsApplyEntry {
    param([Parameter(Mandatory)][string]$Setting,[Parameter(Mandatory)][bool]$Changed,$Before = $null,$After = $null)
    return [ordered]@{ Setting = $Setting; Changed = [bool]$Changed; Before = $Before; After = $After }
}

function Set-VgtDefenderSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Settings,
        [Parameter(Mandatory)][System.Collections.ArrayList]$Report
    )
    Assert-VgtAdministrator
    $preference = Get-MpPreference -ErrorAction Stop
    $current = [ordered]@{
        cloudBlockLevel = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'CloudBlockLevel')) $script:VgtCloudBlockLevelMap $script:VgtCloudBlockLevelNames
        mapsReporting = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'MAPSReporting')) $script:VgtMapsReportingMap $script:VgtMapsReportingNames
        submitSamplesConsent = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'SubmitSamplesConsent')) $script:VgtSampleConsentMap $script:VgtSampleConsentNames
        networkProtection = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'EnableNetworkProtection')) $script:VgtDefenderModeMap $script:VgtDefenderModeNames
        puaProtection = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'PUAProtection')) $script:VgtDefenderModeMap $script:VgtDefenderModeNames
        controlledFolderAccess = ConvertTo-VgtEnumName (ConvertTo-VgtOptionalInt (Get-VgtPropertyValue $preference 'EnableControlledFolderAccess')) $script:VgtDefenderModeMap $script:VgtDefenderModeNames
    }
    $changeParameters = @{}
    foreach ($key in @('cloudBlockLevel','mapsReporting','submitSamplesConsent','networkProtection','puaProtection','controlledFolderAccess')) {
        if (-not $Settings.Contains($key)) { continue }
        $desired = [string]$Settings[$key]
        $before = $current[$key]
        $changed = $null -eq $before -or $before -cne $desired
        if ($changed) {
            switch ($key) {
                'cloudBlockLevel' { $changeParameters['CloudBlockLevel'] = $desired }
                'mapsReporting' { $changeParameters['MAPSReporting'] = $desired }
                'submitSamplesConsent' { $changeParameters['SubmitSamplesConsent'] = $desired }
                'networkProtection' { $changeParameters['EnableNetworkProtection'] = $desired }
                'puaProtection' { $changeParameters['PUAProtection'] = $desired }
                'controlledFolderAccess' { $changeParameters['EnableControlledFolderAccess'] = $desired }
            }
        }
        [void]$Report.Add((New-VgtSettingsApplyEntry -Setting ('defender.' + $key) -Changed $changed -Before $before -After $desired))
    }
    if ($changeParameters.Count -gt 0) { Set-MpPreference @changeParameters }

    if ($Settings.Contains('asrRules')) {
        $currentIds = @(Get-VgtPropertyValue $preference 'AttackSurfaceReductionRules_Ids')
        $currentActions = @(Get-VgtPropertyValue $preference 'AttackSurfaceReductionRules_Actions')
        if ($currentIds.Count -ne $currentActions.Count) { throw [InvalidOperationException]::new('Defender ASR rule state is inconsistent.') }
        $mergedIds = [System.Collections.Generic.List[string]]::new()
        $mergedActions = [System.Collections.Generic.List[int]]::new()
        $indexById = @{}
        for ($index = 0; $index -lt $currentIds.Count; $index++) {
            $rawId = [string]$currentIds[$index]
            $guid = [guid]::Empty
            if (-not [guid]::TryParse($rawId,[ref]$guid)) { continue }
            $id = $guid.ToString().ToLowerInvariant()
            if ($indexById.ContainsKey($id)) { continue }
            $rawAction = ConvertTo-VgtOptionalInt $currentActions[$index]
            if ($null -eq $rawAction) { throw [InvalidOperationException]::new('Defender ASR rule action is unavailable.') }
            $indexById[$id] = $mergedIds.Count
            [void]$mergedIds.Add($id)
            [void]$mergedActions.Add([int]$rawAction)
        }
        $asrChanged = $false
        foreach ($rule in @($Settings['asrRules'])) {
            $id = [string]$rule['id']
            $canonical = [string]$rule['action']
            $desired = 1
            if ($canonical -eq 'Disabled') { $desired = 0 } elseif ($canonical -eq 'AuditMode') { $desired = 2 } elseif ($canonical -eq 'Warn') { $desired = 6 }
            $before = $null
            if ($indexById.ContainsKey($id)) {
                $beforeValue = $mergedActions[$indexById[$id]]
                $before = ConvertTo-VgtEnumName $beforeValue $script:VgtAsrActionNumberMap $script:VgtAsrActionNames
                if ($beforeValue -ne $desired) { $mergedActions[$indexById[$id]] = $desired; $asrChanged = $true }
            } else {
                $indexById[$id] = $mergedIds.Count
                [void]$mergedIds.Add($id)
                [void]$mergedActions.Add($desired)
                $asrChanged = $true
            }
            $changed = $null -eq $before -or $before -cne $canonical
            [void]$Report.Add((New-VgtSettingsApplyEntry -Setting ('defender.asrRules.' + $id) -Changed $changed -Before $before -After $canonical))
        }
        if ($asrChanged) {
            Set-MpPreference -AttackSurfaceReductionRules_Ids ([string[]]$mergedIds.ToArray()) -AttackSurfaceReductionRules_Actions ([int[]]$mergedActions.ToArray())
        }
    }
}

function Set-VgtDefenderBaseline {
    param([Parameter(Mandatory)][pscustomobject]$Profile)
    $status = Get-MpComputerStatus
    if (-not $status.AntivirusEnabled) { throw [InvalidOperationException]::new('Microsoft Defender Antivirus is not active.') }

    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -CloudBlockLevel $Profile.cloudBlockLevel
    Set-MpPreference -EnableControlledFolderAccess $Profile.controlledFolderAccess

    $ids = @($script:VgtAsrRuleIds)
    $actions = @($ids | ForEach-Object { $Profile.asrMode })
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions
}

Export-ModuleMember -Function Get-VgtDefenderTelemetry,Get-VgtAsrRuleCatalog,Read-VgtSettingsConfig,Set-VgtDefenderSettings,Set-VgtDefenderBaseline
