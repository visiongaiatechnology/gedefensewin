# GeDefense Windows 4.1 – read-only diagnostic. Does not alter audit policy,
# firewall rules, services, files, credentials, or security settings.
[CmdletBinding()]
param([ValidatePattern('^(|[a-fA-F0-9]{64})$')][string]$ExpectedGeneration='')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$report=[ordered]@{
    timestampUtc=([DateTime]::UtcNow.ToString('o'))
    elevated=$false
    auditPolicyRaw='NOT_CHECKED'
    wfp5157ReadState='NOT_CHECKED'
    recent5157Count=0
    ruleGroupCount=0
    ruleCount=0
    enabledBlockRuleCount=0
    disabledOrNonBlockRuleCount=0
    observedGroups=@()
    expectedGenerationPrefix=if($ExpectedGeneration){$ExpectedGeneration.Substring(0,16).ToLowerInvariant()}else{''}
    expectedGenerationGroupPresent=$null
    findings=@()
    warnings=@()
    declaration='READ_ONLY_NO_ENFORCEMENT_ASSERTION'
}
$warnings=[System.Collections.Generic.List[string]]::new()
$findings=[System.Collections.Generic.List[string]]::new()
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    $report.elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $warnings.Add('Administratorprivilegien konnten nicht ermittelt werden') }
try {
    $pol=& "$env:SystemRoot\System32\auditpol.exe" /get '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' 2>&1
    $report.auditPolicyRaw=(@($pol) -join ' ').Trim()
    if($LASTEXITCODE -ne 0) { $warnings.Add("auditpol meldet Exitcode $LASTEXITCODE") }
    # Locale-dependent response, therefore never assume Enabled from string matching.
} catch { $report.auditPolicyRaw='QUERY_FAILED'; $warnings.Add('auditpol kann nicht abgefragt werden') }
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Security';Id=5157;StartTime=(Get-Date).AddHours(-2)
    } -MaxEvents 250 -ErrorAction Stop)
    $report.wfp5157ReadState='READABLE'
    $report.recent5157Count=$events.Count
} catch {
    if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') {
        $report.wfp5157ReadState='READABLE_NO_EVENTS'
    } else {
        $report.wfp5157ReadState='UNVERIFIED_QUERY_FAILED'
        $warnings.Add('Security-Eventlog 5157 nicht zuverlässig lesbar')
    }
}
try {
    $rules=@(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object { $_.Name -like 'VGT-GeDefense-TI-*' -or $_.Group -like 'VGT GeDefense Threat Intelligence *' })
    $report.ruleCount=$rules.Count
    $report.enabledBlockRuleCount=@($rules | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }).Count
    $report.disabledOrNonBlockRuleCount=$report.ruleCount-$report.enabledBlockRuleCount
    $groupCounts=@($rules | Group-Object -Property Group | Sort-Object Name)
    $report.ruleGroupCount=$groupCounts.Count
    $report.observedGroups=@($groupCounts | Select-Object -First 20 | ForEach-Object {
        [ordered]@{generationGroup=$_.Name;ruleCount=$_.Count}
    })
    if($report.ruleCount -eq 0){$findings.Add('Keine GeDefense TI-Regeln im Windows-Firewall-Bestand gefunden')}
    if($report.disabledOrNonBlockRuleCount -gt 0){$warnings.Add('GeDefense TI-Regeln nicht durchgängig Enabled/Block')}
    if($ExpectedGeneration){
        $prefix=$ExpectedGeneration.Substring(0,16).ToLowerInvariant()
        $report.expectedGenerationGroupPresent=(@($rules|Where-Object{$_.Group -match [regex]::Escape($prefix)}).Count -gt 0)
        if(-not $report.expectedGenerationGroupPresent){$warnings.Add('Erwartete Generation nicht in den WFP-Regelgruppen gefunden')}
    }
} catch { $warnings.Add('Windows-Firewall-Regeln konnten nicht gelesen werden') }
$report.findings=@($findings)
$report.warnings=@($warnings)
# Avoid printing remote addresses, session keys, user credentials, process paths.
$report | ConvertTo-Json -Depth 6
