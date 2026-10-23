// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// defenderTelemetryScript is a read-only, fixed PowerShell query. It never
// interpolates external input, writes nothing, and emits every property through
// an explicit property lookup so a missing Windows property becomes JSON null
// instead of a fabricated value.
const defenderTelemetryScript = `$ErrorActionPreference='Stop'
function Get-Prop($object,[string]$name) {
  if ($null -eq $object) { return $null }
  $property = $object.PSObject.Properties[$name]
  if ($null -eq $property) { return $null }
  return $property.Value
}
function Str($value) {
  if ($null -eq $value) { return $null }
  return [string]$value
}
function Iso($value) {
  if ($null -eq $value) { return $null }
  try { return ([DateTime]$value).ToUniversalTime().ToString('o') } catch { return $null }
}
function Count-Prop($object,[string]$name) {
  if ($null -eq $object) { return $null }
  $property = $object.PSObject.Properties[$name]
  if ($null -eq $property -or $null -eq $property.Value) { return $null }
  return @($property.Value).Count
}
$status = Get-MpComputerStatus -ErrorAction Stop
$preference = Get-MpPreference -ErrorAction Stop
$asrRules = $null
$idsProperty = $preference.PSObject.Properties['AttackSurfaceReductionRules_Ids']
if ($null -ne $idsProperty -and $null -ne $idsProperty.Value) {
  $ids = @($idsProperty.Value)
  $actionsProperty = $preference.PSObject.Properties['AttackSurfaceReductionRules_Actions']
  $actions = @()
  if ($null -ne $actionsProperty -and $null -ne $actionsProperty.Value) { $actions = @($actionsProperty.Value) }
  $rows = @()
  for ($index = 0; $index -lt $ids.Count; $index++) {
    $action = $null
    if ($index -lt $actions.Count -and $null -ne $actions[$index]) { $action = [int]$actions[$index] }
    $rows += [ordered]@{ id = ([string]$ids[$index]).ToLowerInvariant(); action = $action }
  }
  $asrRules = @($rows)
}
[ordered]@{
  collectedUtc = [DateTime]::UtcNow.ToString('o')
  computerStatus = [ordered]@{
    amServiceEnabled = Get-Prop $status 'AMServiceEnabled'
    amServiceVersion = Str (Get-Prop $status 'AMServiceVersion')
    amEngineVersion = Str (Get-Prop $status 'AMEngineVersion')
    amProductVersion = Str (Get-Prop $status 'AMProductVersion')
    amRunningMode = Str (Get-Prop $status 'AMRunningMode')
    antivirusEnabled = Get-Prop $status 'AntivirusEnabled'
    antispywareEnabled = Get-Prop $status 'AntispywareEnabled'
    behaviorMonitorEnabled = Get-Prop $status 'BehaviorMonitorEnabled'
    ioavProtectionEnabled = Get-Prop $status 'IoavProtectionEnabled'
    onAccessProtectionEnabled = Get-Prop $status 'OnAccessProtectionEnabled'
    realTimeProtectionEnabled = Get-Prop $status 'RealTimeProtectionEnabled'
    nisEnabled = Get-Prop $status 'NISEnabled'
    isTamperProtected = Get-Prop $status 'IsTamperProtected'
    isVirtualMachine = Get-Prop $status 'IsVirtualMachine'
    defenderSignaturesOutOfDate = Get-Prop $status 'DefenderSignaturesOutOfDate'
    tamperProtectionSource = Str (Get-Prop $status 'TamperProtectionSource')
    antivirusSignatureVersion = Str (Get-Prop $status 'AntivirusSignatureVersion')
    antispywareSignatureVersion = Str (Get-Prop $status 'AntispywareSignatureVersion')
    nisSignatureVersion = Str (Get-Prop $status 'NISSignatureVersion')
    nisEngineVersion = Str (Get-Prop $status 'NISEngineVersion')
    antivirusSignatureLastUpdated = Iso (Get-Prop $status 'AntivirusSignatureLastUpdated')
    antispywareSignatureLastUpdated = Iso (Get-Prop $status 'AntispywareSignatureLastUpdated')
    nisSignatureLastUpdated = Iso (Get-Prop $status 'NISSignatureLastUpdated')
    antivirusSignatureAge = Get-Prop $status 'AntivirusSignatureAge'
    antispywareSignatureAge = Get-Prop $status 'AntispywareSignatureAge'
    nisSignatureAge = Get-Prop $status 'NISSignatureAge'
    quickScanAge = Get-Prop $status 'QuickScanAge'
    fullScanAge = Get-Prop $status 'FullScanAge'
    quickScanStartTime = Iso (Get-Prop $status 'QuickScanStartTime')
    quickScanEndTime = Iso (Get-Prop $status 'QuickScanEndTime')
    fullScanStartTime = Iso (Get-Prop $status 'FullScanStartTime')
    fullScanEndTime = Iso (Get-Prop $status 'FullScanEndTime')
    computerState = Get-Prop $status 'ComputerState'
  }
  preferences = [ordered]@{
    disableRealtimeMonitoring = Get-Prop $preference 'DisableRealtimeMonitoring'
    disableBehaviorMonitoring = Get-Prop $preference 'DisableBehaviorMonitoring'
    disableIOAVProtection = Get-Prop $preference 'DisableIOAVProtection'
    disableScriptScanning = Get-Prop $preference 'DisableScriptScanning'
    disableBlockAtFirstSeen = Get-Prop $preference 'DisableBlockAtFirstSeen'
    disableArchiveScanning = Get-Prop $preference 'DisableArchiveScanning'
    disableEmailScanning = Get-Prop $preference 'DisableEmailScanning'
    disableRemovableDriveScanning = Get-Prop $preference 'DisableRemovableDriveScanning'
    disableScanningNetworkFiles = Get-Prop $preference 'DisableScanningNetworkFiles'
    enableNetworkProtection = Get-Prop $preference 'EnableNetworkProtection'
    puaProtection = Get-Prop $preference 'PUAProtection'
    mapsReporting = Get-Prop $preference 'MAPSReporting'
    submitSamplesConsent = Get-Prop $preference 'SubmitSamplesConsent'
    cloudBlockLevel = Get-Prop $preference 'CloudBlockLevel'
    cloudExtendedTimeout = Get-Prop $preference 'CloudExtendedTimeout'
    enableControlledFolderAccess = Get-Prop $preference 'EnableControlledFolderAccess'
    signatureUpdateInterval = Get-Prop $preference 'SignatureUpdateInterval'
    checkForSignaturesBeforeRunningScan = Get-Prop $preference 'CheckForSignaturesBeforeRunningScan'
    scanParameters = Get-Prop $preference 'ScanParameters'
    scanAvgCPULoadFactor = Get-Prop $preference 'ScanAvgCPULoadFactor'
    lowThreatDefaultAction = Get-Prop $preference 'LowThreatDefaultAction'
    moderateThreatDefaultAction = Get-Prop $preference 'ModerateThreatDefaultAction'
    highThreatDefaultAction = Get-Prop $preference 'HighThreatDefaultAction'
    severeThreatDefaultAction = Get-Prop $preference 'SevereThreatDefaultAction'
    unknownThreatDefaultAction = Get-Prop $preference 'UnknownThreatDefaultAction'
    attackSurfaceReductionRules = $asrRules
    attackSurfaceReductionOnlyExclusionsCount = Count-Prop $preference 'AttackSurfaceReductionOnlyExclusions'
    exclusionPathCount = Count-Prop $preference 'ExclusionPath'
    exclusionExtensionCount = Count-Prop $preference 'ExclusionExtension'
    exclusionProcessCount = Count-Prop $preference 'ExclusionProcess'
    controlledFolderAccessProtectedFoldersCount = Count-Prop $preference 'ControlledFolderAccessProtectedFolders'
    controlledFolderAccessAllowedApplicationsCount = Count-Prop $preference 'ControlledFolderAccessAllowedApplications'
  }
} | ConvertTo-Json -Depth 6 -Compress
`

// boundedBuffer truncates instead of growing without bound when a child process
// emits more output than expected.
type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (w *boundedBuffer) Write(data []byte) (int, error) {
	if w.buffer.Len()+len(data) > w.limit {
		remaining := w.limit - w.buffer.Len()
		if remaining > 0 {
			_, _ = w.buffer.Write(data[:remaining])
		}
		w.overflow = true
		return len(data), nil
	}
	return w.buffer.Write(data)
}

// probeDefenderTelemetry executes the fixed read-only Defender query with a
// hard timeout, bounded output and process-tree cancellation.
func probeDefenderTelemetry(ctx context.Context) (DefenderTelemetry, error) {
	if ctx == nil {
		return DefenderTelemetry{}, errors.New("defender telemetry query requires context")
	}
	powerShell, err := winexec.PowerShell()
	if err != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry Windows PowerShell unavailable")
	}
	command := exec.CommandContext(ctx, powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
	command.WaitDelay = 3 * time.Second
	command.Cancel = func() error {
		if command.Process != nil && command.Process.Pid > 0 {
			_ = winexec.KillProcessTree(command.Process.Pid)
		}
		return command.Process.Kill()
	}
	command.Stdin = strings.NewReader(defenderTelemetryScript)
	stdout := &boundedBuffer{limit: maximumDefenderTelemetryBytes}
	stderr := &boundedBuffer{limit: 8 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := winexec.RunTracked(command)
	if ctx.Err() != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry query timed out")
	}
	if stdout.overflow || stderr.overflow {
		return DefenderTelemetry{}, errors.New("defender telemetry output size rejected")
	}
	if runErr != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry query failed")
	}
	snapshot, err := parseDefenderTelemetry(stdout.buffer.Bytes())
	if err != nil {
		return DefenderTelemetry{}, err
	}
	return snapshot, nil
}

var _ io.Writer = (*boundedBuffer)(nil)
