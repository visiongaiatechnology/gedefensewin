// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const processTraceScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Write-VgtWireMessage {
  param([Parameter(Mandatory=$true)][object]$Message)
  $json = $Message | ConvertTo-Json -Compress -Depth 8 -WarningAction SilentlyContinue
  [Console]::Out.WriteLine($json)
  [Console]::Out.Flush()
}
$targets = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@('powershell.exe','pwsh.exe','cmd.exe','cscript.exe','wscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','wmic.exe','certutil.exe','bitsadmin.exe','vssadmin.exe','schtasks.exe') | ForEach-Object { [void]$targets.Add($_) }
Register-CimIndicationEvent -Namespace 'root/cimv2' -ClassName Win32_ProcessStartTrace -SourceIdentifier 'VGT_MHX_ProcessTrace' | Out-Null
Write-VgtWireMessage ([ordered]@{ kind='ready'; timestampUtc=[DateTime]::UtcNow.ToString('o') })
try {
  while ($true) {
    $event = Wait-Event -SourceIdentifier 'VGT_MHX_ProcessTrace' -Timeout 2
    if ($null -eq $event) { Write-VgtWireMessage ([ordered]@{ kind='heartbeat'; timestampUtc=[DateTime]::UtcNow.ToString('o') }); continue }
    try {
      $trace = $event.SourceEventArgs.NewEvent
      $name = [string]$trace.ProcessName
      if (-not $targets.Contains($name)) { continue }
      $pidValue = [uint32]$trace.ProcessID
      $process = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $pidValue) -ErrorAction Stop
      $parent = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$process.ParentProcessId) -ErrorAction SilentlyContinue
      $commandLine = [string]$process.CommandLine
      $encodedFastPath = $commandLine -match '(?i)(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)(?:\s|:|=)'
      $signature = if ($process.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $process.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
      $parentSignature = if ($parent -and $parent.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $parent.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
      $sha = if (-not $encodedFastPath -and $process.ExecutablePath) { (Get-FileHash -LiteralPath $process.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
      $parentSha = if (-not $encodedFastPath -and $parent -and $parent.ExecutablePath) { (Get-FileHash -LiteralPath $parent.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
      $ancestry = @()
      $cursor = $parent
      $seen = [Collections.Generic.HashSet[uint32]]::new()
      $ancestryDepth = if ($encodedFastPath) { 1 } else { 6 }
      for ($depth = 0; $depth -lt $ancestryDepth -and $cursor; $depth++) {
        $cursorPid = [uint32]$cursor.ProcessId
        if (-not $seen.Add($cursorPid)) { break }
        $cursorSignature = if ($depth -eq 0) { $parentSignature } elseif ($cursor.ExecutablePath) { Get-AuthenticodeSignature -LiteralPath $cursor.ExecutablePath -ErrorAction SilentlyContinue } else { $null }
        $cursorHash = if ($depth -eq 0) { $parentSha } elseif ($cursor.ExecutablePath) { (Get-FileHash -LiteralPath $cursor.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { '' }
        $ancestry += [ordered]@{ pid=$cursorPid; image=[string]$cursor.Name; path=[string]$cursor.ExecutablePath; signerStatus=if($cursorSignature){[string]$cursorSignature.Status}else{'Unknown'}; signer=if($cursorSignature -and $cursorSignature.SignerCertificate){[string]$cursorSignature.SignerCertificate.Subject}else{''}; sha256=[string]$cursorHash }
        if ([uint32]$cursor.ParentProcessId -le 4) { break }
        $cursor = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [uint32]$cursor.ParentProcessId) -ErrorAction SilentlyContinue
      }
      Write-VgtWireMessage ([ordered]@{ kind='event'; timestampUtc=[DateTime]::UtcNow.ToString('o'); event=[ordered]@{
        timestampUtc=[DateTime]::UtcNow.ToString('o'); pid=$pidValue; parentPid=[uint32]$process.ParentProcessId
        image=$name; imagePath=[string]$process.ExecutablePath; commandLine=$commandLine
        signerStatus=if($signature){[string]$signature.Status}else{'Unknown'}
        signerSubject=if($signature -and $signature.SignerCertificate){[string]$signature.SignerCertificate.Subject}else{''}
        sha256=[string]$sha; parentImage=if($parent){[string]$parent.Name}else{''}; parentPath=if($parent){[string]$parent.ExecutablePath}else{''}
        parentSigner=if($parentSignature -and $parentSignature.SignerCertificate){[string]$parentSignature.SignerCertificate.Subject}else{''}
        parentSignerStatus=if($parentSignature){[string]$parentSignature.Status}else{'Unknown'}; parentSha256=[string]$parentSha; ancestry=@($ancestry)
      }
      })
    } catch { [Console]::Error.WriteLine(('MHX event enrichment failed: {0}' -f $_.Exception.Message)) }
    finally { Remove-Event -EventIdentifier $event.EventIdentifier -ErrorAction SilentlyContinue }
  }
} finally { Unregister-Event -SourceIdentifier 'VGT_MHX_ProcessTrace' -ErrorAction SilentlyContinue }
`

type processWatcher struct{}

type watcherMessage struct {
	Kind         string        `json:"kind"`
	TimestampUTC string        `json:"timestampUtc"`
	Event        *ProcessEvent `json:"event,omitempty"`
}

func (processWatcher) Run(ctx context.Context, output chan<- ProcessEvent, health chan<- time.Time, faults chan<- error) {
	path, err := windowsPowerShell()
	if err != nil {
		deliverFault(faults, err)
		return
	}
	command := exec.CommandContext(ctx, path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", processTraceScript)
	stdout, err := command.StdoutPipe()
	if err != nil {
		deliverFault(faults, err)
		return
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		deliverFault(faults, err)
		return
	}
	if err := command.Start(); err != nil {
		deliverFault(faults, err)
		return
	}
	go consumeErrors(ctx, stderr, faults)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		var message watcherMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			deliverFault(faults, fmt.Errorf("MHX process telemetry validation failed (%v): %q", err, truncate(scanner.Text(), 512)))
			continue
		}
		timestamp, err := time.Parse(time.RFC3339Nano, message.TimestampUTC)
		if err != nil || (message.Kind != "ready" && message.Kind != "heartbeat" && message.Kind != "event") {
			deliverFault(faults, errors.New("MHX process telemetry protocol rejected"))
			continue
		}
		deliverHealth(health, timestamp.UTC())
		if message.Kind == "event" {
			if message.Event == nil || message.Event.PID == 0 {
				deliverFault(faults, errors.New("MHX process event validation failed"))
				continue
			}
			select {
			case output <- *message.Event:
			case <-ctx.Done():
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		deliverFault(faults, err)
	}
	if err := command.Wait(); err != nil && ctx.Err() == nil {
		deliverFault(faults, fmt.Errorf("MHX process watcher stopped: %w", err))
	}
}

func deliverHealth(health chan<- time.Time, timestamp time.Time) {
	select {
	case health <- timestamp:
	default:
	}
}

func windowsPowerShell() (string, error) {
	if root := os.Getenv("SystemRoot"); filepath.IsAbs(root) {
		path := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	path, err := exec.LookPath("powershell.exe")
	if err == nil {
		return path, nil
	}
	return "", errors.New("Windows PowerShell is unavailable")
}

func consumeErrors(ctx context.Context, reader io.Reader, faults chan<- error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			deliverFault(faults, fmt.Errorf("MHX telemetry provider: %s", truncate(line, 512)))
		}
	}
}

func deliverFault(faults chan<- error, err error) {
	select {
	case faults <- err:
	default:
	}
}
