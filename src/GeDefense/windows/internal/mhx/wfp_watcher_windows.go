// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const wfpBlockTraceScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Write-VgtWireMessage {
  param([Parameter(Mandatory=$true)][object]$Message)
  $json = $Message | ConvertTo-Json -Compress -Depth 5 -WarningAction SilentlyContinue
  [Console]::Out.WriteLine($json)
  [Console]::Out.Flush()
}
function Read-VgtWfpEvents {
  param([string]$XPath='', [switch]$Newest)
  try {
    if ($Newest) { Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 1 -ErrorAction Stop }
    else { Get-WinEvent -LogName 'Security' -FilterXPath $XPath -Oldest -MaxEvents 512 -ErrorAction Stop }
  } catch {
    if ($_.FullyQualifiedErrorId.Split(',')[0] -eq 'NoMatchingEventsFound') { return }
    throw
  }
}
$latest = @(Read-VgtWfpEvents -Newest)
$latestRecord = if ($latest.Count) { [long]$latest[0].RecordId } else { 0L }
$resume = 0L
[void][long]::TryParse($env:GEDEFENSE_WFP_CURSOR,[ref]$resume)
$last = if ($resume -gt 0 -and $latestRecord -ge $resume) { $resume } else { $latestRecord }
Write-VgtWireMessage ([ordered]@{ kind='ready'; recordId=$last; timestampUtc=[DateTime]::UtcNow.ToString('o') })
while ($true) {
  Start-Sleep -Milliseconds 900
  $query = "*[System[EventRecordID > $last and EventID=5157]]"
  $events = @(Read-VgtWfpEvents -XPath $query)
  if ($events.Count -eq 0) {
    Write-VgtWireMessage ([ordered]@{ kind='heartbeat'; timestampUtc=[DateTime]::UtcNow.ToString('o') })
    continue
  }
  foreach ($item in $events) {
    $last = [Math]::Max($last,[long]$item.RecordId)
    try {
      [xml]$xml = $item.ToXml()
      $fields = @{}
      foreach ($entry in @($xml.Event.EventData.Data)) {
        $fields[[string]$entry.Name] = [string]$entry.'#text'
      }
      $pidValue = 0L
      $remotePortValue = 0
      $localPortValue = 0
      $protocolValue = 0
      $filterValue = 0L
      if (-not [long]::TryParse([string]$fields.ProcessID,[ref]$pidValue)) { continue }
      if (-not [int]::TryParse([string]$fields.Protocol,[ref]$protocolValue)) { continue }
      if (-not [long]::TryParse([string]$fields.FilterRTID,[ref]$filterValue)) { $filterValue = 0L }
      $directionToken = [string]$fields.Direction
      if ($directionToken -eq '%%14593' -or $directionToken -match '(?i)outbound|ausgehend') {
        $direction = 'Outbound'
        $remoteAddress = [string]$fields.DestAddress
        [void][int]::TryParse([string]$fields.DestPort,[ref]$remotePortValue)
        [void][int]::TryParse([string]$fields.SourcePort,[ref]$localPortValue)
      } elseif ($directionToken -eq '%%14592' -or $directionToken -match '(?i)inbound|eingehend') {
        $direction = 'Inbound'
        $remoteAddress = [string]$fields.SourceAddress
        [void][int]::TryParse([string]$fields.SourcePort,[ref]$remotePortValue)
        [void][int]::TryParse([string]$fields.DestPort,[ref]$localPortValue)
      } else { continue }
      $application = [string]$fields.Application
      if ($application.Length -gt 2048) { $application = $application.Substring(0,2048) }
      Write-VgtWireMessage ([ordered]@{ kind='event'; timestampUtc=$item.TimeCreated.ToUniversalTime().ToString('o'); event=[ordered]@{
        recordId=[long]$item.RecordId; pid=[uint32]$pidValue; application=$application; direction=$direction; localPort=[int]$localPortValue
        remoteIp=$remoteAddress; remotePort=[int]$remotePortValue; protocol=[int]$protocolValue; filterRuntimeId=[long]$filterValue; filterOrigin=[string]$fields.FilterOrigin
      } })
    } catch {
      [Console]::Error.WriteLine('WFP block event normalization failed.')
    }
  }
}
`

type wfpBlockEvent struct {
	TimestampUTC    time.Time `json:"-"`
	RecordID        int64     `json:"recordId"`
	PID             uint32    `json:"pid"`
	Application     string    `json:"application"`
	Direction       string    `json:"direction"`
	LocalPort       uint16    `json:"localPort"`
	RemoteIP        string    `json:"remoteIp"`
	RemotePort      uint16    `json:"remotePort"`
	Protocol        uint8     `json:"protocol"`
	FilterRuntimeID int64     `json:"filterRuntimeId"`
	FilterOrigin    string    `json:"filterOrigin,omitempty"`
	GeDefenseOrigin bool      `json:"-"`
}

type wfpWireMessage struct {
	Kind         string         `json:"kind"`
	RecordID     int64          `json:"recordId,omitempty"`
	TimestampUTC string         `json:"timestampUtc"`
	Event        *wfpBlockEvent `json:"event,omitempty"`
}

type wfpBlockWatcher struct{}

const wfpBridgeTimeout = 30 * time.Second

// Run owns recovery for this independent sensor; failures cannot permanently
// disable it until the next service restart. Cursor state survives each attempt.
func (wfpBlockWatcher) Run(ctx context.Context, output chan<- wfpBlockEvent, health chan<- time.Time, faults chan<- error) {
	var cursor int64
	superviseWFP(ctx, func(attempt context.Context) error {
		path, err := windowsPowerShell()
		if err != nil {
			return err
		}
		return runWFPCommand(attempt, func(bridge context.Context) *exec.Cmd {
			command := exec.CommandContext(bridge, path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", wfpBlockTraceScript)
			command.Env = append(os.Environ(), "GEDEFENSE_WFP_CURSOR="+strconv.FormatInt(cursor, 10))
			return command
		}, &cursor, output, health, wfpBridgeTimeout)
	}, faults, time.Second, 30*time.Second)
}

func superviseWFP(ctx context.Context, run func(context.Context) error, faults chan<- error, initial, maximum time.Duration) {
	delay := initial
	for ctx.Err() == nil {
		started := time.Now()
		err := run(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("WFP telemetry bridge ended unexpectedly")
		}
		deliverFault(faults, err)
		if time.Since(started) >= maximum {
			delay = initial
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < maximum/2 {
			delay *= 2
		} else {
			delay = maximum
		}
	}
}

// WFP PowerShell performs no child-process execution. Killing this owned
// process cancels event-log reads; Wait joins its stderr copier and releases pipes.
func runWFPCommand(parent context.Context, newCommand func(context.Context) *exec.Cmd, cursor *int64, output chan<- wfpBlockEvent, health chan<- time.Time, timeout time.Duration) (result error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	command := newCommand(ctx)
	command.WaitDelay = 3 * time.Second
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	diagnostics := &wfpDiagnostics{}
	command.Stderr = diagnostics
	if err := command.Start(); err != nil {
		return err
	}
	activity := make(chan struct{}, 1)
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-activity:
				timer.Reset(timeout)
			case <-timer.C:
				cancel(errors.New("WFP telemetry bridge heartbeat timed out"))

				return
			}
		}
	}()
	defer func() {
		cancel(nil)
		<-watchdogDone

		if err := command.Wait(); err != nil && parent.Err() == nil {
			result = errors.Join(result, fmt.Errorf("WFP bridge stopped: %w; %s", err, diagnostics.String()))
		}
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) && parent.Err() == nil {
			result = errors.Join(result, cause)
		}
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if err := forwardWFPMessage(ctx, scanner.Bytes(), cursor, output, health, time.Now().UTC()); err != nil {
			return err
		}
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("WFP telemetry bridge output closed")
}

// Sensor health uses receipt time. Event time remains untouched for correlation.
func forwardWFPMessage(ctx context.Context, raw []byte, cursor *int64, output chan<- wfpBlockEvent, health chan<- time.Time, received time.Time) error {
	var message wfpWireMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return errors.New("WFP block telemetry validation failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("WFP block telemetry trailing data rejected")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, message.TimestampUTC)
	if err != nil || (message.Kind != "ready" && message.Kind != "heartbeat" && message.Kind != "event") {
		return errors.New("WFP block telemetry protocol rejected")
	}
	if message.Kind == "ready" {
		if message.RecordID < 0 {
			return errors.New("WFP record cursor rejected")
		}
		*cursor = message.RecordID
	}
	if message.Kind != "event" {
		deliverHealth(health, received)
		return nil
	}
	event := message.Event
	if event == nil || event.RecordID <= 0 || len(event.Application) > 2048 || len(event.FilterOrigin) > 256 || (event.Direction != "Inbound" && event.Direction != "Outbound") || event.Protocol == 0 {
		return errors.New("WFP block event boundary rejected")
	}
	if event.RecordID <= *cursor {
		deliverHealth(health, received)
		return nil
	}
	address, parseErr := netip.ParseAddr(strings.TrimSpace(event.RemoteIP))
	if parseErr != nil || !address.IsValid() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
		*cursor = event.RecordID
		deliverHealth(health, received)
		return nil
	}
	event.RemoteIP = address.Unmap().String()
	event.FilterOrigin = strings.TrimSpace(event.FilterOrigin)
	event.GeDefenseOrigin = strings.HasPrefix(event.FilterOrigin, "VGT-GeDefense-TI-")
	event.TimestampUTC = timestamp.UTC()
	select {
	case output <- *event:
		*cursor = event.RecordID
		deliverHealth(health, received)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stderr remains bounded even when PowerShell emits a multi-line CLIXML error.
// exec.Cmd joins its writer before diagnostics are inspected.
type wfpDiagnostics struct{ buffer bytes.Buffer }

func (b *wfpDiagnostics) Write(p []byte) (int, error) {
	count := len(p)
	if remaining := 2048 - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, err := b.buffer.Write(p)
		return count, err
	}
	return count, nil
}

func (b *wfpDiagnostics) Len() int       { return b.buffer.Len() }
func (b *wfpDiagnostics) String() string { return b.buffer.String() }
