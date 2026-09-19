// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
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
$latest = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 1 -ErrorAction SilentlyContinue
$last = if ($latest) { [long]$latest.RecordId } else { 0L }
Write-VgtWireMessage ([ordered]@{ kind='ready'; timestampUtc=[DateTime]::UtcNow.ToString('o') })
while ($true) {
  Start-Sleep -Milliseconds 900
  $query = "*[System[EventRecordID > $last and EventID=5157]]"
  $events = @(Get-WinEvent -LogName 'Security' -FilterXPath $query -Oldest -MaxEvents 512 -ErrorAction SilentlyContinue)
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
      if ($directionToken -eq '%%14593') {
        $direction = 'Outbound'
        $remoteAddress = [string]$fields.DestAddress
        [void][int]::TryParse([string]$fields.DestPort,[ref]$remotePortValue)
        [void][int]::TryParse([string]$fields.SourcePort,[ref]$localPortValue)
      } elseif ($directionToken -eq '%%14592') {
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
	TimestampUTC string         `json:"timestampUtc"`
	Event        *wfpBlockEvent `json:"event,omitempty"`
}

type wfpBlockWatcher struct{}

func (wfpBlockWatcher) Run(ctx context.Context, output chan<- wfpBlockEvent, health chan<- time.Time, faults chan<- error) {
	path, err := windowsPowerShell()
	if err != nil {
		deliverFault(faults, err)
		return
	}
	command := exec.CommandContext(ctx, path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
	stdin, err := command.StdinPipe()
	if err != nil {
		deliverFault(faults, err)
		return
	}
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
	go func() { _, _ = io.WriteString(stdin, wfpBlockTraceScript); _ = stdin.Close() }()
	go consumeErrors(ctx, stderr, faults)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var message wfpWireMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			deliverFault(faults, errors.New("WFP block telemetry validation failed"))
			continue
		}
		timestamp, err := time.Parse(time.RFC3339Nano, message.TimestampUTC)
		if err != nil || (message.Kind != "ready" && message.Kind != "heartbeat" && message.Kind != "event") {
			deliverFault(faults, errors.New("WFP block telemetry protocol rejected"))
			continue
		}
		deliverHealth(health, timestamp.UTC())
		if message.Kind != "event" {
			continue
		}
		if message.Event == nil || message.Event.RecordID <= 0 || message.Event.PID == 0 || len(message.Event.Application) > 2048 || len(message.Event.FilterOrigin) > 256 || (message.Event.Direction != "Inbound" && message.Event.Direction != "Outbound") || message.Event.Protocol == 0 {
			deliverFault(faults, errors.New("WFP block event boundary rejected"))
			continue
		}
		address, parseErr := netip.ParseAddr(strings.TrimSpace(message.Event.RemoteIP))
		if parseErr != nil || !address.IsValid() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		message.Event.RemoteIP = address.Unmap().String()
		message.Event.FilterOrigin = strings.TrimSpace(message.Event.FilterOrigin)
		message.Event.GeDefenseOrigin = strings.HasPrefix(message.Event.FilterOrigin, "VGT-GeDefense-TI-")
		message.Event.TimestampUTC = timestamp.UTC()
		select {
		case output <- *message.Event:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil {
		deliverFault(faults, err)
	}
	if err := command.Wait(); err != nil && ctx.Err() == nil {
		deliverFault(faults, fmt.Errorf("WFP block telemetry bridge stopped: %w", err))
	}
}
