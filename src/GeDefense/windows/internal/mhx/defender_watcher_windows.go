// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

const defenderTraceScript = `$ErrorActionPreference='Stop'
$log = 'Microsoft-Windows-Windows Defender/Operational'
$latest = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue
$last = if ($latest) { [long]$latest.RecordId } else { 0L }
while ($true) {
  Start-Sleep -Milliseconds 750
  $query = "*[System[EventRecordID > $last and (EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012)]]"
  $events = @(Get-WinEvent -LogName $log -FilterXPath $query -ErrorAction SilentlyContinue | Sort-Object RecordId)
  foreach ($item in $events) {
    $last = [Math]::Max($last,[long]$item.RecordId)
    [ordered]@{ timestampUtc=$item.TimeCreated.ToUniversalTime().ToString('o'); eventId=[int]$item.Id; recordId=[long]$item.RecordId; message=([string]$item.Message).Substring(0,[Math]::Min(4096,([string]$item.Message).Length)) } | ConvertTo-Json -Compress
  }
}
`

type defenderEvent struct {
	TimestampUTC string `json:"timestampUtc"`
	EventID      int    `json:"eventId"`
	RecordID     int64  `json:"recordId"`
	Message      string `json:"message"`
}

type defenderWatcher struct{}

func (defenderWatcher) Run(ctx context.Context, output chan<- defenderEvent, faults chan<- error) {
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
	go func() { _, _ = io.WriteString(stdin, defenderTraceScript); _ = stdin.Close() }()
	go consumeErrors(ctx, stderr, faults)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var event defenderEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			deliverFault(faults, fmt.Errorf("Defender event validation failed"))
			continue
		}
		select {
		case output <- event:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil {
		deliverFault(faults, err)
	}
	if err := command.Wait(); err != nil && ctx.Err() == nil {
		deliverFault(faults, fmt.Errorf("Defender event bridge stopped: %w", err))
	}
}
