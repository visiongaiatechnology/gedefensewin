// STATUS: PLATIN
//go:build windows

package mhx

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWFPHistoricalEventKeepsReceiptHealthAndOriginalEventTime(t *testing.T) {
	ctx := context.Background()
	output, health := make(chan wfpBlockEvent, 1), make(chan time.Time, 2)
	var cursor int64
	now := time.Now().UTC()
	raw := []byte(`{"kind":"event","timestampUtc":"2020-01-01T00:00:00Z","event":{"recordId":42,"pid":0,"direction":"Inbound","localPort":443,"remoteIp":"8.8.8.8","protocol":6}}`)
	if err := forwardWFPMessage(ctx, raw, &cursor, output, health, now); err != nil {
		t.Fatal(err)
	}
	if got := <-health; !got.Equal(now) {
		t.Fatalf("sensor health used historical event time: %v", got)
	}
	if got := <-output; got.TimestampUTC.Year() != 2020 || got.PID != 0 {
		t.Fatalf("event identity or event time changed: %+v", got)
	}
	if cursor != 42 {
		t.Fatal("delivered record cursor was not preserved")
	}
	if err := forwardWFPMessage(ctx, raw, &cursor, output, health, now); err != nil || len(output) != 0 {
		t.Fatal("resume duplicated an already delivered block", err)
	}
}

func TestWFPRejectedMessageCannotRefreshHealth(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"kind":"ready","timestampUtc":"bad"}`,
		`{"kind":"ready","recordId":-1,"timestampUtc":"2026-10-15T00:00:00Z"}`,
		`{"kind":"event","timestampUtc":"2026-10-15T00:00:00Z"}`,
		`{"kind":"ready","timestampUtc":"2026-10-15T00:00:00Z","unknown":1}`,
		`{"kind":"ready","timestampUtc":"2026-10-15T00:00:00Z"} {}`,
	} {
		var cursor int64
		health := make(chan time.Time, 1)
		if err := forwardWFPMessage(context.Background(), []byte(raw), &cursor, make(chan wfpBlockEvent, 1), health, time.Now()); err == nil || len(health) != 0 {
			t.Fatalf("invalid wire message refreshed health: %s", raw)
		}
	}
}

func TestWFPSupervisorRetriesThenJoinsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	done := make(chan struct{})
	faults := make(chan error, 8)
	go func() {
		defer close(done)
		superviseWFP(ctx, func(context.Context) error {
			if attempts.Add(1) == 3 {
				cancel()
			}
			return errors.New("fixture bridge exited")
		}, faults, time.Millisecond, 4*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not stop")
	}
	if attempts.Load() != 3 || len(faults) != 2 {
		t.Fatalf("unexpected attempts/faults: %d/%d", attempts.Load(), len(faults))
	}
}

func TestWFPSupervisorCancelInterruptsLongBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	faults := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseWFP(ctx, func(context.Context) error { return io.EOF }, faults, time.Hour, time.Hour)
	}()
	<-faults
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backoff blocked cancellation")
	}
}

func TestWFPStallWatchdogTerminatesOwnedProcess(t *testing.T) {
	path, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var command *exec.Cmd
	factory := func(bridge context.Context) *exec.Cmd {
		command = exec.CommandContext(bridge, path, "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60")
		return command
	}
	var cursor int64
	started := time.Now()
	err = runWFPCommand(ctx, factory, &cursor, make(chan wfpBlockEvent, 1), make(chan time.Time, 1), 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "heartbeat timed out") || command.ProcessState == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("stalled process not reaped promptly: %v", err)
	}
}

func TestWFPDiagnosticsAreBounded(t *testing.T) {
	b := &wfpDiagnostics{}
	input := strings.Repeat("x", 100000)
	if n, err := io.WriteString(b, input); err != nil || n != len(input) || b.Len() != 2048 {
		t.Fatalf("diagnostic limit failed: %d/%d, %v", n, b.Len(), err)
	}
}

func TestWFPQueryFailureCannotAnnounceReady(t *testing.T) {
	path, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"NoMatchingEventsFound", "AccessDenied"} {
		t.Run(code, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			fixture := `function Get-WinEvent {
 [CmdletBinding()] param($FilterHashtable,$LogName,$FilterXPath,$MaxEvents,[switch]$Oldest)
 $record=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('isolated fixture'),'` + code + `',[Management.Automation.ErrorCategory]::ReadError,$null)
 $PSCmdlet.ThrowTerminatingError($record)
}
`
			source := strings.Replace(wfpBlockTraceScript, "while ($true)", "for ($fixtureIndex=0;$fixtureIndex -lt 1;$fixtureIndex++)", 1)
			command := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", fixture+source)
			data, runErr := command.CombinedOutput()
			ready := strings.Contains(string(data), `"kind":"ready"`)
			if code == "NoMatchingEventsFound" {
				if runErr != nil || !ready || !strings.Contains(string(data), `"kind":"heartbeat"`) {
					t.Fatalf("empty readable log failed: %v: %s", runErr, data)
				}
			} else if runErr == nil || ready {
				t.Fatalf("failed query announced readiness: %v: %s", runErr, data)
			}
		})
	}
}

func TestWFPCancelledDeliveryDoesNotAdvanceCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cursor int64
	health := make(chan time.Time, 1)
	err := forwardWFPMessage(ctx, []byte(`{"kind":"event","timestampUtc":"2020-01-01T00:00:00Z","event":{"recordId":9,"direction":"Inbound","remoteIp":"8.8.8.8","protocol":6}}`), &cursor, make(chan wfpBlockEvent), health, time.Now())
	if !errors.Is(err, context.Canceled) || cursor != 0 || len(health) != 0 {
		t.Fatalf("cancelled delivery committed cursor or health: %d %v", cursor, err)
	}
}

func FuzzWFPWire(f *testing.F) {
	f.Add([]byte(`{"kind":"ready","recordId":1,"timestampUtc":"2026-10-15T00:00:00Z"}`))
	f.Add([]byte(`{"kind":"event","timestampUtc":"2020-01-01T00:00:00Z","event":{"recordId":9,"direction":"Inbound","remoteIp":"8.8.8.8","protocol":6}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		var cursor int64
		health := make(chan time.Time, 1)
		err := forwardWFPMessage(context.Background(), raw, &cursor, make(chan wfpBlockEvent, 1), health, time.Now())
		if err != nil && len(health) != 0 {
			t.Fatal("rejected message refreshed health")
		}
	})
}
