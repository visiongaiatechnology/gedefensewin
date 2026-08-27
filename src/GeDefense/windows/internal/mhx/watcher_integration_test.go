// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestProcessWatcherReceivesEncodedCommand(t *testing.T) {
	if os.Getenv("VGT_MHX_INTEGRATION") != "1" {
		t.Skip("set VGT_MHX_INTEGRATION=1 for Windows process telemetry integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events := make(chan ProcessEvent, 32)
	health := make(chan time.Time, 8)
	faults := make(chan error, 8)
	go (processWatcher{}).Run(ctx, events, health, faults)
	time.Sleep(1500 * time.Millisecond)
	powerShell, err := windowsPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	marker := "VGT_MHX_TELEMETRY_42"
	payload := `$x='` + marker + `'; Start-Sleep -Seconds 3`
	command := exec.CommandContext(ctx, powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedUTF16LE(payload))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	for {
		select {
		case err := <-faults:
			t.Fatal(err)
		case event := <-events:
			decoded, _, encoded, decodeErr := DecodePowerShellCommand(event.CommandLine)
			if encoded && decodeErr == nil && strings.Contains(decoded, marker) {
				if event.PID == 0 || event.ImagePath == "" || len(event.Ancestry) == 0 {
					t.Fatalf("incomplete telemetry: %+v", event)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for encoded-command process telemetry")
		}
	}
}
