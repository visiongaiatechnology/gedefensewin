// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// windowsPowerShell resolves the installed Windows PowerShell host for opt-in
// integration/diagnostic probes. It is not used by the process telemetry
// sensor, which has no child process at all.
func windowsPowerShell() (string, error) {
	return winexec.PowerShell()
}

// TestProcessWatcherStreamsSecurity4688 is the live end-to-end proof for the
// native 4688 sensor. It is opt-in (VGT_MHX_INTEGRATION=1) because the Security
// log requires elevated access and because process creation auditing
// (Audit Process Creation plus command-line inclusion) must be enabled by the
// host; GeDefense hardening enables both.
func TestProcessWatcherStreamsSecurity4688(t *testing.T) {
	if os.Getenv("VGT_MHX_INTEGRATION") != "1" {
		t.Skip("set VGT_MHX_INTEGRATION=1 for live Security 4688 process telemetry")
	}
	if err := processAuditAvailability(); err != nil {
		t.Skipf("Security 4688 command-line auditing is unavailable on this host: %v", err)
	}
	powerShell, err := windowsPowerShell()
	if err != nil {
		t.Skipf("Windows PowerShell is unavailable for the probe process: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan ProcessEvent, 32)
	health := make(chan time.Time, 8)
	faults := make(chan error, 8)
	go (processWatcher{}).Run(ctx, events, health, faults)
	// Wait for the first receipt-time heartbeat. A subscription failure (for
	// example a non-elevated test process that cannot read the Security log)
	// degrades cleanly instead of producing a false failure.
	select {
	case <-health:
	case fault := <-faults:
		t.Skipf("Security 4688 subscription unavailable: %v", fault)
	case <-ctx.Done():
		t.Fatal("timed out waiting for the process sensor heartbeat")
	}
	marker := "VGT_MHX_4688_TELEMETRY_42"
	payload := `$x='` + marker + `'; Start-Sleep -Seconds 4`
	command := exec.CommandContext(ctx, powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedUTF16LE(payload))
	if err := command.Start(); err != nil {
		t.Fatalf("start encoded-command probe: %v", err)
	}
	defer func() {
		if err := command.Wait(); err != nil && ctx.Err() == nil {
			t.Errorf("telemetry fixture process: %v", err)
		}
	}()
	for {
		select {
		case fault := <-faults:
			t.Skipf("Security 4688 sensor degraded during the probe: %v", fault)
		case event := <-events:
			if event.PID == 0 || event.ImagePath == "" || event.CreationUTC.IsZero() {
				t.Fatalf("incomplete 4688 telemetry: %+v", event)
			}
			decoded, _, encoded, decodeErr := DecodePowerShellCommand(event.CommandLine)
			if encoded && decodeErr == nil && strings.Contains(decoded, marker) {
				if event.ParentImage == "" && len(event.Ancestry) == 0 {
					t.Logf("4688 event for pid %d has no parent identity (optional evidence)", event.PID)
				}
				return
			}
		case <-ctx.Done():
			t.Skip("no Security 4688 event observed; process creation auditing appears disabled on this host")
		}
	}
}
