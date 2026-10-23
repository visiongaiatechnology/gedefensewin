// STATUS: PLATIN
package startup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFirstRunAckAndVersionChange(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "startup.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.Required("4.1.4")
	if err != nil || !first.Required || first.Reason != reasonFirstRun {
		t.Fatalf("first run: %+v err=%v", first, err)
	}
	if _, err := state.Acknowledge("4.1.4"); err != nil {
		t.Fatal(err)
	}
	again, err := state.Required("4.1.4")
	if err != nil || again.Required {
		t.Fatalf("acked state: %+v err=%v", again, err)
	}
	updated, err := state.Required("5.0.0-beta.1")
	if err != nil || !updated.Required || updated.Reason != reasonVersionChanged {
		t.Fatalf("version change: %+v err=%v", updated, err)
	}
}

func TestRebootDetectionAndCorruptStateFailsTowardCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup.json")
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := persisted{Version: "4.1.4", UptimeMS: ^uint64(0) - 1, AcknowledgedUTC: time.Now().UTC()}
	raw, _ := json.Marshal(marker)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := state.Required("4.1.4")
	if err != nil || !result.Required || result.Reason != reasonReboot {
		t.Fatalf("reboot marker: %+v err=%v", result, err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = state.Required("4.1.4")
	if err != nil || !result.Required || result.Reason != "state-unreadable" {
		t.Fatalf("corrupt marker must require a check: %+v err=%v", result, err)
	}
}

func TestSetupMarkerSurvivesReadinessAcknowledgement(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "startup.json"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := state.SetupStatus("5.2.0")
	if err != nil || status.Complete {
		t.Fatalf("fresh setup status: %+v err=%v", status, err)
	}
	if _, err := state.CompleteSetup("business", "5.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Acknowledge("5.2.0"); err != nil {
		t.Fatal(err)
	}
	status, err = state.SetupStatus("5.2.0")
	if err != nil || !status.Complete || status.Profile != "business" {
		t.Fatalf("setup marker lost: %+v err=%v", status, err)
	}
	if _, err := state.CompleteSetup("not-a-profile", "5.2.0"); err == nil {
		t.Fatal("unknown setup profile accepted")
	}
}
