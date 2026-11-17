// STATUS: PLATIN VGT SUPREME
package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/witness"
)

func TestV6RuntimeWitnessEnableRequiresProvisioning(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	runtime := newV6Runtime(root, root, "5.3.0", ledger)
	t.Cleanup(func() { _ = runtime.Close() })

	// Default: witness disabled, spyware all sensors enabled.
	runtime.Restore(defaultV6Config())
	if report := runtime.WitnessStatus(); report.Status != witness.StatusDisabled {
		t.Fatalf("expected DISABLED by default, got %s", report.Status)
	}
	if !runtime.SpywareStatus().Enabled {
		t.Fatal("expected spyware enabled by default")
	}

	// Explicit operator activation without witness/settings.json fails closed.
	cfg := defaultV6Config()
	cfg.WitnessEnabled = true
	if err := runtime.Configure(context.Background(), cfg); err == nil {
		t.Fatal("expected missing witness/settings.json to reject explicit enable")
	}
	if report := runtime.WitnessStatus(); report.Status != witness.StatusFault {
		t.Fatalf("expected FAULT after unprovisioned enable attempt, got %s", report.Status)
	}
	if state, _ := runtime.WitnessSettingsState(); state != witnessStateMissing {
		t.Fatalf("expected MISSING witness settings state, got %q", state)
	}
}

func TestV6RuntimeSpywareActiveMode(t *testing.T) {
	root := t.TempDir()
	ledger, err := evidence.Open(filepath.Join(root, "evidence.jsonl"), filepath.Join(root, "evidence.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	runtime := newV6Runtime(root, root, "6.0.0", ledger)
	t.Cleanup(func() { _ = runtime.Close() })

	if status := runtime.SpywareStatus(); status.Mode != v6SpywareModeObserve || status.ActiveEnforced {
		t.Fatalf("expected default observe mode, got %+v", status)
	}
	if err := runtime.SetSpywareMode(context.Background(), "active"); err != nil {
		t.Fatalf("SetSpywareMode active: %v", err)
	}
	if status := runtime.SpywareStatus(); status.Mode != v6SpywareModeActive || !status.ActiveEnforced {
		t.Fatalf("expected active mode, got %+v", status)
	}
	if err := runtime.SetSpywareMode(context.Background(), "bogus"); err == nil {
		t.Fatal("expected invalid spywareMode rejection")
	}
}
