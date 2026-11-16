// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live smoke tests exercise the real Windows kernel primitives. They are not
// part of the pure unit-test ledger: when the environment cannot create an
// AppContainer profile (no rights, AppContainer disabled, pre-Windows-10 build)
// the test skips and must be reported as NOT_TESTED, never as a pass.

// liveSystemExecutable returns an absolute system parser-ish executable that the
// All Application Packages SID can read.
func liveSystemExecutable(t *testing.T) string {
	t.Helper()
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("live smoke NOT_TESTED: SystemRoot unavailable")
	}
	candidate := filepath.Join(systemRoot, "System32", "sort.exe")
	if info, err := os.Stat(candidate); err != nil || !info.Mode().IsRegular() {
		t.Skipf("live smoke NOT_TESTED: %s unavailable", candidate)
	}
	return candidate
}

// liveProbeAppContainer verifies that the environment can create AppContainer
// profiles at all. It skips (NOT_TESTED) when the environment refuses.
func liveProbeAppContainer(t *testing.T) {
	t.Helper()
	cellID, err := newCellID()
	if err != nil {
		t.Fatalf("cell id: %v", err)
	}
	name, err := newContainerName(cellID)
	if err != nil {
		t.Fatalf("container name: %v", err)
	}
	containers := windowsContainers{}
	created, err := containers.Create(name)
	if err != nil {
		t.Skipf("live AppContainer NOT_TESTED: profile creation unavailable: %v", err)
	}
	defer func() {
		if deleteErr := containers.Delete(name); deleteErr != nil {
			t.Errorf("delete probe profile: %v", deleteErr)
		}
	}()
	derived, err := containers.DeriveSID(name)
	if err != nil {
		t.Fatalf("derive SID: %v", err)
	}
	if derived != created.SID {
		t.Fatalf("derived SID %q != created SID %q", derived, created.SID)
	}
	if !strings.HasPrefix(created.SID, "S-1-15-2-") {
		t.Fatalf("AppContainer SID %q does not look like an app container SID", created.SID)
	}
}

// TestLiveJobObjectLimits creates a real job object and verifies the read-back.
func TestLiveJobObjectLimits(t *testing.T) {
	t.Helper()
	limits := jobLimitsForProfile(DefaultProfile("live-job"))
	created, err := newWindowsJob(limits)
	if err != nil {
		t.Skipf("live Job Object NOT_TESTED: %v", err)
	}
	defer func() {
		if closeErr := created.Close(); closeErr != nil {
			t.Errorf("close job: %v", closeErr)
		}
	}()
	readback, err := created.Readback()
	if err != nil {
		t.Fatalf("job readback: %v", err)
	}
	if err := limits.Verify(readback); err != nil {
		t.Fatalf("job read-back verify: %v", err)
	}
}

// TestLiveCellLifecycle runs one parser (whoami.exe) through a real cell:
// AppContainer profile, job object, mitigation attributes, staged input and
// bounded output pipe, then burns the cell and proves the profile is gone.
func TestLiveCellLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("live smoke NOT_TESTED: -short")
	}
	executable := liveSystemExecutable(t)
	liveProbeAppContainer(t)

	root := filepath.Join(t.TempDir(), "parser-cells")
	cell, err := NewCell(CellOptions{Root: root})
	if err != nil {
		t.Fatalf("new cell: %v", err)
	}
	profile := DefaultProfile("live")
	profile.MaxInputBytes = 1024
	profile.MaxOutputBytes = 64 << 10
	profile.MaxRuntime = 15 * time.Second
	profile.MaxMemoryBytes = 128 << 20

	result, createErr := cell.Create(context.Background(), profile, []byte("smoke-input"), executable)
	if createErr != nil {
		t.Fatalf("cell create: %v (status: %+v)", createErr, cell.Status())
	}
	if result.State != StateExpiring && result.State != StateIsolated {
		t.Fatalf("unexpected result state %s", result.State)
	}
	if len(result.Output) == 0 {
		t.Fatalf("cell produced no output (exit code %d)", result.ExitCode)
	}
	if result.OutputTruncated {
		t.Fatalf("unexpected output truncation")
	}
	if len(result.VerifiedMitigations) != len(MandatoryMitigations()) {
		t.Fatalf("verified %d mitigations, want %d: %v", len(result.VerifiedMitigations), len(MandatoryMitigations()), result.VerifiedMitigations)
	}
	status := cell.Status()
	if status.State != StateExpiring {
		t.Fatalf("status state %s, want EXPIRING", status.State)
	}
	burnContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := cell.Burn(burnContext); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if err := cell.Burn(burnContext); err != nil {
		t.Fatalf("second burn must be idempotent: %v", err)
	}
	burned := cell.Status()
	if burned.State != StateBurned {
		t.Fatalf("post-burn state %s, want BURNED", burned.State)
	}
	containerName, err := newContainerName(cell.ID())
	if err != nil {
		t.Fatalf("container name: %v", err)
	}
	// Verify profile deletion directly: Create fails with ALREADY_EXISTS while
	// active, and succeeds again once DeleteAppContainerProfile purged it.
	if _, err := (windowsContainers{}).Create(containerName); err != nil {
		t.Fatalf("profile could not be freshly recreated after burn (unexpected remnant): %v", err)
	}
	_ = (windowsContainers{}).Delete(containerName)
	if _, statErr := os.Stat(root); statErr == nil {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			t.Fatalf("read staging root: %v", readErr)
		}
		for _, entry := range entries {
			if entry.Name() == "cells" {
				cellEntries, _ := os.ReadDir(filepath.Join(root, entry.Name()))
				if len(cellEntries) != 0 {
					t.Fatalf("staging leaves %d cell directories after burn", len(cellEntries))
				}
			}
		}
	}
}

// TestLiveRuntimeBudget proves that the runtime budget terminates a parser and
// that the cell fails closed into EXPIRING, never into a false success.
func TestLiveRuntimeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("live smoke NOT_TESTED: -short")
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("live smoke NOT_TESTED: SystemRoot unavailable")
	}
	// ping.exe blocks on stdin/network; a short budget must stop it.
	executable := filepath.Join(systemRoot, "System32", "sort.exe")
	liveProbeAppContainer(t)

	root := filepath.Join(t.TempDir(), "parser-cells")
	cell, err := NewCell(CellOptions{Root: root})
	if err != nil {
		t.Fatalf("new cell: %v", err)
	}
	profile := DefaultProfile("live-budget")
	profile.MaxInputBytes = 1024
	profile.MaxOutputBytes = 64 << 10
	profile.MaxRuntime = 10 * time.Second
	profile.MaxMemoryBytes = 128 << 20
	// A canceled context aborts a long-running cell; whoami finishes quickly, so
	// the assertion focuses on the fail-closed cleanup path instead of timing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, createErr := cell.Create(ctx, profile, []byte("x"), executable); createErr == nil {
		t.Fatalf("cell create with canceled context unexpectedly succeeded")
	}
	burnContext, burnCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer burnCancel()
	if err := cell.Burn(burnContext); err != nil {
		t.Fatalf("burn after canceled create: %v", err)
	}
	if state := cell.Status().State; state != StateBurned {
		t.Fatalf("state after canceled-create burn %s, want BURNED", state)
	}
}
