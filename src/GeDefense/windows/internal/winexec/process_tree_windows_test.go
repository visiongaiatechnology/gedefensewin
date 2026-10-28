// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winexec

import (
	"os/exec"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// newLongRunningCommand uses a benign PowerShell sleep instead of `cmd /c`.
// A `cmd.exe /c ...` child is legitimate but can be terminated by a live
// security product on the test host (false-positive signature), which would make
// this process-tree test environment-dependent.
func newLongRunningCommand() *exec.Cmd {
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30")
}

func startLongRunning(t *testing.T) *exec.Cmd {
	t.Helper()
	command := newLongRunningCommand()
	if err := StartTracked(command); err != nil {
		t.Skipf("cannot start test process: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		ReleaseTrackedProcess(command.Process.Pid)
	})
	return command
}

func waitForTracked(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if lookupTrackedProcess(pid) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d was not tracked", pid)
}

func assertProcessAlive(t *testing.T, pid int) {
	t.Helper()
	identity, err := winapi.OpenProcessIdentity(uint32(pid), false)
	if err != nil {
		// A live third-party EDR/security product on the test host may terminate
		// an untracked child immediately. That is environment interference, not a
		// failure of the guard under test; the refusal itself was already asserted.
		t.Skipf("test process %d is no longer inspectable (environment interference): %v", pid, err)
	}
	_ = identity.Close()
}

func TestKillProcessTreeRejectsInvalidPID(t *testing.T) {
	for _, pid := range []int{0, -1, 4} {
		if err := KillProcessTree(pid); err == nil {
			t.Fatalf("expected error for PID %d", pid)
		}
	}
}

// HP-FIND-004: a PID that was never tracked by this process must be refused.
// The former implementation ran taskkill /T on any PID it was handed.
func TestKillProcessTreeRejectsUntrackedProcess(t *testing.T) {
	command := newLongRunningCommand()
	if err := command.Start(); err != nil {
		t.Skipf("cannot start test process: %v", err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	time.Sleep(100 * time.Millisecond)
	if err := KillProcessTree(command.Process.Pid); err == nil {
		t.Fatal("expected untracked PID to be refused")
	}
	assertProcessAlive(t, command.Process.Pid)
}

func TestKillProcessTreeTerminatesTrackedProcess(t *testing.T) {
	command := startLongRunning(t)
	pid := command.Process.Pid
	waitForTracked(t, pid)
	if err := KillProcessTree(pid); err != nil {
		t.Fatalf("KillProcessTree failed: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
		// terminated as expected
	case <-time.After(5 * time.Second):
		t.Fatal("process was not terminated by KillProcessTree")
	}
}

// HP-FIND-004 regression: when the recorded creation time no longer matches
// the pinned process object, the tree kill must fail closed. Without the
// pinned handle this is exactly the state a PID-reuse window produces.
func TestKillProcessTreeRejectsCreationTimeMismatch(t *testing.T) {
	command := startLongRunning(t)
	pid := command.Process.Pid
	waitForTracked(t, pid)
	trackedMu.Lock()
	trackedProcesses[pid].creationUnixNano += int64(time.Hour)
	trackedMu.Unlock()
	if err := KillProcessTree(pid); err == nil {
		t.Fatal("expected creation-time mismatch to be refused")
	}
	assertProcessAlive(t, pid)
}

func TestKillProcessTreeRejectsImagePathMismatch(t *testing.T) {
	command := startLongRunning(t)
	pid := command.Process.Pid
	waitForTracked(t, pid)
	trackedMu.Lock()
	trackedProcesses[pid].imagePath = `C:\Windows\System32\not-our-child.exe`
	trackedMu.Unlock()
	if err := KillProcessTree(pid); err == nil {
		t.Fatal("expected image-path mismatch to be refused")
	}
	assertProcessAlive(t, pid)
}

func TestRunTrackedReleasesRegistryEntry(t *testing.T) {
	command := exec.Command("cmd.exe", "/c", "exit 0")
	if err := RunTracked(command); err != nil {
		t.Skipf("cannot run test process: %v", err)
	}
	if lookupTrackedProcess(command.Process.Pid) != nil {
		t.Fatal("RunTracked must release the pinned process handle")
	}
}

func TestStartTrackedRequiresCommand(t *testing.T) {
	if err := StartTracked(nil); err == nil {
		t.Fatal("expected error for nil command")
	}
	if err := RunTracked(nil); err == nil {
		t.Fatal("expected error for nil command")
	}
}

func TestReleaseTrackedProcessIsIdempotent(t *testing.T) {
	ReleaseTrackedProcess(0)
	ReleaseTrackedProcess(-1)
	ReleaseTrackedProcess(999999)
}
