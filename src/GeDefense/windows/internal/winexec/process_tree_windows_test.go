// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winexec

import (
	"os/exec"
	"testing"
	"time"
)

func TestKillProcessTreeRejectsInvalidPID(t *testing.T) {
	if err := KillProcessTree(0); err == nil {
		t.Fatal("expected error for PID 0")
	}
	if err := KillProcessTree(-1); err == nil {
		t.Fatal("expected error for PID -1")
	}
}

func TestKillProcessTreeTerminatesRunningProcess(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start test process: %v", err)
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	time.Sleep(100 * time.Millisecond)
	if err := KillProcessTree(pid); err != nil {
		t.Fatalf("KillProcessTree failed: %v", err)
	}

	select {
	case <-done:
		// Process terminated as expected
	case <-time.After(5 * time.Second):
		t.Fatal("process was not terminated by KillProcessTree")
	}
}
