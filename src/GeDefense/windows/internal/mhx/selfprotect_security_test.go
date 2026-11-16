// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winexec"
)

// TestSelfProtectionRequiresAnchoredInstallPath proves FIND-WIN-001 is closed:
// the former unanchored `\vgt\gedefense\` substring match granted full sovereign
// immunity to any payload the user could place in a matching temporary path.
func TestSelfProtectionRequiresAnchoredInstallPath(t *testing.T) {
	bypassPaths := []string{
		`C:\Users\Public\vgt\gedefense\gedefense-windows.exe`,
		`C:\Users\Public\AppData\Local\Temp\vgt\gedefense\GeDefenseCenter.exe`,
		`C:\vgt\gedefense\gedefense-windows.exe`,
		`C:\Program Files\VGT\GeDefenseEvil\gedefense-windows.exe`,
		`C:\Program Files\VGT\GeDefense\..\..\evil.exe`,
	}
	for _, path := range bypassPaths {
		event := ProcessEvent{PID: 4242, Image: "gedefense-windows.exe", ImagePath: path}
		if isGeDefenseSelfOrChild(event) {
			t.Fatalf("unanchored path %q must not grant self-protection immunity", path)
		}
	}

	trusted := ProcessEvent{PID: 4243, Image: "gedefense-windows.exe", ImagePath: `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`}
	if !isGeDefenseSelfOrChild(trusted) {
		t.Fatal("installed product binary must stay self-protected")
	}
}

// TestSelfProtectionRejectsParentPathInjection proves the former blanket
// "parent image is GeDefense" exemption cannot be forged from a temporary path.
func TestSelfProtectionRejectsParentPathInjection(t *testing.T) {
	event := ProcessEvent{
		PID:         5151,
		ParentPID:   6161,
		ParentImage: "gedefense-windows.exe",
		ParentPath:  `C:\Users\Public\vgt\gedefense\gedefense-windows.exe`,
		Image:       "payload.exe",
		ImagePath:   `C:\Users\Public\payload.exe`,
	}
	if isGeDefenseSelfOrChild(event) {
		t.Fatal("parent path injection must not grant self-protection immunity")
	}
}

// TestTrackedChildIsSelfProtected proves the evidence-backed replacement for the
// removed command-line substring exemption: a child this service started and
// pins is exempt, nobody else.
func TestTrackedChildIsSelfProtected(t *testing.T) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("SystemRoot unavailable")
	}
	cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")
	command := exec.Command(cmdPath, "/c", "ping", "-n", "4", "127.0.0.1")
	if err := winexec.StartTracked(command); err != nil {
		t.Fatalf("start tracked child: %v", err)
	}
	pid := uint32(command.Process.Pid)
	defer func() {
		_ = command.Wait()
		winexec.ReleaseTrackedProcess(int(pid))
	}()
	if !isTrackedChild(pid) {
		t.Fatalf("tracked child pid %d not recognised", pid)
	}
	if !isGeDefenseSelfOrChild(ProcessEvent{PID: pid, Image: "cmd.exe", ImagePath: cmdPath}) {
		t.Fatal("tracked child must be recognised as self process")
	}
}

// TestProtectedOSProcessBlocklist proves the SYSTEM-kill-DoS breakpoint
// (FIND-WIN-002 / CHAIN-WIN-001): canonical critical OS binaries can never be a
// kinetic target, while a renamed copy outside the system directory can.
func TestProtectedOSProcessBlocklist(t *testing.T) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	system32 := filepath.Join(systemRoot, "System32")
	positive := []struct{ image, path string }{
		{"System", ""},
		{"lsass.exe", filepath.Join(system32, "lsass.exe")},
		{"svchost.exe", filepath.Join(system32, "svchost.exe")},
		{"csrss.exe", filepath.Join(system32, "csrss.exe")},
		{"MsMpEng.exe", `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.0\MsMpEng.exe`},
	}
	for _, target := range positive {
		if !IsProtectedOSProcess(target.image, target.path) {
			t.Fatalf("expected protected OS process for %q (%q)", target.image, target.path)
		}
	}
	negative := []struct{ image, path string }{
		{"svchost.exe", `C:\Users\Public\svchost.exe`},
		{"lsass.exe", `C:\Users\Public\AppData\Local\Temp\lsass.exe`},
		{"cmd.exe", filepath.Join(system32, "cmd.exe")},
		{"payload.exe", `C:\Users\Public\payload.exe`},
	}
	for _, target := range negative {
		if IsProtectedOSProcess(target.image, target.path) {
			t.Fatalf("unexpected protection for %q (%q)", target.image, target.path)
		}
	}
}

// TestTerminationTargetRequiresFullIdentity proves a bare PID is no longer kill
// authority: the request must carry creation time and image path.
func TestTerminationTargetRequiresFullIdentity(t *testing.T) {
	engine := &Engine{}
	cases := []TerminationTarget{
		{PID: 4, CreationUnixNano: 1, ImagePath: `C:\Windows\System32\lsass.exe`},
		{PID: 1234, CreationUnixNano: 0, ImagePath: `C:\Users\Public\payload.exe`},
		{PID: 1234, CreationUnixNano: 1, ImagePath: ""},
		{PID: 1234, CreationUnixNano: 1, ImagePath: `C:\Windows\System32\lsass.exe`},
	}
	for _, target := range cases {
		if err := engine.terminateTargetVerified(target); err == nil {
			t.Fatalf("expected identity rejection for target %+v", target)
		}
	}
}
