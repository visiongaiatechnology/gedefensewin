// STATUS: PLATIN VGT SUPREME
package scriptengine

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPowerShellArgumentsAreHardened(t *testing.T) {
	arguments := powerShellArguments(`C:\Program Files\VGT\GeDefense\engine\Invoke-VgtHardening.ps1`, `C:\ProgramData\VGT\out.json`, []string{"-Mode", "Enforce"})
	joined := strings.Join(arguments, " ")
	for _, required := range []string{
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy AllSigned",
		"-File " + `C:\Program Files\VGT\GeDefense\engine\Invoke-VgtHardening.ps1`,
		"-OutputPath " + `C:\ProgramData\VGT\out.json`,
		"-Mode Enforce",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("hardened PowerShell arguments are missing %q: %v", required, arguments)
		}
	}
	if strings.Contains(joined, "-ExecutionPolicy Bypass") || strings.Contains(joined, "-ExecutionPolicy Unrestricted") {
		t.Fatalf("unsafe execution policy in arguments: %v", arguments)
	}
}

func TestHardenedPowerShellEnvironmentSanitizesModulePath(t *testing.T) {
	t.Setenv("PSModulePath", `C:\Users\attacker\Documents\WindowsPowerShell\Modules`)
	environment := hardenedPowerShellEnvironment()
	moduleEntries := 0
	for _, entry := range environment {
		if strings.HasPrefix(strings.ToUpper(entry), "PSMODULEPATH=") {
			moduleEntries++
			if strings.Contains(strings.ToLower(entry), `documents\windowspowershell`) {
				t.Fatalf("inherited user PSModulePath survived sanitization: %q", entry)
			}
			if !strings.Contains(entry, filepath.Join("System32", "WindowsPowerShell", "v1.0", "Modules")) {
				t.Fatalf("PSModulePath does not point at the system module root: %q", entry)
			}
		}
	}
	if moduleEntries != 1 {
		t.Fatalf("expected exactly one sanitized PSModulePath entry, got %d (%v)", moduleEntries, environment)
	}
}

func TestNewRejectsNonAbsolutePaths(t *testing.T) {
	if _, err := New("relative.ps1", `C:\ProgramData\VGT`, 30); err == nil {
		t.Fatal("relative script path accepted")
	}
	if _, err := New(`C:\Program Files\VGT\script.ps1`, "relative", 30); err == nil {
		t.Fatal("relative operation root accepted")
	}
}
