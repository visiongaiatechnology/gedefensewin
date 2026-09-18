// STATUS: DIAMANT VGT SUPREME
package winexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPowerShellResolvesNativeSystemBinary(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := powerShellFromRoot(root)
	if err != nil {
		t.Fatalf("powerShellFromRoot() error: %v", err)
	}
	if path != executable {
		t.Fatalf("resolved path = %q, want %q", path, executable)
	}
}

func TestPowerShellRejectsUntrustedRoots(t *testing.T) {
	for _, root := range []string{"", `relative\\windows`} {
		if _, err := powerShellFromRoot(root); err == nil {
			t.Fatalf("powerShellFromRoot(%q) accepted an untrusted root", root)
		}
	}
}
