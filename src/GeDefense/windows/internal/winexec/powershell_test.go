// STATUS: DIAMANT VGT SUPREME
package winexec

import "testing"

func TestPowerShellResolvesNativeSystemBinary(t *testing.T) {
	path, err := PowerShell()
	if err != nil {
		t.Fatalf("PowerShell() error: %v", err)
	}
	if path == "" {
		t.Fatal("PowerShell() returned an empty path")
	}
}

func TestPowerShellRejectsUntrustedRoots(t *testing.T) {
	for _, root := range []string{"", `relative\\windows`} {
		if _, err := powerShellFromRoot(root); err == nil {
			t.Fatalf("powerShellFromRoot(%q) accepted an untrusted root", root)
		}
	}
}
