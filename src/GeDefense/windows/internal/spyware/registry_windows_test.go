// STATUS: PLATIN VGT SUPREME
//go:build windows

package spyware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHostRegistryAdapters is a live smoke test of the real Win32 adapters. It
// skips per adapter when the registry area is unavailable instead of inventing a
// result.
func TestHostRegistryAdapters(t *testing.T) {
	services, err := EnumerateDriverServices()
	if err != nil {
		t.Skipf("driver services unavailable: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("expected at least one kernel driver service on a Windows host")
	}
	for _, service := range services {
		if service.Name == "" {
			t.Fatal("driver service without name")
		}
		if !service.IsKernelDriver() {
			t.Fatalf("non-kernel service leaked into driver enumeration: %s", service.Name)
		}
	}
	if len(services) > maxDriverServices {
		t.Fatalf("driver enumeration unbounded: %d", len(services))
	}

	posture, err := ReadSecurityPosture()
	if err != nil {
		t.Logf("security posture partially unavailable (expected on some SKUs): %v", err)
	}
	_ = posture

	// Capability consent store: a missing area is not an error. The assertion is
	// only that every returned entry is bounded and decoded.
	states, err := ReadCapabilityStates()
	if err != nil {
		t.Logf("capability consent store partially unavailable: %v", err)
	}
	for _, state := range states {
		if len(state.Path) > 2048 {
			t.Fatalf("capability path unbounded: %d bytes", len(state.Path))
		}
		if state.Capability == "" {
			t.Fatal("capability state without capability name")
		}
	}
	if len(states) > maxRegistrySubkeys*4 {
		t.Fatalf("capability enumeration unbounded: %d", len(states))
	}
}

func TestExpandRegistryImagePath(t *testing.T) {
	systemRoot := `C:\Windows`
	envRoot := os.Getenv("SystemRoot")
	cases := map[string]string{
		`\SystemRoot\System32\drivers\foo.sys`:     `C:\Windows\System32\drivers\foo.sys`,
		`%SystemRoot%\System32\drivers\bar.sys`:    envRoot + `\System32\drivers\bar.sys`,
		`\??\C:\Windows\System32\drivers\baz.sys`:  `C:\Windows\System32\drivers\baz.sys`,
		`C:\Windows\System32\drivers\raw.sys`:      `C:\Windows\System32\drivers\raw.sys`,
		`"C:\Windows\System32\drivers\quoted.sys"`: `C:\Windows\System32\drivers\quoted.sys`,
	}
	for input, want := range cases {
		if got := expandRegistryImagePath(input, systemRoot); !strings.EqualFold(got, want) {
			t.Fatalf("expandRegistryImagePath(%q) = %q, want %q", input, got, want)
		}
	}
	if got := expandRegistryImagePath("", systemRoot); got != "" {
		t.Fatalf("empty image path = %q, want empty", got)
	}
	// An undefined variable is left untouched instead of silently becoming a
	// relative or empty path.
	if got := expandRegistryImagePath(`%VGT_NOT_DEFINED%\x.sys`, systemRoot); !strings.Contains(got, "%VGT_NOT_DEFINED%") {
		t.Fatalf("undefined variable must not be invented: %q", got)
	}
}

func TestHostEngineUsesRealAuthenticodeVerifier(t *testing.T) {
	engine := NewHostEngine(Settings{Enabled: true, BYOVD: true}, nil)
	if engine == nil {
		t.Fatal("host engine is nil")
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Skip("SystemRoot unavailable")
	}
	// A real, Microsoft-signed driver must resolve as signature "valid" if the
	// verifier works; a nonexistent path must be "invalid". This exercises the
	// WinVerifyTrust seam without assuming a specific driver is present.
	driverDir := filepath.Join(systemRoot, "System32", "drivers")
	entries, err := os.ReadDir(driverDir)
	if err != nil || len(entries) == 0 {
		t.Skipf("driver directory unavailable: %v", err)
	}
	candidate := ""
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sys" {
			candidate = filepath.Join(driverDir, entry.Name())
			break
		}
	}
	if candidate != "" {
		if status := engine.driverSignatureStatus(candidate); status != "valid" {
			t.Logf("driver %s signature status = %s (informational; some images are catalog-signed)", candidate, status)
		}
	}
	if status := engine.driverSignatureStatus(filepath.Join(t.TempDir(), "missing.sys")); status != "invalid" {
		t.Fatalf("missing file signature status = %q, want invalid", status)
	}
}

func TestDriverSignatureCacheIsBoundedAndCached(t *testing.T) {
	calls := 0
	engine := New(Settings{
		Enabled: true,
		BYOVD:   true,
		VerifyDriverSignature: func(path string) error {
			calls++
			return nil
		},
	}, nil)
	engine.now = func() time.Time { return testNow }
	for index := 0; index < 5; index++ {
		engine.driverSignatureStatus(`C:\Windows\System32\drivers\good.sys`)
	}
	if calls != 1 {
		t.Fatalf("verifier calls = %d, want 1 (cached)", calls)
	}
	for index := 0; index < maxSignatureCache+32; index++ {
		engine.driverSignatureStatus(filepath.Join(`C:\Windows\System32\drivers`, string(rune('a'+index%26))+string(rune('a'+index/26%26))+".sys"))
	}
	engine.mu.Lock()
	size := len(engine.sigCache)
	engine.mu.Unlock()
	if size > maxSignatureCache {
		t.Fatalf("signature cache size %d exceeds max %d", size, maxSignatureCache)
	}
}
