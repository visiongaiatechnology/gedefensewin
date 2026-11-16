// STATUS: PLATIN VGT SUPREME

package trust

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/product"
)

func mustAnchor(t *testing.T) product.InstallAnchor {
	t.Helper()
	anchor, err := product.ResolveInstallAnchor(`C:\Program Files`)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	return anchor
}

func TestVerifierDeniesOutsideAnchorWithoutResolverCall(t *testing.T) {
	var calls atomic.Int32
	verifier := NewVerifier(mustAnchor(t), func(string) error {
		calls.Add(1)
		return nil
	}, time.Minute)

	outside := []string{
		`C:\Users\Public\vgt\gedefense\payload.exe`,
		`C:\Program Files\VGT\GeDefenseEvil\payload.exe`,
		`C:\Program Files\VGT\GeDefense\..\..\evil.exe`,
	}
	for _, path := range outside {
		if verifier.TrustedTreePath(path) {
			t.Fatalf("expected denial for %q", path)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("resolver must not run for paths outside the anchor, ran %d times", calls.Load())
	}
}

func TestVerifierRequiresReparseFreeResolution(t *testing.T) {
	anchor := mustAnchor(t)
	verifier := NewVerifier(anchor, func(path string) error {
		if path == `C:\Program Files\VGT\GeDefense\bin\evil.exe` {
			return errors.New("resolves through a reparse point")
		}
		return nil
	}, time.Minute)

	if !verifier.TrustedTreePath(`C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`) {
		t.Fatal("expected trusted path")
	}
	if verifier.TrustedTreePath(`C:\Program Files\VGT\GeDefense\bin\evil.exe`) {
		t.Fatal("resolver rejection must deny trust")
	}
}

func TestVerifierCacheIsBoundedAndExpires(t *testing.T) {
	anchor := mustAnchor(t)
	var calls atomic.Int32
	now := time.Unix(1700000000, 0)
	verifier := NewVerifier(anchor, func(string) error {
		calls.Add(1)
		return nil
	}, time.Minute)
	verifier.now = func() time.Time { return now }

	path := `C:\Program Files\VGT\GeDefense\bin\gedefense-windows.exe`
	for i := 0; i < 5; i++ {
		if !verifier.TrustedTreePath(path) {
			t.Fatal("expected trusted path")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want 1 (cached)", calls.Load())
	}
	now = now.Add(2 * time.Minute)
	if !verifier.TrustedTreePath(path) {
		t.Fatal("expected trusted path after expiry")
	}
	if calls.Load() != 2 {
		t.Fatalf("resolver calls = %d, want 2 after expiry", calls.Load())
	}

	verifier.max = 4
	for i := 0; i < 20; i++ {
		verifier.TrustedTreePath(`C:\Program Files\VGT\GeDefense\bin\unique-` + string(rune('a'+i)) + `.exe`)
	}
	verifier.mu.RLock()
	size := len(verifier.cache)
	verifier.mu.RUnlock()
	if size > verifier.max {
		t.Fatalf("cache size %d exceeds max %d", size, verifier.max)
	}
}

func TestVerifierDisabledFailsClosed(t *testing.T) {
	if NewVerifier(product.InstallAnchor{}, func(string) error { return nil }, time.Minute).Enabled() {
		t.Fatal("zero anchor must be disabled")
	}
	if Default().TrustedTreePath(`C:\Program Files\VGT\GeDefense\bin\x.exe`) && !Default().Enabled() {
		t.Fatal("disabled verifier must deny")
	}
}
