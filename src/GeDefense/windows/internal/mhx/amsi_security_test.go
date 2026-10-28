// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"strings"
	"testing"
)

func TestAmsiLocalModuleIdentityAndOffset(t *testing.T) {
	path, size, err := localAmsiModuleIdentity()
	if err != nil {
		t.Fatalf("local amsi.dll identity unavailable: %v", err)
	}
	if size == 0 || !strings.HasSuffix(strings.ToLower(path), `\amsi.dll`) {
		t.Fatalf("invalid local amsi identity: path=%q size=%d", path, size)
	}
	if offset := getAmsiScanBufferOffset(); offset == 0 {
		t.Fatalf("AmsiScanBuffer offset must be resolved from %s", path)
	}
}

func TestAmsiScanRejectsInvalidInputs(t *testing.T) {
	if patched, err := isAmsiPatched(0, 1); patched || err != nil {
		t.Fatalf("pid 0 must be rejected without error, got patched=%v err=%v", patched, err)
	}
	if patched, err := isAmsiPatched(4, 1); patched || err != nil {
		t.Fatalf("pid 4 must be rejected without error, got patched=%v err=%v", patched, err)
	}
	if patched, err := isAmsiPatched(100, 0); patched || err != nil {
		t.Fatalf("zero offset must be a no-op, got patched=%v err=%v", patched, err)
	}
}
