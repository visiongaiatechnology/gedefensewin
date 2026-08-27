// STATUS: DIAMANT VGT SUPREME
package security

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateTokenIsStableAndConstantTimeComparable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.token")
	first, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !TokenEqual(first, second) {
		t.Fatal("persisted token did not round-trip")
	}
	if TokenEqual(first, first+"x") || TokenEqual("", "") {
		t.Fatal("invalid tokens compared equal")
	}
}
