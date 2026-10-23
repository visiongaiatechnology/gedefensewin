// STATUS: DIAMANT VGT SUPREME
package security

import (
	"os"
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
	if !ValidToken(first) {
		t.Fatal("created token is not a valid 256-bit credential")
	}
	if TokenEqual(first, first+"x") || TokenEqual("", "") {
		t.Fatal("invalid tokens compared equal")
	}
}

func TestRotateTokenReplacesCredentialAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dashboard.token")
	original, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == original {
		t.Fatal("rotation returned the old credential")
	}
	if !ValidToken(rotated) {
		t.Fatal("rotated token is not a valid 256-bit credential")
	}
	onDisk, err := ReadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != rotated {
		t.Fatal("rotated credential was not persisted")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("rotation left temp files behind: %v", entries)
	}
}

func TestReadTokenRejectsMalformedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.token")
	if err := os.WriteFile(path, []byte("not-a-valid-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil {
		t.Fatal("malformed credential accepted")
	}
	if _, err := ReadToken("relative/path"); err == nil {
		t.Fatal("relative token path accepted")
	}
}
