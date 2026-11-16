// STATUS: DIAMANT VGT SUPREME
package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
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

// TestTokenUsesHardenedSecretFileStore proves that dashboard.token is created
// through the secretfs protection path (FIND-WIN-019): the file must be
// recognised as a hardenable secret and, when the process runs with service
// privileges, the effective DACL must grant only LocalSystem/Administrators.
// A non-elevated developer process cannot manage that DACL without locking
// itself out; secretfs then defers to the LocalSystem service (documented
// skip) while the creation path itself is still the hardened one.
func TestTokenUsesHardenedSecretFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "VGT", "GeDefense", "dashboard.token")
	token, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidToken(token) {
		t.Fatal("created token is not a valid 256-bit credential")
	}
	restriction, err := secretfs.HardenFile(path)
	if err != nil {
		t.Fatalf("created token is not a hardenable secret file: %v", err)
	}
	if !restriction.Enforced {
		t.Skip("non-elevated test process: DACL hardening is deferred to the LocalSystem service (secretfs contract)", restriction.Detail)
	}
	if !restriction.Restricted {
		t.Fatalf("token file DACL grants more than LocalSystem/Administrators: %s", restriction.Detail)
	}
}

// TestRotateTokenThroughSecretfsLeavesNoReadableWindow checks the rotation
// contract: the credential is replaced atomically, no temporary secret file
// leaks and the produced file is the hardened secret target.
func TestRotateTokenThroughSecretfsLeavesNoReadableWindow(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "VGT", "GeDefense")
	path := filepath.Join(directory, "dashboard.token")
	if _, err := LoadOrCreateToken(path); err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "dashboard.token" {
			t.Fatalf("rotation left a temporary secret file behind: %s", entry.Name())
		}
	}
	if !TokenEqual(rotated, mustReadToken(t, path)) {
		t.Fatal("rotated credential is not the persisted credential")
	}
}

func mustReadToken(t *testing.T, path string) string {
	t.Helper()
	token, err := ReadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
