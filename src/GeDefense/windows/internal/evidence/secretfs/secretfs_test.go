// STATUS: DIAMANT VGT SUPREME

package secretfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateRawKeyRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "test.key")
	first, err := LoadOrCreateRawKey(path, 32)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("key length=%d", len(first))
	}
	second, err := LoadOrCreateRawKey(path, 32)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("reloaded key differs from created key")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 32 || strings.ContainsAny(string(raw), "\r\n") {
		t.Fatalf("unexpected key encoding: %q", raw)
	}
}

func TestLoadOrCreateRawKeyRejectsCorruptMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "test.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRawKey(path, 32); err == nil {
		t.Fatal("corrupt key material was accepted")
	}
}

func TestEnsureSecretDirAndHardenFileAreFailClosedForReparseTargets(t *testing.T) {
	root := t.TempDir()
	if _, err := EnsureSecretDir(root); err != nil {
		t.Fatalf("EnsureSecretDir(%q): %v", root, err)
	}
	file := filepath.Join(root, "key")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HardenFile(file); err != nil {
		t.Fatalf("HardenFile: %v", err)
	}
	if _, err := HardenFile(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing secret file reported as hardened")
	}
}

func TestCreateSecretFileIsAtomicAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	path := filepath.Join(dir, "state.json")
	if err := CreateSecretFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := CreateSecretFile(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "second" {
		t.Fatalf("replaced content=%q", raw)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".secretfs-") {
			t.Fatalf("temporary secret file leaked: %s", entry.Name())
		}
	}
}

func TestRestrictionReportsServiceEnforcementAvailability(t *testing.T) {
	canEnforce, err := canManageServiceDACL()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "keys")
	restriction, err := EnsureSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restriction.Enforced != canEnforce {
		t.Fatalf("Enforced=%t want %t", restriction.Enforced, canEnforce)
	}
	if canEnforce && !restriction.Restricted {
		t.Fatalf("service process did not restrict secret directory: %+v", restriction)
	}
}
