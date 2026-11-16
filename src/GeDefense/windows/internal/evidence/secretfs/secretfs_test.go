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

// TestCreateSecretFileAppliesDACLBeforeFirstSecretByte is the regression test
// for FIND-WIN-019: the creation path used to write the secret material first
// and harden the DACL afterwards, leaving a readable window. The seam runs at
// the moment the restrictive DACL is applied and fails if the file already
// contains payload bytes.
func TestCreateSecretFileAppliesDACLBeforeFirstSecretByte(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	path := filepath.Join(dir, "state.json")

	previous := hardenBeforeFirstSecretByte
	t.Cleanup(func() { hardenBeforeFirstSecretByte = previous })
	observations := 0
	hardenBeforeFirstSecretByte = func(target string) (Restriction, error) {
		observations++
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("hardened target does not exist: %v", statErr)
		}
		if info.Size() != 0 {
			t.Fatalf("secret bytes were written before the DACL was applied: %d bytes", info.Size())
		}
		return previous(target)
	}

	if err := CreateSecretFile(path, []byte("top-secret-payload")); err != nil {
		t.Fatal(err)
	}
	if observations == 0 {
		t.Fatal("hardening seam was never invoked")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "top-secret-payload" {
		t.Fatalf("stored payload=%q", raw)
	}
	if _, err := HardenFile(path); err != nil {
		t.Fatalf("final secret file is not hardenable: %v", err)
	}
}

// TestCreateSecretFileExclusiveAppliesDACLBeforeFirstSecretByte covers the
// exclusive-create variant used for dashboard.token.
func TestCreateSecretFileExclusiveAppliesDACLBeforeFirstSecretByte(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "token")
	path := filepath.Join(dir, "dashboard.token")

	previous := hardenBeforeFirstSecretByte
	t.Cleanup(func() { hardenBeforeFirstSecretByte = previous })
	observations := 0
	hardenBeforeFirstSecretByte = func(target string) (Restriction, error) {
		observations++
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("hardened target does not exist: %v", statErr)
		}
		if info.Size() != 0 {
			t.Fatalf("credential bytes were written before the DACL was applied: %d bytes", info.Size())
		}
		return previous(target)
	}

	if err := CreateSecretFileExclusive(path, []byte("credential\n")); err != nil {
		t.Fatal(err)
	}
	if observations == 0 {
		t.Fatal("hardening seam was never invoked")
	}
	if err := CreateSecretFileExclusive(path, []byte("second\n")); err == nil {
		t.Fatal("exclusive creation overwrote an existing secret file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "credential\n" {
		t.Fatalf("stored payload=%q", raw)
	}
}
