// STATUS: PLATIN VGT SUPREME

package titan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewStartsDegradedWhenQuarantineMetadataTampered proves the FIND-WIN-012
// availability contract: a tampered quarantine metadata record must never be
// re-signed, must block restore/review for that ID, and must NOT stop the
// protection service from starting. Before this change New() returned the vault
// error and the whole sensor went dark.
func TestNewStartsDegradedWhenQuarantineMetadataTampered(t *testing.T) {
	root := t.TempDir()
	vaultRoot := filepath.Join(root, "quarantine")
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	writeLegacyVaultKey(t, vaultRoot, key)
	id := strings.Repeat("a", 32)
	writeVaultMetadataFixture(t, vaultRoot, testLegacyEntry(t, id, "quarantined-payload"))

	// First open migrates the unauthenticated legacy record exactly once and
	// installs the protected key.
	if _, err := OpenVault(vaultRoot); err != nil {
		t.Fatalf("initial legacy migration failed: %v", err)
	}

	// Tamper the authenticated field the migration just protected.
	metadataPath := filepath.Join(vaultRoot, id+".json")
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read metadata fixture: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode metadata fixture: %v", err)
	}
	record["originalPath"] = `C:\Users\Public\planted.exe`
	tampered, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode tampered metadata: %v", err)
	}
	if err := os.WriteFile(metadataPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered metadata: %v", err)
	}

	engine, err := New(root, "5.3.1-test", nil)
	if err != nil {
		t.Fatalf("service must start degraded instead of refusing to start: %v", err)
	}
	defer func() { _ = engine.Close() }()

	status := engine.Status()
	if len(status.QuarantineIntegrity) == 0 {
		t.Fatal("tampered quarantine metadata was not surfaced in Status.QuarantineIntegrity")
	}
	if status.QuarantineIntegrity[0].ID != id {
		t.Fatalf("integrity issue id = %q, want %q", status.QuarantineIntegrity[0].ID, id)
	}
	if status.State != "DEGRADED" {
		t.Fatalf("state = %q, want DEGRADED", status.State)
	}

	// Restore of the tampered ID must stay blocked; the record was not re-signed.
	if _, err := engine.RestoreQuarantine(id, "test restore"); err == nil {
		t.Fatal("restore of tampered quarantine metadata must fail closed")
	}
	rawAfter, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read metadata after open: %v", err)
	}
	if string(rawAfter) != string(tampered) {
		t.Fatal("tampered metadata was silently rewritten/re-signed")
	}
}

// TestNewFailsClosedOnNonIntegrityVaultError proves unrelated vault failures still
// abort construction; only the integrity case degrades.
func TestNewFailsClosedOnNonIntegrityVaultError(t *testing.T) {
	root := t.TempDir()
	// A quarantine path that is a file instead of a directory is a hard error.
	vaultRoot := filepath.Join(root, "quarantine")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, "5.3.1-test", nil); err == nil {
		t.Fatal("expected construction failure for an unusable vault root")
	}
}
