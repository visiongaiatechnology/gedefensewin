// STATUS: PLATIN VGT SUPREME
package titan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addRestoreFixture(t *testing.T, vault *Vault, body string) QuarantineEntry {
	t.Helper()
	source := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Add(source, "Quarantäne im Restore-TOCTOU-Test", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("quarantine did not remove the source: %v", err)
	}
	return entry
}

// FIND-WIN-021: a restore target that already exists is never overwritten.
func TestVaultRestoreRefusesExistingTargetWithoutOverwrite(t *testing.T) {
	vault, err := OpenVault(filepath.Join(t.TempDir(), "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	entry := addRestoreFixture(t, vault, "restore payload")
	if err := os.MkdirAll(filepath.Dir(entry.OriginalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.OriginalPath, []byte("existing target content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(entry.ID, "Besitzer versucht Restore auf existierendes Ziel"); err == nil {
		t.Fatal("restore accepted an already existing target")
	}
	content, err := os.ReadFile(entry.OriginalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "existing target content" {
		t.Fatalf("restore overwrote the existing target: %q", string(content))
	}
	stored, err := vault.readMetadata(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "QUARANTINED" {
		t.Fatalf("failed restore changed the state to %q", stored.State)
	}
}

// FIND-WIN-021: a target that exists as a directory is rejected as well.
func TestVaultRestoreRefusesDirectoryTarget(t *testing.T) {
	vault, err := OpenVault(filepath.Join(t.TempDir(), "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	entry := addRestoreFixture(t, vault, "restore payload")
	if err := os.MkdirAll(entry.OriginalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(entry.ID, "Besitzer versucht Restore auf Verzeichnisziel"); err == nil {
		t.Fatal("restore accepted a directory as target")
	}
}

// FIND-WIN-021: the captured MOTW sidecar is authenticated; tampering with it
// blocks the restore fail-closed before any target is created.
func TestVaultRestoreBlocksTamperedZoneRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := addRestoreFixture(t, vault, "zone record payload")
	zonePath := filepath.Join(root, entry.ID+vaultZoneRecordSuffix)
	zoneBytes, err := os.ReadFile(zonePath)
	if err != nil {
		t.Fatalf("authenticated zone record is missing: %v", err)
	}
	if len(zoneBytes) == 0 {
		t.Fatal("zone record is empty")
	}
	zoneBytes[len(zoneBytes)-1] ^= 0xff
	if err := os.WriteFile(zonePath, zoneBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(entry.ID, "Besitzer versucht Restore mit manipuliertem MOTW-Record"); err == nil {
		t.Fatal("restore accepted a tampered zone record")
	}
	if _, err := os.Stat(entry.OriginalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore created a target despite a tampered zone record: %v", err)
	}
}

// FIND-WIN-021: legacy entries without a captured MOTW record are restored, but
// the missing verification is explicit (RESTORED_DEGRADED), not silent.
func TestVaultRestoreLegacyEntryWithoutZoneRecordIsDegraded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := addRestoreFixture(t, vault, "legacy restore payload")
	if err := os.Remove(filepath.Join(root, entry.ID+vaultZoneRecordSuffix)); err != nil {
		t.Fatal(err)
	}
	restored, err := vault.Restore(entry.ID, "Besitzer stellt Legacy-Objekt ohne MOTW-Record wieder her")
	if err != nil {
		t.Fatalf("legacy restore failed: %v", err)
	}
	if restored.State != "RESTORED_DEGRADED" {
		t.Fatalf("legacy restore state=%q, want RESTORED_DEGRADED", restored.State)
	}
	if !strings.Contains(restored.RestoreReason, "DEGRADED") || !strings.Contains(restored.RestoreReason, "Mark-of-the-Web") {
		t.Fatalf("degraded restore is not documented: %q", restored.RestoreReason)
	}
	if _, err := os.Stat(entry.OriginalPath); err != nil {
		t.Fatalf("legacy restore did not recreate the target: %v", err)
	}
}

// FIND-WIN-021: every quarantine operation records a zone identifier state, even
// when the verified state is "no Mark-of-the-Web".
func TestVaultAddWritesAuthenticatedZoneRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := addRestoreFixture(t, vault, "zone absence payload")
	if _, err := os.Stat(filepath.Join(root, entry.ID+vaultZoneRecordSuffix)); err != nil {
		t.Fatalf("add did not record the zone identifier state: %v", err)
	}
	raw, present, err := vault.readZoneRecord(entry.ID)
	if err != nil || !present {
		t.Fatalf("zone record not readable: present=%t err=%v", present, err)
	}
	if len(raw) != 0 {
		t.Fatalf("MOTW-less source produced a non-empty zone record: %q", string(raw))
	}
	restored, err := vault.Restore(entry.ID, "Besitzer stellt Objekt ohne Mark-of-the-Web wieder her")
	if err != nil {
		t.Fatal(err)
	}
	if restored.State != "RESTORED" {
		t.Fatalf("restore state=%q, want RESTORED for a verified MOTW-less object", restored.State)
	}
}
