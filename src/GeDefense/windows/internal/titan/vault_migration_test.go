// STATUS: PLATIN VGT SUPREME
package titan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLegacyEntry(t *testing.T, id, payload string) QuarantineEntry {
	t.Helper()
	if len(id) != 32 {
		t.Fatalf("legacy test id %q is not 32 characters", id)
	}
	sum := sha256.Sum256([]byte(payload))
	return QuarantineEntry{
		ID:           id,
		CreatedUTC:   time.Now().UTC().Add(-time.Hour),
		OriginalPath: filepath.Join(t.TempDir(), "legacy.exe"),
		OriginalName: "legacy.exe",
		SHA256:       hex.EncodeToString(sum[:]),
		Size:         int64(len(payload)),
		FileType:     "EXECUTABLE",
		Reason:       "Legacy-Migrationstest",
		State:        "QUARANTINED",
		// The original was already removed when the entry was created, so the
		// crash-recovery path must not rewrite the record during the test.
		OriginalGone: true,
	}
}

func writeLegacyVaultKey(t *testing.T, root string, key []byte) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(key))
	if err := os.WriteFile(filepath.Join(root, vaultKeyName), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeVaultMetadataFixture(t *testing.T, root string, entry QuarantineEntry) []byte {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(root, entry.ID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeQuarantineEntry(t *testing.T, raw []byte) QuarantineEntry {
	t.Helper()
	var entry QuarantineEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func testVaultKey(t *testing.T, seed byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = seed + byte(index)
	}
	return key
}

// FIND-WIN-012: the legacy one-time migration signs a pre-authentication vault
// exactly once and the second start does not change any MAC.
func TestVaultLegacyMigrationSignsOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	key := testVaultKey(t, 1)
	writeLegacyVaultKey(t, root, key)
	entry := testLegacyEntry(t, strings.Repeat("a", 31)+"1", "legacy body")
	if _, err := os.Stat(filepath.Join(root, entry.ID+".json")); err == nil {
		t.Fatal("fixture metadata unexpectedly exists before write")
	}
	writeVaultMetadataFixture(t, root, entry)

	vault, err := OpenVault(root)
	if err != nil {
		t.Fatalf("legacy migration failed: %v", err)
	}
	if issues := vault.IntegrityIssues(); len(issues) != 0 {
		t.Fatalf("clean legacy migration reported integrity issues: %+v", issues)
	}
	if _, err := os.Stat(filepath.Join(root, "keys", vaultKeyName)); err != nil {
		t.Fatalf("protected key was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, vaultKeyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy root key was not retired: %v", err)
	}
	firstBytes := readFileBytes(t, filepath.Join(root, entry.ID+".json"))
	migrated := decodeQuarantineEntry(t, firstBytes)
	if migrated.MetadataMAC == "" {
		t.Fatal("legacy metadata was not authenticated by the first migration")
	}
	if err := vault.verifyMetadataAuthentication(migrated); err != nil {
		t.Fatalf("migrated metadata MAC does not verify: %v", err)
	}

	second, err := OpenVault(root)
	if err != nil {
		t.Fatalf("second open after migration failed: %v", err)
	}
	secondBytes := readFileBytes(t, filepath.Join(root, entry.ID+".json"))
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("second start changed the migrated metadata MAC")
	}
	if issues := second.IntegrityIssues(); len(issues) != 0 {
		t.Fatalf("second open reported integrity issues: %+v", issues)
	}
}

// FIND-WIN-012: a tampered metadata record with a valid key is never re-signed,
// is blocked for restore, and the remaining vault stays usable.
func TestVaultTamperedMetadataIsNotResignedAndBlocksRestore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(source, []byte("tamper fixture body"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Add(source, "Quarantäne im Migrations-Tamper-Test", "")
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(root, entry.ID+".json")
	tampered := decodeQuarantineEntry(t, readFileBytes(t, metadataPath))
	tampered.OriginalPath = filepath.Join(t.TempDir(), "redirected.exe")
	tamperedBytes := writeVaultMetadataFixture(t, root, tampered)

	reopened, openErr := OpenVault(root)
	var integrityErr *VaultMetadataIntegrityError
	if !errors.As(openErr, &integrityErr) {
		t.Fatalf("expected *VaultMetadataIntegrityError, got %v", openErr)
	}
	if reopened == nil {
		t.Fatal("vault must stay usable after a metadata integrity violation")
	}
	issues := reopened.IntegrityIssues()
	if len(issues) != 1 || issues[0].ID != entry.ID {
		t.Fatalf("unexpected integrity issues: %+v", issues)
	}
	if after := readFileBytes(t, metadataPath); !bytes.Equal(after, tamperedBytes) {
		t.Fatal("tampered metadata was re-signed during the open")
	}
	if _, err := reopened.Restore(entry.ID, "Restore muss für tamperte Metadaten blockiert sein"); err == nil {
		t.Fatal("restore of a blocked object was accepted")
	}
	// The authenticated part of the vault must remain operational.
	second := filepath.Join(t.TempDir(), "second.exe")
	if err := os.WriteFile(second, []byte("second body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Add(second, "Quarantäne nach Integritätsbefund", ""); err != nil {
		t.Fatalf("vault was unusable after an integrity finding: %v", err)
	}
}

// FIND-WIN-012: a stripped MAC on a vault with an existing protected key is a
// fail-closed integrity violation, never a signing opportunity.
func TestVaultMissingMACWithProtectedKeyIsBlocked(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	vault, err := OpenVault(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(source, []byte("missing mac body"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Add(source, "Quarantäne im Fehlende-MAC-Test", "")
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(root, entry.ID+".json")
	stripped := decodeQuarantineEntry(t, readFileBytes(t, metadataPath))
	stripped.MetadataMAC = ""
	strippedBytes := writeVaultMetadataFixture(t, root, stripped)

	reopened, openErr := OpenVault(root)
	var integrityErr *VaultMetadataIntegrityError
	if !errors.As(openErr, &integrityErr) {
		t.Fatalf("expected *VaultMetadataIntegrityError, got %v", openErr)
	}
	if reopened == nil {
		t.Fatal("vault must stay usable after a missing MAC")
	}
	if after := readFileBytes(t, metadataPath); !bytes.Equal(after, strippedBytes) {
		t.Fatal("metadata without MAC was re-signed")
	}
	restored := decodeQuarantineEntry(t, readFileBytes(t, metadataPath))
	if restored.MetadataMAC != "" {
		t.Fatal("missing MAC was filled in place")
	}
}

// FIND-WIN-012: metadata planted before the first key exists cannot be blessed
// by the freshly generated key.
func TestVaultFreshKeyWithForeignMetadataIsBlocked(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := testLegacyEntry(t, strings.Repeat("b", 31)+"1", "planted body")
	plantedBytes := writeVaultMetadataFixture(t, root, entry)

	vault, openErr := OpenVault(root)
	var integrityErr *VaultMetadataIntegrityError
	if !errors.As(openErr, &integrityErr) {
		t.Fatalf("expected *VaultMetadataIntegrityError, got %v", openErr)
	}
	if vault == nil {
		t.Fatal("fresh vault must stay usable")
	}
	if issues := vault.IntegrityIssues(); len(issues) != 1 || issues[0].ID != entry.ID {
		t.Fatalf("unexpected integrity issues: %+v", issues)
	}
	if after := readFileBytes(t, filepath.Join(root, entry.ID+".json")); !bytes.Equal(after, plantedBytes) {
		t.Fatal("planted metadata was signed with the freshly generated key")
	}
}

// FIND-WIN-012: a crash between signing and protected-key creation must resume
// idempotently without rewriting already signed records.
func TestVaultLegacyCrashResumeIsIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	key := testVaultKey(t, 7)
	writeLegacyVaultKey(t, root, key)
	signedEntry := testLegacyEntry(t, strings.Repeat("c", 31)+"1", "signed body")
	probe := &Vault{root: root, rawKey: key}
	mac, err := probe.metadataMAC(signedEntry)
	if err != nil {
		t.Fatal(err)
	}
	signedEntry.MetadataMAC = mac
	signedBytes := writeVaultMetadataFixture(t, root, signedEntry)
	unsignedEntry := testLegacyEntry(t, strings.Repeat("c", 31)+"2", "unsigned body")
	writeVaultMetadataFixture(t, root, unsignedEntry)

	vault, err := OpenVault(root)
	if err != nil {
		t.Fatalf("crash-resume migration failed: %v", err)
	}
	if issues := vault.IntegrityIssues(); len(issues) != 0 {
		t.Fatalf("crash-resume migration reported issues: %+v", issues)
	}
	if after := readFileBytes(t, filepath.Join(root, signedEntry.ID+".json")); !bytes.Equal(after, signedBytes) {
		t.Fatal("already signed record was rewritten during crash-resume migration")
	}
	unsignedAfter := decodeQuarantineEntry(t, readFileBytes(t, filepath.Join(root, unsignedEntry.ID+".json")))
	if unsignedAfter.MetadataMAC == "" {
		t.Fatal("remaining unsigned legacy record was not migrated")
	}
	if err := vault.verifyMetadataAuthentication(unsignedAfter); err != nil {
		t.Fatalf("resumed migration produced an invalid MAC: %v", err)
	}
}

// FIND-WIN-012: a legacy record with an invalid MAC is reported, not signed.
func TestVaultLegacyInvalidMACIsBlockedNotSigned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quarantine")
	key := testVaultKey(t, 3)
	writeLegacyVaultKey(t, root, key)
	entry := testLegacyEntry(t, strings.Repeat("d", 31)+"1", "tampered legacy body")
	probe := &Vault{root: root, rawKey: testVaultKey(t, 200)}
	mac, err := probe.metadataMAC(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.MetadataMAC = mac
	tamperedBytes := writeVaultMetadataFixture(t, root, entry)

	vault, openErr := OpenVault(root)
	var integrityErr *VaultMetadataIntegrityError
	if !errors.As(openErr, &integrityErr) {
		t.Fatalf("expected *VaultMetadataIntegrityError, got %v", openErr)
	}
	if vault == nil {
		t.Fatal("vault must stay usable after a legacy integrity violation")
	}
	if after := readFileBytes(t, filepath.Join(root, entry.ID+".json")); !bytes.Equal(after, tamperedBytes) {
		t.Fatal("invalid legacy MAC was silently re-signed")
	}
	if _, err := vault.Restore(entry.ID, "Restore muss für tamperte Legacy-Metadaten blockiert sein"); err == nil {
		t.Fatal("restore of a blocked legacy object was accepted")
	}
}
