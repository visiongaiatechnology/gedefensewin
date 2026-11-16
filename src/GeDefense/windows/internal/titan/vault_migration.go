// STATUS: PLATIN VGT SUPREME
package titan

// Quarantine metadata migration and integrity verification (FIND-WIN-012).
//
// The historic OpenVault path re-signed every <id>.json it could parse, which
// meant an attacker who edited OriginalPath had that edit blessed with a fresh
// valid HMAC on the next service start. The contract enforced here is:
//
//   - a metadata record that already carries a MAC is verified with a
//     constant-time comparison and is NEVER rewritten,
//   - a missing MAC is only signed in the true first-migration case: a legacy
//     root-level vault.key exists and the protected keys/vault.key does not
//     exist yet,
//   - in every other case a missing or invalid MAC is a fail-closed integrity
//     violation: the record stays untouched, is blocked and is reported,
//   - the protected key is created atomically only after the legacy records
//     were signed, so a crash simply repeats an idempotent migration.

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const maxVaultMetadataFiles = maxQuarantineEntries

// VaultIntegrityIssue is one bounded quarantine metadata integrity finding.
// Detail never contains file content, only the rejected invariant.
type VaultIntegrityIssue struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// VaultMetadataIntegrityError reports metadata records whose authentication
// could not be verified. The vault remains usable for the authenticated
// records; callers must record this error as evidence and must not treat the
// affected objects as restorable.
type VaultMetadataIntegrityError struct {
	Issues []VaultIntegrityIssue
}

func (err *VaultMetadataIntegrityError) Error() string {
	if err == nil || len(err.Issues) == 0 {
		return "titan vault metadata integrity violation"
	}
	return fmt.Sprintf("titan vault metadata integrity violation: %d object(s) blocked, first %s: %s",
		len(err.Issues), err.Issues[0].ID, err.Issues[0].Detail)
}

// vaultKeyState records how the vault key was obtained on this open, which
// decides whether unsigned legacy metadata may be migrated once.
type vaultKeyState struct {
	key                 []byte
	protectedKeyExisted bool
	legacyKeyExisted    bool
	legacyKeyPending    bool
}

func loadVaultKeyState(root string) (vaultKeyState, error) {
	protected := filepath.Join(root, "keys", vaultKeyName)
	legacy := filepath.Join(root, vaultKeyName)
	protectedExists := vaultFileExists(protected)
	legacyExists := vaultFileExists(legacy)
	switch {
	case protectedExists:
		key, err := secretfs.LoadOrCreateRawKey(protected, 32)
		if err != nil {
			return vaultKeyState{}, err
		}
		return vaultKeyState{key: key, protectedKeyExisted: true, legacyKeyExisted: legacyExists}, nil
	case legacyExists:
		// The protected key is deliberately NOT created here. It is created
		// atomically after the legacy metadata migration succeeded, so a crash
		// before that point repeats the idempotent migration instead of treating
		// unsigned records as tampered.
		raw, err := os.ReadFile(legacy)
		if err != nil {
			return vaultKeyState{}, fmt.Errorf("titan legacy vault key is unreadable: %w", err)
		}
		key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(key) != 32 {
			return vaultKeyState{}, errors.New("titan legacy vault key is invalid")
		}
		return vaultKeyState{key: key, legacyKeyExisted: true, legacyKeyPending: true}, nil
	default:
		// Fresh install. Any pre-existing metadata record cannot be authenticated
		// with a key that was just generated and is therefore an integrity
		// violation, never a migration candidate.
		key, err := secretfs.LoadOrCreateRawKey(protected, 32)
		if err != nil {
			return vaultKeyState{}, err
		}
		return vaultKeyState{key: key}, nil
	}
}

func vaultFileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// migrateMetadata verifies every existing metadata record before any write can
// happen. It returns the blocked records and a hard error only for I/O failures
// that leave the vault unsafe to use.
func (v *Vault) migrateMetadata(state vaultKeyState) ([]VaultIntegrityIssue, error) {
	ids, err := v.quarantineMetadataIDs()
	if err != nil {
		return nil, err
	}
	issues := make([]VaultIntegrityIssue, 0, 4)
	for _, id := range ids {
		entry, readErr := v.readMetadataLegacy(id)
		if readErr != nil {
			issues = append(issues, VaultIntegrityIssue{ID: id, Detail: "Metadata ist nicht lesbar oder verletzt Invarianten: " + readErr.Error()})
			continue
		}
		if entry.MetadataMAC != "" {
			if verifyErr := v.verifyMetadataAuthentication(entry); verifyErr != nil {
				// Never re-sign a record whose MAC does not verify.
				issues = append(issues, VaultIntegrityIssue{ID: id, Detail: verifyErr.Error()})
				continue
			}
			// Valid MAC: the record is left byte-for-byte untouched.
			continue
		}
		if !state.legacyKeyPending {
			issues = append(issues, VaultIntegrityIssue{ID: id,
				Detail: "Metadata-Authentifizierung fehlt bei vorhandenem Vault-Schlüssel; keine Neusignatur (fail-closed)."})
			continue
		}
		// True first migration: a validated legacy record is signed exactly once.
		v.metadataAuth = true
		if writeErr := v.writeMetadata(entry); writeErr != nil {
			return nil, writeErr
		}
	}
	if state.legacyKeyPending {
		if err := createProtectedVaultKey(v.root, v.rawKey); err != nil {
			return nil, err
		}
	}
	if state.legacyKeyExisted {
		if err := retireLegacyVaultKey(v.root); err != nil {
			return nil, err
		}
	}
	return issues, nil
}

func (v *Vault) quarantineMetadataIDs() ([]string, error) {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, 32)
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".json")
		if !validQuarantineID(id) {
			continue
		}
		ids = append(ids, id)
		if len(ids) > maxVaultMetadataFiles {
			return nil, errors.New("titan vault metadata count boundary exceeded")
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// createProtectedVaultKey installs keys/vault.key atomically through secretfs
// (temp file, flush, DACL hardening, rename) and verifies the round trip before
// the legacy key may be retired.
func createProtectedVaultKey(root string, key []byte) error {
	protected := filepath.Join(root, "keys", vaultKeyName)
	if vaultFileExists(protected) {
		return errors.New("titan vault key creation collided with an existing protected key")
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(key))
	if err := secretfs.CreateSecretFile(protected, encoded); err != nil {
		return fmt.Errorf("titan vault key creation: %w", err)
	}
	if _, err := secretfs.HardenFile(protected); err != nil {
		return fmt.Errorf("titan vault key hardening: %w", err)
	}
	loaded, err := secretfs.LoadOrCreateRawKey(protected, 32)
	if err != nil {
		return fmt.Errorf("titan vault key verification: %w", err)
	}
	if len(loaded) != len(key) || subtle.ConstantTimeCompare(loaded, key) != 1 {
		return errors.New("titan vault key migration verification failed")
	}
	return nil
}

// retireLegacyVaultKey removes the historic root-level key once the protected
// key is durably in place. If removal is impossible the legacy file is at least
// hardened to the service-only DACL; it is never silently left world-readable.
func retireLegacyVaultKey(root string) error {
	legacy := filepath.Join(root, vaultKeyName)
	if err := os.Remove(legacy); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if _, hardenErr := secretfs.HardenFile(legacy); hardenErr != nil {
			return fmt.Errorf("titan legacy vault key could not be retired or hardened: %w", errors.Join(err, hardenErr))
		}
	}
	return nil
}
