// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
)

const (
	maxQuarantineFileBytes = 64 << 20
	maxQuarantineEntries   = 4096
	vaultDefaultMaxBytes   = 1 << 30
	vaultDiskReserveBytes  = 512 << 20
	vaultKeyName           = "vault.key"
	metadataMACLabel       = "VGT-GEDEFENSE-TITAN-QUARANTINE-METADATA-V1"
)

// Vault is an authenticated-encryption store for isolated objects. It keeps a
// copy of the encrypted object even after restore so the evidence trail stays
// reconstructable. It enforces a hard total quota (entries + bytes) and a disk
// reserve so a local flood of risky files cannot fill the system volume
// (DP-FIND-006). Metadata is authenticated with a key derived from the vault key
// so a restore target cannot be rewritten by tampering with <id>.json
// (DP-FIND-015).
type Vault struct {
	mu           sync.Mutex
	root         string
	aed          cipher.AEAD
	rawKey       []byte
	maxEntries   int
	maxBytes     int64
	diskReserve  uint64
	metadataAuth bool
	usageEntries int
	usageBytes   int64
}

type restoreTargetError struct{ detail string }

func (e *restoreTargetError) Error() string { return "titan restore target rejected: " + e.detail }

func errRestoreTarget(detail string) error { return &restoreTargetError{detail: detail} }

func OpenVault(root string) (*Vault, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("titan vault root must be absolute")
	}
	if err := ensurePrivateDir(root); err != nil {
		return nil, err
	}
	key, err := loadOrCreateVaultKey(root)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	vault := &Vault{
		root: root, aed: aed, rawKey: key,
		maxEntries: maxQuarantineEntries, maxBytes: vaultDefaultMaxBytes, diskReserve: vaultDiskReserveBytes,
	}
	if err := vault.migrateMetadata(); err != nil {
		return nil, err
	}
	vault.metadataAuth = true
	vault.recoverOriginalState()
	if err := vault.recountUsageLocked(); err != nil {
		return nil, err
	}
	return vault, nil
}

// loadOrCreateVaultKey stores the AES key in a dedicated keys/ subdirectory with
// a SYSTEM/Administrators-only DACL (DP-FIND-001) and migrates the historic
// root-level vault.key once.
func loadOrCreateVaultKey(root string) ([]byte, error) {
	protected := filepath.Join(root, "keys", vaultKeyName)
	legacy := filepath.Join(root, vaultKeyName)
	if _, err := os.Lstat(protected); errors.Is(err, os.ErrNotExist) {
		if raw, legacyErr := os.ReadFile(legacy); legacyErr == nil {
			key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
			if decodeErr != nil || len(key) != 32 {
				return nil, errors.New("titan vault key is invalid")
			}
			if err := secretfs.CreateSecretFile(protected, []byte(base64.RawStdEncoding.EncodeToString(key))); err != nil {
				return nil, err
			}
			_ = os.Remove(legacy)
			if _, err := secretfs.HardenFile(protected); err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	return secretfs.LoadOrCreateRawKey(protected, 32)
}

// migrateMetadata upgrades legacy unauthenticated metadata files in place. It
// validates every legacy record before signing it; unreadable files are left
// untouched so readMetadata rejects them fail-closed afterwards.
func (v *Vault) migrateMetadata() error {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return err
	}
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".json")
		if !validQuarantineID(id) {
			continue
		}
		entry, readErr := v.readMetadataLegacy(id)
		if readErr != nil {
			continue
		}
		v.metadataAuth = true
		if writeErr := v.writeMetadata(entry); writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// recoverOriginalState repairs the crash window between removing the original
// file and persisting OriginalGone=true (DP-FIND-015 recovery gap).
func (v *Vault) recoverOriginalState() {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return
	}
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".json")
		if !validQuarantineID(id) {
			continue
		}
		entry, readErr := v.readMetadata(id)
		if readErr != nil || entry.OriginalGone || entry.State == "RESTORED" {
			continue
		}
		if _, statErr := os.Lstat(entry.OriginalPath); errors.Is(statErr, os.ErrNotExist) {
			entry.OriginalGone = true
			_ = v.writeMetadata(entry)
		}
	}
}

func (v *Vault) recountUsageLocked() error {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return err
	}
	count := 0
	var total int64
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".json")
		if !validQuarantineID(id) {
			continue
		}
		entry, readErr := v.readMetadata(id)
		if readErr != nil {
			continue
		}
		count++
		total += entry.Size
	}
	v.usageEntries = count
	v.usageBytes = total
	return nil
}

func (v *Vault) metadataMAC(entry QuarantineEntry) (string, error) {
	entry.MetadataMAC = ""
	raw, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	derived := hmac.New(sha256.New, v.rawKey)
	_, _ = derived.Write([]byte(metadataMACLabel))
	mac := hmac.New(sha256.New, derived.Sum(nil))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Add encrypts and isolates a regular file. The original is removed only after
// the encrypted copy and its metadata have both been durably written. If the
// removal fails, OriginalGone=false is exposed instead of pretending success.
func (v *Vault) Add(source, reason, eventID string) (QuarantineEntry, error) {
	return v.add(source, reason, eventID, "")
}

// AddExpected binds containment to the hash observed in the triggering event.
// A file substituted between observation and action is rejected before it can
// be encrypted or removed.
func (v *Vault) AddExpected(source, reason, eventID, expectedSHA256 string) (QuarantineEntry, error) {
	return v.add(source, reason, eventID, expectedSHA256)
}

func (v *Vault) add(source, reason, eventID, expectedSHA256 string) (QuarantineEntry, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return QuarantineEntry{}, errors.New("titan quarantine reason boundary rejected")
	}
	source = filepath.Clean(source)
	if !filepath.IsAbs(source) || len(source) > 260 {
		return QuarantineEntry{}, errors.New("titan quarantine source path rejected")
	}
	// Open through the reparse-safe primitive and bind all subsequent operations
	// to this handle identity instead of re-checking the path (DP-FIND-007).
	file, identity, err := openVaultSource(source)
	if err != nil {
		return QuarantineEntry{}, err
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return QuarantineEntry{}, statErr
	}
	if info.Size() < 0 || info.Size() > maxQuarantineFileBytes {
		_ = file.Close()
		return QuarantineEntry{}, errors.New("titan quarantine file size boundary rejected")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxQuarantineFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return QuarantineEntry{}, readErr
	}
	if closeErr != nil {
		return QuarantineEntry{}, closeErr
	}
	if len(payload) > maxQuarantineFileBytes {
		return QuarantineEntry{}, errors.New("titan quarantine file grew beyond the size boundary")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	if expectedSHA256 != "" && !strings.EqualFold(hash, expectedSHA256) {
		return QuarantineEntry{}, errors.New("titan quarantine hash does not match the observed event")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.usageEntries >= v.maxEntries {
		return QuarantineEntry{}, errors.New("titan quarantine entry quota exceeded; review or prune the vault before containment can continue")
	}
	if v.usageBytes+int64(len(payload)) > v.maxBytes {
		return QuarantineEntry{}, errors.New("titan quarantine byte quota exceeded; review or prune the vault before containment can continue")
	}
	if v.diskReserve > 0 {
		free, freeErr := freeDiskBytes(v.root)
		if freeErr != nil {
			return QuarantineEntry{}, freeErr
		}
		if free < uint64(len(payload))+v.diskReserve {
			return QuarantineEntry{}, errors.New("titan quarantine disk reserve would be exhausted; containment refused")
		}
	}
	idRandom := make([]byte, 16)
	if _, err := rand.Read(idRandom); err != nil {
		return QuarantineEntry{}, err
	}
	id := hex.EncodeToString(idRandom)
	entry := QuarantineEntry{
		ID: id, CreatedUTC: time.Now().UTC(), OriginalPath: source, OriginalName: filepath.Base(source),
		SHA256: hash, Size: int64(len(payload)), FileType: classifyFile(source), EventID: eventID,
		Reason: reason, State: "QUARANTINED",
	}
	encrypted, err := v.encrypt(id, payload)
	if err != nil {
		return QuarantineEntry{}, err
	}
	if err := atomicWriteFile(v.objectPath(id), encrypted); err != nil {
		return QuarantineEntry{}, err
	}
	if err := v.writeMetadata(entry); err != nil {
		_ = os.Remove(v.objectPath(id))
		return QuarantineEntry{}, err
	}
	// Re-open the path and compare the file identity before deleting. The
	// encrypted copy is already durable, so a mismatch aborts containment and
	// reports the substitution instead of deleting the wrong object.
	current, currentIdentity, currentErr := openVaultSource(source)
	if currentErr != nil {
		_ = os.Remove(v.objectPath(id))
		_ = os.Remove(v.metadataPath(id))
		return QuarantineEntry{}, errors.New("titan quarantine source changed before isolation: " + currentErr.Error())
	}
	_ = current.Close()
	if !sameVaultFile(identity, currentIdentity) {
		_ = os.Remove(v.objectPath(id))
		_ = os.Remove(v.metadataPath(id))
		return QuarantineEntry{}, errors.New("titan quarantine source was substituted before isolation")
	}
	if err := os.Remove(source); err == nil {
		entry.OriginalGone = true
		if err := v.writeMetadata(entry); err != nil {
			return entry, err
		}
	} else {
		entry.OriginalGone = false
	}
	v.usageEntries++
	v.usageBytes += entry.Size
	return entry, nil
}

func (v *Vault) List() []QuarantineEntry {
	v.mu.Lock()
	defer v.mu.Unlock()
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return []QuarantineEntry{}
	}
	result := make([]QuarantineEntry, 0, 32)
	count := 0
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		count++
		if count > maxQuarantineEntries {
			break
		}
		entry, err := v.readMetadata(strings.TrimSuffix(item.Name(), ".json"))
		if err != nil {
			continue
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].CreatedUTC.After(result[right].CreatedUTC)
	})
	return result
}

// Usage reports the true vault usage (not capped by the display window).
func (v *Vault) Usage() (entries int, bytes int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.usageEntries, v.usageBytes
}

// Limits publishes the enforced quota envelope.
func (v *Vault) Limits() (maxEntries int, maxBytes int64, diskReserve uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.maxEntries, v.maxBytes, v.diskReserve
}

func (v *Vault) Bytes() int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.usageBytes
}

func (v *Vault) Review(id, note string) (QuarantineEntry, error) {
	note = strings.TrimSpace(note)
	if len(note) < 8 || len(note) > 512 {
		return QuarantineEntry{}, errors.New("titan review reason boundary rejected")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, err := v.readMetadata(id)
	if err != nil {
		return QuarantineEntry{}, err
	}
	entry.Reviewed = true
	entry.ReviewNote = note
	if err := v.writeMetadata(entry); err != nil {
		return QuarantineEntry{}, err
	}
	return entry, nil
}

func (v *Vault) Restore(id, reason string) (QuarantineEntry, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 {
		return QuarantineEntry{}, errors.New("titan restore reason boundary rejected")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, err := v.readMetadata(id)
	if err != nil {
		return QuarantineEntry{}, err
	}
	if entry.State == "RESTORED" {
		return QuarantineEntry{}, errors.New("titan object was already restored")
	}
	if !entry.OriginalGone {
		return QuarantineEntry{}, errors.New("titan object was never removed from its original path")
	}
	target := filepath.Clean(entry.OriginalPath)
	if !filepath.IsAbs(target) || len(target) > 260 {
		return QuarantineEntry{}, errRestoreTarget("target path boundary rejected")
	}
	// The restore target comes from authenticated metadata; additionally require
	// that no parent component is a reparse point so an attacker cannot redirect
	// the write through a swapped junction (DP-FIND-015).
	if err := validateRestoreTargetChain(target); err != nil {
		return QuarantineEntry{}, err
	}
	if _, err := os.Lstat(target); err == nil {
		return QuarantineEntry{}, errors.New("titan restore target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return QuarantineEntry{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return QuarantineEntry{}, err
	}
	objectFile, _, openErr := openVaultSource(v.objectPath(id))
	if openErr != nil {
		return QuarantineEntry{}, openErr
	}
	encrypted, readErr := io.ReadAll(io.LimitReader(objectFile, maxQuarantineFileBytes+int64(v.aed.NonceSize())+16+1))
	closeErr := objectFile.Close()
	if readErr != nil {
		return QuarantineEntry{}, readErr
	}
	if closeErr != nil {
		return QuarantineEntry{}, closeErr
	}
	payload, err := v.decrypt(id, encrypted)
	if err != nil {
		return QuarantineEntry{}, err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != entry.SHA256 {
		return QuarantineEntry{}, errors.New("titan restore hash verification failed")
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".titan-restore-*.tmp")
	if err != nil {
		return QuarantineEntry{}, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return QuarantineEntry{}, err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return QuarantineEntry{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return QuarantineEntry{}, err
	}
	if err := temporary.Close(); err != nil {
		return QuarantineEntry{}, err
	}
	if _, err := os.Lstat(target); err == nil {
		return QuarantineEntry{}, errors.New("titan restore target appeared during restore")
	} else if !errors.Is(err, os.ErrNotExist) {
		return QuarantineEntry{}, err
	}
	if err := moveNoReplace(temporaryPath, target); err != nil {
		return QuarantineEntry{}, err
	}
	entry.State = "RESTORED"
	entry.RestoredUTC = time.Now().UTC()
	entry.RestoreReason = reason
	if err := v.writeMetadata(entry); err != nil {
		return QuarantineEntry{}, err
	}
	return entry, nil
}

// PruneRestoredOlderThan removes retained encrypted copies and metadata of
// objects that were restored longer than the owner-approved retention period
// ago. It is the explicit retention hook required by DP-FIND-006; it is never
// invoked automatically because deleting evidence is an owner decision.
func (v *Vault) PruneRestoredOlderThan(age time.Duration) (int, error) {
	if age <= 0 {
		return 0, errors.New("titan quarantine retention period rejected")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().UTC().Add(-age)
	removed := 0
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".json")
		if !validQuarantineID(id) {
			continue
		}
		entry, readErr := v.readMetadata(id)
		if readErr != nil || entry.State != "RESTORED" || entry.RestoredUTC.IsZero() || entry.RestoredUTC.After(cutoff) {
			continue
		}
		if err := os.Remove(v.objectPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		if err := os.Remove(v.metadataPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		if entry.Size > 0 && v.usageBytes >= entry.Size {
			v.usageBytes -= entry.Size
		}
		if v.usageEntries > 0 {
			v.usageEntries--
		}
		removed++
	}
	return removed, nil
}

func (v *Vault) decrypt(id string, encrypted []byte) ([]byte, error) {
	nonceSize := v.aed.NonceSize()
	if len(encrypted) < nonceSize+16 {
		return nil, errors.New("titan quarantine object is truncated")
	}
	nonce := encrypted[:nonceSize]
	payload, err := v.aed.Open(nil, nonce, encrypted[nonceSize:], []byte(id))
	if err != nil {
		return nil, errors.New("titan quarantine authentication failed")
	}
	return payload, nil
}

func (v *Vault) encrypt(id string, payload []byte) ([]byte, error) {
	nonce := make([]byte, v.aed.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return v.aed.Seal(nonce, nonce, payload, []byte(id)), nil
}

func (v *Vault) objectPath(id string) string   { return filepath.Join(v.root, id+".bin") }
func (v *Vault) metadataPath(id string) string { return filepath.Join(v.root, id+".json") }

func (v *Vault) writeMetadata(entry QuarantineEntry) error {
	if v.metadataAuth {
		mac, err := v.metadataMAC(entry)
		if err != nil {
			return err
		}
		entry.MetadataMAC = mac
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return atomicWriteFile(v.metadataPath(entry.ID), append(raw, '\n'))
}

func (v *Vault) readMetadata(id string) (QuarantineEntry, error) {
	entry, err := v.readMetadataLegacy(id)
	if err != nil {
		return QuarantineEntry{}, err
	}
	if !v.metadataAuth {
		return entry, nil
	}
	if entry.MetadataMAC == "" {
		return QuarantineEntry{}, errors.New("titan quarantine metadata authentication is missing")
	}
	expected, err := v.metadataMAC(entry)
	if err != nil {
		return QuarantineEntry{}, err
	}
	provided, providedErr := hex.DecodeString(entry.MetadataMAC)
	expectedBytes, expectedErr := hex.DecodeString(expected)
	if providedErr != nil || expectedErr != nil || len(provided) != sha256.Size || !hmac.Equal(provided, expectedBytes) {
		return QuarantineEntry{}, errors.New("titan quarantine metadata authentication failed")
	}
	return entry, nil
}

func (v *Vault) readMetadataLegacy(id string) (QuarantineEntry, error) {
	if !validQuarantineID(id) {
		return QuarantineEntry{}, errors.New("titan quarantine id rejected")
	}
	raw, err := os.ReadFile(v.metadataPath(id))
	if err != nil {
		return QuarantineEntry{}, err
	}
	if len(raw) == 0 || len(raw) > 32<<10 {
		return QuarantineEntry{}, errors.New("titan quarantine metadata size rejected")
	}
	var entry QuarantineEntry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return QuarantineEntry{}, fmt.Errorf("titan quarantine metadata validation: %w", err)
	}
	if entry.ID != id || !validSHA256(entry.SHA256) || entry.OriginalPath == "" || entry.Size < 0 || entry.Size > maxQuarantineFileBytes {
		return QuarantineEntry{}, errors.New("titan quarantine metadata invariant rejected")
	}
	return entry, nil
}

func validQuarantineID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, char := range id {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}
