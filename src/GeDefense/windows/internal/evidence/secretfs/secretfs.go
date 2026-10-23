// STATUS: DIAMANT VGT SUPREME
//
// Package secretfs owns creation, storage and access-control hardening of
// service-local secret material (evidence HMAC keys, Titan Ed25519 signing
// seeds, quarantine AES keys, feed authority keys).
//
// Security contract (DP-FIND-001 / VGT-022 / VGT-049):
//
//   - Mode bits are not an access-control mechanism on Windows. Every key file
//     is therefore created through this package and receives an explicit,
//     inheritance-protected DACL granting full access only to LocalSystem
//     (S-1-5-18) and Builtin Administrators (S-1-5-32-544).
//   - The restrictive DACL is applied and then *verified* by reading the
//     effective DACL back from the filesystem. A file that still grants access
//     to any other principal (for example the inherited operator-group RX ACE
//     from the installer's data-root grant) is rejected fail-closed.
//   - Hardening is performed when the process runs with service privileges
//     (LocalSystem/Administrator token). A non-privileged developer process
//     cannot manage an administrator-only DACL without locking itself out, so
//     it falls back to mode bits and reports Enforced=false. The installed
//     service runs as LocalSystem (installer `obj= LocalSystem`), so production
//     always executes the hardened path.
//
// Installer coordination note (no installer edit is required for this fix, and
// none was made): the installer keeps granting the operator group (OI)(CI)RX on
// %ProgramData%\VGT\GeDefense. Key files created by this package carry their own
// protected DACL, so that inherited grant no longer exposes key material. As
// defense-in-depth the installer should in a future release grant the operator
// group RX only on non-secret subdirectories (evidence/*.jsonl,
// quarantine/*.json metadata) and treat every `keys/` directory as
// SYSTEM/Administrators-only.
package secretfs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	secretFileMode = 0o600
	secretDirMode  = 0o700
)

// Restriction reports the effective protection state of a secret path.
type Restriction struct {
	Path       string
	Restricted bool
	Enforced   bool
	Detail     string
}

// EnsureSecretDir creates a directory for secret material and, when the process
// identity can manage a service-only DACL, restricts it to LocalSystem and
// Builtin Administrators.
func EnsureSecretDir(dir string) (Restriction, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return Restriction{}, errors.New("secret directory requires an absolute path")
	}
	cleaned := filepath.Clean(dir)
	if err := os.MkdirAll(cleaned, secretDirMode); err != nil {
		return Restriction{}, err
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return Restriction{}, err
	}
	if !info.IsDir() {
		return Restriction{}, errors.New("secret path is not a directory")
	}
	return restrictPath(cleaned, true)
}

// HardenFile applies and verifies the restrictive DACL on an existing secret
// file. Existing installations that already contain key files with inherited
// operator-group read access are repaired on the next service start.
func HardenFile(path string) (Restriction, error) {
	if path == "" || !filepath.IsAbs(path) {
		return Restriction{}, errors.New("secret file requires an absolute path")
	}
	cleaned := filepath.Clean(path)
	info, err := os.Lstat(cleaned)
	if err != nil {
		return Restriction{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Restriction{}, errors.New("secret path must be a regular non-reparse file")
	}
	return restrictPath(cleaned, false)
}

// LoadOrCreateRawKey loads a base64 (raw std encoding) key of size bytes. When
// the key does not exist it is created with an inheritance-protected DACL.
func LoadOrCreateRawKey(path string, size int) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("secret key requires an absolute path")
	}
	if size <= 0 || size > 4096 {
		return nil, errors.New("secret key size rejected")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(key) != size {
			return nil, errors.New("secret key is invalid")
		}
		if _, hardenErr := HardenFile(path); hardenErr != nil {
			return nil, hardenErr
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := []byte(base64.RawStdEncoding.EncodeToString(key))
	if err := createSecretFile(path, encoded); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadOrCreateEd25519Seed loads or creates a raw Ed25519 seed and returns the
// derived private/public key together with the SHA-256 fingerprint of the
// public key.
func LoadOrCreateEd25519Seed(path string) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	seed, err := LoadOrCreateRawKey(path, ed25519.SeedSize)
	if err != nil {
		return nil, nil, "", err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(publicKey)
	return privateKey, publicKey, hex.EncodeToString(fingerprint[:]), nil
}

// CreateSecretFile writes a new secret file atomically-replaceably: the new
// content is written to a sibling temporary file, hardened and only then renamed
// onto the target. Used for key rollover and authenticated state anchors.
func CreateSecretFile(path string, payload []byte) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("secret file requires an absolute path")
	}
	directory := filepath.Dir(path)
	if _, err := EnsureSecretDir(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".secretfs-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := temporary.Chmod(secretFileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if _, err := HardenFile(temporaryPath); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

func createSecretFile(path string, payload []byte) error {
	directory := filepath.Dir(path)
	if _, err := EnsureSecretDir(directory); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, secretFileMode)
	if err != nil {
		return err
	}
	writeErr := func() error {
		if _, err := file.Write(payload); err != nil {
			return err
		}
		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	if _, err := HardenFile(path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("secret file access control: %w", err)
	}
	return nil
}
