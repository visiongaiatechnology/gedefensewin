// STATUS: DIAMANT VGT SUPREME
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// TokenLength is the length of a base64url encoded 256-bit control-plane
// credential. It is enforced on load, on rotation and by every HTTP wrapper.
const TokenLength = 43

var (
	errTokenPathRelative = errors.New("token path must be absolute")
	errStoredToken       = errors.New("stored dashboard token is invalid")
)

// LoadOrCreateToken loads the control-plane credential from path or creates a
// new 256-bit credential when the file does not exist yet. The file is created
// atomically with an exclusive create; concurrent creators reload the winner.
func LoadOrCreateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errTokenPathRelative
	}
	if token, err := ReadToken(path); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateToken(path)
	}
	if err != nil {
		return "", err
	}
	_, writeErr := file.Write([]byte(token + "\n"))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return "", writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", closeErr
	}
	return token, nil
}

// ReadToken loads and validates an existing control-plane credential. A token
// must be exactly TokenLength base64url characters decoding to 32 bytes.
func ReadToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errTokenPathRelative
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if !ValidToken(token) {
		return "", errStoredToken
	}
	return token, nil
}

// RotateToken atomically replaces the credential file with a freshly generated
// 256-bit credential and returns the new token. The replacement happens via a
// temp file in the same directory plus rename, so a crash cannot leave a
// partial credential and the NTFS ACL inheritance of the directory is kept.
// The returned token is NOT persisted anywhere else; callers must update their
// in-memory authority and revoke every session that was authorized by the old
// credential.
func RotateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errTokenPathRelative
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	file, err := os.CreateTemp(directory, ".dashboard.token-*")
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", err
	}
	if _, err := file.Write([]byte(token + "\n")); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", err
	}
	cleanup = false
	return token, nil
}

// ValidToken reports whether value is a well-formed 256-bit control-plane
// credential. It never compares secrets; use TokenEqual for that.
func ValidToken(value string) bool {
	if len(value) != TokenLength {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// TokenEqual compares two credentials in constant time. Empty values and
// length mismatches never compare equal.
func TokenEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
