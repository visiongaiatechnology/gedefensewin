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

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence/secretfs"
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
// exclusively through the hardened secret-file store: the SYSTEM/Administrators
// DACL is applied to the still empty file before the first credential byte is
// written (FIND-WIN-019). Concurrent creators reload the winner.
func LoadOrCreateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errTokenPathRelative
	}
	if token, err := ReadToken(path); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	if err := secretfs.CreateSecretFileExclusive(path, []byte(token+"\n")); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreateToken(path)
		}
		return "", err
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
// 256-bit credential and returns the new token. The replacement is performed by
// the hardened secret-file store: the restrictive SYSTEM/Administrators DACL is
// applied to the sibling temporary file while it is still empty, the secret is
// written only afterwards and the ready file is renamed onto the target, so a
// crash can never leave a partial credential and the replaced file can never
// keep a wider inherited DACL. The returned token is NOT persisted anywhere
// else; callers must update their in-memory authority and revoke every session
// that was authorized by the old credential.
func RotateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errTokenPathRelative
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	if err := secretfs.CreateSecretFile(path, []byte(token+"\n")); err != nil {
		return "", err
	}
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
