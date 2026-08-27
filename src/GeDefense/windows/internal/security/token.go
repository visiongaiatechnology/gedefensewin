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

func LoadOrCreateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("token path must be absolute")
	}
	if raw, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(raw))
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
		if decodeErr != nil || len(decoded) != 32 {
			return "", errors.New("stored dashboard token is invalid")
		}
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
	temporary := path + ".new"
	if err := os.WriteFile(temporary, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return token, nil
}

func TokenEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
