// STATUS: DIAMANT VGT SUPREME
//go:build windows

package settings

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// atomicWrite commits payload through a 0600 temporary file in the target
// directory and an atomic MoveFileEx replace. A crash can therefore leave
// either the previous document or the complete next document, never a partial
// JSON state.
func atomicWrite(path string, payload []byte) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".vgt-settings-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer cleanup.RemoveInto(&err, temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	err = errors.Join(err, temporary.Close())
	if err != nil {
		return err
	}
	return winapi.MoveFileReplace(temporaryPath, path)
}
