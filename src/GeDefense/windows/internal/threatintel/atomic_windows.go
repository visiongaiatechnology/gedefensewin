// STATUS: DIAMANT VGT SUPREME
//go:build windows

package threatintel

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func atomicWrite(path string, payload []byte) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".vgt-ti-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer cleanup.RemoveInto(&err, temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
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
