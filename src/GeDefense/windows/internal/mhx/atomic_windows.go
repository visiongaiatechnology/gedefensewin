// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"os"
	"path/filepath"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

func atomicWrite(path string, payload []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".mhx-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return winapi.MoveFileReplace(temporaryPath, path)
}
