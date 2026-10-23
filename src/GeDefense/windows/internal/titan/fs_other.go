// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package titan

import "os"

func replaceFile(temporaryPath, path string) error {
	return os.Rename(temporaryPath, path)
}

func replaceNoOverwrite(fromPath, toPath string) error {
	if _, err := os.Lstat(toPath); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(fromPath, toPath)
}
