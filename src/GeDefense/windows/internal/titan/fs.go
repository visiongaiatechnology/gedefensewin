// STATUS: DIAMANT VGT SUPREME
package titan

import (
	"errors"
	"os"
	"path/filepath"
)

func ensurePrivateDir(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("titan private directory requires an absolute path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("titan private path is not a directory")
	}
	return nil
}

func atomicWriteFile(path string, payload []byte) (err error) {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("titan atomic write requires an absolute path")
	}
	directory := filepath.Dir(path)
	if err := ensurePrivateDir(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".titan-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = replaceFile(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

func moveNoReplace(fromPath, toPath string) error {
	if fromPath == "" || toPath == "" {
		return errors.New("titan move requires both paths")
	}
	return replaceNoOverwrite(fromPath, toPath)
}
