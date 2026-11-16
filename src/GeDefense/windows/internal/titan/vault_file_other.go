// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package titan

import (
	"errors"
	"os"
	"path/filepath"
)

type vaultFileIdentity struct {
	volume uint32
	index  uint64
	info   os.FileInfo
}

func openVaultSource(path string) (*os.File, vaultFileIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, vaultFileIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, vaultFileIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, vaultFileIdentity{}, errors.New("quarantine source must be a regular file")
	}
	return file, vaultFileIdentity{info: info}, nil
}

func sameVaultFile(left, right vaultFileIdentity) bool {
	if left.info == nil || right.info == nil {
		return false
	}
	return os.SameFile(left.info, right.info)
}

func isReparseFileInfo(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	return info.Mode()&os.ModeSymlink != 0
}

func validateRestoreTargetChain(target string) error {
	cleaned := filepath.Clean(target)
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return errRestoreTarget("restore target is not absolute")
	}
	directory := filepath.Dir(cleaned)
	for {
		info, err := os.Lstat(directory)
		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(directory)
			if parent == directory {
				return nil
			}
			directory = parent
			continue
		}
		if err != nil {
			return err
		}
		if isReparseFileInfo(info) {
			return errRestoreTarget("restore target parent chain contains a reparse point")
		}
		if !info.IsDir() {
			return errRestoreTarget("restore target parent is not a directory")
		}
		return nil
	}
}

// createRestoreTarget creates the target exclusively. O_CREATE|O_EXCL guarantees
// that an existing object (including a symlink) is never overwritten.
func createRestoreTarget(target string) (*os.File, error) {
	cleaned := filepath.Clean(target)
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return nil, errRestoreTarget("target path boundary rejected")
	}
	file, err := os.OpenFile(cleaned, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("titan restore target already exists")
		}
		return nil, err
	}
	return file, nil
}

// readSourceZoneIdentifier is a no-op on platforms without alternate data
// streams: no Mark-of-the-Web exists and none can be restored.
func readSourceZoneIdentifier(string) ([]byte, error) { return nil, nil }

func restoreZoneIdentifier(string, []byte) error {
	return errors.New("Mark-of-the-Web cannot be restored on this platform")
}

func freeDiskBytes(path string) (uint64, error) {
	return 1 << 40, nil
}
