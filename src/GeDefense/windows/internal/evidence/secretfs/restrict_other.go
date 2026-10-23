// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package secretfs

import (
	"errors"
	"os"
)

// canManageServiceDACL on POSIX systems means: are we able to set 0600/0700
// permission bits, which is the platform's access-control mechanism.
func canManageServiceDACL() (bool, error) {
	return true, nil
}

func restrictPath(path string, directory bool) (Restriction, error) {
	restriction := Restriction{Path: path, Enforced: true}
	mode := os.FileMode(secretFileMode)
	if directory {
		mode = secretDirMode
	}
	if err := os.Chmod(path, mode); err != nil {
		restriction.Detail = err.Error()
		return restriction, err
	}
	info, err := os.Stat(path)
	if err != nil {
		restriction.Detail = err.Error()
		return restriction, err
	}
	if info.IsDir() != directory {
		restriction.Detail = "secret path type mismatch"
		return restriction, errors.New("secret path type mismatch")
	}
	if info.Mode().Perm()&0o077 != 0 {
		restriction.Detail = "secret permissions are not private"
		return restriction, errors.New("secret permissions are not private")
	}
	restriction.Restricted = true
	restriction.Detail = "private POSIX permission bits applied"
	return restriction, nil
}

func replaceFile(temporaryPath, path string) error {
	return os.Rename(temporaryPath, path)
}
