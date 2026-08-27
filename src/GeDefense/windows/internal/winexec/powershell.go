// STATUS: DIAMANT VGT SUPREME
package winexec

import (
	"errors"
	"os"
	"path/filepath"
)

// PowerShell returns the validated, architecture-native Windows PowerShell path.
func PowerShell() (string, error) {
	return powerShellFromRoot(os.Getenv("SystemRoot"))
}

func powerShellFromRoot(systemRoot string) (string, error) {
	if systemRoot == "" || !filepath.IsAbs(systemRoot) {
		return "", errors.New("SystemRoot is unavailable")
	}
	path := filepath.Join(filepath.Clean(systemRoot), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("Windows PowerShell is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Windows PowerShell path is not a regular file")
	}
	return path, nil
}
