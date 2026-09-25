// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// KillProcessTree terminates a process and all of its descendants on Windows.
func KillProcessTree(pid int) error {
	if pid <= 0 {
		return errors.New("invalid process ID")
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" || !filepath.IsAbs(systemRoot) {
		systemRoot = `C:\Windows`
	}
	taskkill := filepath.Join(filepath.Clean(systemRoot), "System32", "taskkill.exe")
	info, err := os.Lstat(taskkill)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("taskkill is unavailable")
	}
	cmd := exec.Command(taskkill, "/F", "/T", "/PID", strconv.Itoa(pid))
	return cmd.Run()
}
