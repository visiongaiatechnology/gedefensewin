// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	procNtSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess  = ntdll.NewProc("NtResumeProcess")
)

// Suspend calls ntdll!NtSuspendProcess on the open process handle.
// The caller must have opened the process with ProcessSuspendResume and already
// verified creation time and image path against PID reuse.
func (p ProcessIdentity) Suspend() error {
	if p.Handle == 0 {
		return errors.New("process handle is closed")
	}
	status, _, _ := procNtSuspendProcess.Call(uintptr(p.Handle))
	if int32(status) < 0 {
		return fmt.Errorf("NtSuspendProcess failed for pid %d: NTSTATUS 0x%08x", p.PID, uint32(status))
	}
	return nil
}

// Resume calls ntdll!NtResumeProcess on the open process handle.
func (p ProcessIdentity) Resume() error {
	if p.Handle == 0 {
		return errors.New("process handle is closed")
	}
	status, _, _ := procNtResumeProcess.Call(uintptr(p.Handle))
	if int32(status) < 0 {
		return fmt.Errorf("NtResumeProcess failed for pid %d: NTSTATUS 0x%08x", p.PID, uint32(status))
	}
	return nil
}

// ValidateLocalFixedRegularFile enforces path, local fixed-drive, non-ADS, and
// non-reparse invariants using kernel handle verification before an external
// scanner (such as MpCmdRun.exe) inspects the file.
func ValidateLocalFixedRegularFile(path string) (string, error) {
	if len(path) == 0 || len(path) > maxAuthenticodePathBytes || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("file path boundary rejected")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("file path must be absolute")
	}
	clean := filepath.Clean(path)
	if len(clean) >= 3 && strings.IndexByte(clean[2:], ':') >= 0 {
		return "", errors.New("alternate data stream path rejected")
	}
	volume := filepath.VolumeName(clean)
	if len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("local drive path required")
	}
	driveType, err := DriveType(volume + string(filepath.Separator))
	if err != nil || driveType != DriveFixed {
		return "", errors.New("local fixed drive required")
	}
	file, _, err := OpenRegularFileNoReparse(clean)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if err := verifyResolvedFilePath(clean, file); err != nil {
		return "", err
	}
	return clean, nil
}
