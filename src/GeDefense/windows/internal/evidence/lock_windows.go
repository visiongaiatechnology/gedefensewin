// STATUS: DIAMANT VGT SUPREME
//go:build windows

package evidence

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockFileFailImmediately = 0x00000001
	lockFileExclusiveLock   = 0x00000002
)

var (
	evidenceKernel32 = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = evidenceKernel32.NewProc("LockFileEx")
	procUnlockFileEx = evidenceKernel32.NewProc("UnlockFileEx")
)

// acquireWriterLock takes an exclusive, process-wide lock on the ledger file.
// The HMAC chain has a single writer contract: two service instances or tools
// appending to the same file would create duplicate sequence numbers and
// invalidate the chain. LockFileEx is released by the kernel even when the
// process crashes.
func acquireWriterLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped syscall.Overlapped
	result, _, _ := procLockFileEx.Call(
		file.Fd(),
		uintptr(lockFileExclusiveLock|lockFileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		return nil, errors.New("evidence ledger is already in use by another writer")
	}
	return file, nil
}

func releaseWriterLock(file *os.File) {
	if file == nil {
		return
	}
	var overlapped syscall.Overlapped
	_, _, _ = procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	_ = file.Close()
}
