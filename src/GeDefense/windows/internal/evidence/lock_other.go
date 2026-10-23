// STATUS: DIAMANT VGT SUPREME
//go:build !windows

package evidence

import "os"

// acquireWriterLock is a no-op on non-Windows platforms. The shipped product is
// a Windows service (single LocalSystem instance); the Windows implementation
// enforces the single-writer contract with LockFileEx.
func acquireWriterLock(path string) (*os.File, error) {
	return nil, nil
}

func releaseWriterLock(file *os.File) {}
