// STATUS: PLATIN
//go:build windows

package winapi

import (
	"fmt"
	"log"
)

// CheckBOOL consults GetLastError only after an API reports failure. Successful
// Win32 calls may leave a stale last-error value, which is not an operation error.
func CheckBOOL(operation string, result uintptr, callErr error) error {
	if result != 0 {
		return nil
	}
	if err := errnoResult(callErr); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s failed", operation)
}

// CheckHRESULT checks the signed HRESULT itself, not the thread's last error.
func CheckHRESULT(operation string, result uintptr) error {
	if int32(result) < 0 {
		return fmt.Errorf("%s failed (HRESULT 0x%08x)", operation, uint32(result))
	}
	return nil
}

// ReportError records best-effort UI/cleanup failures where a callback cannot
// return an error. Callers return errors directly for correctness-critical work.
func ReportError(operation string, err error) {
	if err != nil {
		log.Printf("%s: %v", operation, err)
	}
}
