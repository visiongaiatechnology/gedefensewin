// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Shared Win32 adapters. The package deliberately does not import the project's
// internal/winapi helper: the isolation primitives must be self-contained and
// reviewable in one place, so every DLL entry point used by parser cells is
// declared here or next to the feature that needs it.

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	userenv  = syscall.NewLazyDLL("userenv.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procLocalFree         = kernel32.NewProc("LocalFree")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")

	procConvertSidToStringSidW = advapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSidToSidW = advapi32.NewProc("ConvertStringSidToSidW")
	procFreeSid                = advapi32.NewProc("FreeSid")
)

// Windows error codes used for precise, non-fatal classification.
const (
	errorInsufficientBuffer syscall.Errno = 122
	errorInvalidParameter   syscall.Errno = 87
	errorAccessDenied       syscall.Errno = 5
	errorAlreadyExists      syscall.Errno = 183
	errorFileNotFound       syscall.Errno = 2
	errorPathNotFound       syscall.Errno = 3
	errorNotSupported       syscall.Errno = 50
	errorInvalidHandle      syscall.Errno = 6
)

// Common HRESULT values returned by the userenv AppContainer API.
const (
	hresultAlreadyExists = 0x800700B7 // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
	hresultNotFound      = 0x80070490 // HRESULT_FROM_WIN32(ERROR_NOT_FOUND)
	hresultFileNotFound  = 0x80070002 // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
	hresultAccessDenied  = 0x80070005 // HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)
)

// closeHandle closes a kernel handle and tolerates an already closed handle.
func closeHandle(handle syscall.Handle) error {
	if handle == 0 || handle == syscall.InvalidHandle {
		return nil
	}
	result, _, callErr := procCloseHandle.Call(uintptr(handle))
	if result == 0 {
		if err := errnoOrNil(callErr); err != nil {
			return fmt.Errorf("CloseHandle: %w", err)
		}
		return errors.New("CloseHandle failed")
	}
	return nil
}

// errnoOrNil normalizes the stale last-error value that successful Win32 calls
// leave behind. It returns nil for a zero errno.
func errnoOrNil(err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == 0 {
		return nil
	}
	return err
}

// checkBOOL converts a BOOL result plus the stale last-error into an error.
func checkBOOL(operation string, result uintptr, callErr error) error {
	if result != 0 {
		return nil
	}
	if err := errnoOrNil(callErr); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s failed", operation)
}

// hresultError converts a signed HRESULT into an error, optionally mapping the
// documented AppContainer codes onto package sentinels.
func hresultError(operation string, hresult uintptr) error {
	code := uint32(hresult)
	if int32(code) >= 0 {
		return nil
	}
	switch code {
	case hresultAlreadyExists:
		return fmt.Errorf("%s: %w (HRESULT 0x%08X)", operation, ErrContainerExists, code)
	case hresultNotFound, hresultFileNotFound:
		return fmt.Errorf("%s: %w (HRESULT 0x%08X)", operation, ErrContainerNotFound, code)
	case hresultAccessDenied:
		return fmt.Errorf("%s: access denied (HRESULT 0x%08X): %w", operation, code, errorAccessDenied)
	default:
		return fmt.Errorf("%s failed (HRESULT 0x%08X)", operation, code)
	}
}

// utf16Ptr converts a Go string to a NUL terminated UTF-16 pointer, rejecting
// embedded NUL bytes.
func utf16Ptr(value string) (*uint16, error) {
	for index := 0; index < len(value); index++ {
		if value[index] == 0 {
			return nil, errors.New("NUL byte rejected")
		}
	}
	return syscall.UTF16PtrFromString(value)
}

// utf16String reads a NUL terminated UTF-16 string from a Win32 pointer. The
// caller guarantees a bounded string (SIDs and fixed names only).
func utf16String(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	// 256 UTF-16 code units is far above the SID string ceiling and keeps the
	// slice construction bounded even if the pointer is malformed.
	return syscall.UTF16ToString(unsafe.Slice(pointer, 256))
}

// sidToString converts a PSID to its canonical S-1-... string form. The caller
// keeps ownership of the SID unless it was allocated by a conversion helper.
func sidToString(sid uintptr) (string, error) {
	if sid == 0 {
		return "", errors.New("nil SID")
	}
	var text *uint16
	result, _, callErr := procConvertSidToStringSidW.Call(sid, uintptr(unsafe.Pointer(&text)))
	if result == 0 {
		if err := errnoOrNil(callErr); err != nil {
			return "", fmt.Errorf("ConvertSidToStringSidW: %w", err)
		}
		return "", errors.New("ConvertSidToStringSidW failed")
	}
	defer func() { _, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(text))) }()
	value := utf16String(text)
	if len(value) == 0 || len(value) > 256 {
		return "", errors.New("SID string out of bounds")
	}
	return value, nil
}

// sidFromString allocates a PSID from its S-1-... string form. The caller must
// release it with freeSID.
func sidFromString(value string) (uintptr, error) {
	if value == "" || len(value) > 256 {
		return 0, errors.New("SID string out of bounds")
	}
	pointer, err := utf16Ptr(value)
	if err != nil {
		return 0, err
	}
	var sid uintptr
	result, _, callErr := procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&sid)))
	if result == 0 {
		if err := errnoOrNil(callErr); err != nil {
			return 0, fmt.Errorf("ConvertStringSidToSidW: %w", err)
		}
		return 0, errors.New("ConvertStringSidToSidW failed")
	}
	if sid == 0 {
		return 0, errors.New("ConvertStringSidToSidW returned nil SID")
	}
	return sid, nil
}

// freeSID releases a SID allocated by the userenv or advapi32 conversion
// helpers.
func freeSID(sid uintptr) {
	if sid != 0 {
		_, _, _ = procFreeSid.Call(sid)
	}
}
