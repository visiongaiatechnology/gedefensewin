// STATUS: DIAMANT VGT SUPREME
//go:build windows

package parsercells

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Handle-based I/O adapter. A cell never receives a writable directory: it gets
// one inherited read handle for the staged input and one inherited anonymous
// pipe handle for its merged stdout/stderr. Output is drained concurrently with
// execution and capped at the profile ceiling; exceeding the cap truncates the
// run and the caller burns the cell.

const (
	// genericRead is GENERIC_READ.
	genericRead uint32 = 0x80000000
	// fileShareRead and fileShareDelete are the only shares for staged input.
	fileShareRead   uint32 = 0x00000001
	fileShareDelete uint32 = 0x00000004
	// openExisting is OPEN_EXISTING.
	openExisting uint32 = 3
	// fileFlagSequentialScan hints one-pass reads.
	fileFlagSequentialScan uint32 = 0x08000000
	// handleFlagInherit is HANDLE_FLAG_INHERIT.
	handleFlagInherit uint32 = 0x00000001
	// errorBrokenPipe and errorNoData are the pipe EOF codes.
	errorBrokenPipe syscall.Errno = 109
	errorNoData     syscall.Errno = 232
	// drainChunkBytes bounds one pipe read.
	drainChunkBytes int64 = 64 << 10
)

var (
	procCreatePipe           = kernel32.NewProc("CreatePipe")
	procSetHandleInheritance = kernel32.NewProc("SetHandleInformation")
	procPeekNamedPipe        = kernel32.NewProc("PeekNamedPipe")
	procReadFile             = kernel32.NewProc("ReadFile")
)

// errDrainTimeout reports that output draining did not finish in the bounded
// window. It never reaches a caller as a success.
var errDrainTimeout = errors.New("parsercells: output drain timed out")

// OpenInputHandle opens the staged input for inheritance by the parser. The
// returned handle is inheritable; the parent-side copy is closed immediately
// after CreateProcessW.
func (p *windowsPlatform) OpenInputHandle(path string) (syscall.Handle, error) {
	pointer, err := utf16Ptr(path)
	if err != nil {
		return 0, fmt.Errorf("parsercells: input path: %w", err)
	}
	attributes := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
	}
	handle, err := syscall.CreateFile(
		pointer,
		genericRead,
		fileShareRead|fileShareDelete,
		&attributes,
		openExisting,
		fileFlagSequentialScan,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("parsercells: open staged input: %w", err)
	}
	return handle, nil
}

// CreateOutputPipe creates an anonymous pipe. Only the write end is inheritable
// so the child cannot keep the read end open and the parent cannot leak its
// read end into the cell.
func (p *windowsPlatform) CreateOutputPipe() (syscall.Handle, syscall.Handle, error) {
	var readHandle syscall.Handle
	var writeHandle syscall.Handle
	attributes := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
	}
	result, _, callErr := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&readHandle)),
		uintptr(unsafe.Pointer(&writeHandle)),
		uintptr(unsafe.Pointer(&attributes)),
		0,
	)
	if err := checkBOOL("CreatePipe", result, callErr); err != nil {
		return 0, 0, fmt.Errorf("parsercells: %w", err)
	}
	result, _, callErr = procSetHandleInheritance.Call(uintptr(readHandle), uintptr(handleFlagInherit), 0)
	if result == 0 {
		_ = closeHandle(readHandle)
		_ = closeHandle(writeHandle)
		return 0, 0, fmt.Errorf("parsercells: SetHandleInformation(read): %w", errnoOrNil(callErr))
	}
	return readHandle, writeHandle, nil
}

// DrainOutput reads the pipe until EOF, the output ceiling is exceeded or the
// bounded timeout expires. It never allocates more than limit bytes (plus one
// detection chunk) and never blocks indefinitely: PeekNamedPipe + bounded sleep
// keeps the call cancellable without overlapped I/O.
func (p *windowsPlatform) DrainOutput(handle syscall.Handle, limit int64, timeout time.Duration) ([]byte, bool, error) {
	if handle == 0 || handle == syscall.InvalidHandle {
		return nil, false, errors.New("parsercells: drain requires a pipe handle")
	}
	if limit <= 0 || limit > HardMaxOutputBytes {
		return nil, false, fmt.Errorf("parsercells: output limit %d outside (0,%d]", limit, HardMaxOutputBytes)
	}
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 0, int(min64(limit, drainChunkBytes)))
	for {
		if time.Now().After(deadline) {
			return buffer, false, errDrainTimeout
		}
		var available uint32
		result, _, callErr := procPeekNamedPipe.Call(
			uintptr(handle), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0,
		)
		if result == 0 {
			err := errnoOrNil(callErr)
			if errors.Is(err, errorBrokenPipe) || errors.Is(err, errorNoData) {
				return buffer, false, nil
			}
			return buffer, false, fmt.Errorf("parsercells: PeekNamedPipe: %w", err)
		}
		if available == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		chunkSize := int64(available)
		if chunkSize > drainChunkBytes {
			chunkSize = drainChunkBytes
		}
		chunk := make([]byte, chunkSize)
		var read uint32
		if err := syscall.ReadFile(handle, chunk, &read, nil); err != nil {
			err = errnoOrNil(err)
			if errors.Is(err, errorBrokenPipe) || errors.Is(err, errorNoData) {
				return buffer, false, nil
			}
			return buffer, false, fmt.Errorf("parsercells: read pipe: %w", err)
		}
		if read == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		buffer = append(buffer, chunk[:read]...)
		if int64(len(buffer)) > limit {
			return buffer[:limit], true, nil
		}
	}
}

// min64 returns the smaller of two positive int64 values.
func min64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
