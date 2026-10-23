// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileListDirectory         = 0x00000001
	fileShareAll              = 0x00000007
	openExistingDirectory     = 3
	fileFlagBackupSemantics   = 0x02000000
	fileFlagOverlapped        = 0x40000000
	fileNotifyChangeFileName  = 0x00000001
	fileNotifyChangeDirName   = 0x00000002
	fileNotifyChangeSize      = 0x00000008
	fileNotifyChangeLastWrite = 0x00000010
	fileNotifyChangeCreation  = 0x00000040
	fileNotifyChangeSecurity  = 0x00000100
	maxDirectoryEvents        = 4096
	directoryBufferBytes      = 64 << 10
)

// DirectoryChange is one native ReadDirectoryChangesW notification.
type DirectoryChange struct {
	Action uint32
	Path   string
}

// ErrDirectoryOverflow means the kernel buffer overflowed. The caller must
// surface telemetry loss and rebuild a baseline for the affected root.
var ErrDirectoryOverflow = errors.New("directory change buffer overflow")

type DirectoryWatcher struct {
	root       string
	handle     syscall.Handle
	event      Handle
	overlapped syscall.Overlapped
	buffer     []byte
	closed     bool
}

func OpenDirectoryWatcher(root string) (*DirectoryWatcher, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("directory watcher requires an absolute path")
	}
	cleaned := filepath.Clean(root)
	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("directory watcher target is not a directory")
	}
	pointer, err := syscall.UTF16PtrFromString(cleaned)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(pointer, fileListDirectory, fileShareAll, nil, openExistingDirectory,
		fileFlagBackupSemantics|fileFlagOverlapped, 0)
	if err != nil {
		return nil, err
	}
	event, _, eventErr := CreateEvent("", false, false)
	if eventErr != nil || event == 0 {
		_ = syscall.CloseHandle(handle)
		if eventErr != nil {
			return nil, eventErr
		}
		return nil, errors.New("directory watcher event creation failed")
	}
	watcher := &DirectoryWatcher{root: cleaned, handle: handle, event: event, buffer: make([]byte, directoryBufferBytes)}
	watcher.overlapped.HEvent = syscall.Handle(event)
	return watcher, nil
}

func (w *DirectoryWatcher) Read(ctx context.Context) ([]DirectoryChange, error) {
	if w == nil || w.closed {
		return nil, errors.New("directory watcher is closed")
	}
	if ctx == nil {
		return nil, errors.New("directory watcher context required")
	}
	var returned uint32
	filter := uint32(fileNotifyChangeFileName | fileNotifyChangeDirName | fileNotifyChangeSize | fileNotifyChangeLastWrite | fileNotifyChangeCreation | fileNotifyChangeSecurity)
	err := syscall.ReadDirectoryChanges(w.handle, &w.buffer[0], uint32(len(w.buffer)), true, filter, &returned, &w.overlapped, 0)
	if err != nil && !errors.Is(err, syscall.ERROR_IO_PENDING) {
		return nil, err
	}
	// With an overlapped handle, the syscall wrapper reports success for
	// ERROR_IO_PENDING and returns a zero-byte count. The completion event is
	// authoritative; only a completed zero-byte result means buffer overflow.
	if err != nil || returned == 0 {
		if waitErr := w.wait(ctx); waitErr != nil {
			return nil, waitErr
		}
		returned, err = getOverlappedResult(w.handle, &w.overlapped)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	if returned == 0 {
		return nil, ErrDirectoryOverflow
	}
	if returned > uint32(len(w.buffer)) {
		return nil, errors.New("directory watcher response boundary rejected")
	}
	return w.parse(w.buffer[:returned])
}

func (w *DirectoryWatcher) wait(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			_ = syscall.CancelIoEx(w.handle, &w.overlapped)
			_, _ = getOverlappedResult(w.handle, &w.overlapped)
			return ctx.Err()
		default:
		}
		result, err := syscall.WaitForSingleObject(syscall.Handle(w.event), 250)
		if err != nil {
			return err
		}
		switch result {
		case syscall.WAIT_OBJECT_0:
			return nil
		case syscall.WAIT_TIMEOUT:
			continue
		default:
			return fmt.Errorf("directory watcher wait returned %d", result)
		}
	}
}

func (w *DirectoryWatcher) parse(buffer []byte) ([]DirectoryChange, error) {
	changes := make([]DirectoryChange, 0, 16)
	offset := 0
	for {
		if offset+12 > len(buffer) {
			return nil, errors.New("directory watcher record truncated")
		}
		next := binary.LittleEndian.Uint32(buffer[offset : offset+4])
		action := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
		nameLength := binary.LittleEndian.Uint32(buffer[offset+8 : offset+12])
		if nameLength%2 != 0 || nameLength > 32<<10 {
			return nil, errors.New("directory watcher filename boundary rejected")
		}
		start := offset + 12
		end := start + int(nameLength)
		if end > len(buffer) {
			return nil, errors.New("directory watcher filename truncated")
		}
		nameUnits := unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[start])), int(nameLength/2))
		name := syscall.UTF16ToString(nameUnits)
		if strings.ContainsRune(name, 0) {
			return nil, errors.New("directory watcher filename contains NUL")
		}
		path := filepath.Clean(filepath.Join(w.root, name))
		if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(w.root)+string(os.PathSeparator)) && !strings.EqualFold(path, w.root) {
			return nil, errors.New("directory watcher path escaped its root")
		}
		changes = append(changes, DirectoryChange{Action: action, Path: path})
		if len(changes) > maxDirectoryEvents {
			return nil, errors.New("directory watcher event boundary exceeded")
		}
		if next == 0 {
			break
		}
		if next < 12 || int(next) > len(buffer)-offset {
			return nil, errors.New("directory watcher chain boundary rejected")
		}
		offset += int(next)
	}
	return changes, nil
}

func (w *DirectoryWatcher) Close() error {
	if w == nil || w.closed {
		return nil
	}
	w.closed = true
	_ = syscall.CancelIoEx(w.handle, &w.overlapped)
	handleErr := syscall.CloseHandle(w.handle)
	eventErr := CloseHandle(w.event)
	return errors.Join(handleErr, eventErr)
}

var (
	procGetOverlappedResult = kernel32.NewProc("GetOverlappedResult")
)

func getOverlappedResult(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
	var transferred uint32
	result, _, callErr := procGetOverlappedResult.Call(uintptr(handle), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(&transferred)), 0)
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return 0, err
		}
		return 0, errors.New("GetOverlappedResult failed")
	}
	return transferred, nil
}
