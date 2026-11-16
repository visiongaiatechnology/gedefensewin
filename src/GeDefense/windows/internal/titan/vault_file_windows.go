// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

type vaultFileIdentity struct {
	volume uint32
	index  uint64
	info   os.FileInfo
}

// openVaultSource opens a quarantine source through the reparse-safe Win32
// primitive and returns a stable volume-serial/file-index identity. The identity
// is re-checked immediately before the original is removed, so a substituted
// file is never deleted under the observed path (DP-FIND-005/007).
func openVaultSource(path string) (*os.File, vaultFileIdentity, error) {
	file, metadata, err := winapi.OpenRegularFileNoReparse(path)
	if err != nil {
		return nil, vaultFileIdentity{}, err
	}
	return file, vaultFileIdentity{volume: metadata.VolumeSerial, index: metadata.FileIndex}, nil
}

func sameVaultFile(left, right vaultFileIdentity) bool {
	if left.volume == 0 && left.index == 0 {
		return false
	}
	return left.volume == right.volume && left.index == right.index
}

func isReparseFileInfo(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes&winapi.FileAttributeReparsePoint != 0
	}
	return true
}

// validateRestoreTargetChain rejects restore targets whose existing parent chain
// contains a reparse point (junction/symlink/cloud tag), so a restore cannot be
// redirected through a swapped directory.
func validateRestoreTargetChain(target string) error {
	cleaned := filepath.Clean(target)
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return errRestoreTarget("restore target is not absolute")
	}
	volume := filepath.VolumeName(cleaned)
	remainder := cleaned[len(volume):]
	current := volume + string(os.PathSeparator)
	for _, part := range splitPath(remainder) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if current == cleaned {
			return nil
		}
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				// The remaining path does not exist yet; nothing can redirect it.
				return nil
			}
			return err
		}
		if isReparseFileInfo(info) {
			return errRestoreTarget("restore target parent chain contains a reparse point")
		}
		if !info.IsDir() {
			return errRestoreTarget("restore target parent is not a directory")
		}
	}
	return nil
}

func splitPath(remainder string) []string {
	parts := make([]string, 0, 16)
	for len(remainder) > 0 {
		index := len(remainder)
		for position := 0; position < len(remainder); position++ {
			if remainder[position] == os.PathSeparator || remainder[position] == '/' {
				index = position
				break
			}
		}
		if index > 0 {
			parts = append(parts, remainder[:index])
		}
		if index >= len(remainder) {
			break
		}
		remainder = remainder[index+1:]
	}
	return parts
}

// createRestoreTarget creates the restore target with CREATE_NEW|OPEN_REPARSE_POINT
// and verifies through the returned handle that the final resolved path equals the
// requested canonical path. The target can therefore neither be overwritten nor
// redirected through a swapped junction between validation and creation
// (FIND-WIN-021).
func createRestoreTarget(target string) (*os.File, error) {
	cleaned := filepath.Clean(target)
	if cleaned == "" || !filepath.IsAbs(cleaned) || len(cleaned) > 260 {
		return nil, errRestoreTarget("target path boundary rejected")
	}
	pointer, err := syscall.UTF16PtrFromString(cleaned)
	if err != nil {
		return nil, errRestoreTarget("target path rejected: " + err.Error())
	}
	handle, err := syscall.CreateFile(pointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.CREATE_NEW,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_EXISTS) || errors.Is(err, syscall.ERROR_ALREADY_EXISTS) {
			return nil, errors.New("titan restore target already exists")
		}
		return nil, fmt.Errorf("titan restore target creation: %w", err)
	}
	file := os.NewFile(uintptr(handle), cleaned)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		_ = os.Remove(cleaned)
		return nil, errors.New("titan restore target handle conversion failed")
	}
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &information); err != nil {
		_ = file.Close()
		_ = os.Remove(cleaned)
		return nil, fmt.Errorf("titan restore target identity unavailable: %w", err)
	}
	if information.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = file.Close()
		_ = os.Remove(cleaned)
		return nil, errRestoreTarget("restore target is a reparse point or directory")
	}
	actual, err := vaultFinalPath(syscall.Handle(file.Fd()))
	if err != nil {
		_ = file.Close()
		_ = os.Remove(cleaned)
		return nil, err
	}
	// The requested path may use an 8.3 short-name alias (temporary directories
	// frequently do); resolve it to the long form before comparing, a junction or
	// symlink redirect still resolves to a different directory.
	expected := cleaned
	if longPath, longErr := vaultLongPath(cleaned); longErr == nil {
		expected = longPath
	}
	if !strings.EqualFold(filepath.Clean(actual), filepath.Clean(expected)) {
		_ = file.Close()
		// Delete the file that was actually created (the resolved target), not the
		// requested alias that points through the redirected parent.
		_ = os.Remove(actual)
		return nil, errRestoreTarget("restore target resolved through a reparse point or alias")
	}
	return file, nil
}

func vaultLongPath(path string) (string, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 1024)
	result, _, callErr := procGetLongPathNameW.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if result == 0 {
		return "", errors.Join(errors.New("GetLongPathNameW failed"), errnoOrNil(callErr))
	}
	if result > uintptr(len(buffer)) {
		return "", errors.New("long path exceeds the boundary")
	}
	return syscall.UTF16ToString(buffer[:result]), nil
}

func vaultFinalPath(handle syscall.Handle) (string, error) {
	buffer := make([]uint16, 1024)
	result, _, callErr := procGetFinalPathNameByHandle.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
	)
	if result == 0 {
		return "", fmt.Errorf("titan restore target path unavailable: %w",
			errors.Join(errors.New("GetFinalPathNameByHandleW failed"), errnoOrNil(callErr)))
	}
	if result > uintptr(len(buffer)) {
		return "", errRestoreTarget("restore target resolved path exceeds the boundary")
	}
	actual := syscall.UTF16ToString(buffer[:result])
	actual = strings.TrimPrefix(actual, `\\?\`)
	return actual, nil
}

func errnoOrNil(callErr error) error {
	if callErr == nil || callErr == syscall.Errno(0) {
		return errors.New("no Win32 error reported")
	}
	return callErr
}

// readSourceZoneIdentifier captures the bounded :Zone.Identifier ADS of a file
// that is about to be quarantined. A hostile oversized stream is reduced to its
// parsed zone id (an unparsable body is conservatively kept as Internet zone 3),
// so capture can never allocate without bound.
func readSourceZoneIdentifier(path string) ([]byte, error) {
	file, err := os.Open(path + zoneIdentifierStream)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxZoneIdentifierBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) <= maxZoneIdentifierBytes {
		return raw, nil
	}
	zoneID := titanParseZoneIdentifierID(raw[:maxZoneIdentifierBytes])
	if zoneID == "" {
		zoneID = "3"
	}
	return []byte("[ZoneTransfer]\r\nZoneId=" + zoneID + "\r\n"), nil
}

func titanParseZoneIdentifierID(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "zoneid=") {
			continue
		}
		value := strings.TrimSpace(line[len("ZoneId="):])
		if len(value) == 0 || len(value) > 8 {
			continue
		}
		numeric := true
		for _, char := range value {
			if char < '0' || char > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			return value
		}
	}
	return ""
}

// restoreZoneIdentifier writes the preserved Mark-of-the-Web back to the
// restored file as its :Zone.Identifier alternate data stream.
func restoreZoneIdentifier(target string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > maxZoneIdentifierBytes {
		return errors.New("titan zone identifier restore boundary rejected")
	}
	stream := target + zoneIdentifierStream
	pointer, err := syscall.UTF16PtrFromString(stream)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(pointer, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("titan zone identifier restore: %w", err)
	}
	file := os.NewFile(uintptr(handle), stream)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return errors.New("titan zone identifier handle conversion failed")
	}
	writeErr := func() error {
		if _, err := file.Write(raw); err != nil {
			return err
		}
		return file.Sync()
	}()
	return errors.Join(writeErr, file.Close())
}

// freeDiskBytes returns the free space on the volume containing path.
func freeDiskBytes(path string) (uint64, error) {
	var freeAvailable, total, totalFree uint64
	pointer, err := syscall.UTF16PtrFromString(filepath.Clean(filepath.Dir(path)))
	if err != nil {
		return 0, err
	}
	proc := diskKernel32.NewProc("GetDiskFreeSpaceExW")
	result, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(unsafe.Pointer(&freeAvailable)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if result == 0 {
		return 0, callErr
	}
	return freeAvailable, nil
}

var (
	diskKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetFinalPathNameByHandle = diskKernel32.NewProc("GetFinalPathNameByHandleW")
	procGetLongPathNameW         = diskKernel32.NewProc("GetLongPathNameW")
)
