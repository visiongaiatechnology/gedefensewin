// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"os"
	"path/filepath"
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

var diskKernel32 = syscall.NewLazyDLL("kernel32.dll")
