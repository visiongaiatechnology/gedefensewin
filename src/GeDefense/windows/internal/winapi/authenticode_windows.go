// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// UI-FIND-002 mitigation: fail-closed Authenticode verification for local
// executables that the operator UI is about to launch.
//
// The UI host is an external Chromium kiosk, not an embedded renderer, so the
// launcher resolves an executable path itself. VerifyAuthenticode adds the
// missing publisher check: the resolved file must carry a WinVerifyTrust
// (WINTRUST_ACTION_GENERIC_VERIFY_V2) valid signature. Every non-zero HRESULT
// is an error - unsigned, invalid, distrusted or malformed files are never
// launched by a caller that honours this helper.
//
// Boundaries enforced before WinVerifyTrust runs:
//
//   - absolute path only, bounded length, local fixed drive (UNC, device and
//     placeholder paths are rejected, so verification never triggers a
//     network/authentication side effect),
//   - symlinks, junctions and mount points on any existing path component are
//     rejected; the final component is opened with FILE_FLAG_OPEN_REPARSE_POINT
//     and the handle's final resolved path must equal the requested path,
//   - the signature is verified through the already-open file handle, so a
//     swap between path resolution and verification cannot substitute a
//     different file (no TOCTOU between the checks),
//   - directory and non-regular files are rejected.
//
// Trust model: the helper proves "validly signed by a publisher that chains to
// a trusted root and is not explicitly distrusted on this machine". It does
// not pin a specific publisher name and deliberately performs no network
// retrieval (WTD_CACHE_ONLY_URL_RETRIEVAL, no revocation fetch) so an offline
// or air-gapped host can still validate its locally installed binaries; fresh
// revocation data is a documented residual limitation, not silently claimed.

const (
	// maxAuthenticodePathBytes bounds the path string before any Win32 call.
	maxAuthenticodePathBytes = 1024

	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionIgnore     = 0
	wtdCacheOnlyURLRetrieval = 0x00001000
)

var (
	wintrustDLL = syscall.NewLazyDLL("wintrust.dll")

	procWinVerifyTrust           = wintrustDLL.NewProc("WinVerifyTrust")
	procGetFinalPathNameByHandle = kernel32.NewProc("GetFinalPathNameByHandleW")
)

// trustGUID mirrors the Windows GUID layout used for the WinVerifyTrust action.
type trustGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// winTrustActionGenericVerifyV2 is WINTRUST_ACTION_GENERIC_VERIFY_V2
// (00AAC56B-CD44-11d0-8CC2-00C04FC295EE).
var winTrustActionGenericVerifyV2 = trustGUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

// winTrustFileInfo mirrors WINTRUST_FILE_INFO.
type winTrustFileInfo struct {
	cbStruct     uint32
	filePath     *uint16
	file         uintptr
	knownSubject uintptr
}

// winTrustData mirrors WINTRUST_DATA (Windows 8+ layout, including
// pSignatureSettings). Go's struct alignment reproduces the C layout on both
// amd64 and 386; cbStruct is derived from unsafe.Sizeof for the build target.
type winTrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	file               *winTrustFileInfo
	stateAction        uint32
	wvtStateData       uintptr
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

// VerifyAuthenticode verifies that the local executable file carries a valid
// Authenticode signature trusted by this Windows installation. It fails closed
// for unsigned/invalid files, reparse points, non-absolute paths, network paths
// and missing files. Callers must treat any error as "do not launch".
func VerifyAuthenticode(localPath string) error {
	clean, err := validateAuthenticodePath(localPath)
	if err != nil {
		return err
	}
	// Open once, reparse-safe, and verify through that handle. Opening with
	// FILE_FLAG_OPEN_REPARSE_POINT means the final component is never followed;
	// the final-path check below additionally rejects intermediate reparse
	// components (junctions, mount points).
	file, _, err := OpenRegularFileNoReparse(clean)
	if err != nil {
		return fmt.Errorf("authenticode: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := verifyResolvedFilePath(clean, file); err != nil {
		return err
	}
	if err := winVerifyTrustFile(clean, file.Fd()); err != nil {
		return err
	}
	return nil
}

// validateAuthenticodePath enforces the path boundary before any file or
// publisher work happens.
func validateAuthenticodePath(localPath string) (string, error) {
	if localPath == "" {
		return "", errors.New("authenticode: local file path required")
	}
	if len(localPath) > maxAuthenticodePathBytes {
		return "", errors.New("authenticode: local file path exceeds the boundary")
	}
	if strings.IndexByte(localPath, 0) >= 0 {
		return "", errors.New("authenticode: local file path contains a NUL byte")
	}
	if !filepath.IsAbs(localPath) {
		return "", errors.New("authenticode: local file path must be absolute")
	}
	clean := filepath.Clean(localPath)
	volume := filepath.VolumeName(clean)
	if len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("authenticode: local drive path required (UNC and device paths are rejected)")
	}
	driveType, err := DriveType(volume + string(filepath.Separator))
	if err != nil {
		return "", fmt.Errorf("authenticode: local drive type unavailable: %w", err)
	}
	if driveType != DriveFixed {
		return "", errors.New("authenticode: local fixed drive required")
	}
	if pathContainsReparseComponent(clean) {
		return "", errors.New("authenticode: reparse point on the path is rejected")
	}
	return clean, nil
}

// pathContainsReparseComponent rejects symlinks, junctions and mount points on
// every existing component of the path. Missing components are not reported
// here; opening the final file fails closed on its own.
func pathContainsReparseComponent(path string) bool {
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(path, current)
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		pointer, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return true
		}
		attributes, err := syscall.GetFileAttributes(pointer)
		if err != nil {
			return false
		}
		if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
	}
	return false
}

// verifyResolvedFilePath compares the final path of the open handle with the
// requested path. A difference means a component was resolved through a
// reparse point, an alias or a short name; verification refuses such paths.
func verifyResolvedFilePath(expected string, file *os.File) error {
	buffer := make([]uint16, 1024)
	result, _, callErr := procGetFinalPathNameByHandle.Call(
		file.Fd(),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
	)
	if result == 0 {
		return errors.Join(errors.New("authenticode: resolved file path unavailable"), errnoResult(callErr))
	}
	if result > uintptr(len(buffer)) {
		return errors.New("authenticode: resolved file path exceeds the boundary")
	}
	actual := syscall.UTF16ToString(buffer[:result])
	actual = strings.TrimPrefix(actual, `\\?\`)
	if !strings.EqualFold(filepath.Clean(actual), expected) {
		return errors.New("authenticode: file path resolves through a reparse point or alias")
	}
	return nil
}

// winVerifyTrustFile runs WinVerifyTrust against the open handle. With
// WTD_UI_NONE the hwnd parameter must be INVALID_HANDLE_VALUE.
func winVerifyTrustFile(path string, handle uintptr) error {
	pathPointer, err := utf16Ptr(path)
	if err != nil {
		return fmt.Errorf("authenticode: %w", err)
	}
	fileInfo := winTrustFileInfo{
		cbStruct: uint32(unsafe.Sizeof(winTrustFileInfo{})),
		filePath: pathPointer,
		file:     handle,
	}
	data := winTrustData{
		cbStruct:         uint32(unsafe.Sizeof(winTrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceFile,
		file:             &fileInfo,
		stateAction:      wtdStateActionIgnore,
		provFlags:        wtdCacheOnlyURLRetrieval,
	}
	result, _, _ := procWinVerifyTrust.Call(
		^uintptr(0),
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	status := int32(uint32(result))
	if status != 0 {
		return fmt.Errorf("authenticode: WinVerifyTrust rejected the file (hr=0x%08X)", uint32(status))
	}
	return nil
}
