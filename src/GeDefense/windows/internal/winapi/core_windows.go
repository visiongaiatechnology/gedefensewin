// STATUS: DIAMANT VGT SUPREME
//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type Handle uintptr

const (
	ErrorAlreadyExists syscall.Errno = 183
	WaitObject0        uint32        = 0
	Infinite           uint32        = 0xFFFFFFFF

	MBOK              uint32 = 0x00000000
	MBIconError       uint32 = 0x00000010
	MBIconInformation uint32 = 0x00000040

	ProcessTerminate               uint32 = 0x0001
	ProcessQueryLimitedInformation uint32 = 0x1000

	MoveFileReplaceExisting uint32 = 0x00000001
	MoveFileWriteThrough    uint32 = 0x00000008

	DriveFixed uint32 = 3

	GenericRead               uint32 = 0x80000000
	FileShareRead             uint32 = 0x00000001
	FileShareWrite            uint32 = 0x00000002
	FileShareDelete           uint32 = 0x00000004
	OpenExisting              uint32 = 3
	FileAttributeDirectory    uint32 = 0x00000010
	FileAttributeReparsePoint uint32 = 0x00000400
	FileFlagOpenReparsePoint  uint32 = 0x00200000
	FileFlagSequentialScan    uint32 = 0x08000000

	TokenQuery     uint32 = 0x0008
	TokenElevation uint32 = 20
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCloseHandle           = kernel32.NewProc("CloseHandle")
	procCreateMutexW          = kernel32.NewProc("CreateMutexW")
	procCreateEventW          = kernel32.NewProc("CreateEventW")
	procSetEvent              = kernel32.NewProc("SetEvent")
	procWaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	procGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procOpenProcess           = kernel32.NewProc("OpenProcess")
	procTerminateProcess      = kernel32.NewProc("TerminateProcess")
	procGetProcessTimes       = kernel32.NewProc("GetProcessTimes")
	procQueryFullProcessImage = kernel32.NewProc("QueryFullProcessImageNameW")
	procMoveFileExW           = kernel32.NewProc("MoveFileExW")
	procGetLogicalDrives      = kernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW         = kernel32.NewProc("GetDriveTypeW")
	procGetModuleHandleW      = kernel32.NewProc("GetModuleHandleW")
	procCreateFileW           = kernel32.NewProc("CreateFileW")
	procGetFileInfoByHandle   = kernel32.NewProc("GetFileInformationByHandle")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
	procShellExecuteW         = shell32.NewProc("ShellExecuteW")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = advapi32.NewProc("GetTokenInformation")
)

func errnoResult(err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == 0 {
		return nil
	}
	return err
}

func utf16Ptr(value string) (*uint16, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return nil, errors.New("NUL byte rejected")
	}
	return syscall.UTF16PtrFromString(value)
}

func CloseHandle(handle Handle) error {
	if handle == 0 {
		return nil
	}
	result, _, callErr := procCloseHandle.Call(uintptr(handle))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("CloseHandle failed")
	}
	return nil
}

func CreateMutex(name string) (Handle, bool, error) {
	pointer, err := utf16Ptr(name)
	if err != nil {
		return 0, false, err
	}
	handle, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(pointer)))
	if handle == 0 {
		if err := errnoResult(callErr); err != nil {
			return 0, false, err
		}
		return 0, false, errors.New("CreateMutexW failed")
	}
	existed := errors.Is(callErr, ErrorAlreadyExists)
	return Handle(handle), existed, nil
}

func CreateEvent(name string, manualReset, initialState bool) (Handle, bool, error) {
	pointer, err := utf16Ptr(name)
	if err != nil {
		return 0, false, err
	}
	manual := uintptr(0)
	if manualReset {
		manual = 1
	}
	initial := uintptr(0)
	if initialState {
		initial = 1
	}
	handle, _, callErr := procCreateEventW.Call(0, manual, initial, uintptr(unsafe.Pointer(pointer)))
	if handle == 0 {
		if err := errnoResult(callErr); err != nil {
			return 0, false, err
		}
		return 0, false, errors.New("CreateEventW failed")
	}
	return Handle(handle), errors.Is(callErr, ErrorAlreadyExists), nil
}

func SetEvent(handle Handle) error {
	result, _, callErr := procSetEvent.Call(uintptr(handle))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("SetEvent failed")
	}
	return nil
}

func WaitForSingleObject(handle Handle, milliseconds uint32) (uint32, error) {
	result, _, callErr := procWaitForSingleObject.Call(uintptr(handle), uintptr(milliseconds))
	if uint32(result) == 0xFFFFFFFF {
		if err := errnoResult(callErr); err != nil {
			return uint32(result), err
		}
		return uint32(result), errors.New("WaitForSingleObject failed")
	}
	return uint32(result), nil
}

func MessageBox(title, message string, style uint32) error {
	caption, err := utf16Ptr(title)
	if err != nil {
		return err
	}
	text, err := utf16Ptr(message)
	if err != nil {
		return err
	}
	result, _, callErr := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), uintptr(MBOK|style))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("MessageBoxW failed")
	}
	return nil
}

func ShellOpenURL(target string) error {
	if target == "" || len(target) > 4096 {
		return errors.New("URL boundary rejected")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Port() != "17831" || parsed.RawQuery != "" || parsed.Path != "/" {
		return errors.New("URL target rejected")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
		return errors.New("URL host rejected")
	}
	operation, _ := utf16Ptr("open")
	value, err := utf16Ptr(target)
	if err != nil {
		return err
	}
	result, _, callErr := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(operation)), uintptr(unsafe.Pointer(value)), 0, 0, 1)
	if result <= 32 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return fmt.Errorf("ShellExecuteW rejected URL with status %d", result)
	}
	return nil
}

func IsProcessElevated() bool {
	process, _, _ := procGetCurrentProcess.Call()
	var token Handle
	result, _, _ := procOpenProcessToken.Call(process, uintptr(TokenQuery), uintptr(unsafe.Pointer(&token)))
	if result == 0 || token == 0 {
		return false
	}
	defer CloseHandle(token)
	var elevation uint32
	var returned uint32
	result, _, _ = procGetTokenInformation.Call(uintptr(token), uintptr(TokenElevation), uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)))
	return result != 0 && returned >= uint32(unsafe.Sizeof(elevation)) && elevation != 0
}

type FileTime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (f FileTime) ticks() uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}

func fileTimeUnixNano(f FileTime) int64 {
	const epochDifference100ns = uint64(116444736000000000)
	value := f.ticks()
	if value <= epochDifference100ns {
		return 0
	}
	return int64((value - epochDifference100ns) * 100)
}

type ProcessIdentity struct {
	Handle           Handle
	PID              uint32
	CreationUnixNano int64
	ImagePath        string
}

func OpenProcessIdentity(pid uint32, terminate bool) (ProcessIdentity, error) {
	if pid <= 4 {
		return ProcessIdentity{}, errors.New("protected process boundary")
	}
	access := ProcessQueryLimitedInformation
	if terminate {
		access |= ProcessTerminate
	}
	handle, _, callErr := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if handle == 0 {
		if err := errnoResult(callErr); err != nil {
			return ProcessIdentity{}, err
		}
		return ProcessIdentity{}, errors.New("OpenProcess failed")
	}
	identity := ProcessIdentity{Handle: Handle(handle), PID: pid}
	var creation, exit, kernel, user FileTime
	result, _, timeErr := procGetProcessTimes.Call(handle, uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if result == 0 {
		CloseHandle(identity.Handle)
		if err := errnoResult(timeErr); err != nil {
			return ProcessIdentity{}, err
		}
		return ProcessIdentity{}, errors.New("GetProcessTimes failed")
	}
	identity.CreationUnixNano = fileTimeUnixNano(creation)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	result, _, pathErr := procQueryFullProcessImage.Call(handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if result == 0 || size == 0 || int(size) > len(buffer) {
		CloseHandle(identity.Handle)
		if err := errnoResult(pathErr); err != nil {
			return ProcessIdentity{}, err
		}
		return ProcessIdentity{}, errors.New("QueryFullProcessImageNameW failed")
	}
	identity.ImagePath = syscall.UTF16ToString(buffer[:size])
	return identity, nil
}

func (p *ProcessIdentity) Close() error {
	if p == nil || p.Handle == 0 {
		return nil
	}
	err := CloseHandle(p.Handle)
	p.Handle = 0
	return err
}

func (p ProcessIdentity) Terminate(exitCode uint32) error {
	if p.Handle == 0 {
		return errors.New("process handle is closed")
	}
	result, _, callErr := procTerminateProcess.Call(uintptr(p.Handle), uintptr(exitCode))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("TerminateProcess failed")
	}
	return nil
}

func SameImagePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

type byHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       FileTime
	LastAccessTime     FileTime
	LastWriteTime      FileTime
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

type FileMetadata struct {
	Size             int64
	ModifiedUnixNano int64
	VolumeSerial     uint32
	FileIndex        uint64
}

func OpenRegularFileNoReparse(path string) (*os.File, FileMetadata, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, FileMetadata{}, errors.New("absolute file path required")
	}
	pointer, err := utf16Ptr(filepath.Clean(path))
	if err != nil {
		return nil, FileMetadata{}, err
	}
	handle, _, callErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(GenericRead),
		uintptr(FileShareRead|FileShareWrite|FileShareDelete),
		0,
		uintptr(OpenExisting),
		uintptr(FileFlagOpenReparsePoint|FileFlagSequentialScan),
		0,
	)
	if handle == ^uintptr(0) || handle == 0 {
		if err := errnoResult(callErr); err != nil {
			return nil, FileMetadata{}, err
		}
		return nil, FileMetadata{}, errors.New("CreateFileW failed")
	}
	var info byHandleFileInformation
	result, _, infoErr := procGetFileInfoByHandle.Call(handle, uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		procCloseHandle.Call(handle)
		if err := errnoResult(infoErr); err != nil {
			return nil, FileMetadata{}, err
		}
		return nil, FileMetadata{}, errors.New("GetFileInformationByHandle failed")
	}
	if info.FileAttributes&(FileAttributeDirectory|FileAttributeReparsePoint) != 0 {
		procCloseHandle.Call(handle)
		return nil, FileMetadata{}, errors.New("directory or reparse point rejected")
	}
	file := os.NewFile(handle, filepath.Base(path))
	if file == nil {
		procCloseHandle.Call(handle)
		return nil, FileMetadata{}, errors.New("file handle conversion failed")
	}
	size := int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
	meta := FileMetadata{
		Size:             size,
		ModifiedUnixNano: fileTimeUnixNano(info.LastWriteTime),
		VolumeSerial:     info.VolumeSerialNumber,
		FileIndex:        uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}
	return file, meta, nil
}

func MoveFileReplace(temporaryPath, path string) error {
	from, err := utf16Ptr(temporaryPath)
	if err != nil {
		return err
	}
	to, err := utf16Ptr(path)
	if err != nil {
		return err
	}
	result, _, callErr := procMoveFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), uintptr(MoveFileReplaceExisting|MoveFileWriteThrough))
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return err
		}
		return errors.New("MoveFileExW failed")
	}
	return nil
}

func LogicalDrives() (uint32, error) {
	result, _, callErr := procGetLogicalDrives.Call()
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return 0, err
		}
		return 0, errors.New("GetLogicalDrives failed")
	}
	return uint32(result), nil
}

func DriveType(root string) (uint32, error) {
	pointer, err := utf16Ptr(root)
	if err != nil {
		return 0, err
	}
	result, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(pointer)))
	if result == 0 {
		return 0, errors.New("GetDriveTypeW failed")
	}
	return uint32(result), nil
}

func ModuleHandle() (Handle, error) {
	result, _, callErr := procGetModuleHandleW.Call(0)
	if result == 0 {
		if err := errnoResult(callErr); err != nil {
			return 0, err
		}
		return 0, errors.New("GetModuleHandleW failed")
	}
	return Handle(result), nil
}
