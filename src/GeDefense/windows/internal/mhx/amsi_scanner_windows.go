// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	listModulesAll          = 0x03

	maxAmsiModules       = 4096
	maxAmsiModuleNameLen = 512
)

var (
	psapiDLL                 = syscall.NewLazyDLL("psapi.dll")
	kernel32DLL              = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory    = kernel32DLL.NewProc("ReadProcessMemory")
	procGetProcAddress       = kernel32DLL.NewProc("GetProcAddress")
	procLoadLibraryW         = kernel32DLL.NewProc("LoadLibraryW")
	procFreeLibrary          = kernel32DLL.NewProc("FreeLibrary")
	procEnumProcessModulesEx = psapiDLL.NewProc("EnumProcessModulesEx")
	procGetModuleBaseNameW   = psapiDLL.NewProc("GetModuleBaseNameW")
	procGetModuleFileNameExW = psapiDLL.NewProc("GetModuleFileNameExW")
	procGetModuleInformation = psapiDLL.NewProc("GetModuleInformation")

	amsiOffsetOnce   sync.Once
	cachedAmsiOffset uintptr
	amsiLocalOnce    sync.Once
	amsiLocalPath    string
	amsiLocalSize    uint32
	amsiLocalErr     error
)

type amsiModuleInfo struct {
	base uintptr
	size uint32
}

func getModuleInformation(process, module uintptr) (amsiModuleInfo, error) {
	var info struct {
		base uintptr
		size uint32
		_    uintptr
	}
	ret, _, err := procGetModuleInformation.Call(process, module, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Sizeof(info)))
	if ret == 0 || info.size == 0 {
		return amsiModuleInfo{}, fmt.Errorf("GetModuleInformation failed: %v", err)
	}
	return amsiModuleInfo{base: info.base, size: info.size}, nil
}

func getModuleFileName(process, module uintptr) (string, error) {
	buf := make([]uint16, maxAmsiModuleNameLen)
	ret, _, err := procGetModuleFileNameExW.Call(process, module, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if ret == 0 || ret >= uintptr(len(buf)) {
		return "", fmt.Errorf("GetModuleFileNameExW failed: %v", err)
	}
	return syscall.UTF16ToString(buf[:ret]), nil
}

// localAmsiModuleIdentity derives the local amsi.dll path and PE image size from
// the file system. psapi's GetModuleInformation/GetModuleFileNameExW reject the
// pseudo handle of the current process, which previously made the whole AMSI
// shield fail closed on every LotL process. Parsing the PE header is
// deterministic and does not depend on load state.
func localAmsiModuleIdentity() (string, uint32, error) {
	amsiLocalOnce.Do(func() {
		path := system32Binary("amsi.dll")
		size, err := peImageSize(path)
		if err != nil {
			amsiLocalErr = fmt.Errorf("read local amsi.dll identity: %w", err)
			return
		}
		amsiLocalPath = strings.ToLower(filepath.Clean(path))
		amsiLocalSize = size
	})
	return amsiLocalPath, amsiLocalSize, amsiLocalErr
}

// peImageSize returns OptionalHeader.SizeOfImage from a PE32/PE32+ file.
func peImageSize(path string) (uint32, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return 0, err
	}
	if len(data) < 0x40 {
		return 0, errors.New("PE header truncated")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return 0, errors.New("PE DOS signature missing")
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if eLfanew < 0 || eLfanew+24 > len(data) || string(data[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return 0, errors.New("PE signature missing")
	}
	optional := eLfanew + 24
	if optional+60 > len(data) {
		return 0, errors.New("PE optional header truncated")
	}
	magic := binary.LittleEndian.Uint16(data[optional:])
	if magic != 0x10b && magic != 0x20b {
		return 0, fmt.Errorf("unsupported PE optional magic 0x%x", magic)
	}
	size := binary.LittleEndian.Uint32(data[optional+56:])
	if size == 0 || size > 64<<20 {
		return 0, fmt.Errorf("implausible PE SizeOfImage: %d", size)
	}
	return size, nil
}

func getAmsiScanBufferOffset() uintptr {
	amsiOffsetOnce.Do(func() {
		libName, err := syscall.UTF16PtrFromString("amsi.dll")
		if err != nil {
			return
		}
		hAmsi, _, _ := procLoadLibraryW.Call(uintptr(unsafe.Pointer(libName)))
		if hAmsi == 0 {
			return
		}
		defer procFreeLibrary.Call(hAmsi)

		funcName := []byte("AmsiScanBuffer\x00")
		pAmsiScanBuffer, _, _ := procGetProcAddress.Call(hAmsi, uintptr(unsafe.Pointer(&funcName[0])))
		if pAmsiScanBuffer != 0 && pAmsiScanBuffer > hAmsi {
			cachedAmsiOffset = pAmsiScanBuffer - hAmsi
		}
	})
	return cachedAmsiOffset
}

func isAmsiPatched(pid uint32, amsiOffset uintptr) (bool, error) {
	if pid <= 4 || amsiOffset == 0 {
		return false, nil
	}
	hProcess, _, _ := kernel32DLL.NewProc("OpenProcess").Call(
		uintptr(processQueryInformation|processVMRead),
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return false, errors.New("open process for memory scan rejected")
	}
	defer winapi.CloseHandle(winapi.Handle(hProcess))

	var needed uint32
	ret, _, _ := procEnumProcessModulesEx.Call(
		hProcess,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		uintptr(listModulesAll),
	)
	if ret == 0 || needed == 0 {
		return false, errors.New("enum process modules (size pass) failed")
	}
	numModules := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if numModules <= 0 || numModules > maxAmsiModules {
		return false, fmt.Errorf("process module list out of bounds: %d", numModules)
	}
	modules := make([]uintptr, numModules)
	ret, _, _ = procEnumProcessModulesEx.Call(
		hProcess,
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(listModulesAll),
	)
	if ret == 0 {
		return false, errors.New("enum process modules (data pass) failed")
	}
	loaded := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if loaded < numModules {
		numModules = loaded
	}

	var remoteAmsiBase uintptr
	var buf [maxAmsiModuleNameLen]uint16
	for i := 0; i < numModules; i++ {
		buf[0] = 0
		lenName, _, _ := procGetModuleBaseNameW.Call(
			hProcess,
			modules[i],
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if lenName == 0 || lenName >= uintptr(len(buf)) {
			continue
		}
		modName := strings.ToLower(syscall.UTF16ToString(buf[:lenName]))
		if modName == "amsi.dll" {
			remoteAmsiBase = modules[i]
			break
		}
	}

	if remoteAmsiBase == 0 {
		return false, nil
	}

	// The cached offset is only valid for the exact same amsi.dll image. Verify
	// the remote module's path and image size before trusting it; a mismatch
	// (different Windows build, injected DLL with the same name) must never
	// produce a scan verdict.
	localPath, localSize, localErr := localAmsiModuleIdentity()
	if localErr != nil {
		return false, localErr
	}
	remoteInfo, infoErr := getModuleInformation(hProcess, remoteAmsiBase)
	if infoErr != nil {
		return false, infoErr
	}
	remotePath, pathErr := getModuleFileName(hProcess, remoteAmsiBase)
	if pathErr != nil {
		return false, pathErr
	}
	if remoteInfo.size != localSize || !strings.HasSuffix(strings.ToLower(filepath.Clean(remotePath)), `\amsi.dll`) {
		return false, fmt.Errorf("remote amsi.dll identity mismatch (remote=%s size=%d, local=%s size=%d)", remotePath, remoteInfo.size, localPath, localSize)
	}
	if amsiOffset == 0 || amsiOffset >= uintptr(remoteInfo.size) {
		return false, errors.New("amsi scan offset outside remote module bounds")
	}

	targetAddress := remoteAmsiBase + amsiOffset
	var memBuffer [8]byte
	var bytesRead uintptr
	readRet, _, _ := procReadProcessMemory.Call(
		hProcess,
		targetAddress,
		uintptr(unsafe.Pointer(&memBuffer[0])),
		uintptr(len(memBuffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if readRet == 0 || bytesRead < 4 {
		return false, errors.New("read process memory failed")
	}

	// 1. mov eax, 0x80070057; ret (B8 57 00 07 80)
	if memBuffer[0] == 0xB8 && memBuffer[1] == 0x57 && memBuffer[2] == 0x00 && memBuffer[3] == 0x07 && memBuffer[4] == 0x80 {
		return true, nil
	}
	// 2. Unconditional jump (EB or E9)
	if memBuffer[0] == 0xEB || memBuffer[0] == 0xE9 {
		return true, nil
	}
	// 3. Immediate return (C3)
	if memBuffer[0] == 0xC3 {
		return true, nil
	}
	// 4. xor eax, eax; ret (31 C0 C3)
	if memBuffer[0] == 0x31 && memBuffer[1] == 0xC0 && memBuffer[2] == 0xC3 {
		return true, nil
	}

	return false, nil
}
