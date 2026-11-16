// STATUS: PLATIN VGT SUPREME
//go:build windows

package mhx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// AMSI memory shield (FIND-WIN-011).
//
// The scanner re-reads the live AmsiScanBuffer prologue of a target process. It
// is hardened against the three failure modes of the previous implementation:
//
//   - PID reuse: the target is only ever scanned through a handle whose
//     creation time and image path were verified against the observed 4688
//     event, so a recycled PID can not be scanned (and later killed) as if it
//     were the observed interpreter.
//   - WOW64: a 32-bit target loads SysWOW64\amsi.dll; the scanner derives the
//     amsi.dll identity (path, SizeOfImage, AmsiScanBuffer export RVA) for the
//     target bitness instead of comparing against the 64-bit image.
//   - Single 8-byte sample: a bounded 64-byte prologue window is compared
//     against several known patch shapes and re-scanned after a bounded
//     interval, so a late patch is still detected while a scan storm is
//     throttled.
//
// An unverifiable target yields an error ("unverified"), never a patched
// verdict, so the caller logs it instead of killing a process on weak evidence.

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	processQueryLimited     = 0x1000
	listModulesAll          = 0x03

	maxAmsiModules       = 4096
	maxAmsiModuleNameLen = 512
	// amsiPrologueWindowBytes bounds the remote read. Every interesting patch
	// shape lives at the function entry, so a small fixed window is sufficient
	// and keeps the ReadProcessMemory call bounded.
	amsiPrologueWindowBytes = 64
	// maxAmsiRecheckEntries bounds the repeated-scan memo.
	maxAmsiRecheckEntries = 64
	// amsiRecheckInterval throttles re-scanning an unchanged clean process. A
	// patched verdict is cached permanently for its (pid, creation) identity.
	amsiRecheckInterval = 15 * time.Second
	// maxAmsiImageBytes bounds the local amsi.dll read before PE parsing.
	maxAmsiImageBytes = 8 << 20
	maxAmsiExports    = 4096
	maxAmsiExportName = 256
	maxAmsiSections   = 96
)

var (
	psapiDLL                 = syscall.NewLazyDLL("psapi.dll")
	kernel32DLL              = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory    = kernel32DLL.NewProc("ReadProcessMemory")
	procGetProcAddress       = kernel32DLL.NewProc("GetProcAddress")
	procLoadLibraryW         = kernel32DLL.NewProc("LoadLibraryW")
	procFreeLibrary          = kernel32DLL.NewProc("FreeLibrary")
	procOpenProcessScan      = kernel32DLL.NewProc("OpenProcess")
	procEnumProcessModulesEx = psapiDLL.NewProc("EnumProcessModulesEx")
	procGetModuleBaseNameW   = psapiDLL.NewProc("GetModuleBaseNameW")
	procGetModuleFileNameExW = psapiDLL.NewProc("GetModuleFileNameExW")
	procGetModuleInformation = psapiDLL.NewProc("GetModuleInformation")

	amsiOffsetOnce   sync.Once
	cachedAmsiOffset uintptr

	amsiIdentityOnce  sync.Once
	amsiNativeImage   amsiImageIdentity
	amsiWow64Image    amsiImageIdentity
	amsiNativeErr     error
	amsiWow64Err      error
	amsiRecheckMu     sync.Mutex
	amsiRecheckResult map[amsiRecheckKey]amsiRecheckEntry
)

// amsiImageIdentity is the on-disk identity of the amsi.dll image a target of
// the given bitness loads.
type amsiImageIdentity struct {
	path      string // canonical, lower-cased on-disk path
	size      uint32 // PE SizeOfImage
	exportRVA uint32 // RVA of the AmsiScanBuffer export
	wow64     bool
}

type amsiRecheckKey struct {
	pid      uint32
	creation int64
}

type amsiRecheckEntry struct {
	patched bool
	at      time.Time
}

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

// readAmsiImageIdentity derives the path, PE image size and AmsiScanBuffer export
// RVA for the native or WOW64 amsi.dll. Parsing the file header is deterministic
// and does not depend on load state (psapi rejects pseudo handles).
func readAmsiImageIdentity(wow64 bool) (amsiImageIdentity, error) {
	directory := "System32"
	if wow64 {
		directory = "SysWOW64"
	}
	path := filepath.Join(triageSystemRoot(), directory, "amsi.dll")
	size, exportRVA, err := peImageIdentity(path, "AmsiScanBuffer")
	if err != nil {
		return amsiImageIdentity{}, fmt.Errorf("read %s identity: %w", path, err)
	}
	return amsiImageIdentity{
		path:      strings.ToLower(filepath.Clean(path)),
		size:      size,
		exportRVA: exportRVA,
		wow64:     wow64,
	}, nil
}

func amsiImageIdentityFor(wow64 bool) (amsiImageIdentity, error) {
	amsiIdentityOnce.Do(func() {
		amsiNativeImage, amsiNativeErr = readAmsiImageIdentity(false)
		amsiWow64Image, amsiWow64Err = readAmsiImageIdentity(true)
	})
	if wow64 {
		return amsiWow64Image, amsiWow64Err
	}
	return amsiNativeImage, amsiNativeErr
}

// localAmsiModuleIdentity exposes the native amsi.dll identity for diagnostics
// and the existing signer/offset contract.
func localAmsiModuleIdentity() (string, uint32, error) {
	identity, err := amsiImageIdentityFor(false)
	if err != nil {
		return "", 0, fmt.Errorf("read local amsi.dll identity: %w", err)
	}
	return identity.path, identity.size, nil
}

type peSection struct {
	virtualAddress uint32
	virtualSize    uint32
	rawSize        uint32
	rawPointer     uint32
}

// peImageIdentity returns PE OptionalHeader.SizeOfImage and the export RVA of
// symbol. Every file and RVA offset is bounds-checked; a malformed image is an
// error, never a scan verdict.
func peImageIdentity(path, symbol string) (uint32, uint32, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAmsiImageBytes))
	if err != nil {
		return 0, 0, err
	}
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return 0, 0, errors.New("PE DOS signature missing")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOffset < 0 || peOffset+24 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return 0, 0, errors.New("PE signature missing")
	}
	coff := peOffset + 4
	numberOfSections := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	optional := coff + 20
	if numberOfSections <= 0 || numberOfSections > maxAmsiSections || optionalSize < 96 || optional+optionalSize > len(data) {
		return 0, 0, errors.New("PE optional/section header out of bounds")
	}
	var directoryOffset int
	switch magic := binary.LittleEndian.Uint16(data[optional:]); magic {
	case 0x10b:
		directoryOffset = optional + 96
	case 0x20b:
		directoryOffset = optional + 112
	default:
		return 0, 0, fmt.Errorf("unsupported PE optional magic 0x%x", magic)
	}
	sizeOfImage := binary.LittleEndian.Uint32(data[optional+56:])
	if sizeOfImage == 0 || sizeOfImage > 512<<20 {
		return 0, 0, fmt.Errorf("implausible PE SizeOfImage: %d", sizeOfImage)
	}
	if directoryOffset+8 > optional+optionalSize || directoryOffset+8 > len(data) {
		return 0, 0, errors.New("PE data directory out of bounds")
	}
	exportDirectoryRVA := binary.LittleEndian.Uint32(data[directoryOffset:])
	exportDirectorySize := binary.LittleEndian.Uint32(data[directoryOffset+4:])
	if exportDirectoryRVA == 0 || exportDirectorySize < 40 || exportDirectorySize > 16<<20 {
		return 0, 0, errors.New("PE export directory missing or implausible")
	}
	sections, ok := peSections(data, optional+optionalSize, numberOfSections)
	if !ok {
		return 0, 0, errors.New("PE section table truncated")
	}
	exportOffset, mapped := peRVAtoFileOffset(sections, len(data), exportDirectoryRVA)
	if !mapped || exportOffset+40 > len(data) {
		return 0, 0, errors.New("PE export directory unmapped")
	}
	numberOfFunctions := int(binary.LittleEndian.Uint32(data[exportOffset+20:]))
	numberOfNames := int(binary.LittleEndian.Uint32(data[exportOffset+24:]))
	if numberOfNames <= 0 || numberOfNames > maxAmsiExports || numberOfFunctions < numberOfNames {
		return 0, 0, errors.New("PE export name/function count out of bounds")
	}
	functionsRVA := binary.LittleEndian.Uint32(data[exportOffset+28:])
	namesRVA := binary.LittleEndian.Uint32(data[exportOffset+32:])
	ordinalsRVA := binary.LittleEndian.Uint32(data[exportOffset+36:])
	functionsOffset, okFunctions := peRVAtoFileOffset(sections, len(data), functionsRVA)
	namesOffset, okNames := peRVAtoFileOffset(sections, len(data), namesRVA)
	ordinalsOffset, okOrdinals := peRVAtoFileOffset(sections, len(data), ordinalsRVA)
	if !okFunctions || !okNames || !okOrdinals {
		return 0, 0, errors.New("PE export tables unmapped")
	}
	if namesOffset+numberOfNames*4 > len(data) || ordinalsOffset+numberOfNames*2 > len(data) {
		return 0, 0, errors.New("PE export tables truncated")
	}
	for index := 0; index < numberOfNames; index++ {
		nameRVA := binary.LittleEndian.Uint32(data[namesOffset+index*4:])
		nameOffset, nameMapped := peRVAtoFileOffset(sections, len(data), nameRVA)
		if !nameMapped || nameOffset >= len(data) {
			continue
		}
		end := nameOffset
		for end < len(data) && data[end] != 0 && end-nameOffset <= maxAmsiExportName {
			end++
		}
		if end-nameOffset > maxAmsiExportName || string(data[nameOffset:end]) != symbol {
			continue
		}
		ordinal := int(binary.LittleEndian.Uint16(data[ordinalsOffset+index*2:]))
		if ordinal < 0 || ordinal >= numberOfFunctions {
			return 0, 0, errors.New("PE export ordinal out of bounds")
		}
		functionOffset := functionsOffset + ordinal*4
		if functionOffset < 0 || functionOffset+4 > len(data) {
			return 0, 0, errors.New("PE export function RVA out of bounds")
		}
		exportRVA := binary.LittleEndian.Uint32(data[functionOffset:])
		if exportRVA == 0 || exportRVA >= sizeOfImage {
			return 0, 0, errors.New("PE export function RVA implausible")
		}
		return sizeOfImage, exportRVA, nil
	}
	return 0, 0, fmt.Errorf("PE export %q not found", symbol)
}

func peSections(data []byte, offset, count int) ([]peSection, bool) {
	if count <= 0 || count > maxAmsiSections || offset < 0 || offset+count*40 > len(data) {
		return nil, false
	}
	sections := make([]peSection, count)
	for index := 0; index < count; index++ {
		base := offset + index*40
		sections[index] = peSection{
			virtualSize:    binary.LittleEndian.Uint32(data[base+8:]),
			virtualAddress: binary.LittleEndian.Uint32(data[base+12:]),
			rawSize:        binary.LittleEndian.Uint32(data[base+16:]),
			rawPointer:     binary.LittleEndian.Uint32(data[base+20:]),
		}
	}
	return sections, true
}

func peRVAtoFileOffset(sections []peSection, dataLength int, rva uint32) (int, bool) {
	for _, section := range sections {
		span := section.virtualSize
		if span == 0 {
			span = section.rawSize
		}
		if span == 0 || uint64(rva) < uint64(section.virtualAddress) || uint64(rva) >= uint64(section.virtualAddress)+uint64(span) {
			continue
		}
		delta := uint64(rva) - uint64(section.virtualAddress)
		if delta >= uint64(section.rawSize) {
			return 0, false
		}
		offset := uint64(section.rawPointer) + delta
		if offset >= uint64(dataLength) {
			return 0, false
		}
		return int(offset), true
	}
	return 0, false
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

// classifyAmsiModulePath maps a remote module path to the bitness of the
// amsi.dll image the target actually loaded. Anything outside the canonical
// %SystemRoot%\System32 or %SystemRoot%\SysWOW64 location (for example an
// injected DLL that is merely named amsi.dll) is rejected as unverifiable
// instead of being scanned.
func classifyAmsiModulePath(remotePath string) (wow64 bool, err error) {
	clean := strings.ToLower(filepath.Clean(strings.TrimSpace(remotePath)))
	if clean == "" || clean == "." {
		return false, errors.New("remote amsi.dll path is empty")
	}
	root := triageSystemRoot()
	switch clean {
	case root + `\system32\amsi.dll`:
		return false, nil
	case root + `\syswow64\amsi.dll`:
		return true, nil
	}
	return false, fmt.Errorf("remote amsi.dll path is not a canonical Windows image: %q", truncate(remotePath, 96))
}

// amsiScanWindowLength bounds the prologue read against the remote module size.
// An offset outside the module is an error (unverified), never a clean verdict.
func amsiScanWindowLength(moduleSize uint32, offset uintptr) (int, error) {
	if moduleSize == 0 {
		return 0, errors.New("remote amsi module size is zero")
	}
	if offset >= uintptr(moduleSize) {
		return 0, errors.New("amsi scan offset outside remote module bounds")
	}
	available := int(uintptr(moduleSize) - offset)
	if available > amsiPrologueWindowBytes {
		available = amsiPrologueWindowBytes
	}
	if available < 8 {
		return 0, errors.New("amsi prologue window is too small for a verdict")
	}
	return available, nil
}

// amsiProloguePatchPatterns lists the entry-point shapes written by known AMSI
// bypass patches. Each pattern starts at byte 0 of AmsiScanBuffer.
var amsiProloguePatchPatterns = [][]byte{
	{0xB8, 0x57, 0x00, 0x07, 0x80},             // mov eax, 0x80070057 (classic bypass)
	{0xB8, 0x05, 0x00, 0x07, 0x80},             // mov eax, 0x80070005 (E_ACCESSDENIED)
	{0x31, 0xC0, 0xC3},                         // xor eax, eax; ret (32-bit)
	{0x33, 0xC0, 0xC3},                         // xor eax, eax; ret (alternative encoding)
	{0x48, 0x31, 0xC0, 0xC3},                   // xor rax, rax; ret (64-bit)
	{0x48, 0x33, 0xC0, 0xC3},                   // xor rax, rax; ret (alternative encoding)
	{0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00}, // mov rax, 0
	{0xC3}, // ret
	{0xEB}, // jmp rel8 (entry trampoline)
	{0xE9}, // jmp rel32 (entry trampoline)
}

// isAmsiProloguePatched evaluates a bounded prologue window against the known
// patch shapes. It is a pure function so tests can drive it with synthetic
// memory without touching a live process.
func isAmsiProloguePatched(window []byte) bool {
	if len(window) < 2 {
		return false
	}
	for _, pattern := range amsiProloguePatchPatterns {
		if bytes.HasPrefix(window, pattern) {
			return true
		}
	}
	// mov eax, imm32 followed by a return stub within the first 12 bytes.
	if window[0] == 0xB8 {
		limit := len(window)
		if limit > 12 {
			limit = 12
		}
		for index := 5; index < limit; index++ {
			if window[index] == 0xC3 {
				return true
			}
		}
	}
	return false
}

func amsiRecheckLookup(key amsiRecheckKey) (bool, bool) {
	amsiRecheckMu.Lock()
	defer amsiRecheckMu.Unlock()
	entry, exists := amsiRecheckResult[key]
	if !exists {
		return false, false
	}
	if entry.patched {
		return true, true
	}
	if time.Since(entry.at) < amsiRecheckInterval {
		return false, true
	}
	return false, false
}

func amsiRecheckStore(key amsiRecheckKey, patched bool) {
	amsiRecheckMu.Lock()
	defer amsiRecheckMu.Unlock()
	if amsiRecheckResult == nil {
		amsiRecheckResult = make(map[amsiRecheckKey]amsiRecheckEntry, maxAmsiRecheckEntries)
	}
	if _, exists := amsiRecheckResult[key]; !exists && len(amsiRecheckResult) >= maxAmsiRecheckEntries {
		var oldestKey amsiRecheckKey
		oldest := time.Now()
		first := true
		for candidate, entry := range amsiRecheckResult {
			if first || entry.at.Before(oldest) {
				oldestKey, oldest, first = candidate, entry.at, false
			}
		}
		delete(amsiRecheckResult, oldestKey)
	}
	amsiRecheckResult[key] = amsiRecheckEntry{patched: patched, at: time.Now()}
}

func enumProcessModules(handle winapi.Handle) ([]uintptr, error) {
	var needed uint32
	ret, _, _ := procEnumProcessModulesEx.Call(uintptr(handle), 0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(listModulesAll))
	if ret == 0 || needed == 0 {
		return nil, errors.New("enum process modules (size pass) failed")
	}
	numModules := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if numModules <= 0 || numModules > maxAmsiModules {
		return nil, fmt.Errorf("process module list out of bounds: %d", numModules)
	}
	modules := make([]uintptr, numModules)
	ret, _, _ = procEnumProcessModulesEx.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules))*unsafe.Sizeof(modules[0]),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(listModulesAll),
	)
	if ret == 0 {
		return nil, errors.New("enum process modules (data pass) failed")
	}
	loaded := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if loaded < numModules {
		modules = modules[:loaded]
	}
	return modules, nil
}

// findAmsiModule locates the amsi.dll module and returns its base and full path.
// A zero base means the target does not load AMSI at all (not an error).
func findAmsiModule(handle winapi.Handle, modules []uintptr) (uintptr, string, error) {
	var buf [maxAmsiModuleNameLen]uint16
	for _, module := range modules {
		buf[0] = 0
		lenName, _, _ := procGetModuleBaseNameW.Call(
			uintptr(handle),
			module,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if lenName == 0 || lenName >= uintptr(len(buf)) {
			continue
		}
		if !strings.EqualFold(syscall.UTF16ToString(buf[:lenName]), "amsi.dll") {
			continue
		}
		path, err := getModuleFileName(uintptr(handle), module)
		if err != nil {
			return 0, "", err
		}
		return module, path, nil
	}
	return 0, "", nil
}

// openAmsiScanHandle opens a memory-read handle for the observed process. The
// shared validated identity handle only has PROCESS_QUERY_LIMITED_INFORMATION
// (which is sufficient for identity but not for ReadProcessMemory), so the scan
// handle is re-proven against the already verified identity on the pinned
// handle before a single byte is read. A handle pins the kernel process object,
// which closes the PID-reuse window between verification and scan.
func openAmsiScanHandle(event ProcessEvent, verified winapi.ProcessIdentity) (winapi.ProcessIdentity, error) {
	handle, _, callErr := procOpenProcessScan.Call(
		uintptr(processVMRead|processQueryInformation|processQueryLimited),
		0,
		uintptr(event.PID),
	)
	if handle == 0 {
		return winapi.ProcessIdentity{}, fmt.Errorf("open process for memory scan rejected: %w", winapi.CheckBOOL("OpenProcess", handle, callErr))
	}
	identity, err := winapi.QueryProcessIdentity(winapi.Handle(handle))
	if err != nil {
		return winapi.ProcessIdentity{}, errors.Join(err, winapi.CloseHandle(winapi.Handle(handle)))
	}
	if identity.CreationUnixNano != verified.CreationUnixNano || !winapi.SameImagePath(identity.ImagePath, verified.ImagePath) {
		return winapi.ProcessIdentity{}, errors.Join(errors.New("process identity changed between verification and scan"), winapi.CloseHandle(winapi.Handle(handle)))
	}
	identity.PID = event.PID
	return identity, nil
}

func isAmsiPatched(event ProcessEvent, amsiOffset uintptr) (bool, error) {
	if event.PID <= 4 || amsiOffset == 0 {
		return false, nil
	}
	// 1. Proving the observed identity first means a recycled PID can never be
	// scanned: a handle obtained here pins the kernel process object.
	observed, err := openObservedProcess(event, false)
	if err != nil {
		return false, fmt.Errorf("AMSI scan identity rejected: %w", err)
	}
	defer func() { _ = observed.Close() }()

	// 2. Repeated-scan memo: a patched verdict is permanent for this identity, a
	// clean verdict is re-scanned after amsiRecheckInterval so a late patch is
	// still detected. Unverifiable scans are never cached.
	recheckKey := amsiRecheckKey{pid: event.PID, creation: observed.CreationUnixNano}
	if patched, known := amsiRecheckLookup(recheckKey); known {
		return patched, nil
	}

	scanIdentity, err := openAmsiScanHandle(event, observed)
	if err != nil {
		return false, err
	}
	defer func() { _ = scanIdentity.Close() }()
	handle := scanIdentity.Handle

	modules, err := enumProcessModules(handle)
	if err != nil {
		return false, err
	}
	remoteBase, remotePath, err := findAmsiModule(handle, modules)
	if err != nil {
		return false, err
	}
	if remoteBase == 0 {
		// The target does not load AMSI; there is no patch to detect.
		return false, nil
	}
	remoteInfo, err := getModuleInformation(uintptr(handle), remoteBase)
	if err != nil {
		return false, err
	}
	wow64, err := classifyAmsiModulePath(remotePath)
	if err != nil {
		return false, err
	}
	identity, err := amsiImageIdentityFor(wow64)
	if err != nil {
		return false, err
	}
	if remoteInfo.size != identity.size || !strings.EqualFold(filepath.Clean(remotePath), identity.path) {
		return false, fmt.Errorf("remote amsi.dll identity mismatch (remote=%s size=%d, disk=%s size=%d)", remotePath, remoteInfo.size, identity.path, identity.size)
	}
	offset := uintptr(identity.exportRVA)
	if !wow64 && amsiOffset != offset {
		// The caller resolved AmsiScanBuffer through LoadLibrary in the service
		// process. A mismatch means the loaded image is not the trusted on-disk
		// System32 image, so the scan is unverified instead of trusted.
		return false, fmt.Errorf("amsi scan offset mismatch (caller=%d disk=%d)", amsiOffset, offset)
	}
	windowLength, err := amsiScanWindowLength(remoteInfo.size, offset)
	if err != nil {
		return false, err
	}
	memory := make([]byte, windowLength)
	var bytesRead uintptr
	readRet, _, _ := procReadProcessMemory.Call(
		uintptr(handle),
		remoteBase+offset,
		uintptr(unsafe.Pointer(&memory[0])),
		uintptr(len(memory)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if readRet == 0 || bytesRead < 4 || bytesRead > uintptr(len(memory)) {
		return false, errors.New("read process memory failed")
	}
	patched := isAmsiProloguePatched(memory[:bytesRead])
	amsiRecheckStore(recheckKey, patched)
	return patched, nil
}
