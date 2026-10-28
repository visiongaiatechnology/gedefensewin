// STATUS: DIAMANT VGT SUPREME
//go:build windows

package mhx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// Bounded, best-effort image provenance probes for the process-creation sensor.
//
// The native 4688 sensor must not trust the image file name alone: a valid
// system LOLBin can be copied to a harmless looking name. This file reads the
// PE version resource ("OriginalFilename" and "CompanyName") of the image under
// a strict local-path boundary and verifies the Authenticode signature only for
// triage-relevant events. All reads are bounded and cached (path+size+mtime,
// at most maximumProcessImageProbeCache entries) so the event hot path performs
// one metadata read per unique image, not per event.
const (
	// maximumProcessImageBytes bounds the image file size before any version
	// resource read. All tracked Windows LOLBins are far below this limit.
	maximumProcessImageBytes = 256 << 20
	// maximumProcessVersionBlockBytes bounds the version resource block that is
	// allocated and handed to version.dll.
	maximumProcessVersionBlockBytes = 256 << 10
	// maximumProcessVersionStringChars bounds each extracted version string.
	maximumProcessVersionStringChars = 256
	// maximumProcessVersionTranslations bounds the VarFileInfo translation table.
	maximumProcessVersionTranslations = 32
	// maximumProcessImageProbeCache bounds the version/signer cache. A real
	// Windows boot observes more than 512 unique image paths, so the cache is
	// sized to keep steady-state triage free of repeated version reads while
	// still bounding memory (4096 entries with <=256-rune strings).
	maximumProcessImageProbeCache = 4096

	processCreationAuditPolicyKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
	processCreationAuditPolicyValue = "ProcessCreationIncludeCmdLine_Enabled"
	regGetValueTypeDWORD            = 0x00000010 // RRF_RT_REG_DWORD
)

var (
	versionDLL  = syscall.NewLazyDLL("version.dll")
	advapi32DLL = syscall.NewLazyDLL("advapi32.dll")

	procGetFileVersionInfoSizeW = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = versionDLL.NewProc("VerQueryValueW")
	procRegGetValueW            = advapi32DLL.NewProc("RegGetValueW")
)

// imageVersionMetadata is the bounded subset of the PE version resource that
// the process sensor needs.
type imageVersionMetadata struct {
	originalFilename string
	companyName      string
	available        bool
}

// knownLolbinOriginalName normalizes a PE OriginalFilename value to a tracked
// LOLBin name. Windows version APIs report language-resource (MUI) variants of
// system binaries as "<name>.MUI" (for example "PowerShell.EXE.MUI"), so that
// suffix is stripped before the shared allowlist is consulted.
func knownLolbinOriginalName(value string) (string, bool) {
	name := filepath.Base(strings.TrimSpace(value))
	if isKnownLolbinImage(name) {
		return name, true
	}
	if stripped := strings.TrimSuffix(strings.ToLower(name), ".mui"); stripped != strings.ToLower(name) && isKnownLolbinImage(stripped) {
		return stripped, true
	}
	return "", false
}

// isRenamedLolbin reports whether the image claims a tracked LOLBin original
// filename while its file name is something else (for example a copy of
// powershell.exe named updater.exe).
func (metadata imageVersionMetadata) isRenamedLolbin(image string) bool {
	if !metadata.available || metadata.originalFilename == "" {
		return false
	}
	original, known := knownLolbinOriginalName(metadata.originalFilename)
	if !known {
		return false
	}
	return !strings.EqualFold(original, strings.TrimSpace(filepath.Base(image)))
}

// imageProbeKey identifies one immutable image read. Size and modification time
// are part of the key so a replaced image is never served from a stale cache.
type imageProbeKey struct {
	path       string
	size       int64
	modifiedNS int64
}

type imageProbeEntry struct {
	version imageVersionMetadata
	signer  string // empty until an Authenticode verification is requested
}

// processImageProbe is a bounded FIFO cache for version resources and signer
// state. A zero value is ready for use.
type processImageProbe struct {
	mu    sync.Mutex
	cache map[imageProbeKey]imageProbeEntry
	order []imageProbeKey
}

// inspectProcessImagePath enforces the local fixed-drive boundary before any
// version or signature read: absolute path only, 2-character drive letter,
// fixed drive, no alternate data stream, no reparse point on any component and
// a regular file below the size cap. UNC, device and extended-length paths are
// rejected by the volume check, so no network or device side effect can occur.
func inspectProcessImagePath(value string) (string, winapi.FileMetadata, error) {
	if value == "" {
		return "", winapi.FileMetadata{}, errors.New("image path required")
	}
	if len(value) > maximumProcessImagePathBytes {
		return "", winapi.FileMetadata{}, errors.New("image path exceeds the boundary")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", winapi.FileMetadata{}, errors.New("image path contains NUL")
	}
	if !filepath.IsAbs(value) {
		return "", winapi.FileMetadata{}, errors.New("image path must be absolute")
	}
	clean := filepath.Clean(value)
	volume := filepath.VolumeName(clean)
	if len(volume) != 2 || volume[1] != ':' {
		return "", winapi.FileMetadata{}, errors.New("local drive image path required")
	}
	if strings.IndexByte(clean[2:], ':') >= 0 {
		return "", winapi.FileMetadata{}, errors.New("image path alternate data stream rejected")
	}
	driveType, err := winapi.DriveType(volume + string(filepath.Separator))
	if err != nil {
		return "", winapi.FileMetadata{}, fmt.Errorf("image drive type unavailable: %w", err)
	}
	if driveType != winapi.DriveFixed {
		return "", winapi.FileMetadata{}, errors.New("local fixed drive image path required")
	}
	if processImagePathHasReparsePoint(clean) {
		return "", winapi.FileMetadata{}, errors.New("image path reparse point rejected")
	}
	file, metadata, err := winapi.OpenRegularFileNoReparse(clean)
	if err != nil {
		return "", winapi.FileMetadata{}, fmt.Errorf("image file rejected: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", winapi.FileMetadata{}, fmt.Errorf("image file release failed: %w", err)
	}
	if metadata.Size > maximumProcessImageBytes {
		return "", winapi.FileMetadata{}, errors.New("image size exceeds the boundary")
	}
	return clean, metadata, nil
}

// processImagePathHasReparsePoint fails closed: an unreadable component is
// treated like a reparse point instead of being followed.
func processImagePathHasReparsePoint(path string) bool {
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
			return true
		}
		if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
	}
	return false
}

// inspect returns the cached version metadata for imagePath. The returned key
// addresses the same cache entry and is used for the lazy signer probe.
func (p *processImageProbe) inspect(imagePath string) (imageVersionMetadata, imageProbeKey, bool) {
	clean, metadata, err := inspectProcessImagePath(imagePath)
	if err != nil {
		return imageVersionMetadata{}, imageProbeKey{}, false
	}
	key := imageProbeKey{path: strings.ToLower(clean), size: metadata.Size, modifiedNS: metadata.ModifiedUnixNano}
	if entry, ok := p.lookup(key); ok {
		return entry.version, key, true
	}
	entry := imageProbeEntry{version: readProcessImageVersion(clean)}
	p.store(key, entry)
	return entry.version, key, true
}

// signerStatus verifies Authenticode once per cache entry. It is only called
// for triage-relevant events; non-triaged events never run WinVerifyTrust.
func (p *processImageProbe) signerStatus(key imageProbeKey) string {
	entry, ok := p.lookup(key)
	if !ok {
		return ""
	}
	if entry.signer != "" {
		return entry.signer
	}
	entry.signer = verifyProcessImageSigner(key.path)
	p.update(key, entry)
	return entry.signer
}

func (p *processImageProbe) lookup(key imageProbeKey) (imageProbeEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[key]
	return entry, ok
}

func (p *processImageProbe) store(key imageProbeKey, entry imageProbeEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache == nil {
		p.cache = make(map[imageProbeKey]imageProbeEntry, 64)
	}
	if _, exists := p.cache[key]; exists {
		p.cache[key] = entry
		return
	}
	if len(p.order) >= maximumProcessImageProbeCache {
		delete(p.cache, p.order[0])
		p.order = p.order[1:]
	}
	p.cache[key] = entry
	p.order = append(p.order, key)
}

func (p *processImageProbe) update(key imageProbeKey, entry imageProbeEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.cache[key]; exists {
		p.cache[key] = entry
	}
}

// verifyProcessImageSigner maps Authenticode verification onto the signer
// states the evaluator already understands. A rejected trust chain is reported
// as "NotSigned"; paths that cannot be verified locally (for example a file
// that vanished between the boundary check and verification) stay "Unknown"
// instead of being claimed as unsigned evidence.
//
// WinVerifyTrust evaluates embedded signatures only: catalog-only signed system
// binaries (several Windows 11 inbox tools) report "NotSigned" even though
// Windows trusts their catalog entry. That residual limitation is documented in
// the task report; the evaluator suppresses the signature signal for system
// LOLBin paths.
func verifyProcessImageSigner(imagePath string) string {
	status := authenticateImageStatus(imagePath)
	if status != "Unknown" {
		return status
	}
	// 8.3 short-name aliases (for example C:\Users\MASTER~1\...) make the
	// WinVerifyTrust path comparison fail without touching the signature. Retry
	// once through the canonical long path before reporting an unknown state.
	resolved, err := filepath.EvalSymlinks(imagePath)
	if err != nil || resolved == "" || strings.EqualFold(resolved, imagePath) ||
		len(resolved) > maximumProcessImagePathBytes || strings.IndexByte(resolved, 0) >= 0 {
		return status
	}
	if resolvedStatus := authenticateImageStatus(resolved); resolvedStatus != "Unknown" {
		return resolvedStatus
	}
	return status
}

func authenticateImageStatus(imagePath string) string {
	err := winapi.VerifyAuthenticode(imagePath)
	if err == nil {
		return "Valid"
	}
	if strings.Contains(err.Error(), "WinVerifyTrust rejected") {
		return "NotSigned"
	}
	return "Unknown"
}

// readProcessImageVersion reads OriginalFilename and CompanyName from the PE
// version resource. Every allocation is bounded; a malformed or missing
// resource simply yields no metadata (best effort, never an event failure).
func readProcessImageVersion(imagePath string) imageVersionMetadata {
	pointer, err := syscall.UTF16PtrFromString(imagePath)
	if err != nil {
		return imageVersionMetadata{}
	}
	var ignoredHandle uint32
	size, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&ignoredHandle)))
	if size == 0 || size > maximumProcessVersionBlockBytes {
		return imageVersionMetadata{}
	}
	block := make([]byte, int(size))
	result, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pointer)),
		0,
		size,
		uintptr(unsafe.Pointer(&block[0])),
	)
	if result == 0 {
		return imageVersionMetadata{}
	}
	translations := processVersionTranslations(block)
	candidates := make([]string, 0, len(translations)+2)
	for _, translation := range translations {
		candidates = append(candidates, fmt.Sprintf(`\StringFileInfo\%04x%04x`, translation[0], translation[1]))
	}
	// Files without a translation table are still readable through the
	// conventional US-English Unicode code page.
	candidates = append(candidates, `\StringFileInfo\040904b0`, `\StringFileInfo\000004b0`)
	seen := make(map[string]struct{}, len(candidates))
	originalFilename, companyName := "", ""
	for _, prefix := range candidates {
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		if originalFilename == "" {
			if value, ok := queryVersionString(block, prefix+`\OriginalFilename`); ok {
				originalFilename = value
			}
		}
		if companyName == "" {
			if value, ok := queryVersionString(block, prefix+`\CompanyName`); ok {
				companyName = value
			}
		}
		if originalFilename != "" && companyName != "" {
			break
		}
	}
	return imageVersionMetadata{
		originalFilename: originalFilename,
		companyName:      companyName,
		available:        originalFilename != "" || companyName != "",
	}
}

// processVersionTranslations decodes the VarFileInfo translation table into
// bounded (language, code page) pairs.
func processVersionTranslations(block []byte) [][2]uint16 {
	raw, ok := queryVersionBlockBytes(block, `\VarFileInfo\Translation`)
	if !ok {
		return nil
	}
	count := len(raw) / 4
	if count > maximumProcessVersionTranslations {
		count = maximumProcessVersionTranslations
	}
	translations := make([][2]uint16, 0, count)
	for index := 0; index < count; index++ {
		offset := index * 4
		translations = append(translations, [2]uint16{
			binary.LittleEndian.Uint16(raw[offset:]),
			binary.LittleEndian.Uint16(raw[offset+2:]),
		})
	}
	return translations
}

func queryVersionBlock(block []byte, subBlock string) (unsafe.Pointer, uint32, bool) {
	if len(block) == 0 || subBlock == "" {
		return nil, 0, false
	}
	name, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return nil, 0, false
	}
	var pointer unsafe.Pointer
	var length uint32
	result, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&block[0])),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&pointer)),
		uintptr(unsafe.Pointer(&length)),
	)
	if result == 0 || pointer == nil || length == 0 {
		return nil, 0, false
	}
	return pointer, length, true
}

// queryVersionBlockBytes returns a bounded copy view of a binary block (for
// example the translation table). The returned slice references the version
// block and must not escape the caller's block lifetime.
func queryVersionBlockBytes(block []byte, subBlock string) ([]byte, bool) {
	pointer, length, ok := queryVersionBlock(block, subBlock)
	if !ok {
		return nil, false
	}
	offset := uintptr(pointer) - uintptr(unsafe.Pointer(&block[0]))
	if offset >= uintptr(len(block)) {
		return nil, false
	}
	if uintptr(length) > uintptr(len(block))-offset {
		return nil, false
	}
	return unsafe.Slice((*byte)(pointer), int(length)), true
}

// queryVersionString copies a version string out of the block. VerQueryValue
// reports string lengths in UTF-16 code units; the slice is additionally
// clamped to the block end so neither a lying length nor a byte-counted length
// can read outside the allocated block. UTF16ToString stops at the first NUL.
func queryVersionString(block []byte, subBlock string) (string, bool) {
	pointer, length, ok := queryVersionBlock(block, subBlock)
	if !ok {
		return "", false
	}
	offset := uintptr(pointer) - uintptr(unsafe.Pointer(&block[0]))
	if offset >= uintptr(len(block)) {
		return "", false
	}
	available := (uintptr(len(block)) - offset) / 2
	count := uintptr(length)
	if count > available {
		count = available
	}
	if count > maximumProcessVersionStringChars {
		count = maximumProcessVersionStringChars
	}
	if count == 0 {
		return "", false
	}
	value := sanitizeVersionString(syscall.UTF16ToString(unsafe.Slice((*uint16)(pointer), int(count))))
	if value == "" {
		return "", false
	}
	return value, true
}

// sanitizeVersionString strips control characters/NULs, trims the edges and
// bounds the result to maximumProcessVersionStringChars runes.
func sanitizeVersionString(value string) string {
	cleaned := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	cleaned = strings.TrimSpace(cleaned)
	if runes := []rune(cleaned); len(runes) > maximumProcessVersionStringChars {
		cleaned = string(runes[:maximumProcessVersionStringChars])
	}
	return cleaned
}

// processAuditAvailability verifies the Windows audit configuration the sensor
// depends on: process creation events only carry a command line when
// ProcessCreationIncludeCmdLine_Enabled is set. Without that setting the
// command-line triage and evaluation contract cannot be honoured, so the
// sensor reports a clear fault each attempt instead of pretending to be
// healthy while producing name-only telemetry.
func processAuditAvailability() error {
	value, err := readRegistryDWORD(processCreationAuditPolicyKey, processCreationAuditPolicyValue)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
			return errors.New("process telemetry: Security 4688 command-line auditing is not configured (ProcessCreationIncludeCmdLine_Enabled is absent)")
		}
		return fmt.Errorf("process telemetry: Security 4688 audit policy unavailable: %w", err)
	}
	if value != 1 {
		return fmt.Errorf("process telemetry: Security 4688 command-line auditing is disabled (ProcessCreationIncludeCmdLine_Enabled=%d)", value)
	}
	return nil
}

// readRegistryDWORD reads one 32-bit value through native advapi32!RegGetValueW
// (no child process, no PowerShell).
func readRegistryDWORD(subKey, valueName string) (uint32, error) {
	if subKey == "" || valueName == "" {
		return 0, errors.New("registry target required")
	}
	subKeyPointer, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, err
	}
	valuePointer, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return 0, err
	}
	var data uint32
	size := uint32(unsafe.Sizeof(data))
	status, _, _ := procRegGetValueW.Call(
		uintptr(syscall.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(subKeyPointer)),
		uintptr(unsafe.Pointer(valuePointer)),
		uintptr(regGetValueTypeDWORD),
		0,
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&size)),
	)
	if status != 0 {
		return 0, syscall.Errno(status)
	}
	if size != uint32(unsafe.Sizeof(data)) {
		return 0, errors.New("registry value size rejected")
	}
	return data, nil
}
