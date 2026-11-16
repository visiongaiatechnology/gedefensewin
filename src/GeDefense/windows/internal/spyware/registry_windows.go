// STATUS: PLATIN VGT SUPREME
//go:build windows

package spyware

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

const (
	keyRead              = 0x20019 // KEY_READ
	maxRegistrySubkeys   = 4096
	maxRegistryValueSize = 64 * 1024
	maxDriverServices    = 4096
)

var advapi32Spyware = syscall.NewLazyDLL("advapi32.dll")
var kernel32Spyware = syscall.NewLazyDLL("kernel32.dll")
var procRegNotifyChangeKeyValue = advapi32Spyware.NewProc("RegNotifyChangeKeyValue")
var procCreateEventW = kernel32Spyware.NewProc("CreateEventW")
var procWaitForSingleObject = kernel32Spyware.NewProc("WaitForSingleObject")

const (
	waitObject0       = 0
	waitInfinite      = 0xFFFFFFFF
	regNotifyChange   = 0x1 | 0x2 | 0x4 // name, attributes, last set
	regNotifySubtree  = 1
	regNotifyAsyncOff = 0
)

// ReadCapabilityStates reads the current capability-access consent store for the
// capabilities this package monitors. Both machine and user hives are read
// because Windows records packaged and unpackaged usage in both. A missing area
// is not an error (the capability may simply never have been used).
func ReadCapabilityStates() ([]CapabilityState, error) {
	var states []CapabilityState
	var firstErr error
	capabilities := []string{
		CapabilityWebcam,
		CapabilityMicrophone,
		CapabilityGraphicsCapture,
		CapabilityLocation,
	}
	const consentRoot = `SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`
	for _, capability := range capabilities {
		for _, hive := range []struct {
			root syscall.Handle
			name string
		}{{syscall.HKEY_LOCAL_MACHINE, "HKLM"}, {syscall.HKEY_CURRENT_USER, "HKCU"}} {
			path := consentRoot + `\` + capability + `\NonPackaged`
			entries, err := readCapabilityArea(hive.root, path, capability)
			if err != nil {
				if !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) && firstErr == nil {
					firstErr = fmt.Errorf("read capability consent %s: %w", capability, err)
				}
				continue
			}
			states = append(states, entries...)
			if len(states) > maxRegistrySubkeys*4 {
				return states, firstErr
			}
		}
	}
	return states, firstErr
}

func readCapabilityArea(hive syscall.Handle, path, capability string) ([]CapabilityState, error) {
	key, err := openRegistryKey(hive, path)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(key)
	var states []CapabilityState
	for index := uint32(0); index < maxRegistrySubkeys; index++ {
		name, err := enumRegistryKey(key, index)
		if err != nil {
			break
		}
		child, err := openRegistryKey(key, name)
		if err != nil {
			continue
		}
		start, startErr := readRegistryQWORD(child, "LastUsedTimeStart")
		stop, stopErr := readRegistryQWORD(child, "LastUsedTimeStop")
		syscall.RegCloseKey(child)
		if startErr != nil && stopErr != nil {
			continue
		}
		states = append(states, CapabilityState{
			Capability: capability,
			Path:       decodeConsentKeyPath(name),
			Start:      start,
			Stop:       stop,
		})
		if len(states) >= maxRegistrySubkeys {
			break
		}
	}
	return states, nil
}

// decodeConsentKeyPath turns the registry key form "C:#Users#alice#app.exe" (or
// a packaged identity) back into a path for the allowlist decision. It is
// display/decision data only and is bounded.
func decodeConsentKeyPath(key string) string {
	decoded := strings.TrimSpace(key)
	if len(decoded) > 2048 {
		decoded = decoded[:2048]
	}
	if strings.Count(decoded, "#") >= 2 {
		decoded = strings.ReplaceAll(decoded, "#", `\`)
	}
	return decoded
}

// EnumerateDriverServices reads every kernel service under
// HKLM\SYSTEM\CurrentControlSet\Services. It is bounded and skips entries that
// are not kernel drivers.
func EnumerateDriverServices() ([]DriverService, error) {
	root, err := openRegistryKey(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`)
	if err != nil {
		return nil, fmt.Errorf("open services registry: %w", err)
	}
	defer syscall.RegCloseKey(root)
	systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	services := make([]DriverService, 0, 256)
	for index := uint32(0); index < maxRegistrySubkeys; index++ {
		name, err := enumRegistryKey(root, index)
		if err != nil {
			break
		}
		child, err := openRegistryKey(root, name)
		if err != nil {
			continue
		}
		serviceType, typeErr := readRegistryDWORD(child, "Type")
		start, _ := readRegistryDWORD(child, "Start")
		imagePath, _ := readRegistryString(child, "ImagePath")
		syscall.RegCloseKey(child)
		if typeErr != nil {
			continue
		}
		service := DriverService{
			Name:      name,
			Type:      serviceType,
			Start:     start,
			ImagePath: expandRegistryImagePath(imagePath, systemRoot),
		}
		if !service.IsKernelDriver() {
			continue
		}
		services = append(services, service)
		if len(services) >= maxDriverServices {
			break
		}
	}
	return services, nil
}

// ReadSecurityPosture reads the two host settings that decide whether a
// vulnerable driver is a live risk.
func ReadSecurityPosture() (SecurityPosture, error) {
	posture := SecurityPosture{}
	blocklist, blocklistErr := readRegistryDWORDPath(syscall.HKEY_LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\CI\Config`, "VulnerableDriverBlocklistEnable")
	if blocklistErr == nil {
		posture.VulnerableDriverBlocklistEnabled = blocklist == 1
	}
	hvci, hvciErr := readRegistryDWORDPath(syscall.HKEY_LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled")
	if hvciErr == nil {
		posture.HVCIEnabled = hvci == 1
	}
	if blocklistErr != nil && hvciErr != nil {
		return posture, errors.New("security posture settings are unavailable")
	}
	return posture, nil
}

// expandRegistryImagePath resolves the two forms the service registry uses:
// a "\SystemRoot\..." prefix and %SystemRoot% environment strings. The function
// never guesses a drive: it requires an absolute result.
func expandRegistryImagePath(raw, systemRoot string) string {
	value := strings.TrimSpace(strings.Trim(raw, `"`))
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, `\systemroot\`) {
		value = systemRoot + value[len(`\systemroot`):]
	} else if strings.HasPrefix(value, `\??\`) {
		value = value[4:]
	}
	value = expandWindowsEnvironment(value)
	value = strings.TrimSpace(strings.Trim(value, `"`))
	if !filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(value)
}

// expandWindowsEnvironment expands the Windows-style %NAME% form used in the
// service registry as well as the $NAME form understood by os.ExpandEnv. The
// expansion is bounded: an undefined variable is left untouched (so no data is
// invented) and at most eight passes run, so a value cannot expand
// exponentially.
func expandWindowsEnvironment(value string) string {
	value = os.ExpandEnv(value)
	for pass := 0; pass < 8 && strings.Contains(value, "%"); pass++ {
		expanded := false
		for index := 0; index < len(value); index++ {
			if value[index] != '%' {
				continue
			}
			end := strings.IndexByte(value[index+1:], '%')
			if end < 0 {
				break
			}
			name := value[index+1 : index+1+end]
			if name == "" || len(name) > 128 {
				continue
			}
			replacement, found := os.LookupEnv(name)
			if !found {
				continue
			}
			value = value[:index] + replacement + value[index+end+2:]
			expanded = true
			index += len(replacement) - 1
		}
		if !expanded {
			break
		}
	}
	return value
}

// WatchRegistryKey blocks until the given registry key changes or the caller
// signals cancellation. It is the native, event-driven replacement for polling
// the consent store: RegNotifyChangeKeyValue is armed, then the call waits on
// the key event.
func WatchRegistryKey(hive syscall.Handle, path string, ctxDone <-chan struct{}) error {
	key, err := openRegistryKey(hive, path)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	event, _, eventErr := procCreateEventW.Call(0, 1, 0, 0)
	if event == 0 {
		return fmt.Errorf("create registry watch event: %w", eventErr)
	}
	defer syscall.CloseHandle(syscall.Handle(event))
	if result, _, callErr := procRegNotifyChangeKeyValue.Call(
		uintptr(key), regNotifySubtree, regNotifyChange, event, regNotifyAsyncOff,
	); result != 0 {
		return fmt.Errorf("RegNotifyChangeKeyValue: %w", callErr)
	}
	for {
		select {
		case <-ctxDone:
			return errors.New("registry watch cancelled")
		default:
		}
		status, _, _ := procWaitForSingleObject.Call(event, 250)
		if status == waitObject0 {
			return nil
		}
	}
}

func openRegistryKey(root syscall.Handle, subkey string) (syscall.Handle, error) {
	pointer, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, err
	}
	var handle syscall.Handle
	if err := syscall.RegOpenKeyEx(root, pointer, 0, keyRead, &handle); err != nil {
		return 0, err
	}
	return handle, nil
}

func enumRegistryKey(key syscall.Handle, index uint32) (string, error) {
	buffer := make([]uint16, 512)
	length := uint32(len(buffer))
	if err := syscall.RegEnumKeyEx(key, index, &buffer[0], &length, nil, nil, nil, nil); err != nil {
		return "", err
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return "", errors.New("registry subkey name boundary rejected")
	}
	return syscall.UTF16ToString(buffer[:length]), nil
}

func readRegistryString(key syscall.Handle, name string) (string, error) {
	valueType, data, err := readRegistryValue(key, name)
	if err != nil {
		return "", err
	}
	if valueType != syscall.REG_SZ && valueType != syscall.REG_EXPAND_SZ {
		return "", errors.New("registry value is not a string")
	}
	if len(data) < 2 {
		return "", nil
	}
	words := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		word := binary.LittleEndian.Uint16(data[index : index+2])
		if word == 0 {
			break
		}
		words = append(words, word)
	}
	return syscall.UTF16ToString(words), nil
}

func readRegistryDWORD(key syscall.Handle, name string) (uint32, error) {
	valueType, data, err := readRegistryValue(key, name)
	if err != nil {
		return 0, err
	}
	if valueType != syscall.REG_DWORD || len(data) < 4 {
		return 0, errors.New("registry value is not a DWORD")
	}
	return binary.LittleEndian.Uint32(data[:4]), nil
}

func readRegistryQWORD(key syscall.Handle, name string) (uint64, error) {
	valueType, data, err := readRegistryValue(key, name)
	if err != nil {
		return 0, err
	}
	if valueType != syscall.REG_QWORD || len(data) < 8 {
		return 0, errors.New("registry value is not a QWORD")
	}
	return binary.LittleEndian.Uint64(data[:8]), nil
}

func readRegistryDWORDPath(root syscall.Handle, path, name string) (uint32, error) {
	key, err := openRegistryKey(root, path)
	if err != nil {
		return 0, err
	}
	defer syscall.RegCloseKey(key)
	return readRegistryDWORD(key, name)
}

func readRegistryValue(key syscall.Handle, name string) (uint32, []byte, error) {
	pointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	var valueType uint32
	var size uint32
	if err := syscall.RegQueryValueEx(key, pointer, nil, &valueType, nil, &size); err != nil {
		return 0, nil, err
	}
	if size == 0 || size > maxRegistryValueSize {
		return 0, nil, fmt.Errorf("registry value size %d rejected", size)
	}
	buffer := make([]byte, size)
	if err := syscall.RegQueryValueEx(key, pointer, nil, &valueType, &buffer[0], &size); err != nil {
		return 0, nil, err
	}
	if size > uint32(len(buffer)) {
		return 0, nil, errors.New("registry value size changed during read")
	}
	return valueType, buffer[:size], nil
}

// NewHostEngine builds an engine whose driver-signature verifier is the real
// WinVerifyTrust-backed Authenticode check. It is the production constructor for
// the service wiring; tests use New() with an injected verifier.
func NewHostEngine(settings Settings, ledger Ledger) *Engine {
	settings.VerifyDriverSignature = winapi.VerifyAuthenticode
	return New(settings, ledger)
}
