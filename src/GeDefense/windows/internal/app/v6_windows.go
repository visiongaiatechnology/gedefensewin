// STATUS: PLATIN VGT SUPREME
//go:build windows

package app

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/visiongaiatechnology/gedefense/windows/internal/spyware"
	"github.com/visiongaiatechnology/gedefense/windows/internal/winapi"
)

// BootPosture measures the hardware boot & firmware posture (TPM 2.0, TCG WBCL,
// Secure Boot, VBS/HVCI) for the V6 Sovereign status projection.
func (r *v6Runtime) BootPosture() winapi.BootPosture {
	posture, _ := winapi.MeasureBootPosture()
	return posture
}

type hostLSASSEvent struct {
	AccessMask      uint32
	CallerImage     string
	CallerSignature string
}

var (
	user32App = syscall.NewLazyDLL("user32.dll")
	wevtapi   = syscall.NewLazyDLL("wevtapi.dll")

	procOpenInputDesktop          = user32App.NewProc("OpenInputDesktop")
	procCloseDesktop              = user32App.NewProc("CloseDesktop")
	procGetUserObjectInformationW = user32App.NewProc("GetUserObjectInformationW")

	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")

	lsassSeenMu sync.Mutex
	lsassSeen   = make(map[string]struct{}, 128)
)

const (
	desktopReadObjects       = 0x0001
	uoiName                  = 2
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXml        = 1
	maxLSASSEventsPerPoll    = 32
)

func readHostCapabilityStates() ([]spyware.CapabilityState, error) {
	return spyware.ReadCapabilityStates()
}

func readHostDriverServices() ([]spyware.DriverService, error) {
	return spyware.EnumerateDriverServices()
}

func readHostSecurityPosture() (spyware.SecurityPosture, error) {
	return spyware.ReadSecurityPosture()
}

// probeHostWorkstationLock checks the active input desktop honestly. A service
// running in Session 0 normally receives ACCESS_DENIED and reports UNAVAILABLE
// with locked=false so capability findings assume the desktop may be active.
func probeHostWorkstationLock() (bool, string) {
	desktop, _, _ := procOpenInputDesktop.Call(0, 0, desktopReadObjects)
	if desktop == 0 {
		return false, v6LockUnavailable
	}
	defer procCloseDesktop.Call(desktop)

	var buf [128]uint16
	var needed uint32
	ok, _, _ := procGetUserObjectInformationW.Call(
		desktop, uoiName,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ok == 0 {
		return false, v6LockUnavailable
	}
	name := strings.ToLower(strings.TrimSpace(syscall.UTF16ToString(buf[:])))
	if name == "" {
		return false, v6LockUnavailable
	}
	if name == "winlogon" || name == "screen-saver" {
		return true, v6LockLocked
	}
	return false, v6LockUnlocked
}

func readHostPersistenceObservations() ([]spyware.PersistenceObservation, error) {
	now := time.Now().UTC()
	var result []spyware.PersistenceObservation
	var firstErr error

	recordErr := func(err error) {
		if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) && firstErr == nil {
			firstErr = err
		}
	}

	// AppInit_DLLs & LSA packages
	for _, spec := range []struct {
		kind spyware.PersistenceKind
		path string
		name string
	}{
		{spyware.PersistenceAppInitDLLs, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs"},
		{spyware.PersistenceLSAPackages, `SYSTEM\CurrentControlSet\Control\Lsa`, "Security Packages"},
		{spyware.PersistenceLSAPackages, `SYSTEM\CurrentControlSet\Control\Lsa`, "Notification Packages"},
	} {
		vals, err := readRegStringList(syscall.HKEY_LOCAL_MACHINE, spec.path, spec.name)
		recordErr(err)
		for _, v := range vals {
			result = append(result, spyware.PersistenceObservation{
				Kind: spec.kind, KeyPath: `HKLM\` + spec.path, ValueName: spec.name, ValueData: v, ObservedUTC: now,
			})
			if len(result) >= maxPersistencePerScan {
				return result, firstErr
			}
		}
	}

	// IFEO Debugger values
	const ifeoPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	if err := scanSubkeyValue(syscall.HKEY_LOCAL_MACHINE, ifeoPath, "Debugger", spyware.PersistenceIFEO, now, &result); err != nil {
		recordErr(err)
	}
	// SilentProcessExit MonitorProcess values
	const silentPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	if err := scanSubkeyValue(syscall.HKEY_LOCAL_MACHINE, silentPath, "MonitorProcess", spyware.PersistenceSilentProcessExit, now, &result); err != nil {
		recordErr(err)
	}
	// Print Monitors Driver values
	const printPath = `SYSTEM\CurrentControlSet\Control\Print\Monitors`
	if err := scanSubkeyValue(syscall.HKEY_LOCAL_MACHINE, printPath, "Driver", spyware.PersistencePrintMonitor, now, &result); err != nil {
		recordErr(err)
	}
	// AppCertDlls arbitrary named values
	const appCertPath = `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`
	if err := scanAllStringValues(syscall.HKEY_LOCAL_MACHINE, appCertPath, spyware.PersistenceAppCertDLLs, now, &result); err != nil {
		recordErr(err)
	}

	return result, firstErr
}

// pollHostLSASSAccessEvents probes Security channel readability for 4656/4663.
// If the Security log requires SeSecurityPrivilege and denies access, it reports
// the real OS boundary error instead of claiming healthy coverage.
func pollHostLSASSAccessEvents(ctx context.Context) ([]hostLSASSEvent, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	channelPtr, err := syscall.UTF16PtrFromString("Security")
	if err != nil {
		return nil, err
	}
	queryPtr, err := syscall.UTF16PtrFromString(`*[System[(EventID=4656 or EventID=4663)]]`)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if handle == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, errors.New("Security event log query unavailable")
	}
	defer procEvtClose.Call(handle)

	var eventHandles [maxLSASSEventsPerPoll]uintptr
	var returned uint32
	rNext, _, _ := procEvtNext.Call(
		handle,
		uintptr(len(eventHandles)),
		uintptr(unsafe.Pointer(&eventHandles[0])),
		0, 0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if rNext == 0 || returned == 0 {
		return nil, nil
	}
	if int(returned) > len(eventHandles) {
		returned = uint32(len(eventHandles))
	}
	var out []hostLSASSEvent
	for i := uint32(0); i < returned; i++ {
		eh := eventHandles[i]
		if eh == 0 {
			continue
		}
		xmlText := renderLSASSEventXML(eh)
		_, _, _ = procEvtClose.Call(eh)
		if xmlText == "" {
			continue
		}
		if ev, key, ok := parseLSASSEventXML(xmlText); ok {
			lsassSeenMu.Lock()
			if len(lsassSeen) > 2048 {
				lsassSeen = make(map[string]struct{}, 128)
			}
			_, dup := lsassSeen[key]
			if !dup {
				lsassSeen[key] = struct{}{}
			}
			lsassSeenMu.Unlock()
			if !dup {
				out = append(out, ev)
			}
		}
	}
	return out, nil
}

func renderLSASSEventXML(eventHandle uintptr) string {
	var used, count uint32
	_, _, _ = procEvtRender.Call(0, eventHandle, evtRenderEventXml, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if used == 0 || used > 32<<10 {
		return ""
	}
	buf := make([]byte, used)
	ok, _, _ := procEvtRender.Call(0, eventHandle, evtRenderEventXml, uintptr(used), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return ""
	}
	words := make([]uint16, len(buf)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(buf[i*2 : i*2+2])
	}
	return syscall.UTF16ToString(words)
}

func parseLSASSEventXML(xmlText string) (hostLSASSEvent, string, bool) {
	if !strings.Contains(strings.ToLower(xmlText), "lsass.exe") {
		return hostLSASSEvent{}, "", false
	}
	processName := extractXMLDataValue(xmlText, "ProcessName")
	if processName == "" {
		return hostLSASSEvent{}, "", false
	}
	accessStr := strings.TrimSpace(extractXMLDataValue(xmlText, "AccessMask"))
	if accessStr == "" {
		return hostLSASSEvent{}, "", false
	}
	parsedMask, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(accessStr), "0x"), 16, 32)
	if err != nil {
		return hostLSASSEvent{}, "", false
	}
	recID := extractXMLTagText(xmlText, "EventRecordID")
	return hostLSASSEvent{
		AccessMask:      uint32(parsedMask),
		CallerImage:     processName,
		CallerSignature: "unverified",
	}, recID + "|" + processName + "|" + accessStr, true
}

func extractXMLDataValue(xmlText, field string) string {
	marker := `Name='` + field + `'>`
	idx := strings.Index(xmlText, marker)
	if idx < 0 {
		marker = `Name="` + field + `">`
		idx = strings.Index(xmlText, marker)
	}
	if idx < 0 {
		return ""
	}
	rest := xmlText[idx+len(marker):]
	end := strings.Index(rest, "</Data>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func extractXMLTagText(xmlText, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(xmlText, openTag)
	if start < 0 {
		return ""
	}
	rest := xmlText[start+len(openTag):]
	end := strings.Index(rest, closeTag)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func scanSubkeyValue(root syscall.Handle, subkey, valueName string, kind spyware.PersistenceKind, now time.Time, out *[]spyware.PersistenceObservation) error {
	key, err := openWinRegKey(root, subkey)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	for index := uint32(0); index < maxPersistencePerScan && len(*out) < maxPersistencePerScan; index++ {
		name, err := enumWinSubkey(key, index)
		if err != nil {
			break
		}
		child, err := openWinRegKey(key, name)
		if err != nil {
			continue
		}
		vals, _ := readKeyValueStrings(child, valueName)
		_ = syscall.RegCloseKey(child)
		for _, val := range vals {
			*out = append(*out, spyware.PersistenceObservation{
				Kind: kind, KeyPath: filepath.Join(`HKLM`, subkey, name), ValueName: valueName, ValueData: val, ObservedUTC: now,
			})
			if len(*out) >= maxPersistencePerScan {
				break
			}
		}
	}
	return nil
}

func scanAllStringValues(root syscall.Handle, subkey string, kind spyware.PersistenceKind, now time.Time, out *[]spyware.PersistenceObservation) error {
	key, err := openWinRegKey(root, subkey)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	for index := uint32(0); index < maxPersistencePerScan && len(*out) < maxPersistencePerScan; index++ {
		var nameBuf [256]uint16
		nameLen := uint32(len(nameBuf))
		var dataBuf [2048]byte
		dataLen := uint32(len(dataBuf))
		var valType uint32
		r1, _, _ := procRegEnumValueW.Call(
			uintptr(key), uintptr(index),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
			0, uintptr(unsafe.Pointer(&valType)),
			uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataLen)),
		)
		if r1 != 0 {
			break
		}
		if valType != syscall.REG_SZ && valType != syscall.REG_EXPAND_SZ {
			continue
		}
		name := syscall.UTF16ToString(nameBuf[:nameLen])
		for _, v := range decodeUTF16Strings(dataBuf[:dataLen], valType) {
			*out = append(*out, spyware.PersistenceObservation{
				Kind: kind, KeyPath: `HKLM\` + subkey, ValueName: name, ValueData: v, ObservedUTC: now,
			})
		}
	}
	return nil
}

var (
	advapi32App       = syscall.NewLazyDLL("advapi32.dll")
	procRegEnumValueW = advapi32App.NewProc("RegEnumValueW")
)

func openWinRegKey(root syscall.Handle, path string) (syscall.Handle, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var handle syscall.Handle
	if err := syscall.RegOpenKeyEx(root, ptr, 0, syscall.KEY_READ, &handle); err != nil {
		return 0, err
	}
	return handle, nil
}

func enumWinSubkey(key syscall.Handle, index uint32) (string, error) {
	var buf [512]uint16
	size := uint32(len(buf))
	if err := syscall.RegEnumKeyEx(key, index, &buf[0], &size, nil, nil, nil, nil); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

func readRegStringList(root syscall.Handle, path, name string) ([]string, error) {
	key, err := openWinRegKey(root, path)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(key)
	return readKeyValueStrings(key, name)
}

func readKeyValueStrings(key syscall.Handle, name string) ([]string, error) {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var valType, size uint32
	if err := syscall.RegQueryValueEx(key, ptr, nil, &valType, nil, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > 64*1024 {
		return nil, nil
	}
	buf := make([]byte, size)
	if err := syscall.RegQueryValueEx(key, ptr, nil, &valType, &buf[0], &size); err != nil {
		return nil, err
	}
	return decodeUTF16Strings(buf[:size], valType), nil
}

func decodeUTF16Strings(data []byte, valType uint32) []string {
	if len(data) < 2 {
		return nil
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	if valType == syscall.REG_MULTI_SZ {
		var out []string
		start := 0
		for i, w := range words {
			if w == 0 {
				if i > start {
					if s := strings.TrimSpace(syscall.UTF16ToString(words[start:i])); s != "" {
						out = append(out, s)
					}
				}
				start = i + 1
			}
		}
		return out
	}
	if s := strings.TrimSpace(syscall.UTF16ToString(words)); s != "" {
		if valType == syscall.REG_SZ || valType == syscall.REG_EXPAND_SZ {
			return []string{s}
		}
	}
	return nil
}
