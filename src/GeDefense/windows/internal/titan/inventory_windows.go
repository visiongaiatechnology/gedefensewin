// STATUS: DIAMANT VGT SUPREME
//go:build windows

package titan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	regSz                 = 1
	regExpandSz           = 2
	regDword              = 4
	regMultiSz            = 7
	regQword              = 11
	regRead64             = 0x0100
	maxRegistryValueBytes = 64 << 10
	maxRegistrySubkeys    = 4096
	maxRegistryValues     = 4096
	errorNoMoreItems      = syscall.Errno(259)
)

var (
	advapi32Registry = syscall.NewLazyDLL("advapi32.dll")
	procRegEnumValue = advapi32Registry.NewProc("RegEnumValueW")
)

type registryValue struct {
	Kind  uint32
	Text  string
	DWORD uint32
}

type persistenceBaseline struct {
	SchemaVersion int               `json:"schemaVersion"`
	CreatedUTC    time.Time         `json:"createdUtc"`
	Services      map[string]string `json:"services"`
	RunValues     map[string]string `json:"runValues"`
	Security      map[string]string `json:"security"`
	SecureBoot    string            `json:"secureBoot"`
}

func newPersistenceBaseline() persistenceBaseline {
	return persistenceBaseline{SchemaVersion: 1, CreatedUTC: time.Now().UTC(),
		Services: map[string]string{}, RunValues: map[string]string{}, Security: map[string]string{}}
}

func (b persistenceBaseline) validate() error {
	if b.SchemaVersion != 1 || b.Services == nil || b.RunValues == nil || b.Security == nil {
		return errors.New("titan baseline invariant rejected")
	}
	if len(b.Services) > 4096 || len(b.RunValues) > 4096 || len(b.Security) > 128 {
		return errors.New("titan baseline size rejected")
	}
	return nil
}

func (e *Engine) baselinePath() string { return filepath.Join(e.root, "baseline.json") }

func (e *Engine) loadBaseline() (persistenceBaseline, error) {
	raw, err := os.ReadFile(e.baselinePath())
	if errors.Is(err, os.ErrNotExist) {
		return persistenceBaseline{}, os.ErrNotExist
	}
	if err != nil {
		return persistenceBaseline{}, err
	}
	if len(raw) == 0 || len(raw) > 2<<20 {
		return persistenceBaseline{}, errors.New("titan baseline size rejected")
	}
	var baseline persistenceBaseline
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return persistenceBaseline{}, err
	}
	if err := baseline.validate(); err != nil {
		return persistenceBaseline{}, err
	}
	normalizeBaselineServices(&baseline)
	return baseline, nil
}

func (e *Engine) saveBaseline(baseline persistenceBaseline) error {
	payload, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	return atomicWriteFile(e.baselinePath(), append(payload, '\n'))
}

func registryOpen(root syscall.Handle, path string, access uint32) (syscall.Handle, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var handle syscall.Handle
	if err := syscall.RegOpenKeyEx(root, pointer, 0, access, &handle); err != nil {
		return 0, err
	}
	return handle, nil
}

func registryEnumSubkeys(root syscall.Handle, path string) ([]string, error) {
	var handle syscall.Handle
	if path == "" {
		handle = root
	} else {
		opened, err := registryOpen(root, path, syscall.KEY_READ|regRead64)
		if err != nil {
			return nil, err
		}
		handle = opened
		defer func() { _ = syscall.RegCloseKey(handle) }()
	}
	names := make([]string, 0, 32)
	for index := uint32(0); ; index++ {
		buffer := make([]uint16, 512)
		size := uint32(len(buffer))
		err := syscall.RegEnumKeyEx(handle, index, &buffer[0], &size, nil, nil, nil, nil)
		if errors.Is(err, errorNoMoreItems) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			break
		}
		if err != nil {
			return nil, err
		}
		if size == 0 || size > uint32(len(buffer)) {
			return nil, errors.New("registry subkey name boundary rejected")
		}
		names = append(names, syscall.UTF16ToString(buffer[:size]))
		if len(names) > maxRegistrySubkeys {
			return nil, errors.New("registry subkey count boundary exceeded")
		}
	}
	sort.Strings(names)
	return names, nil
}

func registryQueryValue(root syscall.Handle, path, name string) (registryValue, bool, error) {
	handle, err := registryOpen(root, path, syscall.KEY_READ|regRead64)
	if err != nil {
		return registryValue{}, false, err
	}
	defer func() { _ = syscall.RegCloseKey(handle) }()
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return registryValue{}, false, err
	}
	var valueType uint32
	var size uint32
	if err := syscall.RegQueryValueEx(handle, namePointer, nil, &valueType, nil, &size); err != nil {
		return registryValue{}, false, err
	}
	if size > maxRegistryValueBytes {
		return registryValue{}, false, errors.New("registry value size boundary rejected")
	}
	buffer := make([]byte, size+2)
	if err := syscall.RegQueryValueEx(handle, namePointer, nil, &valueType, &buffer[0], &size); err != nil {
		return registryValue{}, false, err
	}
	value := registryValue{Kind: valueType}
	switch valueType {
	case regSz, regExpandSz:
		value.Text = decodeRegistryString(buffer[:size])
	case regMultiSz:
		value.Text = strings.Join(decodeRegistryMultiString(buffer[:size]), " | ")
	case regDword:
		if len(buffer) >= 4 {
			value.DWORD = binary.LittleEndian.Uint32(buffer[:4])
			value.Text = fmt.Sprintf("%d", value.DWORD)
		}
	case regQword:
		if len(buffer) >= 8 {
			value.DWORD = uint32(binary.LittleEndian.Uint64(buffer[:8]))
			value.Text = fmt.Sprintf("%d", binary.LittleEndian.Uint64(buffer[:8]))
		}
	default:
		value.Text = fmt.Sprintf("binary:%d", size)
	}
	return value, true, nil
}

func decodeRegistryString(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		unit := binary.LittleEndian.Uint16(raw[index : index+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return syscall.UTF16ToString(units)
}

func decodeRegistryMultiString(raw []byte) []string {
	result := make([]string, 0, 8)
	start := 0
	for index := 0; index+1 < len(raw); index += 2 {
		if binary.LittleEndian.Uint16(raw[index:index+2]) != 0 {
			continue
		}
		if index > start {
			result = append(result, decodeRegistryString(raw[start:index]))
		}
		start = index + 2
	}
	return result
}

func registryEnumValues(root syscall.Handle, path string) (map[string]registryValue, error) {
	handle, err := registryOpen(root, path, syscall.KEY_READ|regRead64)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.RegCloseKey(handle) }()
	values := make(map[string]registryValue)
	for index := uint32(0); ; index++ {
		nameBuffer := make([]uint16, 512)
		nameSize := uint32(len(nameBuffer))
		dataBuffer := make([]byte, maxRegistryValueBytes)
		dataSize := uint32(len(dataBuffer))
		var valueType uint32
		result, _, callErr := procRegEnumValue.Call(uintptr(handle), uintptr(index),
			uintptr(unsafe.Pointer(&nameBuffer[0])), uintptr(unsafe.Pointer(&nameSize)), 0,
			uintptr(unsafe.Pointer(&valueType)), uintptr(unsafe.Pointer(&dataBuffer[0])), uintptr(unsafe.Pointer(&dataSize)))
		if result == 258 {
			break
		}
		if result != 0 {
			return nil, fmt.Errorf("RegEnumValueW failed with status %d: %w", result, callErr)
		}
		if nameSize == 0 || nameSize > uint32(len(nameBuffer)) || dataSize > uint32(len(dataBuffer)) {
			return nil, errors.New("registry value enumeration boundary rejected")
		}
		name := syscall.UTF16ToString(nameBuffer[:nameSize])
		raw := dataBuffer[:dataSize]
		value := registryValue{Kind: valueType}
		switch valueType {
		case regSz, regExpandSz:
			value.Text = decodeRegistryString(raw)
		case regMultiSz:
			value.Text = strings.Join(decodeRegistryMultiString(raw), " | ")
		case regDword:
			if len(raw) >= 4 {
				value.DWORD = binary.LittleEndian.Uint32(raw[:4])
				value.Text = fmt.Sprintf("%d", value.DWORD)
			}
		case regQword:
			if len(raw) >= 8 {
				value.Text = fmt.Sprintf("%d", binary.LittleEndian.Uint64(raw[:8]))
			}
		default:
			value.Text = fmt.Sprintf("binary:%d", len(raw))
		}
		values[name] = value
		if len(values) > maxRegistryValues {
			return nil, errors.New("registry value count boundary exceeded")
		}
	}
	return values, nil
}

func collectServices() map[string]string {
	services := make(map[string]string)
	names, err := registryEnumSubkeys(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`)
	if err != nil {
		return services
	}
	for _, name := range names {
		path := `SYSTEM\CurrentControlSet\Services\` + name
		imagePath, _, imageErr := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, path, "ImagePath")
		start, _, startErr := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, path, "Start")
		serviceType, _, typeErr := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, path, "Type")
		objectName, _, objectErr := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, path, "ObjectName")
		if errors.Is(imageErr, syscall.ERROR_FILE_NOT_FOUND) && errors.Is(startErr, syscall.ERROR_FILE_NOT_FOUND) && errors.Is(typeErr, syscall.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if objectErr != nil && !errors.Is(objectErr, syscall.ERROR_FILE_NOT_FOUND) {
			continue
		}
		fingerprint := normalizeServiceFingerprint(imagePath.Text, start.Text, serviceType.Text, objectName.Text)
		services[name] = fingerprint
	}
	return services
}

// normalizeServiceFingerprint removes representation-only drift such as
// %SystemRoot% vs C:\Windows and casing. Security-relevant value changes still
// produce a different fingerprint.
func normalizeServiceFingerprint(parts ...string) string {
	normalized := make([]string, len(parts))
	for index, part := range parts {
		value := strings.ToLower(strings.TrimSpace(part))
		value = strings.Trim(value, `"`)
		value = strings.ReplaceAll(value, `\??\c:\windows`, `%systemroot%`)
		value = strings.ReplaceAll(value, `c:\windows`, `%systemroot%`)
		normalized[index] = strings.Join(strings.Fields(value), " ")
	}
	return strings.Join(normalized, "|")
}

func normalizeBaselineServices(baseline *persistenceBaseline) {
	for name, value := range baseline.Services {
		parts := strings.Split(value, "|")
		if len(parts) != 4 {
			continue
		}
		baseline.Services[name] = normalizeServiceFingerprint(parts...)
	}
}

// serviceChange identifies what actually differed in a service fingerprint.
// Windows servicing may toggle BITS between Automatic and Manual without
// changing ImagePath, service type or account. That is maintenance noise, not
// a planted persistence mechanism.
func serviceChange(previous, current string) string {
	before := strings.Split(previous, "|")
	after := strings.Split(current, "|")
	if len(before) != 4 || len(after) != 4 {
		return "OTHER"
	}
	var changed []int
	for index := 0; index < 4; index++ {
		if before[index] != after[index] {
			changed = append(changed, index)
		}
	}
	if len(changed) != 1 {
		return "OTHER"
	}
	switch changed[0] {
	case 0:
		return "IMAGE_PATH"
	case 1:
		return "START_ONLY"
	case 2:
		return "SERVICE_TYPE"
	case 3:
		return "ACCOUNT"
	default:
		return "OTHER"
	}
}

func collectRunValues() map[string]string {
	result := make(map[string]string)
	type runKey struct {
		root syscall.Handle
		path string
		view string
	}
	keys := []runKey{
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM64"},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM32"},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM64-RUNONCE"},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM32-RUNONCE"},
	}
	userHives, err := registryEnumSubkeys(syscall.HKEY_USERS, ``)
	if err == nil {
		for _, sid := range userHives {
			if strings.HasSuffix(strings.ToLower(sid), "_classes") || !strings.HasPrefix(strings.ToUpper(sid), "S-1-") {
				continue
			}
			keys = append(keys,
				runKey{syscall.HKEY_USERS, sid + `\Software\Microsoft\Windows\CurrentVersion\Run`, "HKU:" + sid},
				runKey{syscall.HKEY_USERS, sid + `\Software\Microsoft\Windows\CurrentVersion\RunOnce`, "HKU:" + sid + "-RUNONCE"})
		}
	}
	for _, key := range keys {
		values, err := registryEnumValues(key.root, key.path)
		if err != nil {
			continue
		}
		for name, value := range values {
			result[key.view+"\\"+name] = value.Text
		}
	}
	return result
}

func collectSecurityControls() ([]SecurityControl, map[string]string) {
	type definition struct {
		id, label, path, value, expected string
		secureFn                         func(registryValue, bool) bool
		severity                         Severity
	}
	defs := []definition{
		{"defender-disable-antispyware", "Defender Antivirus nicht per Policy deaktiviert", `SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", "0 oder nicht gesetzt", func(v registryValue, exists bool) bool { return !exists || v.DWORD == 0 }, SeverityCritical},
		{"defender-disable-realtime", "Defender Echtzeitschutz nicht per Policy deaktiviert", `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", "0 oder nicht gesetzt", func(v registryValue, exists bool) bool { return !exists || v.DWORD == 0 }, SeverityCritical},
		{"firewall-domain", "Windows Firewall Domainprofil aktiv", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`, "EnableFirewall", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityCritical},
		{"firewall-private", "Windows Firewall privates Profil aktiv", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, "EnableFirewall", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityCritical},
		{"firewall-public", "Windows Firewall öffentliches Profil aktiv", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`, "EnableFirewall", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityCritical},
		{"lsa-runasppl", "LSA-Schutz als Protected Process", `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL", "1 oder 2", func(v registryValue, exists bool) bool { return exists && v.DWORD >= 1 }, SeverityHigh},
		{"uac-enablelua", "UAC aktiviert", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityHigh},
		{"smb1-disabled", "SMBv1 nicht aktiv", `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1", "0 oder nicht gesetzt", func(v registryValue, exists bool) bool { return !exists || v.DWORD == 0 }, SeverityHigh},
		{"rdp-disabled", "Remote Desktop nicht unnötig freigegeben", `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityHigh},
		{"powershell-logging", "PowerShell ScriptBlock-Logging aktiv", `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging", "1", func(v registryValue, exists bool) bool { return exists && v.DWORD == 1 }, SeverityMedium},
	}
	controls := make([]SecurityControl, 0, len(defs))
	fingerprints := make(map[string]string, len(defs))
	for _, def := range defs {
		value, exists, err := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, def.path, def.value)
		if err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			controls = append(controls, SecurityControl{ID: def.id, Label: def.label, Value: "NICHT MESSBAR", Expected: def.expected, Secure: false, Severity: def.severity})
			fingerprints[def.id] = "unreadable"
			continue
		}
		secure := def.secureFn(value, exists)
		display := "nicht gesetzt"
		if exists {
			display = value.Text
		}
		controls = append(controls, SecurityControl{ID: def.id, Label: def.label, Value: display, Expected: def.expected, Secure: secure, Severity: def.severity})
		fingerprints[def.id] = fmt.Sprintf("%t|%s", secure, display)
	}
	return controls, fingerprints
}

func secureBootState() (*bool, string) {
	value, exists, err := registryQueryValue(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	if err != nil || !exists {
		return nil, "Secure-Boot-Status nicht lesbar; keine Vertrauensbehauptung möglich."
	}
	enabled := value.DWORD == 1
	detail := "Secure Boot ist deaktiviert."
	if enabled {
		detail = "Secure Boot ist aktiv; gemessener Start und TPM-Attestation sind in dieser Phase nicht behauptet."
	}
	return &enabled, detail
}

func (e *Engine) scanPersistence(ctx context.Context) {
	e.markSensor("persistence", SensorDegraded, "Persistenz-Inventar wird aufgebaut.")
	recordFailed := false
	record := func(observation Observation) {
		if err := e.record(observation); err != nil {
			recordFailed = true
		}
	}
	baseline, err := e.loadBaseline()
	if errors.Is(err, os.ErrNotExist) {
		baseline = newPersistenceBaseline()
		baseline.Services = collectServices()
		baseline.RunValues = collectRunValues()
		controls, fingerprints := collectSecurityControls()
		baseline.Security = fingerprints
		e.setSecurityControls(controls)
		secure, bootDetail := secureBootState()
		if secure != nil {
			baseline.SecureBoot = fmt.Sprintf("%t", *secure)
		}
		e.setBootTrust(BootTrust{SecureBoot: secure, MeasuredBoot: false, CheckedUTC: time.Now().UTC(), Detail: bootDetail})
		if saveErr := e.saveBaseline(baseline); saveErr != nil {
			e.markSensor("persistence", SensorDegraded, "Baseline konnte nicht gespeichert werden.")
			return
		}
		e.appendSelfIntegrity("BASELINE_CREATED", "Persistenz- und Sicherheitsbaseline wurde ohne Alarmierung angelegt.", SeverityLow, TrustTolerated)
		e.markSensor("persistence", SensorHealthy, "")
		e.markSensor("security", SensorHealthy, "")
		e.markSensor("boot", SensorHealthy, "")
		return
	}
	if err != nil {
		e.markSensor("persistence", SensorDegraded, "Baseline ist beschädigt und wird nicht als gesund interpretiert.")
		e.appendSelfIntegrity("BASELINE_INVALID", err.Error(), SeverityHigh, TrustCompromised)
		return
	}
	if ctx.Err() != nil {
		return
	}
	currentServices := collectServices()
	currentRun := collectRunValues()
	controls, currentSecurity := collectSecurityControls()
	e.setSecurityControls(controls)
	currentBoot := ""
	if secure, _ := secureBootState(); secure != nil {
		currentBoot = fmt.Sprintf("%t", *secure)
	}
	changed := false
	for name, current := range currentServices {
		previous, exists := baseline.Services[name]
		if !exists {
			changed = true
			record(Observation{Type: EventPersistenceAdded, Severity: SeverityHigh,
				Object: Object{Kind: ObjectService, Path: `HKLM\SYSTEM\CurrentControlSet\Services\` + name, Name: name, SHA256: fingerprintSHA(current)},
				Source: "titan-persistence", Health: "HEALTHY"})
			continue
		}
		if previous != current {
			changed = true
			record(Observation{Type: EventPersistenceChanged, Severity: SeverityMedium,
				Object: Object{Kind: ObjectService, Path: `HKLM\SYSTEM\CurrentControlSet\Services\` + name, Name: name, SHA256: fingerprintSHA(current), Change: serviceChange(previous, current)},
				Source: "titan-persistence", Health: "HEALTHY"})
		}
	}
	for name := range baseline.Services {
		if _, exists := currentServices[name]; !exists {
			changed = true
			record(Observation{Type: EventPersistenceRemoved, Severity: SeverityMedium,
				Object: Object{Kind: ObjectService, Path: `HKLM\SYSTEM\CurrentControlSet\Services\` + name, Name: name},
				Source: "titan-persistence", Health: "HEALTHY"})
		}
	}
	for name, current := range currentRun {
		previous, exists := baseline.RunValues[name]
		if !exists || previous != current {
			changed = true
			record(Observation{Type: EventPersistenceAdded, Severity: SeverityHigh,
				Object: Object{Kind: ObjectRegistryValue, Path: name, Name: name, SHA256: fingerprintSHA(current)},
				Source: "titan-persistence", Health: "HEALTHY"})
		}
	}
	for name := range baseline.RunValues {
		if _, exists := currentRun[name]; !exists {
			changed = true
			record(Observation{Type: EventPersistenceRemoved, Severity: SeverityMedium,
				Object: Object{Kind: ObjectRegistryValue, Path: name, Name: name},
				Source: "titan-persistence", Health: "HEALTHY"})
		}
	}
	for id, current := range currentSecurity {
		previous, exists := baseline.Security[id]
		if !exists {
			baseline.Security[id] = current
			continue
		}
		if previous == current {
			continue
		}
		changed = true
		severity := SeverityHigh
		eventType := EventSecurityChanged
		if strings.HasPrefix(previous, "true|") && strings.HasPrefix(current, "false|") {
			severity = SeverityCritical
			eventType = EventSecurityDowngrade
		}
		record(Observation{Type: eventType, Severity: severity,
			Object: Object{Kind: ObjectRegistryValue, Path: "security-control://" + id, Name: id, SHA256: fingerprintSHA(current)},
			Source: "titan-security", Health: "HEALTHY"})
	}
	if baseline.SecureBoot != "" && currentBoot != "" && baseline.SecureBoot != currentBoot {
		changed = true
		record(Observation{Type: EventBootChanged, Severity: SeverityCritical,
			Object: Object{Kind: ObjectBoot, Path: "uefi://secureboot", Name: "SecureBoot", SHA256: fingerprintSHA(currentBoot)},
			Source: "titan-boot", Health: "HEALTHY"})
	}
	if changed && !recordFailed {
		baseline.Services = currentServices
		baseline.RunValues = currentRun
		baseline.Security = currentSecurity
		if currentBoot != "" {
			baseline.SecureBoot = currentBoot
		}
		baseline.CreatedUTC = time.Now().UTC()
		if err := e.saveBaseline(baseline); err != nil {
			e.markSensor("persistence", SensorDegraded, "Aktualisierte Baseline konnte nicht gespeichert werden.")
			return
		}
	}
	if recordFailed {
		e.markSensor("persistence", SensorDegraded, "Mindestens eine Änderung konnte nicht in die Evidenzkette geschrieben werden; die Baseline wurde bewusst nicht fortgeschrieben.")
		return
	}
	secureBoot, detail := secureBootState()
	tpm := (*bool)(nil)
	e.setBootTrust(BootTrust{SecureBoot: secureBoot, TPM: tpm, MeasuredBoot: false, CheckedUTC: time.Now().UTC(), Detail: detail})
	e.markSensor("persistence", SensorHealthy, "")
	e.markSensor("security", SensorHealthy, "")
	e.markSensor("boot", SensorHealthy, "")
	e.sensorEvent("persistence")
}

func fingerprintSHA(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func (e *Engine) runPersistenceLoop(ctx context.Context) {
	e.sensorWG.Add(1)
	go func() {
		defer e.sensorWG.Done()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				e.scanPersistence(ctx)
				timer.Reset(time.Minute)
			}
		}
	}()
}
