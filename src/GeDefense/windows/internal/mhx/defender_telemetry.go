// STATUS: DIAMANT VGT SUPREME
package mhx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	defenderTelemetrySchemaVersion = 1
	// defenderProbeTimeout bounds the read-only Get-Mp* query. The method is
	// called from request goroutines, never from the engine loop.
	defenderProbeTimeout = 10 * time.Second
	// defenderSuccessTTL avoids hammering PowerShell on repeated UI refreshes.
	defenderSuccessTTL = 30 * time.Second
	// defenderFailureTTL retries an unavailable probe sooner while never
	// blocking on it in the caller beyond defenderProbeTimeout.
	defenderFailureTTL = 10 * time.Second
	// maximumDefenderTelemetryBytes bounds the PowerShell JSON response.
	maximumDefenderTelemetryBytes = 96 << 10
)

// OptionalTime distinguishes "the Windows source did not provide this value"
// from the zero timestamp. It always marshals to an explicit null.
type OptionalTime struct {
	Time  time.Time
	Valid bool
}

// UnmarshalJSON accepts a null or an RFC3339 timestamp emitted by the probe.
func (o *OptionalTime) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		o.Time, o.Valid = time.Time{}, false
		return nil
	}
	var raw string
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return errors.New("defender timestamp must be a string or null")
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return errors.New("defender timestamp rejected")
	}
	o.Time, o.Valid = parsed.UTC(), true
	return nil
}

// MarshalJSON renders an unavailable timestamp as explicit null.
func (o OptionalTime) MarshalJSON() ([]byte, error) {
	if !o.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(o.Time.UTC().Format(time.RFC3339Nano))
}

// DefenderASRRule is one real ASR rule ID/action pair. A nil action is an
// explicit unavailable value, never a fabricated block action.
type DefenderASRRule struct {
	ID     string `json:"id"`
	Action *int   `json:"action"`
}

// DefenderComputerStatus mirrors only documented Get-MpComputerStatus fields.
// Every field is a pointer (or OptionalTime) so a missing property is rendered
// as null instead of a zero value that could be mistaken for evidence.
type DefenderComputerStatus struct {
	AMServiceEnabled                *bool        `json:"amServiceEnabled"`
	AMServiceVersion                *string      `json:"amServiceVersion"`
	AMEngineVersion                 *string      `json:"amEngineVersion"`
	AMProductVersion                *string      `json:"amProductVersion"`
	AMRunningMode                   *string      `json:"amRunningMode"`
	AntivirusEnabled                *bool        `json:"antivirusEnabled"`
	AntispywareEnabled              *bool        `json:"antispywareEnabled"`
	BehaviorMonitorEnabled          *bool        `json:"behaviorMonitorEnabled"`
	IoavProtectionEnabled           *bool        `json:"ioavProtectionEnabled"`
	OnAccessProtectionEnabled       *bool        `json:"onAccessProtectionEnabled"`
	RealTimeProtectionEnabled       *bool        `json:"realTimeProtectionEnabled"`
	NISEnabled                      *bool        `json:"nisEnabled"`
	IsTamperProtected               *bool        `json:"isTamperProtected"`
	IsVirtualMachine                *bool        `json:"isVirtualMachine"`
	DefenderSignaturesOutOfDate     *bool        `json:"defenderSignaturesOutOfDate"`
	TamperProtectionSource          *string      `json:"tamperProtectionSource"`
	AntivirusSignatureVersion       *string      `json:"antivirusSignatureVersion"`
	AntispywareSignatureVersion     *string      `json:"antispywareSignatureVersion"`
	NISSignatureVersion             *string      `json:"nisSignatureVersion"`
	NISEngineVersion                *string      `json:"nisEngineVersion"`
	AntivirusSignatureLastUpdated   OptionalTime `json:"antivirusSignatureLastUpdated"`
	AntispywareSignatureLastUpdated OptionalTime `json:"antispywareSignatureLastUpdated"`
	NISSignatureLastUpdated         OptionalTime `json:"nisSignatureLastUpdated"`
	AntivirusSignatureAge           *int         `json:"antivirusSignatureAge"`
	AntispywareSignatureAge         *int         `json:"antispywareSignatureAge"`
	NISSignatureAge                 *int         `json:"nisSignatureAge"`
	QuickScanAge                    *int         `json:"quickScanAge"`
	FullScanAge                     *int         `json:"fullScanAge"`
	QuickScanStartTime              OptionalTime `json:"quickScanStartTime"`
	QuickScanEndTime                OptionalTime `json:"quickScanEndTime"`
	FullScanStartTime               OptionalTime `json:"fullScanStartTime"`
	FullScanEndTime                 OptionalTime `json:"fullScanEndTime"`
	ComputerState                   *int         `json:"computerState"`
}

// DefenderPreferences mirrors only documented Get-MpPreference fields. No
// exclusion path values are exposed; only counts, so the read-only telemetry
// cannot leak operator filesystem layout.
type DefenderPreferences struct {
	DisableRealtimeMonitoring                      *bool             `json:"disableRealtimeMonitoring"`
	DisableBehaviorMonitoring                      *bool             `json:"disableBehaviorMonitoring"`
	DisableIOAVProtection                          *bool             `json:"disableIOAVProtection"`
	DisableScriptScanning                          *bool             `json:"disableScriptScanning"`
	DisableBlockAtFirstSeen                        *bool             `json:"disableBlockAtFirstSeen"`
	DisableArchiveScanning                         *bool             `json:"disableArchiveScanning"`
	DisableEmailScanning                           *bool             `json:"disableEmailScanning"`
	DisableRemovableDriveScanning                  *bool             `json:"disableRemovableDriveScanning"`
	DisableScanningNetworkFiles                    *bool             `json:"disableScanningNetworkFiles"`
	EnableNetworkProtection                        *int              `json:"enableNetworkProtection"`
	PUAProtection                                  *int              `json:"puaProtection"`
	MAPSReporting                                  *int              `json:"mapsReporting"`
	SubmitSamplesConsent                           *int              `json:"submitSamplesConsent"`
	CloudBlockLevel                                *int              `json:"cloudBlockLevel"`
	CloudExtendedTimeout                           *int              `json:"cloudExtendedTimeout"`
	EnableControlledFolderAccess                   *int              `json:"enableControlledFolderAccess"`
	SignatureUpdateInterval                        *int              `json:"signatureUpdateInterval"`
	CheckForSignaturesBeforeRunningScan            *bool             `json:"checkForSignaturesBeforeRunningScan"`
	ScanParameters                                 *int              `json:"scanParameters"`
	ScanAvgCPULoadFactor                           *int              `json:"scanAvgCPULoadFactor"`
	LowThreatDefaultAction                         *int              `json:"lowThreatDefaultAction"`
	ModerateThreatDefaultAction                    *int              `json:"moderateThreatDefaultAction"`
	HighThreatDefaultAction                        *int              `json:"highThreatDefaultAction"`
	SevereThreatDefaultAction                      *int              `json:"severeThreatDefaultAction"`
	UnknownThreatDefaultAction                     *int              `json:"unknownThreatDefaultAction"`
	AttackSurfaceReductionRules                    []DefenderASRRule `json:"attackSurfaceReductionRules"`
	AttackSurfaceReductionOnlyExclusionsCount      *int              `json:"attackSurfaceReductionOnlyExclusionsCount"`
	ExclusionPathCount                             *int              `json:"exclusionPathCount"`
	ExclusionExtensionCount                        *int              `json:"exclusionExtensionCount"`
	ExclusionProcessCount                          *int              `json:"exclusionProcessCount"`
	ControlledFolderAccessProtectedFoldersCount    *int              `json:"controlledFolderAccessProtectedFoldersCount"`
	ControlledFolderAccessAllowedApplicationsCount *int              `json:"controlledFolderAccessAllowedApplicationsCount"`
}

// DefenderTelemetry is the read-only Defender snapshot contract. Unavailable
// values are explicit null fields; UnavailableFields names the null properties
// so the UI can distinguish "unavailable" from "false"/"zero".
type DefenderTelemetry struct {
	SchemaVersion        int                     `json:"schemaVersion"`
	Available            bool                    `json:"available"`
	Verified             bool                    `json:"verified"`
	Source               string                  `json:"source"`
	CollectedUTC         time.Time               `json:"collectedUtc"`
	SourceTimestampUTC   OptionalTime            `json:"sourceTimestampUtc"`
	DurationMilliseconds int64                   `json:"durationMilliseconds"`
	Cached               bool                    `json:"cached"`
	Error                string                  `json:"error,omitempty"`
	UnavailableFields    []string                `json:"unavailableFields"`
	ComputerStatus       *DefenderComputerStatus `json:"computerStatus"`
	Preferences          *DefenderPreferences    `json:"preferences"`
}

type defenderWireTelemetry struct {
	CollectedUTC   string                  `json:"collectedUtc"`
	ComputerStatus *DefenderComputerStatus `json:"computerStatus"`
	Preferences    *DefenderPreferences    `json:"preferences"`
}

// parseDefenderTelemetry strictly decodes the bounded probe payload. Unknown
// properties are rejected so the schema cannot drift silently.
func parseDefenderTelemetry(raw []byte) (DefenderTelemetry, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	if len(raw) == 0 || len(raw) > maximumDefenderTelemetryBytes {
		return DefenderTelemetry{}, errors.New("defender telemetry size rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire defenderWireTelemetry
	if err := decoder.Decode(&wire); err != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry decoding failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return DefenderTelemetry{}, errors.New("defender telemetry trailing data rejected")
	}
	collected, err := time.Parse(time.RFC3339Nano, wire.CollectedUTC)
	if err != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry source timestamp rejected")
	}
	snapshot := DefenderTelemetry{
		SchemaVersion:      defenderTelemetrySchemaVersion,
		Source:             "Get-MpComputerStatus/Get-MpPreference",
		CollectedUTC:       collected.UTC(),
		SourceTimestampUTC: OptionalTime{Time: collected.UTC(), Valid: true},
		ComputerStatus:     wire.ComputerStatus,
		Preferences:        wire.Preferences,
	}
	snapshot.Available = wire.ComputerStatus != nil && wire.Preferences != nil
	snapshot.Verified = snapshot.Available && wire.ComputerStatus.AntivirusEnabled != nil && wire.ComputerStatus.RealTimeProtectionEnabled != nil
	if !snapshot.Available {
		snapshot.Error = "defender computer status or preferences unavailable"
	}
	snapshot.UnavailableFields = defenderUnavailableFields(wire.ComputerStatus, wire.Preferences)
	return snapshot, nil
}

// defenderUnavailableFields names null properties. Reflection keeps this list
// automatically aligned with the contract instead of drifting by hand; it only
// runs when a (cached) telemetry snapshot is decoded.
func defenderUnavailableFields(status *DefenderComputerStatus, preferences *DefenderPreferences) []string {
	fields := make([]string, 0, 32)
	if status == nil {
		fields = append(fields, "computerStatus")
	} else {
		collectUnavailableFields(reflect.ValueOf(*status), "computerStatus", &fields)
	}
	if preferences == nil {
		fields = append(fields, "preferences")
	} else {
		collectUnavailableFields(reflect.ValueOf(*preferences), "preferences", &fields)
	}
	if len(fields) > 64 {
		fields = fields[:64]
	}
	sort.Strings(fields)
	return fields
}

var optionalTimeType = reflect.TypeOf(OptionalTime{})

func collectUnavailableFields(value reflect.Value, prefix string, out *[]string) {
	valueType := value.Type()
	for index := 0; index < value.NumField(); index++ {
		field := valueType.Field(index)
		name := field.Tag.Get("json")
		if separator := strings.IndexByte(name, ','); separator >= 0 {
			name = name[:separator]
		}
		if name == "" || name == "-" {
			continue
		}
		fieldValue := value.Field(index)
		switch {
		case field.Type == optionalTimeType:
			if !fieldValue.Interface().(OptionalTime).Valid {
				*out = append(*out, prefix+"."+name)
			}
		case field.Type.Kind() == reflect.Pointer:
			if fieldValue.IsNil() {
				*out = append(*out, prefix+"."+name)
			}
		case field.Type.Kind() == reflect.Slice:
			if fieldValue.IsNil() {
				*out = append(*out, prefix+"."+name)
			}
		}
	}
}

// defenderProbeFunc is the platform probe seam. It is nil in production code
// and replaced in tests so the cache/policy behaviour is verifiable without
// touching a live Defender installation.
type defenderProbeFunc func(context.Context) (DefenderTelemetry, error)

// DefenderTelemetry returns a cached or fresh read-only Defender snapshot.
// A failed probe is returned as an explicit unavailable snapshot with no error:
// absence of Defender data is a rendering state, not an API failure. Only an
// unusable caller context is an error.
func (e *Engine) DefenderTelemetry(ctx context.Context) (DefenderTelemetry, error) {
	if e == nil {
		return DefenderTelemetry{}, errors.New("MHX engine unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return DefenderTelemetry{}, errors.New("defender telemetry requires an active request")
	}
	now := time.Now().UTC()
	e.defenderMu.Lock()
	cached := e.defenderCache
	cachedAt := e.defenderCacheAt
	e.defenderMu.Unlock()
	if !cachedAt.IsZero() {
		ttl := defenderSuccessTTL
		if !cached.Available {
			ttl = defenderFailureTTL
		}
		if now.Sub(cachedAt) < ttl {
			cached.Cached = true
			return cached, nil
		}
	}
	probe := e.defenderProbe
	if probe == nil {
		probe = probeDefenderTelemetry
	}
	probeCtx, cancel := context.WithTimeout(ctx, defenderProbeTimeout)
	defer cancel()
	started := time.Now()
	snapshot, err := probe(probeCtx)
	duration := time.Since(started)
	if err != nil {
		failure := unavailableDefenderTelemetry(duration, err)
		e.defenderMu.Lock()
		e.defenderCache = failure
		e.defenderCacheAt = time.Now().UTC()
		e.defenderMu.Unlock()
		return failure, nil
	}
	snapshot.SchemaVersion = defenderTelemetrySchemaVersion
	if snapshot.Source == "" {
		snapshot.Source = "Get-MpComputerStatus/Get-MpPreference"
	}
	if snapshot.CollectedUTC.IsZero() {
		snapshot.CollectedUTC = now
	}
	snapshot.DurationMilliseconds = duration.Milliseconds()
	snapshot.Cached = false
	snapshot.Available = snapshot.ComputerStatus != nil && snapshot.Preferences != nil
	snapshot.Verified = snapshot.Available && snapshot.ComputerStatus.AntivirusEnabled != nil && snapshot.ComputerStatus.RealTimeProtectionEnabled != nil
	if !snapshot.Available && snapshot.Error == "" {
		snapshot.Error = "defender computer status or preferences unavailable"
	}
	snapshot.UnavailableFields = defenderUnavailableFields(snapshot.ComputerStatus, snapshot.Preferences)
	e.defenderMu.Lock()
	e.defenderCache = snapshot
	e.defenderCacheAt = time.Now().UTC()
	e.defenderMu.Unlock()
	return snapshot, nil
}

// cachedDefenderTelemetry returns the last snapshot for Status without
// triggering a PowerShell probe from the status path.
func (e *Engine) cachedDefenderTelemetry() *DefenderTelemetry {
	if e == nil {
		return nil
	}
	e.defenderMu.Lock()
	defer e.defenderMu.Unlock()
	if e.defenderCacheAt.IsZero() {
		return nil
	}
	snapshot := e.defenderCache
	return &snapshot
}

func unavailableDefenderTelemetry(duration time.Duration, probeErr error) DefenderTelemetry {
	message := "defender telemetry unavailable"
	if probeErr != nil {
		message = probeErr.Error()
	}
	return DefenderTelemetry{
		SchemaVersion:        defenderTelemetrySchemaVersion,
		Available:            false,
		Verified:             false,
		Source:               "UNAVAILABLE",
		CollectedUTC:         time.Now().UTC(),
		DurationMilliseconds: duration.Milliseconds(),
		Error:                message,
		UnavailableFields:    []string{"computerStatus", "preferences"},
	}
}
