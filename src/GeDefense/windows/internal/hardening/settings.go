// STATUS: DIAMANT VGT SUPREME
package hardening

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/cleanup"
)

// MaxSettingsConfigBytes bounds the JSON configuration accepted by
// ParseSettingsConfig and ApplySettings.
const MaxSettingsConfigBytes = 64 << 10

// SettingsConfig is the validated per-protection configuration accepted by
// Engine.ApplySettings. Only explicitly listed settings are applied; every
// unknown field or unsupported value is rejected before any system change.
// The same JSON schema is validated a second time by the PowerShell engine.
type SettingsConfig struct {
	SchemaVersion int               `json:"schemaVersion"`
	Defender      *DefenderSettings `json:"defender,omitempty"`
	Firewall      *FirewallSettings `json:"firewall,omitempty"`
	Components    []string          `json:"components,omitempty"`
}

// DefenderSettings lists supported Microsoft Defender preference changes.
// Omitted fields stay untouched.
type DefenderSettings struct {
	CloudBlockLevel        *string          `json:"cloudBlockLevel,omitempty"`
	MAPSReporting          *string          `json:"mapsReporting,omitempty"`
	SubmitSamplesConsent   *string          `json:"submitSamplesConsent,omitempty"`
	NetworkProtection      *string          `json:"networkProtection,omitempty"`
	PUAProtection          *string          `json:"puaProtection,omitempty"`
	ControlledFolderAccess *string          `json:"controlledFolderAccess,omitempty"`
	ASRRules               []ASRRuleSetting `json:"asrRules,omitempty"`
}

// ASRRuleSetting selects the action for one supported ASR rule.
type ASRRuleSetting struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

// FirewallSettings lists supported Windows Firewall profile changes.
type FirewallSettings struct {
	Profiles []FirewallProfileSetting `json:"profiles,omitempty"`
}

// FirewallProfileSetting selects the firewall profile fields to change. A
// profile entry must contain at least one setting besides the profile name.
type FirewallProfileSetting struct {
	Name                            string  `json:"name"`
	Enabled                         *bool   `json:"enabled,omitempty"`
	DefaultInboundAction            *string `json:"defaultInboundAction,omitempty"`
	DefaultOutboundAction           *string `json:"defaultOutboundAction,omitempty"`
	NotifyOnListen                  *bool   `json:"notifyOnListen,omitempty"`
	AllowUnicastResponseToMulticast *bool   `json:"allowUnicastResponseToMulticast,omitempty"`
	LogBlocked                      *bool   `json:"logBlocked,omitempty"`
	LogAllowed                      *bool   `json:"logAllowed,omitempty"`
	LogMaxSizeKilobytes             *int    `json:"logMaxSizeKilobytes,omitempty"`
}

// SettingsApplyReport is evidence emitted by the ApplyConfig operation. It
// contains measured before/after values only; it never contains the raw
// configuration or any secret.
type SettingsApplyReport struct {
	SchemaVersion     int                   `json:"SchemaVersion"`
	TimestampUTC      string                `json:"TimestampUtc"`
	SettingsSHA256    *string               `json:"SettingsSha256"`
	BaselineState     string                `json:"BaselineState"`
	RollbackAvailable bool                  `json:"RollbackAvailable"`
	ChangedCount      int                   `json:"ChangedCount"`
	UnchangedCount    int                   `json:"UnchangedCount"`
	Entries           []SettingsApplyEntry  `json:"Entries"`
	Components        []ComponentApplyEntry `json:"Components"`
}

// SettingsApplyEntry records one measured setting transition.
type SettingsApplyEntry struct {
	Setting string `json:"Setting"`
	Changed bool   `json:"Changed"`
	Before  any    `json:"Before"`
	After   any    `json:"After"`
}

// ComponentApplyEntry records the measured component state before and after an
// ApplyConfig operation.
type ComponentApplyEntry struct {
	ID      string `json:"Id"`
	Before  bool   `json:"Before"`
	After   bool   `json:"After"`
	Changed bool   `json:"Changed"`
}

var (
	cloudBlockLevelValues  = []string{"Default", "Normal", "High", "HighPlus", "ZeroTolerance"}
	mapsReportingValues    = []string{"Disabled", "Basic", "Advanced"}
	sampleConsentValues    = []string{"AlwaysPrompt", "SendSafeSamples", "NeverSend", "SendAllSamples"}
	defenderModeValues     = []string{"Enabled", "AuditMode", "Disabled"}
	firewallInboundValues  = []string{"Block", "Allow"}
	firewallOutboundValues = []string{"Allow", "Block"}
	firewallProfileNames   = []string{"Domain", "Private", "Public"}
	asrActionAliases       = map[string]string{
		"enabled":   "Enabled",
		"block":     "Enabled",
		"auditmode": "AuditMode",
		"audit":     "AuditMode",
		"warn":      "Warn",
		"disabled":  "Disabled",
	}
)

// ParseSettingsConfig decodes and strictly validates a bounded JSON
// configuration document. Unknown fields, duplicate/unsupported entries,
// trailing data and out-of-range values are rejected.
func ParseSettingsConfig(raw []byte) (SettingsConfig, error) {
	if len(raw) == 0 || len(raw) > MaxSettingsConfigBytes {
		return SettingsConfig{}, errors.New("settings config size rejected")
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return SettingsConfig{}, errors.New("settings config encoding rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config SettingsConfig
	if err := decoder.Decode(&config); err != nil {
		return SettingsConfig{}, errors.New("settings config decoding failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil || !errors.Is(err, io.EOF) {
		return SettingsConfig{}, errors.New("settings config trailing data rejected")
	}
	return config.validateAndNormalize()
}

// Validate verifies the configuration without applying it.
func (c SettingsConfig) Validate() error {
	_, err := c.validateAndNormalize()
	return err
}

// ApplySettings validates config, writes it to a private temporary file inside
// the hardening operation root and runs the signed PowerShell engine in
// ApplyConfig mode. The engine validates the file again, records the operation
// in the protected log and evidence ledger, snapshots a reversible baseline and
// returns a measured before/after report together with a fresh audit result.
func (e *Engine) ApplySettings(ctx context.Context, config SettingsConfig) (result Result, err error) {
	normalized, validationErr := config.validateAndNormalize()
	if validationErr != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("hardening.settings", "ApplyConfig", "rejected")
		}
		return Result{}, validationErr
	}
	raw, marshalErr := json.Marshal(normalized)
	if marshalErr != nil {
		return Result{}, errors.New("settings config encoding failed")
	}
	if len(raw) > MaxSettingsConfigBytes {
		return Result{}, errors.New("settings config size rejected")
	}
	digest := sha256.Sum256(raw)
	digestHex := hex.EncodeToString(digest[:])

	configFile, createErr := os.CreateTemp(e.operationRoot, "settings-*.json")
	if createErr != nil {
		if e.ledger != nil {
			_ = e.ledger.Append("hardening.settings", "ApplyConfig", "failed")
		}
		return Result{}, errors.New("settings staging failed")
	}
	configPath := configFile.Name()
	defer cleanup.RemoveInto(&err, configPath)
	if chmodErr := configFile.Chmod(0o600); chmodErr != nil {
		_ = configFile.Close()
		return Result{}, errors.New("settings staging failed")
	}
	if _, writeErr := configFile.Write(raw); writeErr != nil {
		_ = configFile.Close()
		return Result{}, errors.New("settings staging failed")
	}
	if syncErr := configFile.Sync(); syncErr != nil {
		_ = configFile.Close()
		return Result{}, errors.New("settings staging failed")
	}
	if closeErr := configFile.Close(); closeErr != nil {
		return Result{}, errors.New("settings staging failed")
	}
	return e.execute(ctx, "ApplyConfig", "", "", configPath, "ApplyConfig:"+digestHex[:16])
}

// DefenderTelemetry returns the most recently measured Defender telemetry
// snapshot. The method is read-only: it never runs an enforcing operation and
// returns nil when no audit snapshot is available yet.
func (e *Engine) DefenderTelemetry(ctx context.Context) (*DefenderTelemetry, error) {
	result, err := e.Posture(ctx)
	if err != nil {
		return nil, err
	}
	return result.DefenderTelemetry, nil
}

func (c SettingsConfig) validateAndNormalize() (SettingsConfig, error) {
	if c.SchemaVersion != 1 {
		return SettingsConfig{}, errors.New("settings config schema version rejected")
	}
	if c.Defender == nil && c.Firewall == nil && len(c.Components) == 0 {
		return SettingsConfig{}, errors.New("settings config contains no supported settings")
	}
	normalized := SettingsConfig{SchemaVersion: 1}
	if c.Defender != nil {
		defender, err := c.Defender.validateAndNormalize()
		if err != nil {
			return SettingsConfig{}, err
		}
		normalized.Defender = defender
	}
	if c.Firewall != nil {
		firewall, err := c.Firewall.validateAndNormalize()
		if err != nil {
			return SettingsConfig{}, err
		}
		normalized.Firewall = firewall
	}
	if len(c.Components) > 0 {
		components, err := normalizeComponents(c.Components)
		if err != nil {
			return SettingsConfig{}, err
		}
		normalized.Components = components
	}
	return normalized, nil
}

func (d DefenderSettings) validateAndNormalize() (*DefenderSettings, error) {
	normalized := &DefenderSettings{}
	hasSetting := false
	fields := []struct {
		name   string
		value  *string
		values []string
		target **string
	}{
		{name: "cloudBlockLevel", value: d.CloudBlockLevel, values: cloudBlockLevelValues, target: &normalized.CloudBlockLevel},
		{name: "mapsReporting", value: d.MAPSReporting, values: mapsReportingValues, target: &normalized.MAPSReporting},
		{name: "submitSamplesConsent", value: d.SubmitSamplesConsent, values: sampleConsentValues, target: &normalized.SubmitSamplesConsent},
		{name: "networkProtection", value: d.NetworkProtection, values: defenderModeValues, target: &normalized.NetworkProtection},
		{name: "puaProtection", value: d.PUAProtection, values: defenderModeValues, target: &normalized.PUAProtection},
		{name: "controlledFolderAccess", value: d.ControlledFolderAccess, values: defenderModeValues, target: &normalized.ControlledFolderAccess},
	}
	for _, field := range fields {
		if field.value == nil {
			continue
		}
		canonical, ok := canonicalEnum(*field.value, field.values)
		if !ok {
			return nil, fmt.Errorf("settings config rejected: defender.%s", field.name)
		}
		*field.target = &canonical
		hasSetting = true
	}
	if d.ASRRules != nil {
		if len(d.ASRRules) == 0 || len(d.ASRRules) > len(asrRuleDefinitions) {
			return nil, errors.New("settings config rejected: defender.asrRules")
		}
		supported := make(map[string]string, len(asrRuleDefinitions))
		for _, rule := range asrRuleDefinitions {
			supported[strings.ToLower(rule.ID)] = rule.ID
		}
		seen := make(map[string]struct{}, len(d.ASRRules))
		rules := make([]ASRRuleSetting, 0, len(d.ASRRules))
		for _, rule := range d.ASRRules {
			id, ok := supported[strings.ToLower(strings.TrimSpace(rule.ID))]
			if !ok {
				return nil, errors.New("settings config rejected: unsupported ASR rule id")
			}
			if _, duplicate := seen[id]; duplicate {
				return nil, errors.New("settings config rejected: duplicate ASR rule id")
			}
			seen[id] = struct{}{}
			action, ok := asrActionAliases[strings.ToLower(strings.TrimSpace(rule.Action))]
			if !ok {
				return nil, errors.New("settings config rejected: defender.asrRules action")
			}
			rules = append(rules, ASRRuleSetting{ID: id, Action: action})
		}
		normalized.ASRRules = rules
		hasSetting = true
	}
	if !hasSetting {
		return nil, errors.New("settings config contains no supported defender settings")
	}
	return normalized, nil
}

func (f FirewallSettings) validateAndNormalize() (*FirewallSettings, error) {
	if len(f.Profiles) == 0 || len(f.Profiles) > len(firewallProfileNames) {
		return nil, errors.New("settings config rejected: firewall.profiles count")
	}
	seen := make(map[string]struct{}, len(f.Profiles))
	profiles := make([]FirewallProfileSetting, 0, len(f.Profiles))
	for _, profile := range f.Profiles {
		name, ok := canonicalEnum(strings.TrimSpace(profile.Name), firewallProfileNames)
		if !ok {
			return nil, errors.New("settings config rejected: firewall profile name")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.New("settings config rejected: duplicate firewall profile")
		}
		seen[name] = struct{}{}
		normalized := FirewallProfileSetting{Name: name}
		hasSetting := false
		if profile.Enabled != nil {
			value := *profile.Enabled
			normalized.Enabled = &value
			hasSetting = true
		}
		for _, enum := range []struct {
			name   string
			value  *string
			values []string
			target **string
		}{
			{name: "defaultInboundAction", value: profile.DefaultInboundAction, values: firewallInboundValues, target: &normalized.DefaultInboundAction},
			{name: "defaultOutboundAction", value: profile.DefaultOutboundAction, values: firewallOutboundValues, target: &normalized.DefaultOutboundAction},
		} {
			if enum.value == nil {
				continue
			}
			canonical, ok := canonicalEnum(*enum.value, enum.values)
			if !ok {
				return nil, fmt.Errorf("settings config rejected: firewall profile %s", enum.name)
			}
			*enum.target = &canonical
			hasSetting = true
		}
		for _, boolean := range []struct {
			name   string
			value  *bool
			target **bool
		}{
			{name: "notifyOnListen", value: profile.NotifyOnListen, target: &normalized.NotifyOnListen},
			{name: "allowUnicastResponseToMulticast", value: profile.AllowUnicastResponseToMulticast, target: &normalized.AllowUnicastResponseToMulticast},
			{name: "logBlocked", value: profile.LogBlocked, target: &normalized.LogBlocked},
			{name: "logAllowed", value: profile.LogAllowed, target: &normalized.LogAllowed},
		} {
			if boolean.value == nil {
				continue
			}
			value := *boolean.value
			*boolean.target = &value
			hasSetting = true
		}
		if profile.LogMaxSizeKilobytes != nil {
			if *profile.LogMaxSizeKilobytes < 1 || *profile.LogMaxSizeKilobytes > 32767 {
				return nil, errors.New("settings config rejected: firewall log size")
			}
			value := *profile.LogMaxSizeKilobytes
			normalized.LogMaxSizeKilobytes = &value
			hasSetting = true
		}
		if !hasSetting {
			return nil, errors.New("settings config rejected: empty firewall profile entry")
		}
		profiles = append(profiles, normalized)
	}
	return &FirewallSettings{Profiles: profiles}, nil
}

func normalizeComponents(components []string) ([]string, error) {
	if len(components) == 0 || len(components) > len(componentDefinitions) {
		return nil, errors.New("settings config rejected: components count")
	}
	allowed := make(map[string]struct{}, len(componentDefinitions))
	for _, definition := range componentDefinitions {
		allowed[definition.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(components))
	normalized := make([]string, 0, len(components))
	for _, component := range components {
		if _, ok := allowed[component]; !ok {
			return nil, errors.New("settings config rejected: unsupported component")
		}
		if _, duplicate := seen[component]; duplicate {
			return nil, errors.New("settings config rejected: duplicate component")
		}
		seen[component] = struct{}{}
		normalized = append(normalized, component)
	}
	return normalized, nil
}

func canonicalEnum(value string, allowed []string) (string, bool) {
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return candidate, true
		}
	}
	return "", false
}
