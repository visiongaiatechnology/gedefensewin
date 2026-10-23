// STATUS: DIAMANT VGT SUPREME
package mhx

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
	"path/filepath"
	"strings"
	"time"
)

const (
	policySettingsSchemaVersion = 1
	policySettingsFileName      = "policy-settings.json"
	// maximumPolicySettingsBytes bounds the persisted operator policy file.
	maximumPolicySettingsBytes = 16 << 10
	// maximumNotificationEntries bounds the in-memory notification feed.
	maximumNotificationEntries  = 200
	maximumApplicationAllowList = 8
)

const (
	settingsSourceDefault   = "DEFAULT"
	settingsSourcePersisted = "PERSISTED"
	settingsSourceInvalid   = "INVALID_DEFAULT"
)

const (
	notificationKindBlock         = "BLOCK"
	notificationKindDefender      = "DEFENDER"
	notificationKindThreatIntel   = "THREAT_INTELLIGENCE"
	notificationKindKinetic       = "KINETIC"
	processRestrictionUnsupported = "No verified process or command restriction primitive exists in the installed engine scripts; ASR rule sets are fixed by the protection mode. Such settings are rejected instead of being accepted without enforcement."
)

// AutoResponseSettings are enforced in the Go response path. They gate the
// existing PID-reuse protected termination; they never widen evaluator
// response authority.
type AutoResponseSettings struct {
	TerminateProcess          bool     `json:"terminateProcess"`
	CorrelatedNetworkResponse bool     `json:"correlatedNetworkResponse"`
	MinimumSeverity           Severity `json:"minimumSeverity"`
}

// NotificationSettings control the bounded, real-event notification feed. They
// cannot fabricate entries; they only decide which genuine engine events are
// retained for display.
type NotificationSettings struct {
	EventFeedEnabled     bool     `json:"eventFeedEnabled"`
	BlockEvents          bool     `json:"blockEvents"`
	DefenderEvents       bool     `json:"defenderEvents"`
	ThreatIntelEvents    bool     `json:"threatIntelEvents"`
	KineticEvents        bool     `json:"kineticEvents"`
	MinimumSeverity      Severity `json:"minimumSeverity"`
	WindowsToasts        bool     `json:"windowsToasts"`
	ToastMinimumSeverity Severity `json:"toastMinimumSeverity"`
}

// NetworkPolicySettings is read-only and derived from the verified protection
// mode. Default-deny outbound only exists as part of the sovereign mode script.
type NetworkPolicySettings struct {
	DefaultDenyOutbound bool   `json:"defaultDenyOutbound"`
	EnforcedBy          string `json:"enforcedBy"`
}

// ApplicationPolicySettings exposes the real enforcement capability. Only the
// Authenticode-verified allow list is a genuine primitive; there is no app
// deny script and no independent network restriction primitive.
type ApplicationPolicySettings struct {
	AllowListEnforced bool   `json:"allowListEnforced"`
	DenyListSupported bool   `json:"denyListSupported"`
	EnforcedBy        string `json:"enforcedBy"`
}

// ProcessPolicySettings documents the deliberate absence of a process or
// command restriction primitive.
type ProcessPolicySettings struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason"`
}

// PolicySettings is the complete settings snapshot contract. The writable
// portion (AutoResponse, Notifications) is persisted; the read-only sections
// are derived from the live verified protection mode on every call.
type PolicySettings struct {
	SchemaVersion         int                       `json:"schemaVersion"`
	Aggressiveness        string                    `json:"aggressiveness"`
	AggressivenessSource  string                    `json:"aggressivenessSource"`
	AggressivenessDefault string                    `json:"aggressivenessDefault"`
	AutoResponse          AutoResponseSettings      `json:"autoResponse"`
	DefaultAutoResponse   AutoResponseSettings      `json:"defaultAutoResponse"`
	Notifications         NotificationSettings      `json:"notifications"`
	DefaultNotifications  NotificationSettings      `json:"defaultNotifications"`
	Network               NetworkPolicySettings     `json:"network"`
	Application           ApplicationPolicySettings `json:"application"`
	Process               ProcessPolicySettings     `json:"process"`
	Source                string                    `json:"source"`
	Warnings              []string                  `json:"warnings,omitempty"`
	UpdatedUTC            time.Time                 `json:"updatedUtc,omitempty"`
}

// DefaultAutoResponseSettings preserves the historical response behaviour: any
// evaluator-authorized block may terminate, with no severity floor beyond LOW.
func DefaultAutoResponseSettings() AutoResponseSettings {
	return AutoResponseSettings{TerminateProcess: true, CorrelatedNetworkResponse: true, MinimumSeverity: SeverityLow}
}

// DefaultNotificationSettings retains every genuine event class at LOW and
// above. No entry is ever generated without a real engine event.
func DefaultNotificationSettings() NotificationSettings {
	return NotificationSettings{EventFeedEnabled: true, BlockEvents: true, DefenderEvents: true, ThreatIntelEvents: true, KineticEvents: true, MinimumSeverity: SeverityLow, WindowsToasts: true, ToastMinimumSeverity: SeverityLow}
}

// DefaultPolicySettings returns the fail-safe policy used before a persisted
// policy is loaded or after a rejected one.
func DefaultPolicySettings() PolicySettings {
	return PolicySettings{
		SchemaVersion:         policySettingsSchemaVersion,
		Aggressiveness:        "guarded",
		AggressivenessSource:  "PROTECTION_MODE",
		AggressivenessDefault: "guarded",
		AutoResponse:          DefaultAutoResponseSettings(),
		DefaultAutoResponse:   DefaultAutoResponseSettings(),
		Notifications:         DefaultNotificationSettings(),
		DefaultNotifications:  DefaultNotificationSettings(),
		Network:               NetworkPolicySettings{EnforcedBy: "xdr/Set-VgtMhxProtection.ps1 (Sovereign default deny)"},
		Application:           ApplicationPolicySettings{DenyListSupported: true, EnforcedBy: "xdr/Set-VgtMhxApplicationAllow.ps1 (allow) + Set-VgtMhxApplicationDeny.ps1 (Outbound/Inbound Block)"},
		Process:               ProcessPolicySettings{Supported: false, Reason: processRestrictionUnsupported},
		Source:                settingsSourceDefault,
	}
}

type policyPersistedState struct {
	SchemaVersion int                  `json:"schemaVersion"`
	AutoResponse  AutoResponseSettings `json:"autoResponse"`
	Notifications NotificationSettings `json:"notifications"`
	UpdatedUTC    time.Time            `json:"updatedUtc"`
}

// SettingRejection names one unsupported or unenforceable requested field.
type SettingRejection struct {
	Setting string `json:"setting"`
	Reason  string `json:"reason"`
}

// SettingsRejectedError is returned when a settings request contains at least
// one field that cannot be honestly enforced. No field is partially applied.
type SettingsRejectedError struct {
	Rejections []SettingRejection `json:"rejections"`
}

func (e *SettingsRejectedError) Error() string {
	if e == nil || len(e.Rejections) == 0 {
		return "settings request rejected"
	}
	parts := make([]string, 0, len(e.Rejections))
	for _, rejection := range e.Rejections {
		parts = append(parts, rejection.Setting+": "+rejection.Reason)
	}
	return "unsupported or unenforceable settings: " + strings.Join(parts, "; ")
}

// PolicySettingsPatch is a partial settings update. Only present (non-nil)
// sections are changed; every present field is validated before any effect.
type PolicySettingsPatch struct {
	Aggressiveness                 *string                              `json:"aggressiveness,omitempty"`
	AggressivenessDomains          *AggressivenessDomainsPatch          `json:"aggressivenessDomains,omitempty"`
	AutoResponse                   *AutoResponseSettings                `json:"autoResponse,omitempty"`
	Notifications                  *NotificationSettings                `json:"notifications,omitempty"`
	Network                        *NetworkPolicyPatch                  `json:"network,omitempty"`
	Application                    *ApplicationPolicyPatch              `json:"application,omitempty"`
	ApplicationNetworkRestrictions *ApplicationNetworkRestrictionsPatch `json:"applicationNetworkRestrictions,omitempty"`
	Process                        *ProcessPolicyPatch                  `json:"process,omitempty"`
}

// AggressivenessDomainsPatch accepts the UI's per-domain shape only when every
// provided domain names the same verified protection profile. The installed
// scripts apply one protection mode; different per-domain levels cannot be
// enforced and are rejected explicitly instead of being silently collapsed.
type AggressivenessDomainsPatch struct {
	Process     *string `json:"process,omitempty"`
	Network     *string `json:"network,omitempty"`
	Application *string `json:"application,omitempty"`
}

// ApplicationNetworkRestrictionsPatch captures UI fields that have no
// independent verified primitive. Any non-empty request is rejected.
type ApplicationNetworkRestrictionsPatch struct {
	UnknownPolicy  string `json:"unknownPolicy,omitempty"`
	AppControlMode string `json:"appControlMode,omitempty"`
}

// NetworkPolicyPatch cannot enable a network restriction on its own; default
// deny is only reachable through the sovereign protection mode.
type NetworkPolicyPatch struct {
	DefaultDenyOutbound *bool `json:"defaultDenyOutbound,omitempty"`
}

// ApplicationPolicyPatch supports the real Authenticode allow list and rejects
// the non-existent deny primitive.
type ApplicationPolicyPatch struct {
	AllowList []string `json:"allowList,omitempty"`
	DenyList  []string `json:"denyList,omitempty"`
}

// ProcessPolicyPatch is always rejected when it requests enforcement; there is
// no verified primitive behind it.
type ProcessPolicyPatch struct {
	AllowedPaths    []string `json:"allowedPaths,omitempty"`
	BlockedPaths    []string `json:"blockedPaths,omitempty"`
	BlockedCommands []string `json:"blockedCommands,omitempty"`
}

func (e *Engine) policySettingsPath() string {
	return filepath.Join(e.root, policySettingsFileName)
}

// loadPolicySettings restores the persisted writable policy. An invalid file
// never crashes startup and never becomes partially effective.
func (e *Engine) loadPolicySettings() {
	defaults := DefaultPolicySettings()
	e.policySettings.Store(&defaults)
	e.mu.Lock()
	e.policySettingsSource = settingsSourceDefault
	e.policySettingsWarning = ""
	e.mu.Unlock()
	raw, err := os.ReadFile(e.policySettingsPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	reject := func(warning string) {
		rejected := DefaultPolicySettings()
		rejected.Source = settingsSourceInvalid
		rejected.Warnings = []string{warning}
		e.policySettings.Store(&rejected)
		e.mu.Lock()
		e.policySettingsSource = settingsSourceInvalid
		e.policySettingsWarning = warning
		e.mu.Unlock()
	}
	if err != nil || len(raw) == 0 || len(raw) > maximumPolicySettingsBytes {
		reject("persisted MHX policy settings rejected; defaults active")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state policyPersistedState
	if err := decoder.Decode(&state); err != nil {
		reject("persisted MHX policy settings rejected; defaults active")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		reject("persisted MHX policy settings trailing data rejected; defaults active")
		return
	}
	if state.SchemaVersion != policySettingsSchemaVersion || validateSeverity(state.AutoResponse.MinimumSeverity) != nil || validateSeverity(state.Notifications.MinimumSeverity) != nil {
		reject("persisted MHX policy settings validation failed; defaults active")
		return
	}
	// Additive migration for V5 notification settings. Existing policy files
	// predate Windows toast preferences; a missing severity is the conservative
	// LOW default, and an explicitly persisted false remains false.
	if state.Notifications.ToastMinimumSeverity == "" {
		state.Notifications.ToastMinimumSeverity = SeverityLow
	}
	if validateSeverity(state.Notifications.ToastMinimumSeverity) != nil {
		reject("persisted notification toast severity validation failed; defaults active")
		return
	}
	restored := DefaultPolicySettings()
	restored.AutoResponse = state.AutoResponse
	restored.Notifications = state.Notifications
	restored.Source = settingsSourcePersisted
	restored.UpdatedUTC = state.UpdatedUTC
	e.policySettings.Store(&restored)
	e.mu.Lock()
	e.policySettingsSource = settingsSourcePersisted
	e.policySettingsWarning = ""
	e.policySettingsPersisted = true
	e.policySettingsUpdatedUTC = state.UpdatedUTC
	e.mu.Unlock()
}

// currentPolicySettings returns the lock-free immutable settings view used by
// hot paths. It always falls back to fail-safe defaults.
func (e *Engine) currentPolicySettings() PolicySettings {
	if e == nil {
		return DefaultPolicySettings()
	}
	if stored := e.policySettings.Load(); stored != nil {
		return *stored
	}
	return DefaultPolicySettings()
}

// PolicySettings returns the effective settings snapshot with read-only
// sections derived from the verified protection mode.
func (e *Engine) PolicySettings() PolicySettings {
	settings := e.currentPolicySettings()
	settings.Warnings = append([]string(nil), settings.Warnings...)
	mode := e.Mode()
	settings.SchemaVersion = policySettingsSchemaVersion
	settings.Aggressiveness = mode
	settings.AggressivenessSource = "PROTECTION_MODE"
	settings.AggressivenessDefault = "guarded"
	settings.DefaultAutoResponse = DefaultAutoResponseSettings()
	settings.DefaultNotifications = DefaultNotificationSettings()
	settings.Network = NetworkPolicySettings{DefaultDenyOutbound: mode == "sovereign", EnforcedBy: "xdr/Set-VgtMhxProtection.ps1 (Sovereign default deny)"}
	settings.Application = ApplicationPolicySettings{AllowListEnforced: mode == "sovereign", DenyListSupported: true, EnforcedBy: "xdr/Set-VgtMhxApplicationAllow.ps1 (allow) + Set-VgtMhxApplicationDeny.ps1 (Outbound/Inbound Block)"}
	settings.Process = ProcessPolicySettings{Supported: false, Reason: processRestrictionUnsupported}
	return settings
}

func validateSeverity(value Severity) error {
	switch value {
	case SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return nil
	default:
		return fmt.Errorf("unsupported severity %q", string(value))
	}
}

func normalizeAggressiveness(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "monitor", "guarded", "sovereign":
		return normalized, nil
	default:
		return "", fmt.Errorf("aggressiveness %q is not a supported protection profile", value)
	}
}

// validateWindowsExecutablePath performs a platform-independent syntactic
// check. The existing PowerShell script performs the authoritative existence,
// Authenticode and reparse-point validation.
func validateWindowsExecutablePath(value string) error {
	if len(value) < 4 || len(value) > 1024 {
		return errors.New("application path length out of bounds")
	}
	if value[1] != ':' || (value[2] != '\\' && value[2] != '/') {
		return errors.New("application path must be an absolute Windows path")
	}
	for _, character := range value {
		if character < 0x20 || character == 0 || character == 0x7f {
			return errors.New("application path contains control characters")
		}
	}
	if !strings.EqualFold(filepath.Ext(value), ".exe") {
		return errors.New("application path must reference an executable")
	}
	if strings.Contains(value, "..") {
		return errors.New("application path traversal rejected")
	}
	return nil
}

// applySettingsRejections merges validated rejection entries and returns a
// single explicit error. Settings are never partially applied on rejection.
func settingsRejectionError(rejections []SettingRejection) error {
	if len(rejections) == 0 {
		return nil
	}
	if len(rejections) > 16 {
		rejections = rejections[:16]
	}
	return &SettingsRejectedError{Rejections: rejections}
}

// SetPolicySettings validates and applies a partial MHX policy update.
//
// Enforceable settings go through their real primitives:
//   - aggressiveness -> Engine.SetMode (verified PowerShell transaction),
//   - application allow list -> xdr/Set-VgtMhxApplicationAllow.ps1 via the
//     existing verified SetApplication path,
//   - auto-response/notification toggles -> persisted Go policy gates.
//
// Unsupported or unenforceable fields (node deny lists, independent network
// default-deny, process/command restrictions) are rejected explicitly before
// any side effect. A rejected request changes nothing.
func (e *Engine) SetPolicySettings(ctx context.Context, patch PolicySettingsPatch) (PolicySettings, error) {
	if e == nil {
		return PolicySettings{}, errors.New("MHX settings controller unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return e.PolicySettings(), errors.New("MHX settings update requires an active request")
	}
	if !filepath.IsAbs(e.root) {
		return e.PolicySettings(), errors.New("MHX settings persistence root unavailable")
	}
	current := e.currentPolicySettings()
	targetProfile := e.Mode()
	var warnings []string
	if patch.Aggressiveness != nil && patch.AggressivenessDomains != nil {
		return e.PolicySettings(), settingsRejectionError([]SettingRejection{{Setting: "aggressiveness", Reason: "aggressiveness and aggressivenessDomains are mutually exclusive"}})
	}
	if patch.Aggressiveness != nil {
		normalized, err := normalizeAggressiveness(*patch.Aggressiveness)
		if err != nil {
			return e.PolicySettings(), settingsRejectionError([]SettingRejection{{Setting: "aggressiveness", Reason: err.Error()}})
		}
		targetProfile = normalized
	}

	var rejections []SettingRejection
	if patch.AggressivenessDomains != nil {
		domains := []struct {
			name  string
			value *string
		}{
			{name: "process", value: patch.AggressivenessDomains.Process},
			{name: "network", value: patch.AggressivenessDomains.Network},
			{name: "application", value: patch.AggressivenessDomains.Application},
		}
		selectedProfile := ""
		requestedDomains := 0
		for _, domain := range domains {
			if domain.value == nil || strings.TrimSpace(*domain.value) == "" {
				continue
			}
			requestedDomains++
			normalized, err := normalizeAggressiveness(*domain.value)
			if err != nil {
				rejections = append(rejections, SettingRejection{Setting: "aggressivenessDomains." + domain.name, Reason: err.Error()})
				continue
			}
			if selectedProfile == "" {
				selectedProfile = normalized
				continue
			}
			if selectedProfile != normalized {
				rejections = append(rejections, SettingRejection{Setting: "aggressivenessDomains", Reason: "per-domain aggressiveness cannot be enforced independently; the installed scripts apply a single verified protection profile"})
			}
		}
		if requestedDomains == 0 {
			rejections = append(rejections, SettingRejection{Setting: "aggressivenessDomains", Reason: "at least one domain aggressiveness value is required"})
		}
		if len(rejections) == 0 && selectedProfile != "" {
			targetProfile = selectedProfile
			warnings = append(warnings, fmt.Sprintf("per-domain aggressiveness was collapsed to the single verified protection profile %q", selectedProfile))
		}
	}
	if patch.ApplicationNetworkRestrictions != nil {
		restrictions := patch.ApplicationNetworkRestrictions
		if strings.TrimSpace(restrictions.UnknownPolicy) != "" {
			rejections = append(rejections, SettingRejection{Setting: "applicationNetworkRestrictions.unknownPolicy", Reason: "no verified unknown-application policy primitive exists; only the Authenticode allow list is enforced in sovereign mode"})
		}
		if strings.TrimSpace(restrictions.AppControlMode) != "" {
			rejections = append(rejections, SettingRejection{Setting: "applicationNetworkRestrictions.appControlMode", Reason: "App Control mode is bound to the verified protection mode (Audit outside sovereign, Enforce in sovereign) and cannot be set independently"})
		}
	}
	if patch.Network != nil && patch.Network.DefaultDenyOutbound != nil {
		if *patch.Network.DefaultDenyOutbound != (targetProfile == "sovereign") {
			rejections = append(rejections, SettingRejection{Setting: "network.defaultDenyOutbound", Reason: "cannot be configured independently of the verified protection mode; select the sovereign aggressiveness profile instead"})
		}
	}
	var applicationAllowList []string
	if patch.Application != nil {
		if len(patch.Application.DenyList) > 0 {
			rejections = append(rejections, SettingRejection{Setting: "application.denyList", Reason: "no verified application deny primitive exists; only the Authenticode allow list is enforced by the installed scripts"})
		}
		if len(patch.Application.AllowList) > 0 {
			if len(patch.Application.AllowList) > maximumApplicationAllowList {
				rejections = append(rejections, SettingRejection{Setting: "application.allowList", Reason: fmt.Sprintf("at most %d applications may be added per request", maximumApplicationAllowList)})
			} else {
				seen := make(map[string]struct{}, len(patch.Application.AllowList))
				for _, entry := range patch.Application.AllowList {
					trimmed := strings.TrimSpace(entry)
					if err := validateWindowsExecutablePath(trimmed); err != nil {
						rejections = append(rejections, SettingRejection{Setting: "application.allowList", Reason: err.Error()})
						break
					}
					key := strings.ToLower(trimmed)
					if _, exists := seen[key]; exists {
						continue
					}
					seen[key] = struct{}{}
					applicationAllowList = append(applicationAllowList, trimmed)
				}
			}
		}
	}
	if patch.Process != nil && (len(patch.Process.AllowedPaths) > 0 || len(patch.Process.BlockedPaths) > 0 || len(patch.Process.BlockedCommands) > 0) {
		rejections = append(rejections, SettingRejection{Setting: "process", Reason: processRestrictionUnsupported})
	}
	nextStored := current
	nextStored.Warnings = append([]string(nil), warnings...)
	nextStored.Source = settingsSourcePersisted
	nextStored.UpdatedUTC = time.Now().UTC()
	if patch.AutoResponse != nil {
		if err := validateSeverity(patch.AutoResponse.MinimumSeverity); err != nil {
			rejections = append(rejections, SettingRejection{Setting: "autoResponse.minimumSeverity", Reason: err.Error()})
		}
		nextStored.AutoResponse = *patch.AutoResponse
	}
	if patch.Notifications != nil {
		if err := validateSeverity(patch.Notifications.MinimumSeverity); err != nil {
			rejections = append(rejections, SettingRejection{Setting: "notifications.minimumSeverity", Reason: err.Error()})
		}
		if err := validateSeverity(patch.Notifications.ToastMinimumSeverity); err != nil {
			rejections = append(rejections, SettingRejection{Setting: "notifications.toastMinimumSeverity", Reason: err.Error()})
		}
		nextStored.Notifications = *patch.Notifications
	}
	if err := settingsRejectionError(rejections); err != nil {
		e.ledgerAppend("mhx.policy-settings", "settings-update", "rejected")
		return e.PolicySettings(), err
	}

	// Evidence preflight: an operator settings transition must never occur
	// without an evidence record.
	if e.ledger != nil {
		if err := e.ledger.Append("mhx.policy-settings", "settings-request", "validated"); err != nil {
			return e.PolicySettings(), fmt.Errorf("MHX settings evidence preflight failed: %w", err)
		}
	}

	if targetProfile != e.Mode() {
		if err := e.SetMode(ctx, targetProfile); err != nil {
			e.ledgerAppend("mhx.policy-settings", "aggressiveness", "rejected")
			return e.PolicySettings(), err
		}
	}
	for index, path := range applicationAllowList {
		if ctx.Err() != nil {
			return e.PolicySettings(), ctx.Err()
		}
		if _, err := e.SetApplication(ctx, "Add", path); err != nil {
			e.ledgerAppend("mhx.policy-settings", "application-allow-list", "failed")
			return e.PolicySettings(), fmt.Errorf("application allow list entry %d rejected: %w", index, err)
		}
	}

	payload, err := json.Marshal(policyPersistedState{SchemaVersion: policySettingsSchemaVersion, AutoResponse: nextStored.AutoResponse, Notifications: nextStored.Notifications, UpdatedUTC: nextStored.UpdatedUTC})
	if err != nil {
		return e.PolicySettings(), err
	}
	if err := atomicWrite(e.policySettingsPath(), append(payload, '\n')); err != nil {
		e.ledgerAppend("mhx.policy-settings", "settings-persist", "failed")
		return e.PolicySettings(), fmt.Errorf("MHX settings persistence failed: %w", err)
	}
	if e.ledger != nil {
		if err := e.ledger.Append("mhx.policy-settings", "settings-applied", "summary-recorded"); err != nil {
			// Roll the file back to the previous verified settings so disk and
			// memory cannot disagree after a failed evidence commit.
			previousPayload, marshalErr := json.Marshal(policyPersistedState{SchemaVersion: policySettingsSchemaVersion, AutoResponse: current.AutoResponse, Notifications: current.Notifications, UpdatedUTC: time.Now().UTC()})
			if marshalErr == nil {
				_ = atomicWrite(e.policySettingsPath(), append(previousPayload, '\n'))
			}
			return e.PolicySettings(), fmt.Errorf("MHX settings evidence commit failed: %w", err)
		}
	}
	published := nextStored
	e.policySettings.Store(&published)
	e.mu.Lock()
	e.policySettingsSource = settingsSourcePersisted
	e.policySettingsWarning = ""
	e.policySettingsPersisted = true
	e.policySettingsUpdatedUTC = nextStored.UpdatedUTC
	e.mu.Unlock()
	return e.PolicySettings(), nil
}

// notificationID derives a stable identifier from the genuine event payload.
func notificationID(kind string, timestamp time.Time, title, detail string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + timestamp.Format(time.RFC3339Nano) + "\x00" + title + "\x00" + detail))
	return hex.EncodeToString(digest[:16])
}

// notifyEvent retains a real engine event when the operator notification policy
// allows that event class. It never creates entries without an actual event.
func (e *Engine) notifyEvent(kind string, severity Severity, title, detail string) {
	if e == nil {
		return
	}
	policy := e.currentPolicySettings().Notifications
	if !policy.EventFeedEnabled {
		return
	}
	switch kind {
	case notificationKindBlock:
		if !policy.BlockEvents {
			return
		}
	case notificationKindDefender:
		if !policy.DefenderEvents {
			return
		}
	case notificationKindThreatIntel:
		if !policy.ThreatIntelEvents {
			return
		}
	case notificationKindKinetic:
		if !policy.KineticEvents {
			return
		}
	default:
		return
	}
	if !severityAtLeast(severity, policy.MinimumSeverity) {
		return
	}
	now := time.Now().UTC()
	entry := Notification{
		ID:           notificationID(kind, now, truncate(title, 160), truncate(detail, 256)),
		TimestampUTC: now,
		Kind:         kind,
		Severity:     severity,
		Title:        truncate(title, 160),
		Detail:       truncate(detail, 256),
	}
	e.mu.Lock()
	e.notifications = append(e.notifications, entry)
	if len(e.notifications) > maximumNotificationEntries {
		e.notifications = append([]Notification(nil), e.notifications[len(e.notifications)-maximumNotificationEntries:]...)
	}
	e.mu.Unlock()
}

func (e *Engine) notifyBlockingAnalysis(result Analysis) {
	e.notifyEvent(notificationKindBlock, result.EffectiveSeverity, result.Detection, result.Classification)
}

// Notification is one genuine blocking/security event retained for display.
type Notification struct {
	ID           string    `json:"id"`
	TimestampUTC time.Time `json:"timestampUtc"`
	Kind         string    `json:"kind"`
	Severity     Severity  `json:"severity"`
	Title        string    `json:"title"`
	Detail       string    `json:"detail"`
}

// Notifications returns the newest-first bounded notification feed.
func (e *Engine) Notifications(limit int) []Notification {
	if e == nil {
		return []Notification{}
	}
	if limit <= 0 || limit > maximumNotificationEntries {
		limit = 50
	}
	e.mu.RLock()
	start := len(e.notifications) - limit
	if start < 0 {
		start = 0
	}
	result := append([]Notification(nil), e.notifications[start:]...)
	e.mu.RUnlock()
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func networkResponsePolicyAllows(settings PolicySettings, severity Severity) bool {
	return settings.AutoResponse.CorrelatedNetworkResponse && severityAtLeast(severity, settings.AutoResponse.MinimumSeverity)
}
