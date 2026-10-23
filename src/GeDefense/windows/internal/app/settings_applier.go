// STATUS: PLATIN
package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/visiongaiatechnology/gedefense/windows/internal/evidence"
	"github.com/visiongaiatechnology/gedefense/windows/internal/hardening"
	"github.com/visiongaiatechnology/gedefense/windows/internal/mhx"
	"github.com/visiongaiatechnology/gedefense/windows/internal/settings"
)

// settingsApplier is the narrow bridge between the generic V5 settings
// authority and the concrete Windows enforcement engines. It deliberately
// supports only primitives that the installed scripts can actually enforce;
// every other changed field is rejected instead of being persisted as a
// pretend setting.
type settingsApplier struct {
	hardening *hardening.Engine
	mhx       *mhx.Engine
	ledger    *evidence.Ledger
}

func (a *settingsApplier) Apply(ctx context.Context, change settings.Change) error {
	if a == nil || a.hardening == nil || a.mhx == nil {
		return errors.New("settings enforcement engine unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("settings apply requires an active request")
	}
	if err := a.applyHardeningSections(ctx, change); err != nil {
		return err
	}
	if err := a.applyMHXSections(ctx, change); err != nil {
		return err
	}
	if err := a.applyKinetic(ctx, change); err != nil {
		return err
	}
	if err := a.applyThreatIntelligence(ctx, change); err != nil {
		return err
	}
	// A profile activation must not be persisted as the new level until the MHX
	// protection-mode transaction has verified the actual Windows policy. The
	// per-section applier only patches MHX options; this closes the gap between
	// "settings document says sovereign" and "enforcement verified sovereign".
	if change.Kind == settings.ChangeProfile {
		target := strings.ToLower(stringValue(change.Sections[settings.SectionMHX]["aggressiveness"]))
		if target == "" {
			target = strings.ToLower(change.ProfileID)
		}
		if target != settings.LevelMonitor && target != settings.LevelGuarded && target != settings.LevelSovereign {
			return fmt.Errorf("protection profile %q has no verified enforcement mode", change.ProfileID)
		}
		if err := a.mhx.SetMode(ctx, target); err != nil {
			return fmt.Errorf("protection profile enforcement rejected: %w", err)
		}
	}
	if changed := changedFields(change.Changed, settings.SectionStartup); len(changed) > 0 {
		return errors.New("startup settings are not enforceable by this build")
	}
	if changed := changedFields(change.Changed, settings.SectionNotifications); len(changed) > 0 {
		return errors.New("notification settings are not enforceable by this build")
	}
	return nil
}

func (a *settingsApplier) applyHardeningSections(ctx context.Context, change settings.Change) error {
	defender := change.Sections[settings.SectionDefender]
	firewall := change.Sections[settings.SectionFirewall]
	hardeningValues := change.Sections[settings.SectionHardening]
	config := hardening.SettingsConfig{SchemaVersion: 1}
	changed := func(section string) map[string]bool {
		set := make(map[string]bool)
		for _, id := range change.Changed {
			if strings.HasPrefix(id, section+".") {
				set[strings.TrimPrefix(id, section+".")] = true
			}
		}
		return set
	}
	if len(defender) > 0 && len(changed(settings.SectionDefender)) > 0 {
		values, err := defenderSettings(defender, changed(settings.SectionDefender))
		if err != nil {
			return err
		}
		config.Defender = values
	}
	if len(firewall) > 0 && len(changed(settings.SectionFirewall)) > 0 {
		values, err := firewallSettings(firewall, changed(settings.SectionFirewall))
		if err != nil {
			return err
		}
		config.Firewall = values
	}
	if len(hardeningValues) > 0 && len(changed(settings.SectionHardening)) > 0 {
		components, err := hardeningComponents(hardeningValues, changed(settings.SectionHardening))
		if err != nil {
			return err
		}
		config.Components = components
	}
	if config.Defender == nil && config.Firewall == nil && len(config.Components) == 0 {
		return nil
	}
	if _, err := a.hardening.ApplySettings(ctx, config); err != nil {
		return fmt.Errorf("Windows protection settings rejected: %w", err)
	}
	return nil
}

func defenderSettings(values map[string]any, changed map[string]bool) (*hardening.DefenderSettings, error) {
	settings := &hardening.DefenderSettings{}
	supported := map[string]bool{
		"cloudBlockLevel": true, "sampleSubmission": true, "networkProtection": true,
		"puaProtection": true, "controlledFolderAccess": true, "asrRuleActions": true,
	}
	for key := range changed {
		if !supported[key] {
			return nil, fmt.Errorf("Defender setting %q is not enforceable by this build", key)
		}
	}
	if changed["cloudBlockLevel"] {
		value := strings.ToLower(stringValue(values["cloudBlockLevel"]))
		mapped := map[string]string{"default": "Default", "moderate": "Normal", "normal": "Normal", "high": "High", "highplus": "HighPlus", "zerotolerance": "ZeroTolerance"}[value]
		if mapped == "" {
			return nil, errors.New("unsupported cloud block level")
		}
		settings.CloudBlockLevel = &mapped
	}
	if changed["sampleSubmission"] {
		value := strings.ToLower(stringValue(values["sampleSubmission"]))
		mapped := map[string]string{"never": "NeverSend", "safe": "SendSafeSamples", "always": "SendAllSamples"}[value]
		if mapped == "" {
			return nil, errors.New("unsupported sample submission mode")
		}
		settings.SubmitSamplesConsent = &mapped
	}
	for key, target := range map[string]**string{
		"networkProtection": &settings.NetworkProtection, "puaProtection": &settings.PUAProtection,
		"controlledFolderAccess": &settings.ControlledFolderAccess,
	} {
		if changed[key] {
			mapped := "Disabled"
			if boolValue(values[key]) {
				mapped = "Enabled"
			}
			*target = &mapped
		}
	}
	if changed["asrRuleActions"] {
		rules, err := asrRules(values["asrRuleActions"])
		if err != nil {
			return nil, err
		}
		settings.ASRRules = rules
	}
	return settings, nil
}

func asrRules(raw any) ([]hardening.ASRRuleSetting, error) {
	items := stringListValue(raw)
	if len(items) > 32 {
		return nil, errors.New("too many ASR rules")
	}
	result := make([]hardening.ASRRuleSetting, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ASR rule entry %q", item)
		}
		id := strings.TrimSpace(parts[0])
		action := strings.TrimSpace(parts[1])
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			return nil, errors.New("ASR rule entries must use the canonical Defender rule UUID")
		}
		result = append(result, hardening.ASRRuleSetting{ID: id, Action: action})
	}
	return result, nil
}

func firewallSettings(values map[string]any, changed map[string]bool) (*hardening.FirewallSettings, error) {
	for key := range changed {
		switch key {
		case "domainProfileEnabled", "privateProfileEnabled", "publicProfileEnabled", "defaultInboundAction",
			"notificationsEnabled", "loggingEnabled", "logMaxSizeKB", "logDroppedPackets":
		default:
			return nil, fmt.Errorf("firewall setting %q is not enforceable by this build", key)
		}
	}
	profiles := make([]hardening.FirewallProfileSetting, 0, 3)
	for name, key := range map[string]string{"Domain": "domainProfileEnabled", "Private": "privateProfileEnabled", "Public": "publicProfileEnabled"} {
		profile := hardening.FirewallProfileSetting{Name: name}
		hasSetting := false
		if changed[key] {
			enabled := boolValue(values[key])
			profile.Enabled = &enabled
			hasSetting = true
		}
		if changed["defaultInboundAction"] {
			action := strings.ToLower(stringValue(values["defaultInboundAction"]))
			mapped := map[string]string{"block": "Block", "allow": "Allow"}[action]
			if mapped == "" {
				return nil, errors.New("unsupported firewall inbound action")
			}
			profile.DefaultInboundAction = &mapped
			hasSetting = true
		}
		if changed["notificationsEnabled"] {
			enabled := boolValue(values["notificationsEnabled"])
			profile.NotifyOnListen = &enabled
			hasSetting = true
		}
		if changed["loggingEnabled"] || changed["logDroppedPackets"] {
			enabled := boolValue(values["loggingEnabled"]) || boolValue(values["logDroppedPackets"])
			profile.LogBlocked = &enabled
			hasSetting = true
		}
		if changed["logMaxSizeKB"] {
			size := intValue(values["logMaxSizeKB"])
			profile.LogMaxSizeKilobytes = &size
			hasSetting = true
		}
		if hasSetting {
			profiles = append(profiles, profile)
		}
	}
	if len(profiles) == 0 {
		return nil, errors.New("no enforceable firewall setting supplied")
	}
	return &hardening.FirewallSettings{Profiles: profiles}, nil
}

func hardeningComponents(values map[string]any, changed map[string]bool) ([]string, error) {
	for key := range changed {
		if key != "enabledComponents" {
			return nil, fmt.Errorf("hardening setting %q is not enforceable by this build", key)
		}
	}
	components := stringListValue(values["enabledComponents"])
	if len(components) == 0 || len(components) > 32 {
		return nil, errors.New("hardening component list is empty or too large")
	}
	return components, nil
}

func (a *settingsApplier) applyMHXSections(ctx context.Context, change settings.Change) error {
	values := change.Sections[settings.SectionMHX]
	if len(values) == 0 {
		return nil
	}
	changed := changedFields(change.Changed, settings.SectionMHX)
	if len(changed) == 0 {
		return nil
	}
	policy := a.mhx.PolicySettings()
	patch := mhx.PolicySettingsPatch{}
	supported := map[string]bool{"aggressiveness": true, "autoTerminate": true, "notificationsEnabled": true}
	for key := range changed {
		switch key {
		case "applicationControl", "networkDefaultDeny":
			// These two are bound to the verified protection mode. A built-in
			// profile activation sets the mode in the same change and therefore
			// already covers them; a direct independent write is rejected.
			if change.Kind == settings.ChangeProfile && (change.ProfileID == settings.LevelSovereign || change.ProfileID == settings.LevelGuarded || change.ProfileID == settings.LevelMonitor) {
				continue
			}
			return fmt.Errorf("MHX setting %q is bound to the verified protection mode and cannot be set independently", key)
		default:
			if !supported[key] {
				return fmt.Errorf("MHX setting %q is not enforceable by this build", key)
			}
		}
	}
	if changed["aggressiveness"] {
		level := strings.ToLower(stringValue(values["aggressiveness"]))
		if level == "" {
			return errors.New("MHX aggressiveness is empty")
		}
		patch.Aggressiveness = &level
	}
	if changed["autoTerminate"] {
		auto := policy.AutoResponse
		auto.TerminateProcess = boolValue(values["autoTerminate"])
		patch.AutoResponse = &auto
	}
	if changed["notificationsEnabled"] {
		notifications := policy.Notifications
		notifications.EventFeedEnabled = boolValue(values["notificationsEnabled"])
		patch.Notifications = &notifications
	}
	if patch.Aggressiveness == nil && patch.AutoResponse == nil && patch.Notifications == nil {
		return nil
	}
	if _, err := a.mhx.SetPolicySettings(ctx, patch); err != nil {
		return fmt.Errorf("MHX settings rejected: %w", err)
	}
	return nil
}

func (a *settingsApplier) applyKinetic(ctx context.Context, change settings.Change) error {
	values := change.Sections[settings.SectionKinetic]
	if len(values) == 0 {
		return nil
	}
	changed := changedFields(change.Changed, settings.SectionKinetic)
	if len(changed) == 0 {
		return nil
	}
	allowed := map[string]bool{
		"persistedArmed": true, "burstWindowSeconds": true, "minEvents": true,
		"minDistinctPorts": true, "autoDisarmSeconds": true, "notificationsEnabled": true,
	}
	for key := range changed {
		if !allowed[key] {
			return fmt.Errorf("Kinetic setting %q is not enforceable by this build", key)
		}
	}
	snapshot := a.mhx.KineticSettings()
	config := snapshot.Config
	configChanged := false
	if changed["burstWindowSeconds"] {
		config.BurstWindowSeconds = intValue(values["burstWindowSeconds"])
		configChanged = true
	}
	if changed["minEvents"] {
		config.MinEvents = intValue(values["minEvents"])
		configChanged = true
	}
	if changed["minDistinctPorts"] {
		config.MinDistinctPorts = intValue(values["minDistinctPorts"])
		configChanged = true
	}
	if changed["autoDisarmSeconds"] {
		config.AutoDisarmSeconds = intValue(values["autoDisarmSeconds"])
		configChanged = true
	}
	if configChanged {
		if _, err := a.mhx.SetKineticConfig(ctx, config); err != nil {
			return fmt.Errorf("Kinetic thresholds rejected: %w", err)
		}
	}
	if changed["persistedArmed"] {
		if _, err := a.mhx.SetKineticDesiredState(ctx, boolValue(values["persistedArmed"])); err != nil {
			return fmt.Errorf("Kinetic persistence intent rejected: %w", err)
		}
	}
	if changed["notificationsEnabled"] {
		policy := a.mhx.PolicySettings()
		notifications := policy.Notifications
		notifications.KineticEvents = boolValue(values["notificationsEnabled"])
		if _, err := a.mhx.SetPolicySettings(ctx, mhx.PolicySettingsPatch{Notifications: &notifications}); err != nil {
			return fmt.Errorf("Kinetic notification policy rejected: %w", err)
		}
	}
	return nil
}

func (a *settingsApplier) applyThreatIntelligence(ctx context.Context, change settings.Change) error {
	values := change.Sections[settings.SectionThreatIntelligence]
	if len(values) == 0 {
		return nil
	}
	changed := changedFields(change.Changed, settings.SectionThreatIntelligence)
	for key := range changed {
		switch key {
		case "pollIntervalSeconds", "protectedNetworks":
		default:
			return fmt.Errorf("Threat Intelligence setting %q is not enforceable by this build", key)
		}
	}
	if changed["pollIntervalSeconds"] {
		seconds := intValue(values["pollIntervalSeconds"])
		if _, err := a.mhx.SetThreatIntelPolling(ctx, seconds); err != nil {
			return fmt.Errorf("Threat Intelligence polling rejected: %w", err)
		}
	}
	if changed["protectedNetworks"] {
		if _, err := a.mhx.SetProtectedNetworkPolicy(ctx, stringListValue(values["protectedNetworks"])); err != nil {
			return fmt.Errorf("protected network policy rejected: %w", err)
		}
	}
	return nil
}

func changedFields(ids []string, section string) map[string]bool {
	result := make(map[string]bool)
	prefix := section + "."
	for _, id := range ids {
		if strings.HasPrefix(id, prefix) {
			result[strings.TrimPrefix(id, prefix)] = true
		}
	}
	return result
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func boolValue(value any) bool {
	boolean, ok := value.(bool)
	return ok && boolean
}

func intValue(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case int64:
		return int(number)
	default:
		return 0
	}
}

func stringListValue(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if direct, ok := value.([]string); ok {
			return direct
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
